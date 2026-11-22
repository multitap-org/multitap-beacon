# Beacon protocol v1

Draft by the netcode session (2026-11-20), fixed and frozen by the beacon session the same
day. The canonical copy is `PROTOCOL.md` in the beacon repo (multitap-org/multitap-beacon, local
`.repos/beacon`); this file is kept identical. The wire code is `wire/beacon_wire.h/.cpp`
there: frontends-common should use that library (submodule), not re-implement the layout.

Goal: two piccolo-family programs that are ALREADY paired (piccolo host + piccoletto client)
find each other across the internet. The server reflects public addresses (STUN-like) and
introduces peers; both sides then punch through NAT on their own ENet socket. NO relay, ever:
if punching fails, the client says "couldn't connect". Decisions (Andrés): free software, MIT,
easy to self-host, server configurable in piccolo with one default; C++.
Later (phase 2): a signed central directory of servers. The protocol must never let anyone
make the server (or a peer) run anything: fixed-size binary messages only, no strings, no
lengths taken from the wire.

## Transport

- UDP only. Server listens on two ports: PRIMARY (default 55430) and SECONDARY (55431, for
  NAT-type detection). IPv6 and IPv4 on one dual-stack socket each (IPv4-mapped).
- PRIMARY answers BIND, REGISTER and MEET. SECONDARY answers BIND only (anything else there is
  dropped). Both also answer STUN Binding Requests (see STUN).
- Every message starts with an 8-byte header:
  `magic "MTBC"` (4) | `version 1` (1) | `type` (1) | `reserved 0` (2).
- Each type has ONE exact total size (table below). A packet is dropped silently when its size
  isn't exactly that, or the magic, version or type is wrong, or the reserved bytes, the zero
  padding or any field rule below doesn't hold. Nothing is ever read as a length.
- Integers little-endian (ports and ttl included). The nonce is 8 opaque bytes (the code holds
  it as a uint64_t written little-endian, so any byte order round-trips).
- Address (20 bytes): 16-byte IPv6 in network order (IPv4 as `::ffff:a.b.c.d`) | port (2, LE)
  | 2 bytes zero. Port 0 is invalid.
- Meeting id (16 bytes): all zero is invalid.
- Anti-amplification: every reply to the sender is the same size or smaller than the request
  (requests are padded with zeros to their reply's size), with ONE exception, STUN (below). The
  server sends to a third address only in one case: the INTRO to a host that registered with a
  valid cookie (so it proved it receives at that address), at most 4 per second per
  registration.
- STUN shares the sockets: a packet whose first byte has its two top bits zero (0x00-0x3F,
  RFC 7983) is STUN; "MTBC" starts with 0x4D. See "STUN" below.

## Messages

Offsets count from the start of the packet (the header is bytes 0-7).

| type | name | dir | total | body |
|---|---|---|---|---|
| 1 | BIND | c->s | 36 | 8 nonce, 16 zero (20) |
| 2 | BOUND | s->c | 36 | 8 nonce, 16 observed address (20) |
| 3 | REGISTER | host->s | 164 | 8 nonce, 16 cookie (16, zero = none), 32 count 1-8, 33 zero (3), 36 ids[8] (16 each) |
| 4 | COOKIE | s->host | 32 | 8 nonce, 16 cookie (16) |
| 5 | REGISTERED | s->host | 36 | 8 nonce, 16 fresh cookie (16), 32 accepted 0-8, 33 zero (1), 34 ttl seconds (2) |
| 6 | MEET | c->s | 52 | 8 nonce, 16 meeting id (16), 32 zero (20) |
| 7 | INTRO | s->both | 52 | 8 nonce (the MEET's), 16 meeting id (16), 32 the other side's address (20) |
| 8 | NOT_FOUND | s->c | 32 | 8 nonce, 16 meeting id (16) |
| 9 | PUNCH | peer<->peer | 32 | 8 nonce (the MEET's), 16 meeting id (16) |

Field rules: REGISTER's ids `[0, count)` are non-zero and the ids from `count` on are all zero;
REGISTERED's accepted is 0-8; every address has a non-zero port and zero padding.

- **Meeting id** (computed by the peers, opaque to the server): first 16 bytes of
  BLAKE2b("multitap beacon v1" || X25519(own static, other's static)). Both sides of a
  pairing compute the same id; the server can't link it to keys or devices. (An all-zero
  result is astronomically unlikely; if it happens, that pairing just can't use beacon.)
- **REGISTER** comes from the host's ENet socket (so the stored address is that socket's NAT
  mapping): one per 8 paired devices, every 20 s (this also keeps the mapping alive).
  - Cookie zero or not valid: the server answers COOKIE only and stores nothing. The host
    resends the REGISTER at once with that cookie.
  - Cookie valid: the server stores, per id, (address, expiry = now + 60 s) and answers
    REGISTERED with how many ids it accepted, the ttl (60) and a FRESH cookie: the host uses
    that one in its next REGISTER, so in steady state there's no extra round trip.
  - Cookie = first 16 bytes of keyed BLAKE2b(key = server secret of epoch E,
    message = address ip (16) | port LE (2) | E as u64 LE (8)). An epoch is 60 s; each epoch
    gets a new random 32-byte secret and the server keeps the previous one, so a cookie is
    valid for 60-120 s. Server restart = new secrets: hosts just get a COOKIE and go on.
  - The server keeps one entry per id AND address family (IPv4 / IPv6). A host whose server has
    both A and AAAA records should register over both (same ENet socket, dual-stack), so a
    client on either family finds it. Re-registering an id from a new address moves the entry
    (NAT rebinding); Noise XX authenticates later, so a hijack can only deny service, and ids
    are secret.
  - Limits: ids per source (default 128; source = the IPv4 address, or the IPv6 /64), total
    entries (default 65536). Ids over a limit aren't stored (accepted < count tells the host).
- **MEET** comes from the client's ENet socket too (that's the address the host will punch).
  Registered: INTRO to the client (host's address) and INTRO to the host (client's address),
  both with the MEET's nonce, same family entry preferred. Not registered: NOT_FOUND. A second
  MEET for the same entry within 250 ms is dropped (the client retries every 500 ms if it got
  nothing).
- **BIND** to PRIMARY and SECONDARY from the same socket: different observed ports =
  endpoint-dependent mapping (symmetric NAT: punching will likely fail; the client can say so
  early).
- **Rate limits** per source (IPv4 address or IPv6 /64): token bucket, default 20 packets/s,
  burst 60, every message type counts. Sources that don't fit in the source table (full of
  recently active sources) share one overflow bucket (default 1000 packets/s). Over the limit:
  dropped silently.
- After INTRO both peers send PUNCH every 100 ms for up to 5 s to the given address while the
  client also starts the ENet connect; first ENet connection wins (then Noise XX as on the LAN,
  which authenticates; PUNCH carries nothing secret). No answer in 5 s: "couldn't connect".
  PUNCH, like the server's replies, arrives on the ENet socket: the intercept callback picks out
  packets that decode as beacon messages (exact size + magic), everything else goes to ENet.
- The host accepts INTRO only from the configured server's address and only for ids it
  registered; the client accepts INTRO / NOT_FOUND only for its pending MEET's nonce and id.

## STUN

beacon is also a plain STUN server for browsers (WebRTC's `iceServers:
[{urls: "stun:<beacon>:55430"}]`): it answers RFC 5389 / 8489 Binding Requests on PRIMARY,
SECONDARY and, if the operator opens it, a STUN-only port (`--stun-port`, usually 3478, off by
default; that socket answers STUN and nothing else).

- Accepted: exactly type 0x0001 (Binding Request) with the magic cookie 0x2112A442; size 20-548
  bytes, a multiple of 4, equal to 20 + the length field; the attributes (4-byte header, value
  padded to 4) fill the body exactly. Their contents are never read (no MESSAGE-INTEGRITY, no
  FINGERPRINT check: public STUN). Anything else is dropped silently: indications, responses,
  other methods, RFC 3489 requests without the cookie. No error responses are ever sent.
- Response: Binding Success (0x0101), same transaction id, one attribute: XOR-MAPPED-ADDRESS
  with the address beacon would report in BOUND (`--public-address` applies). 32 bytes for an
  IPv4 sender (an IPv4-mapped address is answered as family 0x01), 44 for IPv6.
- Same per-source rate limit as every other message.
- **The amplification exception:** browsers send header-only requests (20 bytes) and beacon
  can't make them pad, so a response is 1.6x the request for IPv4 (32 / 20) and 2.2x for IPv6
  (44 / 20). That's what every public STUN server does; the per-source token bucket and the
  overflow bucket cap what any one spoofed address can receive.

## Signaling (WebRTC)

For browsers, which can't send raw UDP: a WebSocket listener carries the WebRTC offer, answer
and ICE candidates between two peers that know the same meeting id. beacon passes them along
without reading them; the peers then connect directly (ICE, with beacon as their STUN server).
There is no relay here either: if ICE fails, the client says "couldn't connect".

### Transport

- WebSocket (RFC 6455) on TCP 55432, bound to 127.0.0.1 by default. beacon never does TLS: a
  proxy (Caddy, Nginx Proxy Manager) serves it as `wss://<beacon>/signal` (any path). Browsers on
  an https page refuse plain ws://, so the proxy is required for any browser use.
- The client opens it with the subprotocol `multitap-beacon.1`
  (`new WebSocket(url, "multitap-beacon.1")`); a handshake without it gets HTTP 400.
- Strict subset: binary messages only, one frame each (no fragmentation), masked, no
  extensions (permessage-deflate is declined), lengths up to 4120 bytes in the 7-bit or 16-bit
  form. Text, continuation, a 64-bit length or a broken rule close the socket (1003, 1002 or
  1009). Ping gets pong; close is echoed.
- Timeouts: 5 s to finish the handshake; a socket that sends no frame for 60 s is closed (1001).
  A host re-sends its JOINs every 20 s, which also keeps the socket open.

### Messages

One binary WebSocket message = one message, with the same 8-byte header as UDP (`"MTBC"`,
version 1, type, two zero bytes) and types from 16 up (they never decode as UDP messages, nor
the reverse). Room = a meeting id (16 bytes, never zero). Every type has one fixed size except
SIGNAL, whose blob size is the WebSocket message's size minus 24 (never a field).

| type | name | dir | total | body |
|---|---|---|---|---|
| 16 | JOIN | c->s | 28 | 8 room (16), 24 role (1 = host, 2 = client), 25 zero (3) |
| 17 | JOINED | s->c | 28 | 8 room (16), 24 other side present (0 / 1), 25 zero (3) |
| 18 | LEAVE | c->s | 24 | 8 room (16) |
| 19 | PEER_JOINED | s->c | 24 | 8 room (16) |
| 20 | LEFT | s->c | 24 | 8 room (16) |
| 21 | SIGNAL | both | 25-4120 | 8 room (16), 24 blob (1-4096 bytes) |
| 22 | NOT_FOUND | s->c | 24 | 8 room (16) |
| 23 | REFUSED | s->c | 28 | 8 room (16), 24 reason (1 = too many rooms on this socket, 2 = room table full, 3 = guests full, 4 = wrong room kind, 5 = guest JOINs too often), 25 zero (3) |
| 24 | GUEST_JOINED | s->c | 28 | 8 room (16), 24 guest (0-7), 25 zero (3) |
| 25 | GUEST_LEFT | s->c | 28 | 8 room (16), 24 guest (0-7), 25 zero (3) |
| 26 | GUEST_SIGNAL | both | 29-4120 | 8 room (16), 24 guest (0-7), 25 zero (3), 28 blob (1-4092 bytes) |

JOIN's role is 1 = host, 2 = client, 3 = guest room host, 4 = guest (guest rooms below).

- A room holds one host socket and one client socket. **JOIN** puts the socket on its role's
  side and answers JOINED (with whether the other side is there); the other side, if present,
  gets PEER_JOINED. JOIN again from the same socket refreshes it (the host's keepalive). JOIN
  for a side another socket holds **replaces** it (a reconnect before the old socket timed
  out): the old socket gets LEFT and leaves the room, and the other side gets PEER_JOINED again
  (start over). One socket can't hold both sides of a room (closed, 1008).
- **SIGNAL** from a socket in the room goes to the other side byte for byte (the whole message,
  header included). With no one on the other side, or from a socket not in the room:
  NOT_FOUND (the client maps it to "host offline", as on UDP).
- **LEAVE**, or the socket closing, takes it out of its rooms; the other side gets LEFT. A room
  with nobody left is forgotten.
- Over a limit, JOIN gets REFUSED (nothing changes). Any other client message that doesn't
  decode, or a server-only type, closes the socket (1002).
- **Blobs are end-to-end encrypted by the peers** (beacon never sees SDP or candidates, so
  never the peers' IPs from them): `crypto_aead_lock` (XChaCha20-Poly1305), a random 24-byte
  nonce per blob, the direction (host to client / client to host) in the associated data, key
  = BLAKE2b("multitap signal v1" || X25519(own, other)). 40 bytes of overhead; a data-channel
  SDP is 0.5-1 KiB, so 4096 is plenty. Tampering only breaks the connection; Noise XX
  authenticates afterwards anyway. (The pairing room, which has no shared key yet, is the one
  plain-text case: see the netcode notes.)

### Guest rooms (guest links)

A piccolo streaming to friends who open a link (piccolo's REMOTE PLAY TOGETHER) meets several
guests in one room:

- **JOIN role 3** (guest room host) makes the room, or refreshes it (the host's 20 s keepalive).
  A second host socket replaces the first: the old one gets LEFT, and so does every guest (they
  start over).
- **JOIN role 4** (guest) only enters a guest room whose host is there (else NOT_FOUND; a guest
  never makes a room). The guest gets the first free index (0-7): JOINED (other side present)
  to the guest, GUEST_JOINED with the index to the host. With 8 guests: REFUSED 3. Guest JOINs
  that aren't refreshes cost a token: 10 a minute per socket, burst 5 (REFUSED 5).
- A guest's **SIGNAL** reaches the host as **GUEST_SIGNAL** with the guest's index; the host's
  GUEST_SIGNAL reaches that guest as SIGNAL. A guest's blob is at most 4092 bytes (it must fit
  with the index): a larger one closes the guest's socket (1009). A GUEST_SIGNAL to an index
  nobody holds gets the host a GUEST_LEFT. The host's plain SIGNAL in a guest room gets
  NOT_FOUND.
- A guest leaving (LEAVE or its socket closing): GUEST_LEFT to the host. The host leaving ends
  the room: every guest gets LEFT.
- Roles 1 / 2 on a guest room, and 3 / 4 on a plain room: REFUSED 4.
- Guests use the same blob sealing as everyone, with a key from the link's token (below), which
  beacon never sees.

### Guest links: the join page and its card

Besides WebSocket, the same listener answers a few plain HTTP/1.1 requests (no Upgrade header):

| request | answer |
|---|---|
| GET or HEAD `/join/<room>` | the join page (HTML): opens piccoletto, with og:title / og:image for chat apps |
| GET or HEAD `/join/<room>/card.png` | the card's PNG, or 404 |
| POST `/join/<room>/card` | 204, or 400 / 403 / 404 / 413 / 429 / 503 |

- A link is `https://<beacon>/join/<room>#<token>`. The token (26 base32 characters, 130 bits)
  is after the `#`: browsers never send it, so beacon never sees it. From it (BLAKE2b, `||` is
  concatenation, the prefixes are their ASCII bytes):
  - card key = BLAKE2b-256("multitap guest card v1" || token), the host's proof for the card;
  - room = the first 13 lowercase base32 characters (RFC 4648 alphabet, 65 bits) of
    BLAKE2b-256("multitap guest room v1" || card key): the link's `<room>`;
  - meeting id = BLAKE2b-128("multitap guest v1" || room): the guest room (signaling) and the
    UDP meeting id;
  - signaling key = BLAKE2b-256("multitap guest signal v1" || token): the blobs' sealing key.
  So beacon can check a card upload against the room without the token, and nobody can put a
  card on someone else's room.
- The upload's body (Content-Length, at most 256 KiB + 97): card key (32), title length (1),
  title (1-64 bytes of UTF-8, no control characters), then a PNG (at most 256 KiB, 1280 x 960:
  its signature and IHDR are checked, nothing else is read). Accepted only while the room's
  host is in its guest room (404 otherwise, checked before the body is read and again after);
  a card key that doesn't hash to the room: 403. One card per room; replacing it 4 times a
  minute at most (429).
- The page is the same for everyone; its title and image are the card's (escaped), or a plain
  "A piccolo session" with the piccolo icon. Its script reads the token from the `#` and offers
  piccoletto: on Android an `intent://join/<room>?t=<token>` with piccoletto in the browser as
  the fallback, elsewhere piccoletto in the browser
  (`https://get-piccolo.app/play/piccoletto/#join=<room>.<token>`; `&b=<host>` is added for a
  beacon other than beacon.get-piccolo.app). The page sends nothing.
- Cards live in memory only (64 by default, `--max-cards`), and are deleted 60 s after their
  guest room ends (the grace covers a host's reconnect). A card being sent when it's replaced
  or deleted is cut off (the connection closes).
- Strict subset: one request per connection (`Connection: close`), heads up to 4 KiB, no
  chunked bodies, no body on GET. Uploads and pages take a slot from small pools (4 and 32 by
  default): with none free, 503. 20 s to send an upload's body, 30 s to read a response.

### Limits

Per socket: 64 rooms; 20 messages per second (burst 60) and 16 KiB per second (burst 64 KiB);
over a rate, the socket closes (1008). Per source (IPv4 address or IPv6 /64): 8 sockets; more
get HTTP 429 at the handshake. 1024 sockets and 65536 rooms in total. All are options.

The source is the TCP peer, or, when the peer is a trusted proxy (`--trusted-proxy`; loopback
always), the last address of the handshake's last `X-Forwarded-For` header. Caddy sets that
header to the client's address (it ignores what clients send unless told to trust them).

## Security notes

- The server never parses anything variable: every message is a fixed struct, checked field by
  field. Fuzzed (libFuzzer) with a decode -> encode round-trip check. The exceptions, each
  fuzzed on its own: STUN's attribute list (only walked to check that it fits), the WebSocket
  handshake (HTTP headers, at most 4 KiB, strict) and frames, SIGNAL's blob (never read:
  its length comes from the frame, capped at 4096), and the guest links' HTTP requests and
  card uploads (fuzzed: request heads, the upload's fields, the PNG's IHDR; the rest of the
  PNG is never read, only served back with nosniff).
- The server is not authenticated in v1 (phase 2: signed directory). A spoofed INTRO can at
  most make a peer send PUNCHes (32 bytes, 50 of them) to some address, and only for an id the
  peer has registered or asked for.
- The server sees which public addresses meet which, and when. It never sees keys, device
  names or game data. It logs counts only.

## Server program (repo multitap-org/multitap-beacon, MIT)

- One small C++20 binary (C-like, no auto / lambdas / templates / exceptions), only
  libc + sockets (Linux; other POSIX / Windows later if cheap) + Monocypher (submodule) for the
  cookie and table hashing. Wire format in its own small library (`beacon_wire.h/.cpp`,
  no dependencies) that frontends-common will also use (submodule in piccolo's deps/); it has
  the signaling messages too (`beacon_signaling_encode` / `_decode`). One epoll loop serves the
  UDP sockets and the WebSocket listener (fixed connection pool and room table, allocated at
  start).
- Command line: ports, bind address, table sizes, per-source limits, log level, and
  `--public-address` for a server behind a NAT with port forwarding: senders with private
  addresses (its own LAN, through NAT loopback) are reported with that public IP and their
  own port; replies still go to their real address. Nothing on the wire changes. Logs counts,
  never meeting ids or addresses.
- Ships: README (self-hosting in 5 minutes), systemd unit, Dockerfile, tests (unit + a loopback
  end-to-end: two fake peers register/meet and get each other's address), a libFuzzer target for
  the parser, builds clean with -Wall -Wextra -Werror and ASan/UBSan.
- Default server for piccolo: domain still to be decided by Andrés (the WebRTC plan uses
  beacon.get-piccolo.app: STUN on 55430, signaling at wss://beacon.get-piccolo.app/signal).

## Changes from the first draft

- Renamed (Andrés): the server is **beacon** (was "rendezvous"): repo multitap-org/multitap-beacon,
  binary `beacon`, library `beacon_wire`. The magic is now "MTBC" (was "MTRV") and the meeting
  id's BLAKE2b prefix is "multitap beacon v1" (was "multitap rendezvous v1").
- Exact sizes and offsets written down (BIND/BOUND 36, REGISTER 164, COOKIE 32, REGISTERED 36,
  MEET/INTRO 52, NOT_FOUND/PUNCH 32); REGISTERED has one zero byte between accepted and ttl.
- PUNCH: nonce first, then id (same order as every other message), and the nonce is the MEET's.
- Strict decoding: reserved bytes, padding and unused ids must be zero; count 1-8; accepted 0-8;
  port non-zero; id non-zero.
- Cookie scheme fixed: per-epoch random secret (60 s) + epoch number in the hash, previous epoch
  accepted; REGISTERED carries a fresh cookie (it used to need a COOKIE round trip every time
  the cookie aged out).
- One entry per id and address family, so IPv4-only and IPv6 clients both find a dual-stack host.
- Per-registration INTRO limit (4/s), per-source limits defined by IPv4 address / IPv6 /64,
  overflow bucket for sources that don't fit the table.
- REGISTER and MEET must come from the ENet socket; SECONDARY answers BIND only.
- STUN Binding (for browsers) on PRIMARY and SECONDARY, and on an optional STUN-only port;
  the one reply larger than its request (2026-11-20, WebRTC plan step 2).
- Signaling over WebSocket (types 16-23, rooms with a role byte, end-to-end encrypted blobs),
  2026-11-20, WebRTC plan step 3.
