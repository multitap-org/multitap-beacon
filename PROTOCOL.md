# Beacon protocol v1

Draft by the netcode session (2026-11-20), fixed and frozen by the beacon session the same
day. The canonical copy is `PROTOCOL.md` in the beacon repo (multitap-org/multitap-beacon, local
`.repos/beacon`); this file is kept identical. The wire code is `wire/beacon_wire.h/.cpp`
there: frontends-common should use that library (submodule), not re-implement the layout.

Goal: two piccolo-family programs that are ALREADY paired (piccolo host + piccoletto client)
find each other across the internet. The server reflects public addresses (STUN-like) and
introduces peers; both sides then punch through NAT on their own ENet socket. NO relay, ever:
if punching fails, the client says "couldn't connect". Decisions (Andrés): free software, MIT,
easy to self-host, server configurable in piccolo with one default; C++ (project STYLE.md).
Later (phase 2): a signed central directory of servers. The protocol must never let anyone
make the server (or a peer) run anything: fixed-size binary messages only, no strings, no
lengths taken from the wire.

## Transport

- UDP only. Server listens on two ports: PRIMARY (default 55430) and SECONDARY (55431, for
  NAT-type detection). IPv6 and IPv4 on one dual-stack socket each (IPv4-mapped).
- PRIMARY answers BIND, REGISTER and MEET. SECONDARY answers BIND only (anything else there is
  dropped).
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
  (requests are padded with zeros to their reply's size). The server sends to a third address
  only in one case: the INTRO to a host that registered with a valid cookie (so it proved it
  receives at that address), at most 4 per second per registration.

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

## Security notes

- The server never parses anything variable: every message is a fixed struct, checked field by
  field. Fuzzed (libFuzzer) with a decode -> encode round-trip check.
- The server is not authenticated in v1 (phase 2: signed directory). A spoofed INTRO can at
  most make a peer send PUNCHes (32 bytes, 50 of them) to some address, and only for an id the
  peer has registered or asked for.
- The server sees which public addresses meet which, and when. It never sees keys, device
  names or game data. It logs counts only.

## Server program (repo multitap-org/multitap-beacon, MIT)

- One small C++20 binary (STYLE.md: C-like, no auto / lambdas / templates / exceptions), only
  libc + sockets (Linux; other POSIX / Windows later if cheap) + Monocypher (submodule) for the
  cookie and table hashing. Wire format in its own small library (`beacon_wire.h/.cpp`,
  no dependencies) that frontends-common will also use (submodule in piccolo's deps/).
- Command line: ports, bind address, table sizes, per-source limits, log level. Logs counts,
  never meeting ids or addresses.
- Ships: README (self-hosting in 5 minutes), systemd unit, Dockerfile, tests (unit + a loopback
  end-to-end: two fake peers register/meet and get each other's address), a libFuzzer target for
  the parser, builds clean with -Wall -Wextra -Werror and ASan/UBSan.
- Default server for piccolo: domain still to be decided by Andrés.

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
