# beacon

A small UDP server that lets two **already paired** devices of the Multitap
family (a [piccolo](https://github.com/multitap-org/piccolo) host and a
piccoletto client) find each other across the internet and connect
**directly**, by UDP hole punching. MIT licensed, one C++ binary, no
configuration file, no database, no disk.

## What it does

1. **Reflects addresses** (BIND / BOUND, like STUN): a device asks "how do you
   see me?" and learns its public address and port. Asking on both ports tells
   it whether its NAT changes ports per destination (symmetric NAT, where
   punching usually fails), so it can say so early.
2. **Keeps a short-lived list of meeting ids**: a piccolo host registers one
   id per paired device every 20 seconds; an id is forgotten 60 seconds after
   the last refresh. A meeting id is a hash both sides of a pairing compute
   from their keys; the server can't tell which devices or keys it belongs to.
3. **Introduces**: when a client asks for an id that is registered, the server
   sends each side the other's public address. Both then send packets to each
   other at the same time, which opens their NATs, and connect directly. The
   connection is encrypted and authenticated end to end (Noise XX, the same as
   on a LAN); the server never sees any of it.

For browsers (WebRTC), which can't send raw UDP, it also is:

4. **A STUN server**: standard Binding Requests on the same UDP ports get the
   sender's public address back.
5. **A signaling relay**: a WebSocket listener (behind a TLS proxy) where two
   peers that know the same meeting id meet in a "room" and pass each other
   their WebRTC offer, answer and ICE candidates. Those messages are encrypted
   end to end by the peers: beacon passes them along without being able to
   read them. The connection itself is then direct, as with UDP.

The wire format is in [`PROTOCOL.md`](PROTOCOL.md): every message is a fixed
size binary struct, nothing is ever read as a length or a string, and a reply
is never bigger than the request that caused it (so the server can't be used
to amplify attacks). The one exception is STUN, whose responses are 32 or 44
bytes for a 20-byte request, as on every STUN server; the rate limits cap it.

## What it doesn't do

- **It never relays traffic, and never will.** No TURN, no fallback through
  the server. If the two devices can't reach each other directly (both behind
  symmetric NATs or strict firewalls, for example), the client tells the user
  it couldn't connect. That keeps a server nearly free to run: it handles a
  few tiny packets per connection, never a game stream.
- No accounts, no logins, no device names, no storage on disk. A restart
  forgets everything; hosts re-register within 20 seconds.
- It doesn't log meeting ids or addresses, only counts (packets, registrations,
  introductions, drops).
- It doesn't authenticate itself (yet): a later version adds a signed
  directory of servers. The peers authenticate each other, so a rogue server
  can at worst fail to introduce them.

## Planned: the netplay lobby

The netplay lobby will live here too, in this server and on its status page:
a list of the open netplay rooms, so players can find a game to join. piccolo
has no netplay yet, so there's no design: what a room shows, how long it's
listed and how joining works are all open. One thing is decided: a room is
listed only when its host chooses to make it public. Pairing introductions stay
as they are, anonymous and never listed.

## Self-hosting in a few minutes

Any Linux machine with a public IP works (a small VPS is plenty: the default
tables take 14 MiB of memory). Open **UDP 55430 and 55431** in your firewall,
on IPv4 and IPv6 if you have it. Then pick one of these.

### Build and run directly

```sh
sudo apt install git cmake ninja-build g++          # Debian / Ubuntu
git clone --recursive https://github.com/multitap-org/multitap-beacon.git
cd multitap-beacon
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/beacon
```

### As a systemd service

After building:

```sh
sudo install -m 755 build/beacon /usr/local/bin/beacon
sudo install -m 644 packaging/beacon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now beacon
journalctl -u beacon -f
```

The unit runs it as a throwaway user with no privileges, no file access and
only IPv4 / IPv6 sockets.

### With Docker

Every push to `main` publishes `ghcr.io/multitap-org/beacon:latest` (amd64 and
arm64; version tags as `:X.Y.Z`):

```sh
docker run -d --name beacon --restart unless-stopped --network host ghcr.io/multitap-org/beacon:latest
```

In a compose file:

```yaml
  beacon:
    image: ghcr.io/multitap-org/beacon:latest
    restart: unless-stopped
    network_mode: host
    command: ["--status-file", "/status/status.json"]
    volumes:
      - ./beacon-status:/status    # owned by uid 65534 (nobody)
```

To build it yourself instead: `git clone --recursive` this repository and
`docker build -t beacon .` in it.

Use `--network host`. The server's whole job is to see where packets really
come from, and Docker's port publishing can hide that (through docker-proxy,
every IPv6 client looks like it comes from the Docker host itself).

### Point piccolo at it

In piccolo (once its client side lands): SETTINGS > NETWORK, beacon
server, `your.host.name` (port 55430 unless you changed it). Give your server a DNS name with both A and
AAAA records if it has IPv6: hosts register over both, so clients on either
find them.

### Behind a NAT (port forwarding)

The server doesn't need a public IP on its own interface: a router or
firewall that forwards UDP 55430 and 55431 to it (plain DNAT, which keeps the
senders' addresses) works. Point the DNS name at the router's public IP.

One case needs help: devices on the server's own network reach it through the
router's NAT loopback, so the server sees their private address and can't
learn their public one. Tell it the public address:

```sh
beacon --public-address 203.0.113.10
```

Senders from private addresses (10/8, 172.16/12, 192.168/16, 100.64/10,
loopback, link-local; IPv6 ULA and link-local) are then reported with that
address and their own port. That's right when the router keeps source ports
on the way out, which Linux-based routers (OpenWrt, most home routers) and
MikroTik do; pfSense and OPNsense change them unless "static port" is set in
their outbound NAT. Devices outside the network don't need any of this.

The router's public IP must be a real one: behind carrier-grade NAT (a WAN
address in 100.64/10 or another private range) nothing outside can reach the
server; use a VPS then.

### Status page

`packaging/status/` is a public page that shows how many clients are online
on the beacon right now and how many pairings (introductions) it made in the
last hour, with charts of the last 7 days, 30 days and 12 months below.
beacon itself serves no HTTP: with `--status-file PATH` it writes counts
(never ids or addresses) every 10 seconds, replacing the file atomically:

```json
{"hosts_online": 12, "introductions_last_hour": 40, "updated": 1795000000}
```

and `history.json` in the same directory, every 15 minutes and when it stops:
three rings of `[bucket start, most hosts online in it, introductions in it]`
(15-minute buckets for a week, hours for 30 days, UTC days for a year),
about 60 KiB when full. beacon reads it back when it starts, so the charts
survive restarts as long as the directory does; buckets while beacon was down
show as gaps.

```json
{"updated": 1795000000,
"week": {"bucket_seconds": 900, "points": [[1794999600, 12, 3], ...]},
"month": {"bucket_seconds": 3600, "points": [...]},
"year": {"bucket_seconds": 86400, "points": [...]}}
```

`hosts_online` counts the distinct host addresses with a live registration: a
host registered over IPv4 and IPv6 counts once, two piccolos behind one public
IP count twice. The page reads `status.json` next to itself every 30 seconds
and says the beacon isn't answering when the file is older than a minute. Any
web server that serves `index.html`, `_site/`, the status file and
`history.json` from one directory works.

The page has the look all piccolo websites share (the sites bar, the footer,
Fredoka + IBM Plex Mono; piccolo-site's `assets/README.md`) from its own copy,
`packaging/status/_site/v1/`, so it stands on its own: it loads nothing from
another server. The Docker image's entrypoint (`packaging/status-page.sh`)
copies `index.html` and `_site/` into `/status` (`BEACON_STATUS_DIR`) at every
start, so the page always matches the image. The copy follows get-piccolo.app:
the Site look workflow compares it with `https://get-piccolo.app/assets/v1/`
every day and opens a pull request when the site changed (by hand:
`tools/fetch-site-assets.sh packaging/status/_site/v1` and
`tools/sync-snippets.sh packaging/status/_site/v1 packaging/status/index.html`).

**systemd + Caddy.** `systemctl edit beacon`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/beacon --status-file /run/beacon/status.json
RuntimeDirectory=beacon
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
```

(`/run` is emptied on reboot, so the charts start over then; beacon restarts
keep them. To keep them across reboots, give beacon a fixed user instead of
`DynamicUser`, `StateDirectory=beacon`, `StateDirectoryMode=0755` and
`--status-file /var/lib/beacon/status.json`: with `DynamicUser` the state
directory sits under `/var/lib/private`, which Caddy can't read.)

and in the Caddyfile (`index.html` and `_site/` copied to `/srv/beacon-status`):

```
beacon.example.org {
    @data path /status.json /history.json
    handle @data {
        root * /run/beacon
        header Cache-Control no-store
        file_server
    }
    handle {
        root * /srv/beacon-status
        file_server
    }
}
```

**Docker (Nginx Proxy Manager or any proxy).** beacon writes into a volume
(and its entrypoint puts the page there), a small nginx container serves it,
and the proxy points a host name at that container:

```yaml
services:
  beacon:
    build: ./multitap-beacon
    network_mode: host
    restart: unless-stopped
    command: ["--status-file", "/status/status.json"]
    volumes:
      - beacon-status:/status
  beacon-page:
    image: nginx:alpine
    restart: unless-stopped
    volumes:
      - beacon-status:/usr/share/nginx/html:ro
volumes:
  beacon-status:
```

In Nginx Proxy Manager, add a proxy host for the status name with forward
host `beacon-page`, port 80 (the containers must share a network with NPM).

### Signaling for browsers (WebRTC)

beacon listens for WebSocket on `127.0.0.1:55432` and never does TLS itself;
browsers on an https page only open `wss://`, so a TLS proxy in front is
required. Clients use `wss://your.host.name/signal`.

**Caddy** (gets the certificate on its own): [`packaging/Caddyfile`](packaging/Caddyfile)
proxies `/signal` to beacon and serves the status page. Caddy replaces
whatever `X-Forwarded-For` a client sends with the client's real address, and
beacon believes that header from loopback, so its per-source limits see the
real clients.

**Nginx Proxy Manager in Docker.** beacon runs with host networking, so a
proxy container on a bridge network can't reach its 127.0.0.1. Bind the
signaling listener to the Docker bridge instead, and trust the Docker
networks' X-Forwarded-For:

```yaml
    command: ["--signal-bind", "172.17.0.1", "--trusted-proxy", "172.16.0.0/12"]
```

(172.17.0.1 is the default `docker0` address; with a compose network, use
its gateway.) Then add a proxy host in NPM: scheme `http`, forward host
`172.17.0.1`, port `55432`, **Websockets Support** on, an SSL certificate,
and a custom location `/signal` if the name also serves the status page. Keep
TCP 55432 closed to the outside (it's only on the bridge address).

Without a proxy (testing only): `--signal-bind 0.0.0.0` exposes plain `ws://`,
which only pages served over http can use.

## Ports and firewall

| port | protocol | what |
|---|---|---|
| 55430 | UDP | primary: address reflection, registration, introductions, STUN |
| 55431 | UDP | secondary: address reflection only (NAT type detection), STUN |
| 3478 | UDP | optional (`--stun-port 3478`): STUN only, the standard STUN port |
| 55432 | TCP | WebSocket signaling for browsers, on 127.0.0.1 only: a TLS proxy (Caddy) in front serves it as wss:// |

Nothing else, inbound or outbound. Browsers use `stun:your.host.name:55430`;
open 3478 only if you want the standard port too. Without the secondary port
(`--secondary-port 0`) everything still works; clients just can't detect a
symmetric NAT early.

## Options

```
--bind ADDRESS            numeric IPv6 or IPv4 address to listen on (default ::, every address,
                          IPv4 included)
--port N                  primary UDP port (default 55430)
--secondary-port N        secondary UDP port for NAT detection, 0 = off (default 55431)
--stun-port N             an extra UDP port that answers STUN only, usually 3478; the primary
                          and secondary ports answer STUN anyway (default 0 = off)
--signal-bind ADDRESS     numeric address for the WebSocket signaling listener (default 127.0.0.1:
                          a TLS proxy such as Caddy goes in front)
--signal-port N           its TCP port, 0 = no signaling (default 55432)
--max-connections N       signaling connections at once (default 1024)
--max-rooms N             signaling rooms at once (default 65536)
--max-connections-per-source N
                          signaling connections from one IPv4 address or IPv6 /64 (default 8)
--trusted-proxy IP[/N]    a proxy whose X-Forwarded-For is believed, e.g. a Docker network
                          (172.16.0.0/12); loopback always is; up to 8 times
--max-entries N           meeting ids kept at once (default 65536)
--max-sources N           source addresses with their own rate limit (default 65536)
--max-ids-per-source N    meeting ids one IPv4 address or IPv6 /64 may register (default 128)
--rate N                  packets per second per source (default 20)
--burst N                 packets a source may send at once (default 60)
--overflow-rate N         packets per second shared by sources that don't fit (default 1000)
--public-address IP       the server's public IPv4 or IPv6 address, for a server behind a NAT
                          with port forwarding (give it twice for both families; default: off)
--stats-interval SECONDS  log counts this often, 0 = never (default 60)
--status-file PATH        write hosts online and introductions in the last hour to this JSON
                          file every 10 s, for the status page (default: off)
--log-level LEVEL         error, warning, info or debug (default info)
```

A "source" is one IPv4 address or one IPv6 /64. Rate limits and the id limit
count per source, so many households behind one carrier-grade NAT address
share them: raise `--rate` and `--max-ids-per-source` if your users are
behind CGNAT.

## Resources

All memory is allocated at startup; nothing is allocated per packet.

| tables | memory |
|---|---|
| default (65536 ids, 65536 sources) | 14 MiB (RSS about 18 MiB) |
| 1M ids, 1M sources | 225 MiB |
| signaling (1024 connections, 65536 rooms) | 16.4 MiB (12.6 KiB per connection) |

Signaling connections have fixed buffers (4.25 KiB in, 8.25 KiB out); one
whose reader is too slow for what's sent to it is closed, never queued
without a bound. Per connection: 64 rooms, 20 messages per second (burst 60)
and 16 KiB per second (burst 64 KiB).

Measured on an RK3588 (one Cortex-A76 core, Release build): the logic alone
handles about 370,000 BIND, 255,000 MEET or 75,000 REGISTER (8 ids) packets
per second; over real loopback sockets, one sending client got about 72,000
replies per second. A host costs one REGISTER every 20 seconds per 8 paired
devices, so one core serves far more hosts than the tables hold.

## Development

C++20 written like C ([`STYLE.md`](STYLE.md)). Linux for now; the wire library
([`wire/beacon_wire.h`](wire/beacon_wire.h)) has no dependencies and
builds anywhere: clients use it as a submodule (the server and tests are off
when this repo is added as a CMake subproject).

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DMULTITAP_WARNINGS_AS_ERRORS=ON
cmake --build build && ctest --test-dir build
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DMULTITAP_WARNINGS_AS_ERRORS=ON -DMULTITAP_SANITIZE=ON
cmake --build build-asan && ctest --test-dir build-asan
```

Tests: `wire` (round trips, golden packets, every reject), `server` (the logic
with a fake clock: cookies, expiry, limits, rate limits, address families,
STUN), `stun` (RFC 5769's test vectors and every reject), `ws` (SHA-1 and
base64 vectors, RFC 6455's accept key, every handshake and frame rule),
`loopback` (real sockets: a fake host registers, a fake client meets, both
get each other's address; STUN on every socket), `signal` (real TCP sockets:
handshake, ping, close, protocol errors, rooms, replacement, room and rate
limits, the per-source limit with X-Forwarded-For, a full pool, timeouts, a
slow reader),
and the `fuzz_*_replay` tests (each fuzz target on every mutation of valid
input plus millions of random ones). With Clang and its sanitizer runtime
(Debian / Ubuntu: `libclang-rt-<version>-dev`) there are also the libFuzzer
targets `beacon_fuzz_wire`, `beacon_fuzz_stun`, `beacon_fuzz_ws_handshake`
and `beacon_fuzz_ws_frame`:

```sh
CC=clang CXX=clang++ cmake -S . -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-fuzz --target beacon_fuzz_wire
./build-fuzz/beacon_fuzz_wire -max_total_time=600
```

`build/beacon_bench logic` measures the logic; `beacon_bench blast
PORT SECONDS` floods a running server with BINDs (start it with high `--rate`
and `--burst`).

Dependencies: [Monocypher](https://monocypher.org) (`deps/monocypher`,
BSD-2-Clause or CC0) for keyed BLAKE2b (cookies and table hashing). The
WebSocket handshake's SHA-1 is written here from RFC 3174.

## License

MIT, see [`LICENSE`](LICENSE). `packaging/status/_site/` is piccolo's shared site look (its fonts are OFL: `_site/v1/fonts/OFL-*.txt`); the logo in it is piccolo's
logo, the Multitap project's own branding.
