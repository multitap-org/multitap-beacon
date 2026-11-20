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

The wire format is in [`PROTOCOL.md`](PROTOCOL.md): every message is a fixed
size binary struct, nothing is ever read as a length or a string, and a reply
is never bigger than the request that caused it (so the server can't be used
to amplify attacks).

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

```sh
git clone --recursive https://github.com/multitap-org/multitap-beacon.git
cd multitap-beacon
docker build -t beacon .
docker run -d --name beacon --restart unless-stopped --network host beacon
```

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

`packaging/status/` is a public page that shows how many piccolos the beacon
can introduce right now, and how many introductions it made in the last hour.
beacon itself serves no HTTP: with `--status-file PATH` it writes counts
(never ids or addresses) every 10 seconds, replacing the file atomically:

```json
{"hosts_online": 12, "introductions_last_hour": 40, "updated": 1795000000}
```

`hosts_online` counts the distinct host addresses with a live registration: a
host registered over IPv4 and IPv6 counts once, two piccolos behind one public
IP count twice. The page reads `status.json` next to itself every 30 seconds
and says the beacon isn't answering when the file is older than a minute. Any
web server that serves `index.html`, `piccolo-logo-dark.svg` and the status
file from one directory works.

**systemd + Caddy.** `systemctl edit beacon`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/beacon --status-file /run/beacon/status.json
RuntimeDirectory=beacon
RuntimeDirectoryMode=0755
```

and in the Caddyfile (the page copied to `/srv/beacon-status`):

```
beacon.example.org {
    handle /status.json {
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

**Docker (Nginx Proxy Manager or any proxy).** beacon writes into a volume,
a small nginx container serves it with the page, and the proxy points a host
name at that container:

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
      - ./multitap-beacon/packaging/status/index.html:/usr/share/nginx/html/index.html:ro
      - ./multitap-beacon/packaging/status/piccolo-logo-dark.svg:/usr/share/nginx/html/piccolo-logo-dark.svg:ro
volumes:
  beacon-status:
```

In Nginx Proxy Manager, add a proxy host for the status name with forward
host `beacon-page`, port 80 (the containers must share a network with NPM).

## Ports and firewall

| port | protocol | what |
|---|---|---|
| 55430 | UDP | primary: address reflection, registration, introductions |
| 55431 | UDP | secondary: address reflection only (NAT type detection) |

Nothing else, inbound or outbound. Without the secondary port
(`--secondary-port 0`) everything still works; clients just can't detect a
symmetric NAT early.

## Options

```
--bind ADDRESS            numeric IPv6 or IPv4 address to listen on (default ::, every address,
                          IPv4 included)
--port N                  primary UDP port (default 55430)
--secondary-port N        secondary UDP port for NAT detection, 0 = off (default 55431)
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
with a fake clock: cookies, expiry, limits, rate limits, address families),
`loopback` (real sockets: a fake host registers, a fake client meets, both get
each other's address), `fuzz_replay` (the fuzz target on every mutation of
every message plus millions of random packets). With Clang and its sanitizer
runtime (Debian / Ubuntu: `libclang-rt-<version>-dev`) there's also the
libFuzzer target `beacon_fuzz_wire`:

```sh
CC=clang CXX=clang++ cmake -S . -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-fuzz --target beacon_fuzz_wire
./build-fuzz/beacon_fuzz_wire -max_total_time=600
```

`build/beacon_bench logic` measures the logic; `beacon_bench blast
PORT SECONDS` floods a running server with BINDs (start it with high `--rate`
and `--burst`).

Dependencies: [Monocypher](https://monocypher.org) (`deps/monocypher`,
BSD-2-Clause or CC0) for keyed BLAKE2b (cookies and table hashing).

## License

MIT, see [`LICENSE`](LICENSE). `packaging/status/piccolo-logo-dark.svg` is piccolo's
logo, the Multitap project's own branding.
