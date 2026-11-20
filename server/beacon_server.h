#pragma once

// beacon_server: what the server does with one packet (PROTOCOL.md), with
// no sockets: the caller hands in the packet, the sender's address and the
// time, and gets back up to two packets to send. That keeps the logic testable
// with a fake clock; beacon_net does the sockets.
//
// Memory: two fixed tables allocated by beacon_server_create() and never
// grown, so nothing allocates per packet.
// - meetings: (meeting id, address family) -> host address, expiry. Slots =
//   the power of two >= 2 * max_entries (load <= 50%).
// - sources: per source (IPv4 address or IPv6 /64) a token bucket and how many
//   meeting entries it owns. Slots = the power of two >= 2 * max_sources.
// Both are open-addressed: an item lives in one of PROBE_WINDOW slots after
// its home slot, the home slot coming from a keyed hash (random key per run)
// so nobody can pick ids or addresses that pile up in one place. Every lookup
// scans the whole window, so freeing a slot never breaks another item's search
// (no tombstones, no moving items).

#include "beacon_wire.h"

#include <cstdint>
#include <vector>

constexpr uint16_t BEACON_ENTRY_TTL_SECONDS = 60;
constexpr uint64_t BEACON_COOKIE_EPOCH_MS = 60000;
// A second MEET for the same entry within this time is dropped (no INTRO flood at the host).
constexpr uint64_t BEACON_INTRO_INTERVAL_MS = 250;
// A source slot with no entries that has been quiet this long may be given to
// another source. Longer than a bucket takes to refill, so losing the slot
// never gives a source more tokens than waiting would.
constexpr uint64_t BEACON_SOURCE_IDLE_MS = 10000;
constexpr uint32_t BEACON_PROBE_WINDOW = 32;
constexpr uint32_t BEACON_MAX_TABLE_ITEMS = 16u * 1024u * 1024u;

struct BeaconServerConfig
{
    uint32_t max_entries = 65536;          // meeting entries in the table, then REGISTER is refused
    uint32_t max_sources = 65536;          // sources with their own rate bucket
    uint32_t max_ids_per_source = 128;     // meeting entries one source may own
    uint32_t rate_per_second = 20;         // packets per source
    uint32_t burst = 60;
    uint32_t overflow_rate_per_second = 1000;  // shared by the sources that don't fit the table
    // --public-address: for a server behind a NAT with port forwarding. A
    // sender with a private address (RFC 1918, CGNAT 100.64/10, loopback,
    // link-local; IPv6 ULA, link-local, loopback) is on the server's own side
    // of that NAT, so the server never sees its public address: it reports
    // this one with the sender's port instead (right when the router keeps
    // source ports, which most Linux-based ones do). Replies still go to the
    // sender's real address. Only `ip` is used.
    bool has_public_ipv4 = false;
    BeaconAddress public_ipv4 = {};
    bool has_public_ipv6 = false;
    BeaconAddress public_ipv6 = {};
};

enum class BeaconSocket : uint8_t
{
    PRIMARY,
    SECONDARY,
};

struct BeaconOutPacket
{
    BeaconSocket socket = BeaconSocket::PRIMARY;
    BeaconAddress to = {};
    uint8_t data[BEACON_MAX_MESSAGE_SIZE] = {};
    uint32_t size = 0;
};

// MEET answers two packets (INTRO to each side); everything else one or none.
constexpr uint32_t BEACON_MAX_OUT_PACKETS = 2;

struct BeaconOutbox
{
    BeaconOutPacket packets[BEACON_MAX_OUT_PACKETS] = {};
    uint32_t count = 0;
};

// Counters since the last beacon_server_stats_reset(); `entries` and
// `sources` are the current table use.
struct BeaconStats
{
    uint64_t packets = 0;
    uint64_t malformed = 0;          // didn't decode (bad size, magic, field...)
    uint64_t unexpected = 0;         // valid but not for the server here (a reply type, REGISTER on SECONDARY...)
    uint64_t rate_limited = 0;
    uint64_t binds = 0;
    uint64_t registers = 0;
    uint64_t cookies_sent = 0;       // REGISTER without a valid cookie
    uint64_t ids_accepted = 0;
    uint64_t ids_refused_source = 0; // over max_ids_per_source
    uint64_t ids_refused_full = 0;   // table full (max_entries or no free slot)
    uint64_t meets = 0;
    uint64_t intros = 0;             // MEETs answered with INTRO (two packets each)
    uint64_t intro_limited = 0;
    uint64_t not_found = 0;
    uint64_t expired = 0;
    uint32_t entries = 0;
    uint32_t sources = 0;
};

struct BeaconEntry
{
    BeaconId id = {};
    BeaconAddress address = {};     // what clients are told (the --public-address one for a private sender)
    BeaconAddress reply_to = {};    // where the host really is: INTROs go here, its source owns the entry
    uint8_t used = 0;
    uint8_t ipv4 = 0;               // part of the key: one entry per id and family
    uint64_t expires_ms = 0;
    uint64_t last_intro_ms = 0;
};

struct BeaconSource
{
    uint8_t key[16] = {};           // IPv4-mapped address, or the IPv6 /64 then zeros
    uint64_t last_ms = 0;           // last refill
    uint32_t tokens_milli = 0;      // tokens * 1000
    uint16_t entries = 0;           // meeting entries owned (never reused while > 0)
    uint8_t used = 0;
};

struct BeaconBucket
{
    uint64_t last_ms = 0;
    uint32_t tokens_milli = 0;
};

struct BeaconServer
{
    BeaconServerConfig config = {};
    std::vector<BeaconEntry> entries;
    std::vector<BeaconSource> sources;
    uint32_t entry_mask = 0;
    uint32_t source_mask = 0;
    uint8_t hash_key[32] = {};
    // Cookie secrets: secrets[epoch & 1] is the current one, the other the previous.
    uint8_t secrets[2][32] = {};
    uint64_t epoch = 0;
    uint64_t epoch_started_ms = 0;
    BeaconBucket overflow = {};
    BeaconStats stats = {};
    uint64_t intros_total = 0;      // since start, never reset (for the status file)
    // beacon_server_count_hosts()'s work space: one address per possible entry,
    // allocated once by beacon_server_create().
    std::vector<BeaconAddress> host_scratch;
};

// Allocates the tables and the secrets. `now_ms` is the caller's monotonic clock.
bool beacon_server_create(BeaconServer* server, const BeaconServerConfig* config, uint64_t now_ms);
void beacon_server_destroy(BeaconServer* server);

// One packet received on `socket` from `from`. Fills `out` (count 0 = send nothing).
void beacon_server_receive(BeaconServer* server, uint64_t now_ms, BeaconSocket socket,
                               const BeaconAddress* from, const uint8_t* data, size_t size,
                               BeaconOutbox* out);

// Housekeeping, about once a second: rotates the cookie secret every epoch and
// frees expired entries (so their sources' counts go down).
void beacon_server_tick(BeaconServer* server, uint64_t now_ms);

void beacon_server_stats_reset(BeaconServer* server);

// Hosts reachable now: the distinct addresses that own a live entry. A host
// that registers over both families counts once (its IPv6 entries whose id
// also has an IPv4 entry are skipped); hosts behind one public IP count
// separately (their ports differ). Sorts the addresses, so it's for every few
// seconds (the status file), not per packet.
uint32_t beacon_server_count_hosts(BeaconServer* server, uint64_t now_ms);

// Bytes the tables take (the meeting and source tables, and the hosts work space) (for the startup log and the README's numbers).
uint64_t beacon_server_table_bytes(const BeaconServer* server);
