#pragma once

// beacon_signal: the WebSocket listener for WebRTC signaling (PROTOCOL.md,
// "Signaling"). Plain TCP (a TLS proxy such as Caddy sits in front: browsers
// need wss://), bound to 127.0.0.1:55432 by default.
//
// Rooms: a room is a meeting id with one host socket and one client socket.
// JOIN puts a socket on its role's side (replacing the socket there, if any),
// SIGNAL passes a message to the other side as is, LEAVE or closing takes the
// socket out. beacon never reads a SIGNAL's blob.
//
// Memory, all allocated by beacon_signal_open() and never grown:
// - a pool of max_connections connections, each with fixed receive and send
//   buffers and its list of rooms. A connection whose send buffer would
//   overflow (a reader slower than what's sent to it) is closed rather than
//   queued without a bound.
// - the room table: open addressing like beacon_server's tables (a keyed
//   hash picks the home slot, every lookup scans the whole window, so freeing
//   a slot never breaks another room's search). Rooms never move, so a
//   connection keeps its rooms' slot numbers.
//
// The caller owns the epoll loop: beacon_signal_open() registers the
// listening socket with tag BEACON_SIGNAL_TAG_LISTEN, and each connection
// with BEACON_SIGNAL_TAG_FIRST_CONNECTION + its index; the caller hands
// those events back. Level-triggered. Output for a connection other than the
// one being handled is only queued (with EPOLLOUT turned on), never sent
// inline, and one that can't take it is freed after the current event, so
// handling one connection never frees another in the middle.

#include "beacon_ws.h"

#include <cstdint>
#include <vector>

constexpr uint64_t BEACON_SIGNAL_TAG_LISTEN = 0x100;
constexpr uint64_t BEACON_SIGNAL_TAG_FIRST_CONNECTION = 0x1000;

// Receive: the handshake or one whole client frame, whichever is larger.
constexpr size_t BEACON_SIGNAL_RECEIVE_SIZE = 4352;
static_assert(BEACON_SIGNAL_RECEIVE_SIZE >= BEACON_WS_MAX_HANDSHAKE, "handshake fits");
static_assert(BEACON_SIGNAL_RECEIVE_SIZE >= BEACON_WS_MAX_CLIENT_HEADER + BEACON_WS_MAX_PAYLOAD, "frame fits");
// Send: two of the largest messages, plus room for control frames.
constexpr size_t BEACON_SIGNAL_SEND_SIZE = 8448;
static_assert(BEACON_SIGNAL_SEND_SIZE >= 2 * (BEACON_WS_MAX_SERVER_HEADER + BEACON_WS_MAX_PAYLOAD), "two messages");

constexpr uint64_t BEACON_SIGNAL_HANDSHAKE_MS = 5000;   // to finish the handshake (slowloris)
constexpr uint64_t BEACON_SIGNAL_IDLE_MS = 60000;       // with no frame from the client
constexpr uint64_t BEACON_SIGNAL_CLOSING_MS = 5000;     // to flush a close before dropping the socket
constexpr uint32_t BEACON_SIGNAL_MAX_CONNECTIONS = 1u << 20;
constexpr uint32_t BEACON_SIGNAL_MAX_ROOMS_PER_CONNECTION = 64;
constexpr uint32_t BEACON_SIGNAL_PROBE_WINDOW = 32;
constexpr uint32_t BEACON_SIGNAL_MAX_TRUSTED = 8;
constexpr uint32_t BEACON_SIGNAL_NONE = 0xffffffffu;

// An address range: `prefix` bits of `ip` (IPv4 as ::ffff:a.b.c.d, so an
// IPv4 /n is 96 + n).
struct BeaconCidr
{
    uint8_t ip[16] = {};
    uint8_t prefix = 128;
};

struct BeaconSignalConfig
{
    uint32_t max_connections = 1024;
    uint32_t max_rooms = 65536;
    uint32_t max_connections_per_source = 8;
    uint32_t messages_per_second = 20;      // per connection: binary messages and pings
    uint32_t message_burst = 60;
    uint32_t bytes_per_second = 16384;      // per connection: their payload bytes
    uint32_t byte_burst = 65536;
    // Proxies whose X-Forwarded-For is believed (loopback always is).
    BeaconCidr trusted[BEACON_SIGNAL_MAX_TRUSTED] = {};
    uint32_t trusted_count = 0;
};

enum class BeaconConnectionState : uint8_t
{
    FREE,
    HANDSHAKE,      // waiting for the HTTP request
    OPEN,           // frames
    CLOSING,        // a close frame or an HTTP error queued: input ignored, closed once sent
};

struct BeaconConnection
{
    int fd = -1;
    BeaconConnectionState state = BeaconConnectionState::FREE;
    bool want_write = false;            // EPOLLOUT is registered
    bool doomed = false;                // on the doomed list: freed when the current event is done
    BeaconAddress peer = {};            // the TCP peer (the proxy, behind one)
    uint8_t source_key[16] = {};        // OPEN: the client (IPv4 address or IPv6 /64), for the per-source limit
    uint64_t deadline_ms = 0;           // HANDSHAKE / CLOSING: closed at this time
    uint64_t last_frame_ms = 0;         // OPEN: idle timeout
    uint64_t messages_last_ms = 0;      // rate limits: token buckets
    uint64_t message_tokens_milli = 0;
    uint64_t bytes_last_ms = 0;
    uint64_t byte_tokens_milli = 0;
    uint32_t room_count = 0;
    uint32_t rooms[BEACON_SIGNAL_MAX_ROOMS_PER_CONNECTION] = {};   // room table slots
    uint32_t receive_used = 0;
    uint32_t send_used = 0;
    uint8_t receive[BEACON_SIGNAL_RECEIVE_SIZE] = {};
    uint8_t send[BEACON_SIGNAL_SEND_SIZE] = {};
};

struct BeaconRoom
{
    BeaconId id = {};
    uint32_t host = BEACON_SIGNAL_NONE;     // connection indexes
    uint32_t client = BEACON_SIGNAL_NONE;
    uint8_t used = 0;
};

struct BeaconSignalStats
{
    uint64_t accepted = 0;
    uint64_t refused_full = 0;          // the pool was full
    uint64_t refused_source = 0;        // HTTP 429: too many connections from one source
    uint64_t handshakes = 0;
    uint64_t bad_handshakes = 0;
    uint64_t joins = 0;
    uint64_t replaced = 0;              // a JOIN took a side from another socket
    uint64_t refused_rooms = 0;         // JOIN over a room limit
    uint64_t signals = 0;               // SIGNALs passed along
    uint64_t not_found = 0;
    uint64_t rate_limited = 0;          // closed for going over a rate
    uint64_t protocol_errors = 0;       // a frame or message broke a rule
    uint64_t timeouts = 0;              // handshake, idle or closing
    uint64_t slow_readers = 0;          // closed because the send buffer was full
    uint32_t open = 0;                  // connections in use now
    uint32_t rooms = 0;                 // rooms in use now
};

struct BeaconSignal
{
    BeaconSignalConfig config = {};
    std::vector<BeaconConnection> connections;
    std::vector<uint32_t> free_slots;   // a stack of free connection indexes
    uint32_t free_count = 0;
    // Connections that couldn't take what they were sent while another one was
    // being handled; freed once that's done (never inline: see doom()).
    std::vector<uint32_t> doomed;
    uint32_t doomed_count = 0;
    std::vector<BeaconRoom> rooms;
    uint32_t room_mask = 0;
    uint8_t hash_key[32] = {};
    int listen_fd = -1;
    int epoll_fd = -1;
    uint16_t port = 0;                  // the bound port (useful when 0 asked for any)
    BeaconSignalStats stats = {};
};

// "a.b.c.d", "a.b.c.d/n", "ipv6" or "ipv6/n" into `out`.
bool beacon_cidr_parse(const char* text, BeaconCidr* out);
bool beacon_cidr_contains(const BeaconCidr* range, const BeaconAddress* address);

// Listens on `bind_address` (numeric IPv4 or IPv6) and `port` (0 = any) and
// registers with `epoll_fd`.
bool beacon_signal_open(BeaconSignal* signal, const BeaconSignalConfig* config, const char* bind_address,
                        uint16_t port, int epoll_fd);
void beacon_signal_close(BeaconSignal* signal);

// The listening socket is readable: accepts what's waiting.
void beacon_signal_accept(BeaconSignal* signal, uint64_t now_ms);

// An epoll event (EPOLLIN / EPOLLOUT / EPOLLERR / EPOLLHUP) for connection `index`.
void beacon_signal_event(BeaconSignal* signal, uint32_t index, uint32_t events, uint64_t now_ms);

// Timeouts, about once a second.
void beacon_signal_tick(BeaconSignal* signal, uint64_t now_ms);

// Clears the counters (not `open` / `rooms`).
void beacon_signal_stats_reset(BeaconSignal* signal);

uint64_t beacon_signal_pool_bytes(const BeaconSignal* signal);
