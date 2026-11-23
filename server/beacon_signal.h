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
// Guest rooms (guest links): one host (role GUEST_HOST) and up to
// BEACON_SIGNALING_MAX_GUESTS guests (role GUEST), each with an index. The
// host must be there first; a guest's SIGNAL reaches the host as GUEST_SIGNAL
// with the guest's index, the host's GUEST_SIGNAL reaches that guest as
// SIGNAL. The host leaving ends the room: every guest gets LEFT.
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
// HTTP (beacon_http.h): a request without an Upgrade header is plain HTTP:
// the guest links' join page, their cards, and the hosts' card uploads. One
// request per connection (Connection: close). A card is kept in memory only,
// one per guest room, and deleted BEACON_CARD_ORPHAN_MS after its guest room
// ends. Pages and uploads take a slot from small pools allocated at open;
// with none free the answer is 503.
//
// The caller owns the epoll loop: beacon_signal_open() registers the
// listening socket with tag BEACON_SIGNAL_TAG_LISTEN, and each connection
// with BEACON_SIGNAL_TAG_FIRST_CONNECTION + its index; the caller hands
// those events back. Level-triggered. Output for a connection other than the
// one being handled is only queued (with EPOLLOUT turned on), never sent
// inline, and one that can't take it is freed after the current event, so
// handling one connection never frees another in the middle.

#include "beacon_http.h"
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
constexpr uint64_t BEACON_HTTP_BODY_MS = 20000;         // to receive a card upload's body
constexpr uint64_t BEACON_HTTP_SEND_MS = 30000;         // to send a response (a card is up to 256 KiB)
constexpr uint64_t BEACON_CARD_ORPHAN_MS = 60000;       // a card outlives its guest room this long (a host's reconnect)
constexpr uint32_t BEACON_HTTP_PAGE_SIZE = 48 * 1024;   // a rendered join page
constexpr uint32_t BEACON_CARD_PUTS_PER_MINUTE = 4;     // per card: replacing it
constexpr uint32_t BEACON_MAX_PUBLIC_URL = 128;

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
    uint32_t guest_joins_per_minute = 10;   // per connection: JOINs as a guest
    uint32_t guest_join_burst = 5;
    uint32_t max_cards = 64;                // in memory, BEACON_CARD_MAX_PNG each
    uint32_t page_slots = 32;               // join pages being sent at once
    uint32_t upload_slots = 4;              // card uploads being received at once
    // The scheme and host in the card's absolute URLs ("https://beacon.example");
    // empty: "https://" + the request's Host.
    char public_url[BEACON_MAX_PUBLIC_URL + 1] = {};
    // Proxies whose X-Forwarded-For is believed (loopback always is).
    BeaconCidr trusted[BEACON_SIGNAL_MAX_TRUSTED] = {};
    uint32_t trusted_count = 0;
};

enum class BeaconConnectionState : uint8_t
{
    FREE,
    HANDSHAKE,      // waiting for the HTTP request
    OPEN,           // frames
    CLOSING,        // a close frame or an HTTP response queued: input ignored, closed once sent
    HTTP_BODY,      // receiving a card upload's body
};

enum class BeaconBodyKind : uint8_t
{
    NONE,
    PAGE,           // a page slot
    CARD,           // a card's PNG (dropped if the card changes meanwhile)
    NOISE,          // the white noise PNG (compiled in)
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
    uint64_t guest_joins_last_ms = 0;
    uint64_t guest_join_tokens_milli = 0;
    uint32_t room_count = 0;
    uint32_t rooms[BEACON_SIGNAL_MAX_ROOMS_PER_CONNECTION] = {};   // room table slots
    uint32_t receive_used = 0;
    uint32_t send_used = 0;
    // HTTP: the upload being received, or the body being sent after the head.
    BeaconJoinRoute route = {};
    uint32_t upload_slot = BEACON_SIGNAL_NONE;
    uint32_t upload_size = 0;           // the Content-Length
    uint32_t upload_used = 0;
    BeaconBodyKind body_kind = BeaconBodyKind::NONE;
    uint32_t body_index = BEACON_SIGNAL_NONE;   // page slot or card
    uint32_t body_generation = 0;               // CARD: the card's generation when it started
    uint32_t body_offset = 0;
    uint32_t body_size = 0;
    uint8_t receive[BEACON_SIGNAL_RECEIVE_SIZE] = {};
    uint8_t send[BEACON_SIGNAL_SEND_SIZE] = {};
};

struct BeaconRoom
{
    BeaconId id = {};
    uint32_t host = BEACON_SIGNAL_NONE;     // connection indexes
    uint32_t client = BEACON_SIGNAL_NONE;   // plain rooms only
    uint32_t guests[BEACON_SIGNALING_MAX_GUESTS] = {BEACON_SIGNAL_NONE, BEACON_SIGNAL_NONE, BEACON_SIGNAL_NONE,
                                                    BEACON_SIGNAL_NONE, BEACON_SIGNAL_NONE, BEACON_SIGNAL_NONE,
                                                    BEACON_SIGNAL_NONE, BEACON_SIGNAL_NONE};
    uint8_t used = 0;
    uint8_t guest_room = 0;                 // made by a GUEST_HOST JOIN
};

struct BeaconCard
{
    uint8_t used = 0;
    char room[BEACON_GUEST_ROOM_SIZE + 1] = {};
    BeaconId meeting = {};                  // the guest room it belongs to
    char title[BEACON_CARD_MAX_TITLE + 1] = {};
    uint32_t png_size = 0;                  // the PNG: card_data[index * BEACON_CARD_MAX_PNG, + png_size); 0 = none
    uint32_t width = 0;                     // its size (the page's og:image:width / height)
    uint32_t height = 0;
    uint32_t generation = 0;                // bumped when replaced or deleted
    uint64_t orphan_since_ms = 0;           // its guest room is gone since (0: it's live)
    uint64_t puts_last_ms = 0;
    uint64_t put_tokens_milli = 0;
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
    uint64_t guest_joins = 0;           // guests let into a guest room
    uint64_t refused_guests = 0;        // guest JOINs refused (full, rate, wrong kind)
    uint64_t rate_limited = 0;          // closed for going over a rate
    uint64_t protocol_errors = 0;       // a frame or message broke a rule
    uint64_t timeouts = 0;              // handshake, idle or closing
    uint64_t slow_readers = 0;          // closed because the send buffer was full
    uint64_t http_requests = 0;
    uint64_t http_refused = 0;          // 4xx / 5xx answers
    uint64_t cards_put = 0;
    uint64_t cards_deleted = 0;
    uint32_t open = 0;                  // connections in use now
    uint32_t rooms = 0;                 // rooms in use now
    uint32_t cards = 0;                 // cards in memory now
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
    std::vector<BeaconCard> cards;
    std::vector<uint8_t> card_data;         // max_cards * BEACON_CARD_MAX_PNG
    std::vector<uint8_t> page_used;         // page_slots flags
    std::vector<uint8_t> page_data;         // page_slots * BEACON_HTTP_PAGE_SIZE
    std::vector<uint8_t> upload_used;       // upload_slots flags
    std::vector<uint8_t> upload_data;       // upload_slots * BEACON_CARD_MAX_UPLOAD
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

// The card of guest room `room` (13 base32 characters), or nullptr.
const BeaconCard* beacon_signal_card(const BeaconSignal* signal, const char* room);

// True if `room` is a guest room whose host is connected (cards live as long
// as that).
bool beacon_signal_guest_room_live(const BeaconSignal* signal, const BeaconId* room);

// Clears the counters (not `open` / `rooms`).
void beacon_signal_stats_reset(BeaconSignal* signal);

uint64_t beacon_signal_pool_bytes(const BeaconSignal* signal);
