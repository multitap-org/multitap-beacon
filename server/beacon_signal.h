#pragma once

// beacon_signal: the WebSocket listener for WebRTC signaling (PROTOCOL.md,
// "Signaling"). Plain TCP (a TLS proxy such as Caddy sits in front: browsers
// need wss://), bound to 127.0.0.1:55432 by default.
//
// Memory: a pool of BeaconSignalConfig::max_connections connections, each
// with fixed receive and send buffers, allocated once by beacon_signal_open().
// Nothing is allocated per connection or per message. A connection whose
// send buffer would overflow (a reader slower than what's sent to it) is
// closed rather than queued without a bound.
//
// The caller owns the epoll loop: beacon_signal_open() registers the
// listening socket with tag BEACON_SIGNAL_TAG_LISTEN, and each connection
// with BEACON_SIGNAL_TAG_FIRST_CONNECTION + its index; the caller hands
// those events back. Level-triggered.

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

struct BeaconSignalConfig
{
    uint32_t max_connections = 1024;
};

enum class BeaconConnectionState : uint8_t
{
    FREE,
    HANDSHAKE,      // waiting for the HTTP request
    OPEN,           // frames
    CLOSING,        // a close frame or a 400 queued: input ignored, closed once sent
};

struct BeaconConnection
{
    int fd = -1;
    BeaconConnectionState state = BeaconConnectionState::FREE;
    bool want_write = false;            // EPOLLOUT is registered
    BeaconAddress peer = {};            // the TCP peer (the proxy, behind one)
    uint64_t deadline_ms = 0;           // HANDSHAKE / CLOSING: closed at this time
    uint64_t last_frame_ms = 0;         // OPEN: idle timeout
    uint32_t receive_used = 0;
    uint32_t send_used = 0;
    uint8_t receive[BEACON_SIGNAL_RECEIVE_SIZE] = {};
    uint8_t send[BEACON_SIGNAL_SEND_SIZE] = {};
};

struct BeaconSignalStats
{
    uint64_t accepted = 0;
    uint64_t refused_full = 0;          // the pool was full
    uint64_t handshakes = 0;
    uint64_t bad_handshakes = 0;
    uint64_t messages = 0;              // binary frames
    uint64_t protocol_errors = 0;       // a frame broke a rule
    uint64_t timeouts = 0;              // handshake, idle or closing
    uint64_t slow_readers = 0;          // closed because the send buffer was full
    uint32_t open = 0;                  // connections in use now
};

struct BeaconSignal
{
    BeaconSignalConfig config = {};
    std::vector<BeaconConnection> connections;
    std::vector<uint32_t> free_slots;   // a stack of free connection indexes
    uint32_t free_count = 0;
    int listen_fd = -1;
    int epoll_fd = -1;
    uint16_t port = 0;                  // the bound port (useful when 0 asked for any)
    BeaconSignalStats stats = {};
};

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

uint64_t beacon_signal_pool_bytes(const BeaconSignal* signal);
