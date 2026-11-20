// beacon_signal: see beacon_signal.h.

#include "beacon_signal.h"

#include "beacon_log.h"
#include "beacon_net.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <unistd.h>

// Connections accepted per readable event, so a flood can't starve the rest.
static constexpr uint32_t ACCEPTS_PER_EVENT = 64;

static BeaconConnection* connection_at(BeaconSignal* signal, uint32_t index)
{
    if (index >= signal->connections.size())
    {
        return nullptr;
    }
    BeaconConnection* connection = &signal->connections[index];
    return connection->state == BeaconConnectionState::FREE ? nullptr : connection;
}

static void connection_free(BeaconSignal* signal, uint32_t index)
{
    BeaconConnection* connection = &signal->connections[index];
    if (connection->fd >= 0)
    {
        epoll_ctl(signal->epoll_fd, EPOLL_CTL_DEL, connection->fd, nullptr);
        close(connection->fd);
    }
    // Only the bookkeeping is reset: the buffers' old bytes are never read
    // (receive_used / send_used say what's valid).
    connection->fd = -1;
    connection->state = BeaconConnectionState::FREE;
    connection->want_write = false;
    connection->receive_used = 0;
    connection->send_used = 0;
    signal->free_slots[signal->free_count++] = index;
    signal->stats.open--;
}

static void set_want_write(BeaconSignal* signal, uint32_t index, bool want)
{
    BeaconConnection* connection = &signal->connections[index];
    if (connection->want_write == want)
    {
        return;
    }
    epoll_event event = {};
    event.events = EPOLLIN | (want ? static_cast<uint32_t>(EPOLLOUT) : 0u);
    event.data.u64 = BEACON_SIGNAL_TAG_FIRST_CONNECTION + index;
    epoll_ctl(signal->epoll_fd, EPOLL_CTL_MOD, connection->fd, &event);
    connection->want_write = want;
}

// Sends what the buffer holds. Returns false if the connection was closed
// (an error, or a CLOSING connection that finished sending).
static bool connection_flush(BeaconSignal* signal, uint32_t index)
{
    BeaconConnection* connection = &signal->connections[index];
    size_t sent_total = 0;
    while (sent_total < connection->send_used)
    {
        ssize_t sent = send(connection->fd, connection->send + sent_total, connection->send_used - sent_total,
                            MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR)
        {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            break;
        }
        if (sent <= 0)
        {
            connection_free(signal, index);
            return false;
        }
        sent_total += static_cast<size_t>(sent);
    }
    if (sent_total > 0)
    {
        memmove(connection->send, connection->send + sent_total, connection->send_used - sent_total);
        connection->send_used -= static_cast<uint32_t>(sent_total);
    }
    if (connection->send_used == 0 && connection->state == BeaconConnectionState::CLOSING)
    {
        connection_free(signal, index);
        return false;
    }
    set_want_write(signal, index, connection->send_used > 0);
    return true;
}

// Appends bytes to the send buffer; false if they don't fit (the caller
// closes the connection: it isn't reading).
static bool queue_bytes(BeaconConnection* connection, const uint8_t* data, size_t size)
{
    if (size > BEACON_SIGNAL_SEND_SIZE - connection->send_used)
    {
        return false;
    }
    memcpy(connection->send + connection->send_used, data, size);
    connection->send_used += static_cast<uint32_t>(size);
    return true;
}

static bool queue_frame(BeaconConnection* connection, BeaconWsOpcode opcode, const uint8_t* payload, size_t size)
{
    uint8_t header[BEACON_WS_MAX_SERVER_HEADER];
    size_t header_size = beacon_ws_frame_header(opcode, size, header);
    if (header_size == 0 || header_size + size > BEACON_SIGNAL_SEND_SIZE - connection->send_used)
    {
        return false;
    }
    queue_bytes(connection, header, header_size);
    queue_bytes(connection, payload, size);
    return true;
}

// Queues a close frame with `code` (0: none) and stops reading. If even that
// doesn't fit, what's queued is dropped and the socket closes at the next
// flush.
static void start_closing(BeaconSignal* signal, uint32_t index, uint16_t code, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    uint8_t payload[2] = {static_cast<uint8_t>(code >> 8), static_cast<uint8_t>(code & 0xffu)};
    if (!queue_frame(connection, BeaconWsOpcode::CLOSE, payload, code == 0 ? 0 : 2))
    {
        connection->send_used = 0;
    }
    connection->state = BeaconConnectionState::CLOSING;
    connection->deadline_ms = now_ms + BEACON_SIGNAL_CLOSING_MS;
    connection->receive_used = 0;
}

// A binary message from the client. Step 3a: echoed back (the rooms of step
// 3b replace this). Returns false if the connection must close (its send
// buffer is full).
static bool handle_message(BeaconSignal* signal, uint32_t index, const uint8_t* payload, size_t size)
{
    signal->stats.messages++;
    return queue_frame(&signal->connections[index], BeaconWsOpcode::BINARY, payload, size);
}

// Parses what the receive buffer holds. Returns false if the connection was
// freed.
static bool connection_process(BeaconSignal* signal, uint32_t index, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    size_t consumed = 0;
    if (connection->state == BeaconConnectionState::HANDSHAKE)
    {
        BeaconWsHandshake handshake;
        BeaconWsParse result = beacon_ws_parse_handshake(connection->receive, connection->receive_used, &handshake);
        if (result == BeaconWsParse::INCOMPLETE)
        {
            return true;
        }
        char response[256];
        if (result == BeaconWsParse::INVALID)
        {
            signal->stats.bad_handshakes++;
            size_t size = beacon_ws_bad_request_response(response, sizeof(response));
            queue_bytes(connection, reinterpret_cast<const uint8_t*>(response), size);
            connection->state = BeaconConnectionState::CLOSING;
            connection->deadline_ms = now_ms + BEACON_SIGNAL_CLOSING_MS;
            connection->receive_used = 0;
            return true;
        }
        signal->stats.handshakes++;
        size_t size = beacon_ws_handshake_response(&handshake, response, sizeof(response));
        queue_bytes(connection, reinterpret_cast<const uint8_t*>(response), size);
        connection->state = BeaconConnectionState::OPEN;
        connection->last_frame_ms = now_ms;
        consumed = handshake.size;
    }
    while (connection->state == BeaconConnectionState::OPEN)
    {
        BeaconWsFrame frame;
        BeaconWsParse result =
            beacon_ws_parse_frame(connection->receive + consumed, connection->receive_used - consumed, &frame);
        if (result == BeaconWsParse::INCOMPLETE)
        {
            break;
        }
        if (result == BeaconWsParse::INVALID)
        {
            signal->stats.protocol_errors++;
            start_closing(signal, index, frame.error_code, now_ms);
            return true;
        }
        const uint8_t* payload = connection->receive + consumed + frame.payload_offset;
        connection->last_frame_ms = now_ms;
        bool ok = true;
        switch (frame.opcode)
        {
            case BeaconWsOpcode::BINARY:
                ok = handle_message(signal, index, payload, frame.payload_size);
                break;
            case BeaconWsOpcode::PING:
                ok = queue_frame(connection, BeaconWsOpcode::PONG, payload, frame.payload_size);
                break;
            case BeaconWsOpcode::CLOSE:
                start_closing(signal, index, frame.close_code, now_ms);
                return true;
            default:
                break;   // PONG: nothing to do
        }
        if (!ok)
        {
            signal->stats.slow_readers++;
            connection_free(signal, index);
            return false;
        }
        consumed += frame.size;
    }
    if (consumed > 0 && connection->state == BeaconConnectionState::OPEN)
    {
        memmove(connection->receive, connection->receive + consumed, connection->receive_used - consumed);
        connection->receive_used -= static_cast<uint32_t>(consumed);
    }
    return true;
}

static void connection_read(BeaconSignal* signal, uint32_t index, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    if (connection->state == BeaconConnectionState::CLOSING)
    {
        // Input is ignored while the close goes out; read it away so the
        // socket doesn't stay readable.
        uint8_t discard[1024];
        ssize_t got = recv(connection->fd, discard, sizeof(discard), MSG_DONTWAIT);
        if (got == 0 || (got < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
        {
            connection_free(signal, index);
        }
        return;
    }
    // The buffer always has room here: a full buffer is either a complete
    // frame (processed below) or refused by the parser's limits.
    size_t room = BEACON_SIGNAL_RECEIVE_SIZE - connection->receive_used;
    ssize_t got = recv(connection->fd, connection->receive + connection->receive_used, room, MSG_DONTWAIT);
    if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
    {
        return;
    }
    if (got <= 0)
    {
        connection_free(signal, index);
        return;
    }
    connection->receive_used += static_cast<uint32_t>(got);
    if (!connection_process(signal, index, now_ms))
    {
        return;
    }
    if (connection->receive_used == BEACON_SIGNAL_RECEIVE_SIZE)
    {
        // Can't happen with the parser's limits; never wait on a full buffer.
        signal->stats.protocol_errors++;
        connection_free(signal, index);
        return;
    }
    connection_flush(signal, index);
}

// ---------------------------------------------------------------------------

bool beacon_signal_open(BeaconSignal* signal, const BeaconSignalConfig* config, const char* bind_address,
                        uint16_t port, int epoll_fd)
{
    *signal = BeaconSignal{};
    if (config->max_connections < 1 || config->max_connections > BEACON_SIGNAL_MAX_CONNECTIONS)
    {
        beacon_log(BeaconLogLevel::error, "signaling: --max-connections out of range");
        return false;
    }
    sockaddr_storage storage = {};
    socklen_t length = 0;
    int family = 0;
    in6_addr ip6 = {};
    in_addr ip4 = {};
    if (inet_pton(AF_INET6, bind_address, &ip6) == 1)
    {
        sockaddr_in6 address = {};
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(port);
        address.sin6_addr = ip6;
        memcpy(&storage, &address, sizeof(address));
        length = sizeof(address);
        family = AF_INET6;
    }
    else if (inet_pton(AF_INET, bind_address, &ip4) == 1)
    {
        sockaddr_in address = {};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr = ip4;
        memcpy(&storage, &address, sizeof(address));
        length = sizeof(address);
        family = AF_INET;
    }
    else
    {
        beacon_log(BeaconLogLevel::error, "signaling: bind address '%s' is not a numeric IPv6 or IPv4 address",
                   bind_address);
        return false;
    }
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        beacon_log(BeaconLogLevel::error, "signaling: socket: %s", strerror(errno));
        return false;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (family == AF_INET6)
    {
        int v6only = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }
    if (bind(fd, reinterpret_cast<const sockaddr*>(&storage), length) != 0 || listen(fd, 128) != 0)
    {
        beacon_log(BeaconLogLevel::error, "signaling: listen on [%s]:%u: %s", bind_address,
                   static_cast<unsigned>(port), strerror(errno));
        close(fd);
        return false;
    }
    sockaddr_storage bound = {};
    socklen_t bound_length = sizeof(bound);
    BeaconAddress bound_address = {};
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_length) != 0 ||
        !beacon_address_from_sockaddr(&bound, &bound_address))
    {
        close(fd);
        return false;
    }
    epoll_event event = {};
    event.events = EPOLLIN;
    event.data.u64 = BEACON_SIGNAL_TAG_LISTEN;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0)
    {
        beacon_log(BeaconLogLevel::error, "signaling: epoll_ctl: %s", strerror(errno));
        close(fd);
        return false;
    }
    signal->config = *config;
    signal->connections.resize(config->max_connections);
    signal->free_slots.resize(config->max_connections);
    // Lowest indexes on top of the stack, so a quiet server touches few pages.
    for (uint32_t i = 0; i < config->max_connections; i++)
    {
        signal->free_slots[i] = config->max_connections - 1 - i;
    }
    signal->free_count = config->max_connections;
    signal->listen_fd = fd;
    signal->epoll_fd = epoll_fd;
    signal->port = bound_address.port;
    return true;
}

void beacon_signal_close(BeaconSignal* signal)
{
    for (uint32_t i = 0; i < signal->connections.size(); i++)
    {
        if (signal->connections[i].state != BeaconConnectionState::FREE)
        {
            connection_free(signal, i);
        }
    }
    if (signal->listen_fd >= 0)
    {
        epoll_ctl(signal->epoll_fd, EPOLL_CTL_DEL, signal->listen_fd, nullptr);
        close(signal->listen_fd);
    }
    *signal = BeaconSignal{};
}

void beacon_signal_accept(BeaconSignal* signal, uint64_t now_ms)
{
    for (uint32_t n = 0; n < ACCEPTS_PER_EVENT; n++)
    {
        sockaddr_storage from = {};
        socklen_t from_length = sizeof(from);
        int fd = accept4(signal->listen_fd, reinterpret_cast<sockaddr*>(&from), &from_length,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0)
        {
            // EAGAIN: nothing left. EMFILE and the like: try again next event.
            return;
        }
        BeaconAddress peer = {};
        if (signal->free_count == 0 || !beacon_address_from_sockaddr(&from, &peer))
        {
            signal->stats.refused_full++;
            close(fd);
            continue;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        uint32_t index = signal->free_slots[--signal->free_count];
        epoll_event event = {};
        event.events = EPOLLIN;
        event.data.u64 = BEACON_SIGNAL_TAG_FIRST_CONNECTION + index;
        if (epoll_ctl(signal->epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0)
        {
            signal->free_count++;
            close(fd);
            continue;
        }
        BeaconConnection* connection = &signal->connections[index];
        connection->fd = fd;
        connection->state = BeaconConnectionState::HANDSHAKE;
        connection->want_write = false;
        connection->peer = peer;
        connection->deadline_ms = now_ms + BEACON_SIGNAL_HANDSHAKE_MS;
        connection->last_frame_ms = now_ms;
        connection->receive_used = 0;
        connection->send_used = 0;
        signal->stats.accepted++;
        signal->stats.open++;
    }
}

void beacon_signal_event(BeaconSignal* signal, uint32_t index, uint32_t events, uint64_t now_ms)
{
    if (connection_at(signal, index) == nullptr)
    {
        return;
    }
    if ((events & EPOLLIN) != 0)
    {
        connection_read(signal, index, now_ms);
        if (connection_at(signal, index) == nullptr)
        {
            return;
        }
    }
    if ((events & EPOLLOUT) != 0)
    {
        if (!connection_flush(signal, index))
        {
            return;
        }
    }
    if ((events & (EPOLLERR | EPOLLHUP)) != 0 && (events & EPOLLIN) == 0)
    {
        connection_free(signal, index);
    }
}

void beacon_signal_tick(BeaconSignal* signal, uint64_t now_ms)
{
    for (uint32_t i = 0; i < signal->connections.size(); i++)
    {
        BeaconConnection* connection = &signal->connections[i];
        switch (connection->state)
        {
            case BeaconConnectionState::HANDSHAKE:
            case BeaconConnectionState::CLOSING:
                if (now_ms >= connection->deadline_ms)
                {
                    signal->stats.timeouts++;
                    connection_free(signal, i);
                }
                break;
            case BeaconConnectionState::OPEN:
                if (now_ms - connection->last_frame_ms >= BEACON_SIGNAL_IDLE_MS)
                {
                    signal->stats.timeouts++;
                    start_closing(signal, i, BEACON_WS_CLOSE_GOING_AWAY, now_ms);
                    connection_flush(signal, i);
                }
                break;
            default:
                break;
        }
    }
}

uint64_t beacon_signal_pool_bytes(const BeaconSignal* signal)
{
    return static_cast<uint64_t>(signal->connections.size()) * sizeof(BeaconConnection) +
           static_cast<uint64_t>(signal->free_slots.size()) * sizeof(uint32_t);
}
