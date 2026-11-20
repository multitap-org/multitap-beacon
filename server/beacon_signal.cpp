// beacon_signal: see beacon_signal.h and PROTOCOL.md ("Signaling").

#include "beacon_signal.h"

#include "beacon_log.h"
#include "beacon_net.h"
#include "beacon_random.h"

#include <monocypher.h>

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <unistd.h>

// Connections accepted per readable event, so a flood can't starve the rest.
static constexpr uint32_t ACCEPTS_PER_EVENT = 64;
static constexpr uint64_t MILLI = 1000;

// ---------------------------------------------------------------------------
// Addresses: sources and trusted proxies
// ---------------------------------------------------------------------------

// The per-source key: the IPv4 address, or the IPv6 /64 (one household).
static void source_key(const BeaconAddress* address, uint8_t key[16])
{
    memset(key, 0, 16);
    memcpy(key, address->ip, beacon_address_is_ipv4(address) ? 16 : 8);
}

bool beacon_cidr_parse(const char* text, BeaconCidr* out)
{
    *out = BeaconCidr{};
    char ip_text[INET6_ADDRSTRLEN + 1];
    const char* slash = strchr(text, '/');
    size_t ip_length = slash != nullptr ? static_cast<size_t>(slash - text) : strlen(text);
    if (ip_length == 0 || ip_length >= sizeof(ip_text))
    {
        return false;
    }
    memcpy(ip_text, text, ip_length);
    ip_text[ip_length] = '\0';
    in_addr ip4 = {};
    in6_addr ip6 = {};
    uint32_t max_prefix = 0;
    uint32_t base = 0;
    if (inet_pton(AF_INET, ip_text, &ip4) == 1)
    {
        out->ip[10] = 0xff;
        out->ip[11] = 0xff;
        memcpy(out->ip + 12, &ip4, 4);
        max_prefix = 32;
        base = 96;
    }
    else if (inet_pton(AF_INET6, ip_text, &ip6) == 1)
    {
        memcpy(out->ip, &ip6, 16);
        max_prefix = 128;
    }
    else
    {
        return false;
    }
    uint32_t prefix = max_prefix;
    if (slash != nullptr)
    {
        const char* digits = slash + 1;
        if (digits[0] < '0' || digits[0] > '9' || strlen(digits) > 3)
        {
            return false;
        }
        char* end = nullptr;
        unsigned long value = strtoul(digits, &end, 10);
        if (end == nullptr || *end != '\0' || value > max_prefix)
        {
            return false;
        }
        prefix = static_cast<uint32_t>(value);
    }
    out->prefix = static_cast<uint8_t>(base + prefix);
    return true;
}

bool beacon_cidr_contains(const BeaconCidr* range, const BeaconAddress* address)
{
    uint32_t full_bytes = range->prefix / 8u;
    if (memcmp(range->ip, address->ip, full_bytes) != 0)
    {
        return false;
    }
    uint32_t rest = range->prefix % 8u;
    if (rest == 0)
    {
        return true;
    }
    uint8_t mask = static_cast<uint8_t>(0xffu << (8u - rest));
    return (range->ip[full_bytes] & mask) == (address->ip[full_bytes] & mask);
}

// Loopback is always trusted: a proxy on the same machine is the usual setup.
static bool peer_trusted(const BeaconSignal* signal, const BeaconAddress* peer)
{
    static const uint8_t LOOPBACK6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (memcmp(peer->ip, LOOPBACK6, 16) == 0 || (beacon_address_is_ipv4(peer) && peer->ip[12] == 127))
    {
        return true;
    }
    for (uint32_t i = 0; i < signal->config.trusted_count; i++)
    {
        if (beacon_cidr_contains(&signal->config.trusted[i], peer))
        {
            return true;
        }
    }
    return false;
}

// A token bucket: `rate` tokens per second up to `burst`, `cost` taken.
static bool bucket_take(uint64_t* tokens_milli, uint64_t* last_ms, uint64_t now_ms, uint64_t rate, uint64_t burst,
                        uint64_t cost)
{
    uint64_t full = burst * MILLI;
    uint64_t elapsed = now_ms > *last_ms ? now_ms - *last_ms : 0;
    // tokens * 1000 per second = rate * 1000 per 1000 ms = rate per ms.
    uint64_t tokens = *tokens_milli + elapsed * rate;
    *tokens_milli = tokens > full ? full : tokens;
    *last_ms = now_ms;
    if (*tokens_milli < cost * MILLI)
    {
        return false;
    }
    *tokens_milli -= cost * MILLI;
    return true;
}

// ---------------------------------------------------------------------------
// Connections: buffers and epoll
// ---------------------------------------------------------------------------

static BeaconConnection* connection_at(BeaconSignal* signal, uint32_t index)
{
    if (index >= signal->connections.size())
    {
        return nullptr;
    }
    BeaconConnection* connection = &signal->connections[index];
    return connection->state == BeaconConnectionState::FREE ? nullptr : connection;
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

// Appends bytes to the send buffer; false if they don't fit.
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

// A connection that can't take what it's sent (it isn't reading): it's
// dropped without a close frame. Only marked here and put on the doomed list,
// because this runs while another connection is being handled; free_doomed()
// frees it (and takes it out of its rooms) once that's done.
static void doom(BeaconSignal* signal, uint32_t index, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    if (connection->doomed)
    {
        return;
    }
    signal->stats.slow_readers++;
    connection->doomed = true;
    connection->send_used = 0;
    connection->receive_used = 0;
    connection->state = BeaconConnectionState::CLOSING;
    connection->deadline_ms = now_ms;
    // One entry per connection at most (the flag), so the list never overflows.
    if (signal->doomed_count < signal->doomed.size())
    {
        signal->doomed[signal->doomed_count++] = index;
    }
}

// Queues a fixed-size signaling message for connection `index` (any OPEN
// one; others are skipped) and turns on its EPOLLOUT.
static void send_message(BeaconSignal* signal, uint32_t index, BeaconSignalingType type, const BeaconId* room,
                         uint8_t value, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    if (connection->state != BeaconConnectionState::OPEN)
    {
        return;
    }
    BeaconSignalingMessage message;
    message.type = type;
    message.room = *room;
    message.peer_present = value;
    if (type == BeaconSignalingType::REFUSED)
    {
        message.reason = static_cast<BeaconRefusal>(value);
    }
    uint8_t bytes[BEACON_SIGNALING_SIZE_JOIN];
    uint32_t size = beacon_signaling_encode(&message, bytes, sizeof(bytes));
    if (size == 0)
    {
        return;
    }
    if (!queue_frame(connection, BeaconWsOpcode::BINARY, bytes, size))
    {
        doom(signal, index, now_ms);
        return;
    }
    set_want_write(signal, index, true);
}

// ---------------------------------------------------------------------------
// Rooms
// ---------------------------------------------------------------------------

static uint32_t room_home(const BeaconSignal* signal, const BeaconId* id)
{
    uint8_t hash[8];
    crypto_blake2b_keyed(hash, sizeof(hash), signal->hash_key, sizeof(signal->hash_key), id->bytes, BEACON_ID_SIZE);
    uint32_t value = static_cast<uint32_t>(hash[0]) | (static_cast<uint32_t>(hash[1]) << 8) |
                     (static_cast<uint32_t>(hash[2]) << 16) | (static_cast<uint32_t>(hash[3]) << 24);
    return value & signal->room_mask;
}

// The room's slot or BEACON_SIGNAL_NONE; `free_slot` gets the window's first
// free slot (or BEACON_SIGNAL_NONE).
static uint32_t room_find(const BeaconSignal* signal, const BeaconId* id, uint32_t* free_slot)
{
    uint32_t home = room_home(signal, id);
    uint32_t found = BEACON_SIGNAL_NONE;
    *free_slot = BEACON_SIGNAL_NONE;
    for (uint32_t i = 0; i < BEACON_SIGNAL_PROBE_WINDOW; i++)
    {
        uint32_t slot = (home + i) & signal->room_mask;
        const BeaconRoom* room = &signal->rooms[slot];
        if (room->used == 0)
        {
            if (*free_slot == BEACON_SIGNAL_NONE)
            {
                *free_slot = slot;
            }
        }
        else if (found == BEACON_SIGNAL_NONE && beacon_id_equal(&room->id, id))
        {
            found = slot;
        }
    }
    return found;
}

static bool list_has(const BeaconConnection* connection, uint32_t slot)
{
    for (uint32_t i = 0; i < connection->room_count; i++)
    {
        if (connection->rooms[i] == slot)
        {
            return true;
        }
    }
    return false;
}

static void list_remove(BeaconConnection* connection, uint32_t slot)
{
    for (uint32_t i = 0; i < connection->room_count; i++)
    {
        if (connection->rooms[i] == slot)
        {
            connection->rooms[i] = connection->rooms[connection->room_count - 1];
            connection->room_count--;
            return;
        }
    }
}

// Takes connection `index` off its side of room `slot` (not off its list),
// tells the other side, and forgets the room if it's empty.
static void room_remove_side(BeaconSignal* signal, uint32_t slot, uint32_t index, uint64_t now_ms)
{
    BeaconRoom* room = &signal->rooms[slot];
    uint32_t other = BEACON_SIGNAL_NONE;
    if (room->host == index)
    {
        room->host = BEACON_SIGNAL_NONE;
        other = room->client;
    }
    else if (room->client == index)
    {
        room->client = BEACON_SIGNAL_NONE;
        other = room->host;
    }
    if (other != BEACON_SIGNAL_NONE)
    {
        send_message(signal, other, BeaconSignalingType::LEFT, &room->id, 0, now_ms);
    }
    if (room->host == BEACON_SIGNAL_NONE && room->client == BEACON_SIGNAL_NONE)
    {
        *room = BeaconRoom{};
        signal->stats.rooms--;
    }
}

static void leave_all_rooms(BeaconSignal* signal, uint32_t index, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    for (uint32_t i = 0; i < connection->room_count; i++)
    {
        room_remove_side(signal, connection->rooms[i], index, now_ms);
    }
    connection->room_count = 0;
}

// ---------------------------------------------------------------------------
// Connection lifetime
// ---------------------------------------------------------------------------

static void connection_free(BeaconSignal* signal, uint32_t index, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    leave_all_rooms(signal, index, now_ms);
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
    connection->doomed = false;
    connection->receive_used = 0;
    connection->send_used = 0;
    signal->free_slots[signal->free_count++] = index;
    signal->stats.open--;
}

// Frees the doomed connections. Freeing one tells its rooms' other sides,
// which can doom more: the loop runs until the list is empty. A connection
// already freed some other way (its doomed flag cleared) is skipped.
static void free_doomed(BeaconSignal* signal, uint64_t now_ms)
{
    while (signal->doomed_count > 0)
    {
        uint32_t index = signal->doomed[--signal->doomed_count];
        BeaconConnection* connection = &signal->connections[index];
        if (connection->doomed && connection->state != BeaconConnectionState::FREE)
        {
            connection_free(signal, index, now_ms);
        }
        connection->doomed = false;
    }
}

// Sends what the buffer holds. Returns false if the connection was freed (an
// error, or a CLOSING connection that finished sending).
static bool connection_flush(BeaconSignal* signal, uint32_t index, uint64_t now_ms)
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
            connection_free(signal, index, now_ms);
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
        connection_free(signal, index, now_ms);
        return false;
    }
    set_want_write(signal, index, connection->send_used > 0);
    return true;
}

// Queues a close frame with `code` (0: none), leaves the connection's rooms
// and stops reading. If even the close doesn't fit, what's queued is dropped
// and the socket closes at the next flush.
static void start_closing(BeaconSignal* signal, uint32_t index, uint16_t code, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    leave_all_rooms(signal, index, now_ms);
    uint8_t payload[2] = {static_cast<uint8_t>(code >> 8), static_cast<uint8_t>(code & 0xffu)};
    if (!queue_frame(connection, BeaconWsOpcode::CLOSE, payload, code == 0 ? 0 : 2))
    {
        connection->send_used = 0;
    }
    connection->state = BeaconConnectionState::CLOSING;
    connection->deadline_ms = now_ms + BEACON_SIGNAL_CLOSING_MS;
    connection->receive_used = 0;
}

// An HTTP error instead of the 101 (the socket closes once it's sent).
static void refuse_handshake(BeaconConnection* connection, const char* response, size_t size, uint64_t now_ms)
{
    queue_bytes(connection, reinterpret_cast<const uint8_t*>(response), size);
    connection->state = BeaconConnectionState::CLOSING;
    connection->deadline_ms = now_ms + BEACON_SIGNAL_CLOSING_MS;
    connection->receive_used = 0;
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

// JOIN: returns false if the connection was closed for it.
static bool handle_join(BeaconSignal* signal, uint32_t index, const BeaconSignalingMessage* message, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    uint32_t free_slot = BEACON_SIGNAL_NONE;
    uint32_t slot = room_find(signal, &message->room, &free_slot);
    if (slot == BEACON_SIGNAL_NONE)
    {
        if (connection->room_count >= BEACON_SIGNAL_MAX_ROOMS_PER_CONNECTION)
        {
            signal->stats.refused_rooms++;
            send_message(signal, index, BeaconSignalingType::REFUSED, &message->room,
                         static_cast<uint8_t>(BeaconRefusal::ROOMS_PER_CONNECTION), now_ms);
            return true;
        }
        if (free_slot == BEACON_SIGNAL_NONE || signal->stats.rooms >= signal->config.max_rooms)
        {
            signal->stats.refused_rooms++;
            send_message(signal, index, BeaconSignalingType::REFUSED, &message->room,
                         static_cast<uint8_t>(BeaconRefusal::ROOMS_FULL), now_ms);
            return true;
        }
        slot = free_slot;
        BeaconRoom* fresh = &signal->rooms[slot];
        *fresh = BeaconRoom{};
        fresh->id = message->room;
        fresh->used = 1;
        signal->stats.rooms++;
    }
    BeaconRoom* room = &signal->rooms[slot];
    bool host = message->role == BeaconRole::HOST;
    uint32_t* side = host ? &room->host : &room->client;
    uint32_t* other = host ? &room->client : &room->host;
    if (*other == index)
    {
        // Both sides of one room on one socket: a client bug.
        signal->stats.protocol_errors++;
        start_closing(signal, index, BEACON_WS_CLOSE_POLICY, now_ms);
        return false;
    }
    if (*side != index)
    {
        if (connection->room_count >= BEACON_SIGNAL_MAX_ROOMS_PER_CONNECTION)
        {
            signal->stats.refused_rooms++;
            send_message(signal, index, BeaconSignalingType::REFUSED, &message->room,
                         static_cast<uint8_t>(BeaconRefusal::ROOMS_PER_CONNECTION), now_ms);
            return true;
        }
        if (*side != BEACON_SIGNAL_NONE)
        {
            // A reconnect before the old socket timed out: the new one wins.
            uint32_t old = *side;
            signal->stats.replaced++;
            list_remove(&signal->connections[old], slot);
            send_message(signal, old, BeaconSignalingType::LEFT, &room->id, 0, now_ms);
        }
        *side = index;
        connection->rooms[connection->room_count++] = slot;
        if (*other != BEACON_SIGNAL_NONE)
        {
            send_message(signal, *other, BeaconSignalingType::PEER_JOINED, &room->id, 0, now_ms);
        }
    }
    signal->stats.joins++;
    bool present = *other != BEACON_SIGNAL_NONE && signal->connections[*other].state == BeaconConnectionState::OPEN;
    send_message(signal, index, BeaconSignalingType::JOINED, &room->id, present ? 1 : 0, now_ms);
    return true;
}

static void handle_leave(BeaconSignal* signal, uint32_t index, const BeaconSignalingMessage* message, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    uint32_t free_slot = BEACON_SIGNAL_NONE;
    uint32_t slot = room_find(signal, &message->room, &free_slot);
    if (slot == BEACON_SIGNAL_NONE || !list_has(connection, slot))
    {
        return;
    }
    list_remove(connection, slot);
    room_remove_side(signal, slot, index, now_ms);
}

// SIGNAL: the whole message (`payload`, header included) goes to the other side.
static void handle_signal(BeaconSignal* signal, uint32_t index, const BeaconSignalingMessage* message,
                          const uint8_t* payload, size_t size, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    uint32_t free_slot = BEACON_SIGNAL_NONE;
    uint32_t slot = room_find(signal, &message->room, &free_slot);
    uint32_t other = BEACON_SIGNAL_NONE;
    if (slot != BEACON_SIGNAL_NONE && list_has(connection, slot))
    {
        const BeaconRoom* room = &signal->rooms[slot];
        other = room->host == index ? room->client : room->host;
    }
    if (other == BEACON_SIGNAL_NONE || signal->connections[other].state != BeaconConnectionState::OPEN)
    {
        signal->stats.not_found++;
        send_message(signal, index, BeaconSignalingType::NOT_FOUND, &message->room, 0, now_ms);
        return;
    }
    if (!queue_frame(&signal->connections[other], BeaconWsOpcode::BINARY, payload, size))
    {
        doom(signal, other, now_ms);
        signal->stats.not_found++;
        send_message(signal, index, BeaconSignalingType::NOT_FOUND, &message->room, 0, now_ms);
        return;
    }
    signal->stats.signals++;
    set_want_write(signal, other, true);
}

// A binary message from an OPEN connection. Returns false if the connection
// is no longer OPEN after it.
static bool handle_message(BeaconSignal* signal, uint32_t index, const uint8_t* payload, size_t size, uint64_t now_ms)
{
    BeaconSignalingMessage message;
    if (!beacon_signaling_decode(payload, size, &message))
    {
        signal->stats.protocol_errors++;
        start_closing(signal, index, BEACON_WS_CLOSE_PROTOCOL_ERROR, now_ms);
        return false;
    }
    switch (message.type)
    {
        case BeaconSignalingType::JOIN:
            if (!handle_join(signal, index, &message, now_ms))
            {
                return false;
            }
            break;
        case BeaconSignalingType::LEAVE:
            handle_leave(signal, index, &message, now_ms);
            break;
        case BeaconSignalingType::SIGNAL:
            handle_signal(signal, index, &message, payload, size, now_ms);
            break;
        default:
            // A server-only type from a client.
            signal->stats.protocol_errors++;
            start_closing(signal, index, BEACON_WS_CLOSE_PROTOCOL_ERROR, now_ms);
            return false;
    }
    return signal->connections[index].state == BeaconConnectionState::OPEN;
}

// The handshake parsed: the client's source, its limit, then 101 or 429.
static void finish_handshake(BeaconSignal* signal, uint32_t index, const BeaconWsHandshake* handshake, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    BeaconAddress source = connection->peer;
    if (handshake->has_forwarded && peer_trusted(signal, &connection->peer))
    {
        source = handshake->forwarded;
    }
    source_key(&source, connection->source_key);
    uint32_t same = 0;
    for (uint32_t i = 0; i < signal->connections.size(); i++)
    {
        const BeaconConnection* other = &signal->connections[i];
        if (i != index && other->state == BeaconConnectionState::OPEN &&
            memcmp(other->source_key, connection->source_key, 16) == 0)
        {
            same++;
        }
    }
    char response[256];
    if (same >= signal->config.max_connections_per_source)
    {
        signal->stats.refused_source++;
        refuse_handshake(connection, response, beacon_ws_too_many_response(response, sizeof(response)), now_ms);
        return;
    }
    signal->stats.handshakes++;
    size_t size = beacon_ws_handshake_response(handshake, response, sizeof(response));
    queue_bytes(connection, reinterpret_cast<const uint8_t*>(response), size);
    connection->state = BeaconConnectionState::OPEN;
    connection->last_frame_ms = now_ms;
    connection->messages_last_ms = now_ms;
    connection->message_tokens_milli = static_cast<uint64_t>(signal->config.message_burst) * MILLI;
    connection->bytes_last_ms = now_ms;
    connection->byte_tokens_milli = static_cast<uint64_t>(signal->config.byte_burst) * MILLI;
    connection->room_count = 0;
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
        if (result == BeaconWsParse::INVALID)
        {
            signal->stats.bad_handshakes++;
            char response[256];
            refuse_handshake(connection, response, beacon_ws_bad_request_response(response, sizeof(response)), now_ms);
            return true;
        }
        finish_handshake(signal, index, &handshake, now_ms);
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
        consumed += frame.size;
        connection->last_frame_ms = now_ms;
        if (frame.opcode == BeaconWsOpcode::BINARY || frame.opcode == BeaconWsOpcode::PING)
        {
            bool allowed = bucket_take(&connection->message_tokens_milli, &connection->messages_last_ms, now_ms,
                                       signal->config.messages_per_second, signal->config.message_burst, 1) &&
                           bucket_take(&connection->byte_tokens_milli, &connection->bytes_last_ms, now_ms,
                                       signal->config.bytes_per_second, signal->config.byte_burst, frame.payload_size);
            if (!allowed)
            {
                signal->stats.rate_limited++;
                start_closing(signal, index, BEACON_WS_CLOSE_POLICY, now_ms);
                return true;
            }
        }
        switch (frame.opcode)
        {
            case BeaconWsOpcode::BINARY:
                handle_message(signal, index, payload, frame.payload_size, now_ms);
                break;
            case BeaconWsOpcode::PING:
                if (!queue_frame(connection, BeaconWsOpcode::PONG, payload, frame.payload_size))
                {
                    doom(signal, index, now_ms);
                }
                break;
            case BeaconWsOpcode::CLOSE:
                start_closing(signal, index, frame.close_code, now_ms);
                return true;
            default:
                break;   // PONG: nothing to do
        }
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
            connection_free(signal, index, now_ms);
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
        connection_free(signal, index, now_ms);
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
        connection_free(signal, index, now_ms);
        return;
    }
    connection_flush(signal, index, now_ms);
}

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

static uint32_t table_slots_for(uint32_t items)
{
    // A power of two with at least twice the items (load <= 50%).
    uint32_t slots = BEACON_SIGNAL_PROBE_WINDOW;
    while (slots < items * 2u)
    {
        slots *= 2;
    }
    return slots;
}

bool beacon_signal_open(BeaconSignal* signal, const BeaconSignalConfig* config, const char* bind_address,
                        uint16_t port, int epoll_fd)
{
    *signal = BeaconSignal{};
    if (config->max_connections < 1 || config->max_connections > BEACON_SIGNAL_MAX_CONNECTIONS ||
        config->max_rooms < 1 || config->max_rooms > (1u << 24) || config->max_connections_per_source < 1 ||
        config->messages_per_second < 1 || config->message_burst < 1 || config->bytes_per_second < 1 ||
        config->byte_burst < BEACON_WS_MAX_PAYLOAD || config->trusted_count > BEACON_SIGNAL_MAX_TRUSTED)
    {
        beacon_log(BeaconLogLevel::error, "signaling: configuration out of range");
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
    if (!beacon_random_fill(signal->hash_key, sizeof(signal->hash_key)))
    {
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
    signal->doomed.resize(config->max_connections);
    // Lowest indexes on top of the stack, so a quiet server touches few pages.
    for (uint32_t i = 0; i < config->max_connections; i++)
    {
        signal->free_slots[i] = config->max_connections - 1 - i;
    }
    signal->free_count = config->max_connections;
    uint32_t room_slots = table_slots_for(config->max_rooms);
    signal->rooms.resize(room_slots);
    signal->room_mask = room_slots - 1;
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
            connection_free(signal, i, 0);
        }
    }
    if (signal->listen_fd >= 0)
    {
        epoll_ctl(signal->epoll_fd, EPOLL_CTL_DEL, signal->listen_fd, nullptr);
        close(signal->listen_fd);
    }
    crypto_wipe(signal->hash_key, sizeof(signal->hash_key));
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
        memset(connection->source_key, 0, sizeof(connection->source_key));
        connection->deadline_ms = now_ms + BEACON_SIGNAL_HANDSHAKE_MS;
        connection->last_frame_ms = now_ms;
        connection->room_count = 0;
        connection->receive_used = 0;
        connection->send_used = 0;
        signal->stats.accepted++;
        signal->stats.open++;
    }
}

static void connection_event(BeaconSignal* signal, uint32_t index, uint32_t events, uint64_t now_ms)
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
        if (!connection_flush(signal, index, now_ms))
        {
            return;
        }
    }
    if ((events & (EPOLLERR | EPOLLHUP)) != 0 && (events & EPOLLIN) == 0)
    {
        connection_free(signal, index, now_ms);
    }
}

void beacon_signal_event(BeaconSignal* signal, uint32_t index, uint32_t events, uint64_t now_ms)
{
    connection_event(signal, index, events, now_ms);
    free_doomed(signal, now_ms);
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
                    connection_free(signal, i, now_ms);
                }
                break;
            case BeaconConnectionState::OPEN:
                if (now_ms - connection->last_frame_ms >= BEACON_SIGNAL_IDLE_MS)
                {
                    signal->stats.timeouts++;
                    start_closing(signal, i, BEACON_WS_CLOSE_GOING_AWAY, now_ms);
                    connection_flush(signal, i, now_ms);
                }
                break;
            default:
                break;
        }
    }
    free_doomed(signal, now_ms);
}

void beacon_signal_stats_reset(BeaconSignal* signal)
{
    uint32_t open = signal->stats.open;
    uint32_t rooms = signal->stats.rooms;
    signal->stats = BeaconSignalStats{};
    signal->stats.open = open;
    signal->stats.rooms = rooms;
}

uint64_t beacon_signal_pool_bytes(const BeaconSignal* signal)
{
    return static_cast<uint64_t>(signal->connections.size()) * sizeof(BeaconConnection) +
           static_cast<uint64_t>(signal->free_slots.size()) * sizeof(uint32_t) +
           static_cast<uint64_t>(signal->rooms.size()) * sizeof(BeaconRoom);
}
