// beacon_signal: see beacon_signal.h and PROTOCOL.md ("Signaling").

#include "beacon_signal.h"

#include "beacon_log.h"
#include "beacon_net.h"
#include "beacon_random.h"

#include <monocypher.h>

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
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
    if (type == BeaconSignalingType::REFUSED)
    {
        message.reason = static_cast<BeaconRefusal>(value);
    }
    else if (type == BeaconSignalingType::GUEST_JOINED || type == BeaconSignalingType::GUEST_LEFT)
    {
        message.guest = value;
    }
    else if (type == BeaconSignalingType::JOINED)
    {
        message.peer_present = value;
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
// A guest room's host is gone: every guest gets LEFT and leaves it, and the
// room is forgotten.
static void guest_room_end(BeaconSignal* signal, uint32_t slot, uint64_t now_ms)
{
    BeaconRoom* room = &signal->rooms[slot];
    for (uint32_t i = 0; i < BEACON_SIGNALING_MAX_GUESTS; i++)
    {
        uint32_t guest = room->guests[i];
        if (guest != BEACON_SIGNAL_NONE)
        {
            room->guests[i] = BEACON_SIGNAL_NONE;
            list_remove(&signal->connections[guest], slot);
            send_message(signal, guest, BeaconSignalingType::LEFT, &room->id, 0, now_ms);
        }
    }
    *room = BeaconRoom{};
    signal->stats.rooms--;
}

static uint32_t guest_index_of(const BeaconRoom* room, uint32_t index)
{
    for (uint32_t i = 0; i < BEACON_SIGNALING_MAX_GUESTS; i++)
    {
        if (room->guests[i] == index)
        {
            return i;
        }
    }
    return BEACON_SIGNAL_NONE;
}

static void room_remove_side(BeaconSignal* signal, uint32_t slot, uint32_t index, uint64_t now_ms)
{
    BeaconRoom* room = &signal->rooms[slot];
    if (room->guest_room != 0)
    {
        if (room->host == index)
        {
            guest_room_end(signal, slot, now_ms);
            return;
        }
        uint32_t guest = guest_index_of(room, index);
        if (guest != BEACON_SIGNAL_NONE)
        {
            room->guests[guest] = BEACON_SIGNAL_NONE;
            if (room->host != BEACON_SIGNAL_NONE)
            {
                send_message(signal, room->host, BeaconSignalingType::GUEST_LEFT, &room->id,
                             static_cast<uint8_t>(guest), now_ms);
            }
        }
        return;
    }
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

// Gives back an HTTP connection's upload and page slots.
static void release_http(BeaconSignal* signal, BeaconConnection* connection)
{
    if (connection->upload_slot != BEACON_SIGNAL_NONE)
    {
        signal->upload_used[connection->upload_slot] = 0;
        connection->upload_slot = BEACON_SIGNAL_NONE;
    }
    if (connection->body_kind == BeaconBodyKind::PAGE && connection->body_index != BEACON_SIGNAL_NONE)
    {
        signal->page_used[connection->body_index] = 0;
    }
    connection->body_kind = BeaconBodyKind::NONE;
    connection->body_index = BEACON_SIGNAL_NONE;
    connection->body_offset = 0;
    connection->body_size = 0;
    connection->upload_size = 0;
    connection->upload_used = 0;
}

static void connection_free(BeaconSignal* signal, uint32_t index, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    leave_all_rooms(signal, index, now_ms);
    release_http(signal, connection);
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
// Moves the next piece of an HTTP body into the send buffer (after what's
// there). False if the body can't go on: its card was replaced or deleted.
static bool refill_body(BeaconSignal* signal, BeaconConnection* connection)
{
    if (connection->body_kind == BeaconBodyKind::NONE || connection->body_offset >= connection->body_size)
    {
        return true;
    }
    const uint8_t* source = nullptr;
    if (connection->body_kind == BeaconBodyKind::PAGE)
    {
        source = signal->page_data.data() + static_cast<size_t>(connection->body_index) * BEACON_HTTP_PAGE_SIZE;
    }
    else if (connection->body_kind == BeaconBodyKind::NOISE)
    {
        size_t noise_size = 0;
        source = beacon_join_noise(&noise_size);
    }
    else
    {
        const BeaconCard* card = &signal->cards[connection->body_index];
        if (card->used == 0 || card->generation != connection->body_generation)
        {
            return false;
        }
        source = signal->card_data.data() + static_cast<size_t>(connection->body_index) * BEACON_CARD_MAX_PNG;
    }
    size_t room = BEACON_SIGNAL_SEND_SIZE - connection->send_used;
    size_t left = connection->body_size - connection->body_offset;
    size_t piece = left < room ? left : room;
    memcpy(connection->send + connection->send_used, source + connection->body_offset, piece);
    connection->send_used += static_cast<uint32_t>(piece);
    connection->body_offset += static_cast<uint32_t>(piece);
    return true;
}

static bool body_done(const BeaconConnection* connection)
{
    return connection->body_kind == BeaconBodyKind::NONE || connection->body_offset >= connection->body_size;
}

static bool connection_flush(BeaconSignal* signal, uint32_t index, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    if (!refill_body(signal, connection))
    {
        connection_free(signal, index, now_ms);
        return false;
    }
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
        if (sent_total == connection->send_used && !body_done(connection))
        {
            // All out: the next piece of the body.
            connection->send_used = 0;
            sent_total = 0;
            if (!refill_body(signal, connection))
            {
                connection_free(signal, index, now_ms);
                return false;
            }
        }
    }
    if (sent_total > 0)
    {
        memmove(connection->send, connection->send + sent_total, connection->send_used - sent_total);
        connection->send_used -= static_cast<uint32_t>(sent_total);
    }
    if (connection->send_used == 0 && connection->state == BeaconConnectionState::CLOSING && body_done(connection))
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

static void refuse_join(BeaconSignal* signal, uint32_t index, const BeaconId* room, BeaconRefusal reason,
                        uint64_t now_ms)
{
    signal->stats.refused_rooms++;
    send_message(signal, index, BeaconSignalingType::REFUSED, room, static_cast<uint8_t>(reason), now_ms);
}

// A token bucket counted per minute (bucket_take's rates are per second).
static bool bucket_take_per_minute(uint64_t* tokens_milli, uint64_t* last_ms, uint64_t now_ms, uint64_t rate,
                                   uint64_t burst)
{
    uint64_t full = burst * MILLI * 60;
    uint64_t elapsed = now_ms > *last_ms ? now_ms - *last_ms : 0;
    // Counted in 1/60000 tokens: `rate` per minute = rate per ms in these units.
    uint64_t tokens = *tokens_milli + elapsed * rate;
    *tokens_milli = tokens > full ? full : tokens;
    *last_ms = now_ms;
    if (*tokens_milli < MILLI * 60)
    {
        return false;
    }
    *tokens_milli -= MILLI * 60;
    return true;
}

// JOIN as a guest room's host: makes the room (or refreshes it). A new host
// socket replaces the old one, and the guests start over (they get LEFT).
static bool handle_join_guest_host(BeaconSignal* signal, uint32_t index, const BeaconSignalingMessage* message,
                                   uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    uint32_t free_slot = BEACON_SIGNAL_NONE;
    uint32_t slot = room_find(signal, &message->room, &free_slot);
    if (slot != BEACON_SIGNAL_NONE && signal->rooms[slot].guest_room == 0)
    {
        refuse_join(signal, index, &message->room, BeaconRefusal::ROOM_KIND, now_ms);
        return true;
    }
    if (slot != BEACON_SIGNAL_NONE && guest_index_of(&signal->rooms[slot], index) != BEACON_SIGNAL_NONE)
    {
        // Host and guest of one room on one socket: a client bug.
        signal->stats.protocol_errors++;
        start_closing(signal, index, BEACON_WS_CLOSE_POLICY, now_ms);
        return false;
    }
    if (slot != BEACON_SIGNAL_NONE && signal->rooms[slot].host == index)
    {
        signal->stats.joins++;
        send_message(signal, index, BeaconSignalingType::JOINED, &message->room, 0, now_ms);
        return true;
    }
    if (connection->room_count >= BEACON_SIGNAL_MAX_ROOMS_PER_CONNECTION)
    {
        refuse_join(signal, index, &message->room, BeaconRefusal::ROOMS_PER_CONNECTION, now_ms);
        return true;
    }
    if (slot != BEACON_SIGNAL_NONE)
    {
        // A reconnect before the old socket timed out: the new one wins, and
        // the guests start over with it.
        uint32_t old = signal->rooms[slot].host;
        signal->stats.replaced++;
        list_remove(&signal->connections[old], slot);
        send_message(signal, old, BeaconSignalingType::LEFT, &message->room, 0, now_ms);
        guest_room_end(signal, slot, now_ms);
        slot = room_find(signal, &message->room, &free_slot);
    }
    if (free_slot == BEACON_SIGNAL_NONE || signal->stats.rooms >= signal->config.max_rooms)
    {
        refuse_join(signal, index, &message->room, BeaconRefusal::ROOMS_FULL, now_ms);
        return true;
    }
    BeaconRoom* room = &signal->rooms[free_slot];
    *room = BeaconRoom{};
    room->id = message->room;
    room->used = 1;
    room->guest_room = 1;
    room->host = index;
    signal->stats.rooms++;
    connection->rooms[connection->room_count++] = free_slot;
    signal->stats.joins++;
    send_message(signal, index, BeaconSignalingType::JOINED, &message->room, 0, now_ms);
    return true;
}

// JOIN as a guest: only into a guest room whose host is there, at most
// BEACON_SIGNALING_MAX_GUESTS at once, and only so often per socket.
static bool handle_join_guest(BeaconSignal* signal, uint32_t index, const BeaconSignalingMessage* message,
                              uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    uint32_t free_slot = BEACON_SIGNAL_NONE;
    uint32_t slot = room_find(signal, &message->room, &free_slot);
    if (slot == BEACON_SIGNAL_NONE || signal->rooms[slot].host == BEACON_SIGNAL_NONE)
    {
        signal->stats.not_found++;
        send_message(signal, index, BeaconSignalingType::NOT_FOUND, &message->room, 0, now_ms);
        return true;
    }
    BeaconRoom* room = &signal->rooms[slot];
    if (room->guest_room == 0)
    {
        signal->stats.refused_guests++;
        refuse_join(signal, index, &message->room, BeaconRefusal::ROOM_KIND, now_ms);
        return true;
    }
    if (room->host == index)
    {
        signal->stats.protocol_errors++;
        start_closing(signal, index, BEACON_WS_CLOSE_POLICY, now_ms);
        return false;
    }
    if (guest_index_of(room, index) != BEACON_SIGNAL_NONE)
    {
        signal->stats.joins++;
        send_message(signal, index, BeaconSignalingType::JOINED, &message->room, 1, now_ms);
        return true;
    }
    if (!bucket_take_per_minute(&connection->guest_join_tokens_milli, &connection->guest_joins_last_ms, now_ms,
                                signal->config.guest_joins_per_minute, signal->config.guest_join_burst))
    {
        signal->stats.refused_guests++;
        refuse_join(signal, index, &message->room, BeaconRefusal::GUEST_RATE, now_ms);
        return true;
    }
    if (connection->room_count >= BEACON_SIGNAL_MAX_ROOMS_PER_CONNECTION)
    {
        refuse_join(signal, index, &message->room, BeaconRefusal::ROOMS_PER_CONNECTION, now_ms);
        return true;
    }
    uint32_t guest = guest_index_of(room, BEACON_SIGNAL_NONE);
    if (guest == BEACON_SIGNAL_NONE)
    {
        signal->stats.refused_guests++;
        refuse_join(signal, index, &message->room, BeaconRefusal::GUESTS_FULL, now_ms);
        return true;
    }
    room->guests[guest] = index;
    connection->rooms[connection->room_count++] = slot;
    signal->stats.joins++;
    signal->stats.guest_joins++;
    send_message(signal, room->host, BeaconSignalingType::GUEST_JOINED, &room->id, static_cast<uint8_t>(guest),
                 now_ms);
    send_message(signal, index, BeaconSignalingType::JOINED, &room->id, 1, now_ms);
    return true;
}

// JOIN: returns false if the connection was closed for it.
static bool handle_join(BeaconSignal* signal, uint32_t index, const BeaconSignalingMessage* message, uint64_t now_ms)
{
    if (message->role == BeaconRole::GUEST_HOST)
    {
        return handle_join_guest_host(signal, index, message, now_ms);
    }
    if (message->role == BeaconRole::GUEST)
    {
        return handle_join_guest(signal, index, message, now_ms);
    }
    BeaconConnection* connection = &signal->connections[index];
    uint32_t free_slot = BEACON_SIGNAL_NONE;
    uint32_t slot = room_find(signal, &message->room, &free_slot);
    if (slot != BEACON_SIGNAL_NONE && signal->rooms[slot].guest_room != 0)
    {
        refuse_join(signal, index, &message->room, BeaconRefusal::ROOM_KIND, now_ms);
        return true;
    }
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

// Queues a re-encoded message for `target` (OPEN) and turns on its EPOLLOUT;
// false if it can't take it (then it's doomed).
static bool forward_message(BeaconSignal* signal, uint32_t target, const BeaconSignalingMessage* message,
                            uint64_t now_ms)
{
    uint8_t bytes[BEACON_SIGNALING_MAX_SIZE];
    uint32_t size = beacon_signaling_encode(message, bytes, sizeof(bytes));
    if (size == 0)
    {
        return false;
    }
    if (!queue_frame(&signal->connections[target], BeaconWsOpcode::BINARY, bytes, size))
    {
        doom(signal, target, now_ms);
        return false;
    }
    set_want_write(signal, target, true);
    return true;
}

// A guest's SIGNAL in its guest room: to the host as GUEST_SIGNAL, with the
// guest's index. The host's own SIGNAL here is a mistake (it must say which
// guest): NOT_FOUND.
static void handle_guest_signal_up(BeaconSignal* signal, uint32_t index, uint32_t slot,
                                   const BeaconSignalingMessage* message, uint64_t now_ms)
{
    const BeaconRoom* room = &signal->rooms[slot];
    uint32_t guest = guest_index_of(room, index);
    uint32_t host = room->host;
    if (guest == BEACON_SIGNAL_NONE || host == BEACON_SIGNAL_NONE ||
        signal->connections[host].state != BeaconConnectionState::OPEN)
    {
        signal->stats.not_found++;
        send_message(signal, index, BeaconSignalingType::NOT_FOUND, &message->room, 0, now_ms);
        return;
    }
    if (message->blob_size > BEACON_SIGNALING_MAX_GUEST_BLOB)
    {
        // Too big to carry the index: the guest's own limit (PROTOCOL.md).
        signal->stats.protocol_errors++;
        start_closing(signal, index, BEACON_WS_CLOSE_TOO_BIG, now_ms);
        return;
    }
    BeaconSignalingMessage up;
    up.type = BeaconSignalingType::GUEST_SIGNAL;
    up.room = message->room;
    up.guest = static_cast<uint8_t>(guest);
    up.blob = message->blob;
    up.blob_size = message->blob_size;
    if (!forward_message(signal, host, &up, now_ms))
    {
        signal->stats.not_found++;
        send_message(signal, index, BeaconSignalingType::NOT_FOUND, &message->room, 0, now_ms);
        return;
    }
    signal->stats.signals++;
}

// GUEST_SIGNAL from a guest room's host: to that guest as SIGNAL. A guest
// that's gone gets the host a GUEST_LEFT (NOT_FOUND couldn't say which).
static void handle_guest_signal_down(BeaconSignal* signal, uint32_t index, const BeaconSignalingMessage* message,
                                     uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    uint32_t free_slot = BEACON_SIGNAL_NONE;
    uint32_t slot = room_find(signal, &message->room, &free_slot);
    if (slot == BEACON_SIGNAL_NONE || !list_has(connection, slot) || signal->rooms[slot].guest_room == 0 ||
        signal->rooms[slot].host != index)
    {
        signal->stats.not_found++;
        send_message(signal, index, BeaconSignalingType::NOT_FOUND, &message->room, 0, now_ms);
        return;
    }
    uint32_t guest = signal->rooms[slot].guests[message->guest];
    BeaconSignalingMessage down;
    down.type = BeaconSignalingType::SIGNAL;
    down.room = message->room;
    down.blob = message->blob;
    down.blob_size = message->blob_size;
    if (guest == BEACON_SIGNAL_NONE || signal->connections[guest].state != BeaconConnectionState::OPEN ||
        !forward_message(signal, guest, &down, now_ms))
    {
        signal->stats.not_found++;
        send_message(signal, index, BeaconSignalingType::GUEST_LEFT, &message->room, message->guest, now_ms);
        return;
    }
    signal->stats.signals++;
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
        if (room->guest_room != 0)
        {
            handle_guest_signal_up(signal, index, slot, message, now_ms);
            return;
        }
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
        case BeaconSignalingType::GUEST_SIGNAL:
            handle_guest_signal_down(signal, index, &message, now_ms);
            break;
        default:
            // A server-only type from a client.
            signal->stats.protocol_errors++;
            start_closing(signal, index, BEACON_WS_CLOSE_PROTOCOL_ERROR, now_ms);
            return false;
    }
    return signal->connections[index].state == BeaconConnectionState::OPEN;
}

// ---------------------------------------------------------------------------
// HTTP: join pages, cards, card uploads
// ---------------------------------------------------------------------------

static uint32_t card_find(const BeaconSignal* signal, const char* room)
{
    for (uint32_t i = 0; i < signal->cards.size(); i++)
    {
        const BeaconCard* card = &signal->cards[i];
        if (card->used != 0 && memcmp(card->room, room, BEACON_GUEST_ROOM_SIZE) == 0)
        {
            return i;
        }
    }
    return BEACON_SIGNAL_NONE;
}

static void card_delete(BeaconSignal* signal, uint32_t index)
{
    BeaconCard* card = &signal->cards[index];
    uint32_t generation = card->generation + 1;
    *card = BeaconCard{};
    // Kept, so a send that started before can tell (refill_body).
    card->generation = generation;
    signal->stats.cards--;
    signal->stats.cards_deleted++;
}

static uint32_t slot_take(std::vector<uint8_t>* used)
{
    for (uint32_t i = 0; i < used->size(); i++)
    {
        if ((*used)[i] == 0)
        {
            (*used)[i] = 1;
            return i;
        }
    }
    return BEACON_SIGNAL_NONE;
}

// A whole response with no body (or a short text one), then the connection closes.
static void http_answer(BeaconSignal* signal, BeaconConnection* connection, uint32_t status, uint64_t now_ms)
{
    if (status >= 400)
    {
        signal->stats.http_refused++;
    }
    char head[512];
    size_t size = beacon_http_response_head(status, nullptr, nullptr, 0, head, sizeof(head));
    connection->send_used = 0;
    queue_bytes(connection, reinterpret_cast<const uint8_t*>(head), size);
    connection->state = BeaconConnectionState::CLOSING;
    connection->deadline_ms = now_ms + BEACON_SIGNAL_CLOSING_MS;
    connection->receive_used = 0;
}

// The scheme and host for absolute URLs.
static void http_base(const BeaconSignal* signal, const BeaconHttpRequest* request, char* out, size_t capacity)
{
    if (signal->config.public_url[0] != '\0')
    {
        snprintf(out, capacity, "%s", signal->config.public_url);
    }
    else if (request->host[0] != '\0')
    {
        snprintf(out, capacity, "https://%s", request->host);
    }
    else
    {
        out[0] = '\0';
    }
}

static const char PAGE_HEADERS[] =
    "Cache-Control: no-store\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "X-Robots-Tag: noindex\r\n"
    "Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\r\n";

static void http_page(BeaconSignal* signal, uint32_t index, const BeaconHttpRequest* request, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    uint32_t slot = slot_take(&signal->page_used);
    if (slot == BEACON_SIGNAL_NONE)
    {
        http_answer(signal, connection, 503, now_ms);
        return;
    }
    char base[BEACON_MAX_PUBLIC_URL + BEACON_HTTP_MAX_HOST + 16];
    http_base(signal, request, base, sizeof(base));
    char image[sizeof(base) + 64];
    char url[sizeof(base) + 64];
    snprintf(url, sizeof(url), "%s/join/%s", base, connection->route.room);
    uint32_t card = card_find(signal, connection->route.room);
    BeaconJoinPage shown;
    shown.title = "A piccolo session";
    shown.page_url = url;
    shown.image_url = image;
    shown.image_width = BEACON_NOISE_WIDTH;
    shown.image_height = BEACON_NOISE_HEIGHT;
    // White noise when there's no screenshot (Andrés).
    snprintf(image, sizeof(image), "%s/join/noise.png", base);
    char description[256];
    snprintf(description, sizeof(description), "%s",
             "Join this game on piccolo: watch it, and play when a seat is free.");
    if (card != BEACON_SIGNAL_NONE)
    {
        const BeaconCard* found = &signal->cards[card];
        shown.title = found->title;
        snprintf(description, sizeof(description),
                 "Playing %s on piccolo. Join: watch it, and play when a seat is free.", found->title);
        if (found->png_size > 0)
        {
            snprintf(image, sizeof(image), "%s/join/%s/card.png", base, connection->route.room);
            shown.image_width = found->width;
            shown.image_height = found->height;
        }
    }
    // The host gone (the session ended, the game closed, or NEW made another
    // link): say so, whatever card is still kept for a minute (Andrés).
    BeaconId meeting;
    beacon_guest_meeting_id(connection->route.room, &meeting);
    if (!beacon_signal_guest_room_live(signal, &meeting))
    {
        shown.ended = true;
        shown.title = "Game offline";
        snprintf(description, sizeof(description), "%s",
                 "This piccolo session ended, or the link is no longer valid. Ask the host for a new one.");
        snprintf(image, sizeof(image), "%s/join/noise.png", base);
        shown.image_width = BEACON_NOISE_WIDTH;
        shown.image_height = BEACON_NOISE_HEIGHT;
    }
    shown.description = description;
    char* page = reinterpret_cast<char*>(signal->page_data.data() + static_cast<size_t>(slot) * BEACON_HTTP_PAGE_SIZE);
    size_t size = beacon_join_page_render(beacon_join_page_builtin(), &shown, page, BEACON_HTTP_PAGE_SIZE);
    if (size == 0)
    {
        signal->page_used[slot] = 0;
        http_answer(signal, connection, 503, now_ms);
        return;
    }
    char head[1024];
    size_t head_size = beacon_http_response_head(200, "text/html; charset=utf-8", PAGE_HEADERS, size, head, sizeof(head));
    connection->send_used = 0;
    queue_bytes(connection, reinterpret_cast<const uint8_t*>(head), head_size);
    connection->body_kind = BeaconBodyKind::PAGE;
    connection->body_index = slot;
    connection->body_offset = 0;
    connection->body_size = request->method == BeaconHttpMethod::HEAD ? 0 : static_cast<uint32_t>(size);
    connection->state = BeaconConnectionState::CLOSING;
    connection->deadline_ms = now_ms + BEACON_HTTP_SEND_MS;
    connection->receive_used = 0;
}

static void http_card_png(BeaconSignal* signal, uint32_t index, const BeaconHttpRequest* request, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    uint32_t card = card_find(signal, connection->route.room);
    if (card == BEACON_SIGNAL_NONE || signal->cards[card].png_size == 0)
    {
        http_answer(signal, connection, 404, now_ms);
        return;
    }
    char head[512];
    size_t head_size = beacon_http_response_head(200, "image/png", "Cache-Control: public, max-age=300\r\n",
                                                 signal->cards[card].png_size, head, sizeof(head));
    connection->send_used = 0;
    queue_bytes(connection, reinterpret_cast<const uint8_t*>(head), head_size);
    connection->body_kind = BeaconBodyKind::CARD;
    connection->body_index = card;
    connection->body_generation = signal->cards[card].generation;
    connection->body_offset = 0;
    connection->body_size = request->method == BeaconHttpMethod::HEAD ? 0 : signal->cards[card].png_size;
    connection->state = BeaconConnectionState::CLOSING;
    connection->deadline_ms = now_ms + BEACON_HTTP_SEND_MS;
    connection->receive_used = 0;
}

// The white noise PNG: small enough for the send buffer at once.
static void http_noise(BeaconSignal* signal, uint32_t index, const BeaconHttpRequest* request, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    size_t size = 0;
    beacon_join_noise(&size);   // its size; refill_body copies it
    char head[512];
    size_t head_size = beacon_http_response_head(200, "image/png", "Cache-Control: public, max-age=86400\r\n", size,
                                                 head, sizeof(head));
    connection->send_used = 0;
    queue_bytes(connection, reinterpret_cast<const uint8_t*>(head), head_size);
    connection->body_kind = BeaconBodyKind::NOISE;
    connection->body_offset = 0;
    connection->body_size = request->method == BeaconHttpMethod::HEAD ? 0 : static_cast<uint32_t>(size);
    connection->state = BeaconConnectionState::CLOSING;
    connection->deadline_ms = now_ms + BEACON_HTTP_SEND_MS;
    connection->receive_used = 0;
}

// The whole upload body is in: check it, put the card, answer.
static void http_upload_done(BeaconSignal* signal, uint32_t index, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    const uint8_t* body =
        signal->upload_data.data() + static_cast<size_t>(connection->upload_slot) * BEACON_CARD_MAX_UPLOAD;
    BeaconCardUpload upload;
    if (!beacon_card_parse_upload(body, connection->upload_size, &upload))
    {
        release_http(signal, connection);
        http_answer(signal, connection, 400, now_ms);
        return;
    }
    char room[BEACON_GUEST_ROOM_SIZE + 1];
    beacon_guest_room_from_card_key(upload.card_key, room);
    if (memcmp(room, connection->route.room, BEACON_GUEST_ROOM_SIZE) != 0)
    {
        release_http(signal, connection);
        http_answer(signal, connection, 403, now_ms);
        return;
    }
    BeaconId meeting;
    beacon_guest_meeting_id(room, &meeting);
    if (!beacon_signal_guest_room_live(signal, &meeting))
    {
        release_http(signal, connection);
        http_answer(signal, connection, 404, now_ms);
        return;
    }
    uint32_t card_index = card_find(signal, room);
    if (card_index == BEACON_SIGNAL_NONE)
    {
        for (uint32_t i = 0; i < signal->cards.size(); i++)
        {
            if (signal->cards[i].used == 0)
            {
                card_index = i;
                break;
            }
        }
        if (card_index == BEACON_SIGNAL_NONE)
        {
            release_http(signal, connection);
            http_answer(signal, connection, 503, now_ms);
            return;
        }
        BeaconCard* fresh = &signal->cards[card_index];
        uint32_t generation = fresh->generation;
        *fresh = BeaconCard{};
        fresh->generation = generation;
        fresh->used = 1;
        memcpy(fresh->room, room, sizeof(fresh->room));
        fresh->meeting = meeting;
        fresh->puts_last_ms = now_ms;
        fresh->put_tokens_milli = static_cast<uint64_t>(BEACON_CARD_PUTS_PER_MINUTE) * MILLI * 60;
        signal->stats.cards++;
    }
    BeaconCard* card = &signal->cards[card_index];
    if (!bucket_take_per_minute(&card->put_tokens_milli, &card->puts_last_ms, now_ms, BEACON_CARD_PUTS_PER_MINUTE,
                                BEACON_CARD_PUTS_PER_MINUTE))
    {
        release_http(signal, connection);
        http_answer(signal, connection, 429, now_ms);
        return;
    }
    if (upload.png_size > 0)
    {
        memcpy(signal->card_data.data() + static_cast<size_t>(card_index) * BEACON_CARD_MAX_PNG, upload.png,
               upload.png_size);
    }
    card->png_size = upload.png_size;
    card->width = upload.width;
    card->height = upload.height;
    memcpy(card->title, upload.title, sizeof(card->title));
    card->generation++;
    card->orphan_since_ms = 0;
    signal->stats.cards_put++;
    release_http(signal, connection);
    http_answer(signal, connection, 204, now_ms);
}

// Copies upload bytes from `data` into the connection's upload slot; when
// the body is whole, finishes it.
static void http_upload_take(BeaconSignal* signal, uint32_t index, const uint8_t* data, size_t size, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    size_t want = connection->upload_size - connection->upload_used;
    size_t take = size < want ? size : want;
    uint8_t* slot = signal->upload_data.data() + static_cast<size_t>(connection->upload_slot) * BEACON_CARD_MAX_UPLOAD;
    memcpy(slot + connection->upload_used, data, take);
    connection->upload_used += static_cast<uint32_t>(take);
    if (connection->upload_used == connection->upload_size)
    {
        http_upload_done(signal, index, now_ms);
    }
}

// A plain HTTP request (no Upgrade header) has been parsed.
static void http_request(BeaconSignal* signal, uint32_t index, const BeaconHttpRequest* request, uint64_t now_ms)
{
    BeaconConnection* connection = &signal->connections[index];
    signal->stats.http_requests++;
    if (!beacon_http_join_route(request->target, &connection->route))
    {
        http_answer(signal, connection, 404, now_ms);
        return;
    }
    bool post = request->method == BeaconHttpMethod::POST;
    if (connection->route.kind == BeaconJoinKind::CARD_PUT)
    {
        if (!post)
        {
            http_answer(signal, connection, 404, now_ms);
            return;
        }
        if (!request->has_content_length)
        {
            http_answer(signal, connection, 400, now_ms);
            return;
        }
        if (request->content_length > BEACON_CARD_MAX_UPLOAD)
        {
            http_answer(signal, connection, 413, now_ms);
            return;
        }
        // Checked before the body comes: a room with no live host can't take a card.
        BeaconId meeting;
        beacon_guest_meeting_id(connection->route.room, &meeting);
        if (!beacon_signal_guest_room_live(signal, &meeting))
        {
            http_answer(signal, connection, 404, now_ms);
            return;
        }
        uint32_t slot = slot_take(&signal->upload_used);
        if (slot == BEACON_SIGNAL_NONE)
        {
            http_answer(signal, connection, 503, now_ms);
            return;
        }
        connection->upload_slot = slot;
        connection->upload_size = static_cast<uint32_t>(request->content_length);
        connection->upload_used = 0;
        connection->state = BeaconConnectionState::HTTP_BODY;
        connection->deadline_ms = now_ms + BEACON_HTTP_BODY_MS;
        // The body's first bytes may have come with the head.
        size_t extra = connection->receive_used - request->head_size;
        const uint8_t* first = connection->receive + request->head_size;
        connection->receive_used = 0;
        if (connection->upload_size == 0)
        {
            http_upload_done(signal, index, now_ms);
            return;
        }
        http_upload_take(signal, index, first, extra, now_ms);
        return;
    }
    if (post)
    {
        http_answer(signal, connection, 404, now_ms);
        return;
    }
    if (connection->route.kind == BeaconJoinKind::NOISE)
    {
        http_noise(signal, index, request, now_ms);
    }
    else if (connection->route.kind == BeaconJoinKind::PAGE)
    {
        http_page(signal, index, request, now_ms);
    }
    else
    {
        http_card_png(signal, index, request, now_ms);
    }
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
    connection->guest_joins_last_ms = now_ms;
    connection->guest_join_tokens_milli = static_cast<uint64_t>(signal->config.guest_join_burst) * MILLI * 60;
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
        BeaconHttpRequest request;
        BeaconHttpParse http = beacon_http_parse_request(connection->receive, connection->receive_used, &request);
        if (http == BeaconHttpParse::INCOMPLETE)
        {
            return true;
        }
        if (http == BeaconHttpParse::OK && !request.upgrade)
        {
            http_request(signal, index, &request, now_ms);
            return true;
        }
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
    if (connection->state == BeaconConnectionState::HTTP_BODY)
    {
        uint8_t* slot =
            signal->upload_data.data() + static_cast<size_t>(connection->upload_slot) * BEACON_CARD_MAX_UPLOAD;
        size_t want = connection->upload_size - connection->upload_used;
        ssize_t body = recv(connection->fd, slot + connection->upload_used, want, MSG_DONTWAIT);
        if (body < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        {
            return;
        }
        if (body <= 0)
        {
            connection_free(signal, index, now_ms);
            return;
        }
        connection->upload_used += static_cast<uint32_t>(body);
        if (connection->upload_used == connection->upload_size)
        {
            http_upload_done(signal, index, now_ms);
        }
        connection_flush(signal, index, now_ms);
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
        config->byte_burst < BEACON_WS_MAX_PAYLOAD || config->trusted_count > BEACON_SIGNAL_MAX_TRUSTED ||
        config->guest_joins_per_minute < 1 || config->guest_join_burst < 1 || config->max_cards > 4096 ||
        config->page_slots < 1 || config->page_slots > 1024 || config->upload_slots > 64)
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
    signal->cards.resize(config->max_cards);
    signal->card_data.resize(static_cast<size_t>(config->max_cards) * BEACON_CARD_MAX_PNG);
    signal->page_used.resize(config->page_slots);
    signal->page_data.resize(static_cast<size_t>(config->page_slots) * BEACON_HTTP_PAGE_SIZE);
    signal->upload_used.resize(config->upload_slots);
    signal->upload_data.resize(static_cast<size_t>(config->upload_slots) * BEACON_CARD_MAX_UPLOAD);
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
            case BeaconConnectionState::HTTP_BODY:
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
    // Cards follow their guest rooms, with a grace period for a host's
    // reconnect.
    for (uint32_t i = 0; i < signal->cards.size(); i++)
    {
        BeaconCard* card = &signal->cards[i];
        if (card->used == 0)
        {
            continue;
        }
        if (beacon_signal_guest_room_live(signal, &card->meeting))
        {
            card->orphan_since_ms = 0;
        }
        else if (card->orphan_since_ms == 0)
        {
            card->orphan_since_ms = now_ms;
        }
        else if (now_ms - card->orphan_since_ms >= BEACON_CARD_ORPHAN_MS)
        {
            card_delete(signal, i);
        }
    }
    free_doomed(signal, now_ms);
}

const BeaconCard* beacon_signal_card(const BeaconSignal* signal, const char* room)
{
    uint32_t index = card_find(signal, room);
    return index == BEACON_SIGNAL_NONE ? nullptr : &signal->cards[index];
}

bool beacon_signal_guest_room_live(const BeaconSignal* signal, const BeaconId* room)
{
    if (signal->rooms.empty())
    {
        return false;
    }
    uint32_t free_slot = BEACON_SIGNAL_NONE;
    uint32_t slot = room_find(signal, room, &free_slot);
    if (slot == BEACON_SIGNAL_NONE)
    {
        return false;
    }
    const BeaconRoom* found = &signal->rooms[slot];
    return found->guest_room != 0 && found->host != BEACON_SIGNAL_NONE &&
           signal->connections[found->host].state == BeaconConnectionState::OPEN;
}

void beacon_signal_stats_reset(BeaconSignal* signal)
{
    uint32_t open = signal->stats.open;
    uint32_t rooms = signal->stats.rooms;
    uint32_t cards = signal->stats.cards;
    signal->stats = BeaconSignalStats{};
    signal->stats.open = open;
    signal->stats.rooms = rooms;
    signal->stats.cards = cards;
}

uint64_t beacon_signal_pool_bytes(const BeaconSignal* signal)
{
    return static_cast<uint64_t>(signal->connections.size()) * sizeof(BeaconConnection) +
           static_cast<uint64_t>(signal->free_slots.size()) * sizeof(uint32_t) +
           static_cast<uint64_t>(signal->rooms.size()) * sizeof(BeaconRoom) +
           static_cast<uint64_t>(signal->cards.size()) * sizeof(BeaconCard) + signal->card_data.size() +
           signal->page_used.size() + signal->page_data.size() + signal->upload_used.size() +
           signal->upload_data.size();
}
