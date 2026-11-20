// beacon_wire: see beacon_wire.h. Offsets are the ones in PROTOCOL.md's
// message table; each type has its own pair of functions so a reader can check
// one row of the table against one pair.

#include "beacon_wire.h"

#include <cstring>

static constexpr uint8_t MAGIC[4] = {'M', 'T', 'B', 'C'};

// Offsets shared by every type.
static constexpr uint32_t OFFSET_NONCE = 8;
static constexpr uint32_t OFFSET_AFTER_NONCE = 16;  // cookie or meeting id
static constexpr uint32_t OFFSET_AFTER_16 = 32;     // what follows the cookie or id

// REGISTER
static constexpr uint32_t OFFSET_REGISTER_COUNT = 32;
static constexpr uint32_t OFFSET_REGISTER_PAD = 33;
static constexpr uint32_t OFFSET_REGISTER_IDS = 36;
// REGISTERED
static constexpr uint32_t OFFSET_REGISTERED_ACCEPTED = 32;
static constexpr uint32_t OFFSET_REGISTERED_PAD = 33;
static constexpr uint32_t OFFSET_REGISTERED_TTL = 34;

static_assert(OFFSET_REGISTER_IDS + BEACON_MAX_IDS * BEACON_ID_SIZE == BEACON_SIZE_REGISTER,
              "REGISTER layout");
static_assert(OFFSET_REGISTERED_TTL + 2 == BEACON_SIZE_REGISTERED, "REGISTERED layout");
static_assert(OFFSET_AFTER_16 + BEACON_ADDRESS_SIZE == BEACON_SIZE_INTRO, "INTRO layout");
static_assert(OFFSET_AFTER_NONCE + BEACON_ADDRESS_SIZE == BEACON_SIZE_BOUND, "BOUND layout");

// ---------------------------------------------------------------------------
// Little helpers
// ---------------------------------------------------------------------------

static void write_u16(uint8_t* p, uint16_t value)
{
    p[0] = static_cast<uint8_t>(value & 0xffu);
    p[1] = static_cast<uint8_t>(value >> 8);
}

static uint16_t read_u16(const uint8_t* p)
{
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

static void write_u64(uint8_t* p, uint64_t value)
{
    for (uint32_t i = 0; i < 8; i++)
    {
        p[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xffu);
    }
}

static uint64_t read_u64(const uint8_t* p)
{
    uint64_t value = 0;
    for (uint32_t i = 0; i < 8; i++)
    {
        value |= static_cast<uint64_t>(p[i]) << (8 * i);
    }
    return value;
}

static bool all_zero(const uint8_t* p, uint32_t size)
{
    uint8_t bits = 0;
    for (uint32_t i = 0; i < size; i++)
    {
        bits = static_cast<uint8_t>(bits | p[i]);
    }
    return bits == 0;
}

// An address is valid on the wire when its port isn't 0 (padding is checked by the reader).
static bool address_valid(const BeaconAddress* address)
{
    return address->port != 0;
}

static void write_address(uint8_t* p, const BeaconAddress* address)
{
    memcpy(p, address->ip, 16);
    write_u16(p + 16, address->port);
    p[18] = 0;
    p[19] = 0;
}

static bool read_address(const uint8_t* p, BeaconAddress* address)
{
    if (p[18] != 0 || p[19] != 0)
    {
        return false;
    }
    memcpy(address->ip, p, 16);
    address->port = read_u16(p + 16);
    return address_valid(address);
}

static void write_header(uint8_t* p, BeaconType type)
{
    memcpy(p, MAGIC, 4);
    p[4] = BEACON_VERSION;
    p[5] = static_cast<uint8_t>(type);
    p[6] = 0;
    p[7] = 0;
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

uint32_t beacon_message_size(uint8_t type)
{
    switch (type)
    {
        case static_cast<uint8_t>(BeaconType::BIND):
            return BEACON_SIZE_BIND;
        case static_cast<uint8_t>(BeaconType::BOUND):
            return BEACON_SIZE_BOUND;
        case static_cast<uint8_t>(BeaconType::REGISTER):
            return BEACON_SIZE_REGISTER;
        case static_cast<uint8_t>(BeaconType::COOKIE):
            return BEACON_SIZE_COOKIE;
        case static_cast<uint8_t>(BeaconType::REGISTERED_REPLY):
            return BEACON_SIZE_REGISTERED;
        case static_cast<uint8_t>(BeaconType::MEET):
            return BEACON_SIZE_MEET;
        case static_cast<uint8_t>(BeaconType::INTRO):
            return BEACON_SIZE_INTRO;
        case static_cast<uint8_t>(BeaconType::NOT_FOUND):
            return BEACON_SIZE_NOT_FOUND;
        case static_cast<uint8_t>(BeaconType::PUNCH):
            return BEACON_SIZE_PUNCH;
        default:
            return 0;
    }
}

bool beacon_id_is_zero(const BeaconId* id)
{
    return all_zero(id->bytes, BEACON_ID_SIZE);
}

bool beacon_id_equal(const BeaconId* a, const BeaconId* b)
{
    return memcmp(a->bytes, b->bytes, BEACON_ID_SIZE) == 0;
}

bool beacon_address_equal(const BeaconAddress* a, const BeaconAddress* b)
{
    return a->port == b->port && memcmp(a->ip, b->ip, 16) == 0;
}

bool beacon_address_is_ipv4(const BeaconAddress* address)
{
    static constexpr uint8_t MAPPED_PREFIX[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    return memcmp(address->ip, MAPPED_PREFIX, 12) == 0;
}

// ---------------------------------------------------------------------------
// Decode: one function per type. `p` is a packet of exactly the type's size
// whose header was already checked; `out` is zeroed.
// ---------------------------------------------------------------------------

static bool decode_bind(const uint8_t* p, BeaconMessage* out)
{
    out->nonce = read_u64(p + OFFSET_NONCE);
    return all_zero(p + OFFSET_AFTER_NONCE, BEACON_SIZE_BIND - OFFSET_AFTER_NONCE);
}

static bool decode_bound(const uint8_t* p, BeaconMessage* out)
{
    out->nonce = read_u64(p + OFFSET_NONCE);
    return read_address(p + OFFSET_AFTER_NONCE, &out->address);
}

static bool decode_register(const uint8_t* p, BeaconMessage* out)
{
    out->nonce = read_u64(p + OFFSET_NONCE);
    memcpy(out->cookie, p + OFFSET_AFTER_NONCE, BEACON_COOKIE_SIZE);
    uint8_t count = p[OFFSET_REGISTER_COUNT];
    if (count < 1 || count > BEACON_MAX_IDS)
    {
        return false;
    }
    if (!all_zero(p + OFFSET_REGISTER_PAD, 3))
    {
        return false;
    }
    out->id_count = count;
    for (uint32_t i = 0; i < BEACON_MAX_IDS; i++)
    {
        const uint8_t* id = p + OFFSET_REGISTER_IDS + i * BEACON_ID_SIZE;
        bool zero = all_zero(id, BEACON_ID_SIZE);
        if (i < count)
        {
            if (zero)
            {
                return false;
            }
            memcpy(out->ids[i].bytes, id, BEACON_ID_SIZE);
        }
        else if (!zero)
        {
            return false;
        }
    }
    return true;
}

static bool decode_cookie(const uint8_t* p, BeaconMessage* out)
{
    out->nonce = read_u64(p + OFFSET_NONCE);
    memcpy(out->cookie, p + OFFSET_AFTER_NONCE, BEACON_COOKIE_SIZE);
    return true;
}

static bool decode_registered(const uint8_t* p, BeaconMessage* out)
{
    out->nonce = read_u64(p + OFFSET_NONCE);
    memcpy(out->cookie, p + OFFSET_AFTER_NONCE, BEACON_COOKIE_SIZE);
    uint8_t accepted = p[OFFSET_REGISTERED_ACCEPTED];
    if (accepted > BEACON_MAX_IDS || p[OFFSET_REGISTERED_PAD] != 0)
    {
        return false;
    }
    out->id_count = accepted;
    out->ttl_seconds = read_u16(p + OFFSET_REGISTERED_TTL);
    return true;
}

// MEET, INTRO, NOT_FOUND and PUNCH all start with nonce + meeting id.
static bool decode_nonce_and_id(const uint8_t* p, BeaconMessage* out)
{
    out->nonce = read_u64(p + OFFSET_NONCE);
    memcpy(out->ids[0].bytes, p + OFFSET_AFTER_NONCE, BEACON_ID_SIZE);
    return !beacon_id_is_zero(&out->ids[0]);
}

static bool decode_meet(const uint8_t* p, BeaconMessage* out)
{
    if (!decode_nonce_and_id(p, out))
    {
        return false;
    }
    return all_zero(p + OFFSET_AFTER_16, BEACON_SIZE_MEET - OFFSET_AFTER_16);
}

static bool decode_intro(const uint8_t* p, BeaconMessage* out)
{
    if (!decode_nonce_and_id(p, out))
    {
        return false;
    }
    return read_address(p + OFFSET_AFTER_16, &out->address);
}

bool beacon_decode(const uint8_t* data, size_t size, BeaconMessage* out)
{
    *out = BeaconMessage{};
    if (data == nullptr || size < BEACON_HEADER_SIZE)
    {
        return false;
    }
    if (memcmp(data, MAGIC, 4) != 0 || data[4] != BEACON_VERSION || data[6] != 0 || data[7] != 0)
    {
        return false;
    }
    uint32_t expected = beacon_message_size(data[5]);
    if (expected == 0 || size != expected)
    {
        return false;
    }
    out->type = static_cast<BeaconType>(data[5]);

    bool ok = false;
    switch (out->type)
    {
        case BeaconType::BIND:
            ok = decode_bind(data, out);
            break;
        case BeaconType::BOUND:
            ok = decode_bound(data, out);
            break;
        case BeaconType::REGISTER:
            ok = decode_register(data, out);
            break;
        case BeaconType::COOKIE:
            ok = decode_cookie(data, out);
            break;
        case BeaconType::REGISTERED_REPLY:
            ok = decode_registered(data, out);
            break;
        case BeaconType::MEET:
            ok = decode_meet(data, out);
            break;
        case BeaconType::INTRO:
            ok = decode_intro(data, out);
            break;
        case BeaconType::NOT_FOUND:
        case BeaconType::PUNCH:
            ok = decode_nonce_and_id(data, out);
            break;
    }
    if (!ok)
    {
        *out = BeaconMessage{};
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Encode: the same rules as decode, checked before anything is written.
// ---------------------------------------------------------------------------

static bool message_valid(const BeaconMessage* m)
{
    switch (m->type)
    {
        case BeaconType::BIND:
        case BeaconType::COOKIE:
            return true;
        case BeaconType::BOUND:
            return address_valid(&m->address);
        case BeaconType::REGISTER:
            if (m->id_count < 1 || m->id_count > BEACON_MAX_IDS)
            {
                return false;
            }
            for (uint32_t i = 0; i < m->id_count; i++)
            {
                if (beacon_id_is_zero(&m->ids[i]))
                {
                    return false;
                }
            }
            return true;
        case BeaconType::REGISTERED_REPLY:
            return m->id_count <= BEACON_MAX_IDS;
        case BeaconType::MEET:
        case BeaconType::NOT_FOUND:
        case BeaconType::PUNCH:
            return !beacon_id_is_zero(&m->ids[0]);
        case BeaconType::INTRO:
            return !beacon_id_is_zero(&m->ids[0]) && address_valid(&m->address);
    }
    return false;
}

uint32_t beacon_encode(const BeaconMessage* message, uint8_t* out, size_t capacity)
{
    uint32_t size = beacon_message_size(static_cast<uint8_t>(message->type));
    if (size == 0 || out == nullptr || capacity < size || !message_valid(message))
    {
        return 0;
    }
    memset(out, 0, size);
    write_header(out, message->type);
    write_u64(out + OFFSET_NONCE, message->nonce);

    switch (message->type)
    {
        case BeaconType::BIND:
            break;
        case BeaconType::BOUND:
            write_address(out + OFFSET_AFTER_NONCE, &message->address);
            break;
        case BeaconType::REGISTER:
            memcpy(out + OFFSET_AFTER_NONCE, message->cookie, BEACON_COOKIE_SIZE);
            out[OFFSET_REGISTER_COUNT] = message->id_count;
            // Only ids [0, count) are written: the rest stay zero, as decode requires.
            for (uint32_t i = 0; i < message->id_count; i++)
            {
                memcpy(out + OFFSET_REGISTER_IDS + i * BEACON_ID_SIZE, message->ids[i].bytes, BEACON_ID_SIZE);
            }
            break;
        case BeaconType::COOKIE:
            memcpy(out + OFFSET_AFTER_NONCE, message->cookie, BEACON_COOKIE_SIZE);
            break;
        case BeaconType::REGISTERED_REPLY:
            memcpy(out + OFFSET_AFTER_NONCE, message->cookie, BEACON_COOKIE_SIZE);
            out[OFFSET_REGISTERED_ACCEPTED] = message->id_count;
            write_u16(out + OFFSET_REGISTERED_TTL, message->ttl_seconds);
            break;
        case BeaconType::MEET:
        case BeaconType::NOT_FOUND:
        case BeaconType::PUNCH:
            memcpy(out + OFFSET_AFTER_NONCE, message->ids[0].bytes, BEACON_ID_SIZE);
            break;
        case BeaconType::INTRO:
            memcpy(out + OFFSET_AFTER_NONCE, message->ids[0].bytes, BEACON_ID_SIZE);
            write_address(out + OFFSET_AFTER_16, &message->address);
            break;
    }
    return size;
}

// ---------------------------------------------------------------------------
// Signaling
// ---------------------------------------------------------------------------

static constexpr uint32_t OFFSET_ROOM = 8;
static constexpr uint32_t OFFSET_ROOM_END = 24;    // JOIN's role, JOINED's flag, REFUSED's reason, SIGNAL's blob
static constexpr uint32_t OFFSET_ROOM_PAD = 25;    // 3 zero bytes after that byte
static_assert(OFFSET_ROOM + BEACON_ID_SIZE == OFFSET_ROOM_END, "room layout");
static_assert(OFFSET_ROOM_END == BEACON_SIGNALING_SIZE_ROOM, "room-only layout");
static_assert(OFFSET_ROOM_PAD + 3 == BEACON_SIGNALING_SIZE_JOIN, "JOIN layout");
static_assert(OFFSET_ROOM_END == BEACON_SIGNALING_SIGNAL_HEADER, "SIGNAL layout");

static uint32_t signaling_fixed_size(uint8_t type)
{
    switch (type)
    {
        case static_cast<uint8_t>(BeaconSignalingType::JOIN):
            return BEACON_SIGNALING_SIZE_JOIN;
        case static_cast<uint8_t>(BeaconSignalingType::JOINED):
            return BEACON_SIGNALING_SIZE_JOINED;
        case static_cast<uint8_t>(BeaconSignalingType::REFUSED):
            return BEACON_SIGNALING_SIZE_REFUSED;
        case static_cast<uint8_t>(BeaconSignalingType::LEAVE):
        case static_cast<uint8_t>(BeaconSignalingType::PEER_JOINED):
        case static_cast<uint8_t>(BeaconSignalingType::LEFT):
        case static_cast<uint8_t>(BeaconSignalingType::NOT_FOUND):
            return BEACON_SIGNALING_SIZE_ROOM;
        default:
            return 0;   // SIGNAL (variable) or not a signaling type
    }
}

bool beacon_signaling_decode(const uint8_t* data, size_t size, BeaconSignalingMessage* out)
{
    *out = BeaconSignalingMessage{};
    if (size < BEACON_SIGNALING_SIZE_ROOM || memcmp(data, MAGIC, 4) != 0 || data[4] != BEACON_VERSION ||
        data[6] != 0 || data[7] != 0)
    {
        return false;
    }
    uint8_t type = data[5];
    if (type == static_cast<uint8_t>(BeaconSignalingType::SIGNAL))
    {
        if (size <= BEACON_SIGNALING_SIGNAL_HEADER || size > BEACON_SIGNALING_MAX_SIZE)
        {
            return false;
        }
        out->blob = data + BEACON_SIGNALING_SIGNAL_HEADER;
        out->blob_size = static_cast<uint32_t>(size - BEACON_SIGNALING_SIGNAL_HEADER);
    }
    else
    {
        uint32_t expected = signaling_fixed_size(type);
        if (expected == 0 || size != expected)
        {
            return false;
        }
    }
    memcpy(out->room.bytes, data + OFFSET_ROOM, BEACON_ID_SIZE);
    if (beacon_id_is_zero(&out->room))
    {
        return false;
    }
    out->type = static_cast<BeaconSignalingType>(type);
    switch (out->type)
    {
        case BeaconSignalingType::JOIN:
            if (data[OFFSET_ROOM_END] != static_cast<uint8_t>(BeaconRole::HOST) &&
                data[OFFSET_ROOM_END] != static_cast<uint8_t>(BeaconRole::CLIENT))
            {
                return false;
            }
            out->role = static_cast<BeaconRole>(data[OFFSET_ROOM_END]);
            return all_zero(data + OFFSET_ROOM_PAD, 3);
        case BeaconSignalingType::JOINED:
            if (data[OFFSET_ROOM_END] > 1)
            {
                return false;
            }
            out->peer_present = data[OFFSET_ROOM_END];
            return all_zero(data + OFFSET_ROOM_PAD, 3);
        case BeaconSignalingType::REFUSED:
            if (data[OFFSET_ROOM_END] != static_cast<uint8_t>(BeaconRefusal::ROOMS_PER_CONNECTION) &&
                data[OFFSET_ROOM_END] != static_cast<uint8_t>(BeaconRefusal::ROOMS_FULL))
            {
                return false;
            }
            out->reason = static_cast<BeaconRefusal>(data[OFFSET_ROOM_END]);
            return all_zero(data + OFFSET_ROOM_PAD, 3);
        default:
            return true;
    }
}

uint32_t beacon_signaling_encode(const BeaconSignalingMessage* message, uint8_t* out, size_t capacity)
{
    uint8_t type = static_cast<uint8_t>(message->type);
    uint32_t size = 0;
    if (message->type == BeaconSignalingType::SIGNAL)
    {
        if (message->blob == nullptr || message->blob_size < 1 || message->blob_size > BEACON_SIGNALING_MAX_BLOB)
        {
            return 0;
        }
        size = BEACON_SIGNALING_SIGNAL_HEADER + message->blob_size;
    }
    else
    {
        size = signaling_fixed_size(type);
    }
    if (size == 0 || capacity < size || beacon_id_is_zero(&message->room))
    {
        return 0;
    }
    switch (message->type)
    {
        case BeaconSignalingType::JOIN:
            if (message->role != BeaconRole::HOST && message->role != BeaconRole::CLIENT)
            {
                return 0;
            }
            break;
        case BeaconSignalingType::JOINED:
            if (message->peer_present > 1)
            {
                return 0;
            }
            break;
        case BeaconSignalingType::REFUSED:
            if (message->reason != BeaconRefusal::ROOMS_PER_CONNECTION && message->reason != BeaconRefusal::ROOMS_FULL)
            {
                return 0;
            }
            break;
        default:
            break;
    }
    memset(out, 0, size);
    memcpy(out, MAGIC, 4);
    out[4] = BEACON_VERSION;
    out[5] = type;
    memcpy(out + OFFSET_ROOM, message->room.bytes, BEACON_ID_SIZE);
    switch (message->type)
    {
        case BeaconSignalingType::JOIN:
            out[OFFSET_ROOM_END] = static_cast<uint8_t>(message->role);
            break;
        case BeaconSignalingType::JOINED:
            out[OFFSET_ROOM_END] = message->peer_present;
            break;
        case BeaconSignalingType::REFUSED:
            out[OFFSET_ROOM_END] = static_cast<uint8_t>(message->reason);
            break;
        case BeaconSignalingType::SIGNAL:
            memcpy(out + BEACON_SIGNALING_SIGNAL_HEADER, message->blob, message->blob_size);
            break;
        default:
            break;
    }
    return size;
}
