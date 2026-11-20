// beacon_wire: the exact byte layout of every beacon message (PROTOCOL.md).
//
// Shared by the server and the clients (frontends-common uses this repo as a
// submodule), so it depends on nothing: no SDL, no sockets, no crypto.
//
// Every message type has ONE fixed size. beacon_decode() accepts a packet
// only when its size is exactly the size of its type and every field rule
// holds (magic, version, reserved and padding bytes zero, counts in range,
// ids non-zero, ports non-zero). It never takes a length from the wire.
// beacon_encode() checks the same rules, so for any packet decode accepts,
// encode gives back the same bytes (the fuzzer checks this).

#pragma once

#include <cstddef>
#include <cstdint>

constexpr uint8_t BEACON_VERSION = 1;
constexpr uint32_t BEACON_HEADER_SIZE = 8;
constexpr uint32_t BEACON_ID_SIZE = 16;
constexpr uint32_t BEACON_COOKIE_SIZE = 16;
constexpr uint32_t BEACON_ADDRESS_SIZE = 20;
constexpr uint32_t BEACON_MAX_IDS = 8;

// Total sizes, header included.
constexpr uint32_t BEACON_SIZE_BIND = 36;
constexpr uint32_t BEACON_SIZE_BOUND = 36;
constexpr uint32_t BEACON_SIZE_REGISTER = 164;
constexpr uint32_t BEACON_SIZE_COOKIE = 32;
constexpr uint32_t BEACON_SIZE_REGISTERED = 36;
constexpr uint32_t BEACON_SIZE_MEET = 52;
constexpr uint32_t BEACON_SIZE_INTRO = 52;
constexpr uint32_t BEACON_SIZE_NOT_FOUND = 32;
constexpr uint32_t BEACON_SIZE_PUNCH = 32;
constexpr uint32_t BEACON_MAX_MESSAGE_SIZE = 164;

// Anti-amplification (PROTOCOL.md): a reply is never larger than its request.
static_assert(BEACON_SIZE_BOUND <= BEACON_SIZE_BIND, "BOUND must not be larger than BIND");
static_assert(BEACON_SIZE_COOKIE <= BEACON_SIZE_REGISTER, "COOKIE must not be larger than REGISTER");
static_assert(BEACON_SIZE_REGISTERED <= BEACON_SIZE_REGISTER, "REGISTERED must not be larger than REGISTER");
static_assert(BEACON_SIZE_INTRO <= BEACON_SIZE_MEET, "INTRO must not be larger than MEET");
static_assert(BEACON_SIZE_NOT_FOUND <= BEACON_SIZE_MEET, "NOT_FOUND must not be larger than MEET");

enum class BeaconType : uint8_t
{
    BIND = 1,
    BOUND = 2,
    REGISTER = 3,
    COOKIE = 4,
    REGISTERED = 5,
    MEET = 6,
    INTRO = 7,
    NOT_FOUND = 8,
    PUNCH = 9,
};

// An address as the protocol carries it: IPv6 bytes in network order (IPv4 as
// ::ffff:a.b.c.d) and the port as a number.
struct BeaconAddress
{
    uint8_t ip[16] = {};
    uint16_t port = 0;
};

struct BeaconId
{
    uint8_t bytes[BEACON_ID_SIZE] = {};
};

// One struct for every type; each type uses the fields its row in PROTOCOL.md
// lists and leaves the others zero (decode zeroes them).
struct BeaconMessage
{
    BeaconType type = BeaconType::BIND;
    uint64_t nonce = 0;                            // every type
    uint8_t cookie[BEACON_COOKIE_SIZE] = {};   // REGISTER, COOKIE, REGISTERED
    uint8_t id_count = 0;                          // REGISTER: count (1-8); REGISTERED: accepted (0-8)
    uint16_t ttl_seconds = 0;                      // REGISTERED
    BeaconId ids[BEACON_MAX_IDS] = {};     // REGISTER: ids[0, count); MEET, INTRO, NOT_FOUND, PUNCH: ids[0]
    BeaconAddress address = {};                // BOUND, INTRO
};

// The exact total size of a type, or 0 for a value that isn't a type.
uint32_t beacon_message_size(uint8_t type);

// True if `data` is exactly one valid message; fills `out` (all unused fields zero).
bool beacon_decode(const uint8_t* data, size_t size, BeaconMessage* out);

// Writes `message` into `out`. Returns the bytes written, or 0 if the message
// breaks a field rule or `capacity` is too small (nothing useful is written then).
uint32_t beacon_encode(const BeaconMessage* message, uint8_t* out, size_t capacity);

// ---------------------------------------------------------------------------
// Signaling (WebRTC), over the WebSocket listener (PROTOCOL.md, "Signaling").
// Each message is one binary WebSocket message with the same 8-byte header
// ("MTBC", version, type, two zero bytes) and its own type numbers (16 and
// up, so a UDP packet with one of them, or the reverse, never decodes). Every
// type has one fixed size except SIGNAL, whose blob is 1-4096 opaque bytes:
// its length is the WebSocket message's length minus 24, never a field.
// ---------------------------------------------------------------------------

constexpr uint32_t BEACON_SIGNALING_MAX_BLOB = 4096;
constexpr uint32_t BEACON_SIGNALING_SIZE_JOIN = 28;
constexpr uint32_t BEACON_SIGNALING_SIZE_JOINED = 28;
constexpr uint32_t BEACON_SIGNALING_SIZE_REFUSED = 28;
// LEAVE, PEER_JOINED, LEFT, NOT_FOUND: the header and the room.
constexpr uint32_t BEACON_SIGNALING_SIZE_ROOM = 24;
constexpr uint32_t BEACON_SIGNALING_SIGNAL_HEADER = 24;
constexpr uint32_t BEACON_SIGNALING_MAX_SIZE = BEACON_SIGNALING_SIGNAL_HEADER + BEACON_SIGNALING_MAX_BLOB;

enum class BeaconSignalingType : uint8_t
{
    JOIN = 16,          // c->s: room, role
    JOINED = 17,        // s->c: room, whether the other side is there
    LEAVE = 18,         // c->s: room
    PEER_JOINED = 19,   // s->c: room (the other side arrived)
    LEFT = 20,          // s->c: room (the other side left, or this socket was replaced)
    SIGNAL = 21,        // both: room, blob (passed to the other side as is)
    NOT_FOUND = 22,     // s->c: room (a SIGNAL with no one on the other side)
    REFUSED = 23,       // s->c: room, reason (a JOIN over a limit)
};

enum class BeaconRole : uint8_t
{
    HOST = 1,
    CLIENT = 2,
};

enum class BeaconRefusal : uint8_t
{
    ROOMS_PER_CONNECTION = 1,   // this socket is in too many rooms
    ROOMS_FULL = 2,             // the server's room table is full
};

struct BeaconSignalingMessage
{
    BeaconSignalingType type = BeaconSignalingType::JOIN;
    BeaconId room = {};                 // every type; never zero
    BeaconRole role = BeaconRole::HOST; // JOIN
    uint8_t peer_present = 0;           // JOINED: 0 or 1
    BeaconRefusal reason = BeaconRefusal::ROOMS_PER_CONNECTION;  // REFUSED
    const uint8_t* blob = nullptr;      // SIGNAL: points into the decoded data
    uint32_t blob_size = 0;             // SIGNAL: 1-4096
};

// True if `data` is exactly one valid signaling message (fields as above,
// padding zero). For SIGNAL, `out->blob` points into `data`.
bool beacon_signaling_decode(const uint8_t* data, size_t size, BeaconSignalingMessage* out);

// Writes `message` into `out` (a SIGNAL's blob must not overlap `out`).
// Returns the bytes written, or 0 if it breaks a field rule or doesn't fit.
uint32_t beacon_signaling_encode(const BeaconSignalingMessage* message, uint8_t* out, size_t capacity);

// Small helpers for both sides.
bool beacon_id_is_zero(const BeaconId* id);
bool beacon_id_equal(const BeaconId* a, const BeaconId* b);
bool beacon_address_equal(const BeaconAddress* a, const BeaconAddress* b);
bool beacon_address_is_ipv4(const BeaconAddress* address);
