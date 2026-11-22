// Wire format: round trips for every type, one golden packet, and the rejects
// (sizes, header, padding, field rules).

#include "beacon_wire.h"

#include <cstdio>
#include <cstring>

static uint32_t g_failures = 0;

static void check(bool ok, const char* what)
{
    if (!ok)
    {
        fprintf(stderr, "FAIL: %s\n", what);
        g_failures++;
    }
}

static BeaconId make_id(uint8_t seed)
{
    BeaconId id;
    for (uint32_t i = 0; i < BEACON_ID_SIZE; i++)
    {
        id.bytes[i] = static_cast<uint8_t>(seed + i);
    }
    return id;
}

static BeaconAddress make_address(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    BeaconAddress address;
    address.ip[10] = 0xff;
    address.ip[11] = 0xff;
    address.ip[12] = a;
    address.ip[13] = b;
    address.ip[14] = c;
    address.ip[15] = d;
    address.port = port;
    return address;
}

// One valid message of each type.
static uint32_t sample_messages(BeaconMessage* out)
{
    uint32_t n = 0;
    BeaconMessage m;

    m = BeaconMessage{};
    m.type = BeaconType::BIND;
    m.nonce = 0x0102030405060708ull;
    out[n++] = m;

    m = BeaconMessage{};
    m.type = BeaconType::BOUND;
    m.nonce = 0xfffffffffffffffeull;
    m.address = make_address(203, 0, 113, 7, 40000);
    out[n++] = m;

    m = BeaconMessage{};
    m.type = BeaconType::REGISTER;
    m.nonce = 42;
    m.id_count = 3;
    for (uint32_t i = 0; i < 16; i++)
    {
        m.cookie[i] = static_cast<uint8_t>(0xa0 + i);
    }
    m.ids[0] = make_id(1);
    m.ids[1] = make_id(50);
    m.ids[2] = make_id(100);
    out[n++] = m;

    m = BeaconMessage{};
    m.type = BeaconType::REGISTER;
    m.nonce = 43;
    m.id_count = 8;
    for (uint32_t i = 0; i < 8; i++)
    {
        m.ids[i] = make_id(static_cast<uint8_t>(10 * i + 1));
    }
    out[n++] = m;

    m = BeaconMessage{};
    m.type = BeaconType::COOKIE;
    m.nonce = 7;
    m.cookie[0] = 1;
    m.cookie[15] = 2;
    out[n++] = m;

    m = BeaconMessage{};
    m.type = BeaconType::REGISTERED_REPLY;
    m.nonce = 8;
    m.cookie[3] = 9;
    m.id_count = 0;
    m.ttl_seconds = 60;
    out[n++] = m;

    m = BeaconMessage{};
    m.type = BeaconType::MEET;
    m.nonce = 9;
    m.ids[0] = make_id(200);
    out[n++] = m;

    m = BeaconMessage{};
    m.type = BeaconType::INTRO;
    m.nonce = 10;
    m.ids[0] = make_id(201);
    m.address.ip[0] = 0x20;
    m.address.ip[1] = 0x01;
    m.address.ip[15] = 0x05;
    m.address.port = 55430;
    out[n++] = m;

    m = BeaconMessage{};
    m.type = BeaconType::NOT_FOUND;
    m.nonce = 11;
    m.ids[0] = make_id(202);
    out[n++] = m;

    m = BeaconMessage{};
    m.type = BeaconType::PUNCH;
    m.nonce = 12;
    m.ids[0] = make_id(203);
    out[n++] = m;

    m = BeaconMessage{};
    m.type = BeaconType::PRESENCE;
    m.nonce = 13;
    m.id_count = 3;
    m.ids[0] = make_id(210);
    m.ids[1] = make_id(211);
    m.ids[2] = make_id(212);
    out[n++] = m;

    m = BeaconMessage{};
    m.type = BeaconType::PRESENT;
    m.nonce = 14;
    m.present = 0x05;
    out[n++] = m;
    return n;
}

static bool messages_equal(const BeaconMessage* a, const BeaconMessage* b)
{
    if (a->type != b->type || a->nonce != b->nonce || a->id_count != b->id_count || a->ttl_seconds != b->ttl_seconds ||
        a->present != b->present ||
        memcmp(a->cookie, b->cookie, sizeof(a->cookie)) != 0 || !beacon_address_equal(&a->address, &b->address))
    {
        return false;
    }
    for (uint32_t i = 0; i < BEACON_MAX_IDS; i++)
    {
        if (!beacon_id_equal(&a->ids[i], &b->ids[i]))
        {
            return false;
        }
    }
    return true;
}

static void test_round_trips()
{
    BeaconMessage samples[16];
    uint32_t count = sample_messages(samples);
    for (uint32_t i = 0; i < count; i++)
    {
        uint8_t packet[BEACON_MAX_MESSAGE_SIZE + 8];
        uint32_t size = beacon_encode(&samples[i], packet, sizeof(packet));
        check(size == beacon_message_size(static_cast<uint8_t>(samples[i].type)), "encode gives the type's size");
        BeaconMessage decoded;
        check(beacon_decode(packet, size, &decoded), "decode accepts what encode wrote");
        check(messages_equal(&samples[i], &decoded), "round trip keeps every field");

        // One byte more or less is never a message.
        check(!beacon_decode(packet, size - 1, &decoded), "one byte short is refused");
        packet[size] = 0;
        check(!beacon_decode(packet, size + 1, &decoded), "one byte long is refused");

        // Too small a buffer: nothing encoded.
        check(beacon_encode(&samples[i], packet, size - 1) == 0, "encode refuses a small buffer");
    }
}

static void test_golden()
{
    // A BIND written out by hand from PROTOCOL.md, so a client written from
    // the spec alone can check itself against the same bytes.
    static constexpr uint8_t BIND[36] = {'M', 'T', 'B', 'C', 1, 1, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    BeaconMessage m;
    check(beacon_decode(BIND, sizeof(BIND), &m), "golden BIND decodes");
    check(m.type == BeaconType::BIND && m.nonce == 0x0102030405060708ull, "golden BIND fields");

    // A BOUND for 203.0.113.7:40000 (0x9c40, little-endian on the wire).
    static constexpr uint8_t BOUND[36] = {'M', 'T', 'B', 'C', 1, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 7,
                                          0x40, 0x9c, 0, 0};
    check(beacon_decode(BOUND, sizeof(BOUND), &m), "golden BOUND decodes");
    check(m.address.port == 40000 && m.address.ip[12] == 203 && beacon_address_is_ipv4(&m.address),
          "golden BOUND address");
    uint8_t again[36];
    check(beacon_encode(&m, again, sizeof(again)) == 36 && memcmp(again, BOUND, 36) == 0,
          "golden BOUND encodes to the same bytes");
}

static void test_header_rejects()
{
    BeaconMessage m = {};
    m.type = BeaconType::BIND;
    uint8_t packet[64];
    uint32_t size = beacon_encode(&m, packet, sizeof(packet));
    BeaconMessage decoded;

    uint8_t bad[64];
    memcpy(bad, packet, size);
    bad[0] = 'X';
    check(!beacon_decode(bad, size, &decoded), "wrong magic is refused");
    memcpy(bad, packet, size);
    bad[4] = 2;
    check(!beacon_decode(bad, size, &decoded), "wrong version is refused");
    memcpy(bad, packet, size);
    bad[6] = 1;
    check(!beacon_decode(bad, size, &decoded), "reserved byte 6 must be zero");
    memcpy(bad, packet, size);
    bad[7] = 0x80;
    check(!beacon_decode(bad, size, &decoded), "reserved byte 7 must be zero");
    for (uint32_t type = 0; type < 256; type++)
    {
        memcpy(bad, packet, size);
        bad[5] = static_cast<uint8_t>(type);
        bool known = type >= 1 && type <= 11;
        if (!known)
        {
            check(!beacon_decode(bad, size, &decoded), "unknown type is refused");
            check(beacon_message_size(static_cast<uint8_t>(type)) == 0, "unknown type has no size");
        }
    }
    check(!beacon_decode(packet, 0, &decoded), "empty packet is refused");
    check(!beacon_decode(nullptr, 36, &decoded), "null packet is refused");
    check(!beacon_decode(packet, 7, &decoded), "half a header is refused");
    memcpy(bad, packet, size);
    bad[5] = static_cast<uint8_t>(BeaconType::REGISTER);
    check(!beacon_decode(bad, size, &decoded), "a BIND-sized REGISTER is refused");
}

static void test_padding_rejects()
{
    BeaconMessage samples[16];
    uint32_t count = sample_messages(samples);
    // Every byte that must be zero, per type, as offsets from PROTOCOL.md.
    for (uint32_t i = 0; i < count; i++)
    {
        uint8_t packet[BEACON_MAX_MESSAGE_SIZE];
        uint32_t size = beacon_encode(&samples[i], packet, sizeof(packet));
        uint32_t zero_from = 0;
        uint32_t zero_to = 0;
        switch (samples[i].type)
        {
            case BeaconType::BIND:
                zero_from = 16;
                zero_to = 36;
                break;
            case BeaconType::BOUND:
                zero_from = 34;
                zero_to = 36;
                break;
            case BeaconType::REGISTER:
                zero_from = 33;
                zero_to = 36;
                break;
            case BeaconType::REGISTERED_REPLY:
                zero_from = 33;
                zero_to = 34;
                break;
            case BeaconType::MEET:
                zero_from = 32;
                zero_to = 52;
                break;
            case BeaconType::INTRO:
                zero_from = 50;
                zero_to = 52;
                break;
            case BeaconType::PRESENCE:
                zero_from = 17;
                zero_to = 20;
                break;
            case BeaconType::PRESENT:
                zero_from = 17;
                zero_to = 20;
                break;
            default:
                break;
        }
        for (uint32_t at = zero_from; at < zero_to; at++)
        {
            uint8_t bad[BEACON_MAX_MESSAGE_SIZE];
            memcpy(bad, packet, size);
            bad[at] = 1;
            BeaconMessage decoded;
            check(!beacon_decode(bad, size, &decoded), "a non-zero padding byte is refused");
        }
    }
}

static void test_field_rejects()
{
    BeaconMessage decoded;
    uint8_t packet[BEACON_MAX_MESSAGE_SIZE];

    BeaconMessage reg = {};
    reg.type = BeaconType::REGISTER;
    reg.id_count = 2;
    reg.ids[0] = make_id(1);
    reg.ids[1] = make_id(2);
    uint32_t size = beacon_encode(&reg, packet, sizeof(packet));
    check(size == BEACON_SIZE_REGISTER, "REGISTER encodes");

    uint8_t bad[BEACON_MAX_MESSAGE_SIZE];
    memcpy(bad, packet, size);
    bad[32] = 0;
    check(!beacon_decode(bad, size, &decoded), "REGISTER count 0 is refused");
    memcpy(bad, packet, size);
    bad[32] = 9;
    check(!beacon_decode(bad, size, &decoded), "REGISTER count 9 is refused");
    memcpy(bad, packet, size);
    bad[36 + 2 * 16 + 5] = 1;
    check(!beacon_decode(bad, size, &decoded), "an id after count must be zero");
    memcpy(bad, packet, size);
    memset(bad + 36 + 16, 0, 16);
    check(!beacon_decode(bad, size, &decoded), "an id before count must not be zero");
    memcpy(bad, packet, size);
    bad[32] = 3;
    check(!beacon_decode(bad, size, &decoded), "count 3 with two ids is refused");

    reg.id_count = 0;
    check(beacon_encode(&reg, packet, sizeof(packet)) == 0, "encode refuses REGISTER count 0");
    reg.id_count = 9;
    check(beacon_encode(&reg, packet, sizeof(packet)) == 0, "encode refuses REGISTER count 9");
    reg.id_count = 3;
    check(beacon_encode(&reg, packet, sizeof(packet)) == 0, "encode refuses a zero id within count");

    BeaconMessage registered = {};
    registered.type = BeaconType::REGISTERED_REPLY;
    registered.id_count = 8;
    size = beacon_encode(&registered, packet, sizeof(packet));
    check(size == BEACON_SIZE_REGISTERED, "REGISTERED accepted 8 encodes");
    packet[32] = 9;
    check(!beacon_decode(packet, size, &decoded), "REGISTERED accepted 9 is refused");

    BeaconMessage meet = {};
    meet.type = BeaconType::MEET;
    check(beacon_encode(&meet, packet, sizeof(packet)) == 0, "encode refuses a zero meeting id");
    meet.ids[0] = make_id(3);
    size = beacon_encode(&meet, packet, sizeof(packet));
    memset(packet + 16, 0, 16);
    check(!beacon_decode(packet, size, &decoded), "a zero meeting id is refused");

    BeaconMessage intro = {};
    intro.type = BeaconType::INTRO;
    intro.ids[0] = make_id(4);
    intro.address = make_address(1, 2, 3, 4, 0);
    check(beacon_encode(&intro, packet, sizeof(packet)) == 0, "encode refuses port 0");
    intro.address.port = 1;
    size = beacon_encode(&intro, packet, sizeof(packet));
    packet[48] = 0;
    packet[49] = 0;
    check(!beacon_decode(packet, size, &decoded), "an INTRO with port 0 is refused");

    BeaconMessage bound = {};
    bound.type = BeaconType::BOUND;
    check(beacon_encode(&bound, packet, sizeof(packet)) == 0, "encode refuses a BOUND with port 0");

    BeaconMessage odd = {};
    odd.type = static_cast<BeaconType>(77);
    check(beacon_encode(&odd, packet, sizeof(packet)) == 0, "encode refuses an unknown type");
}

// Signaling messages: round trips, golden bytes, every reject.
static void test_signaling()
{
    BeaconSignalingMessage m;
    BeaconSignalingMessage d;
    uint8_t out[BEACON_SIGNALING_MAX_SIZE + 8];
    for (uint32_t i = 0; i < BEACON_ID_SIZE; i++)
    {
        m.room.bytes[i] = static_cast<uint8_t>(0xa0 + i);
    }

    m.type = BeaconSignalingType::JOIN;
    m.role = BeaconRole::CLIENT;
    uint32_t size = beacon_signaling_encode(&m, out, sizeof(out));
    const uint8_t golden_join[28] = {'M', 'T', 'B', 'C', 1, 16, 0, 0, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
                                     0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 2, 0, 0, 0};
    check(size == 28 && memcmp(out, golden_join, 28) == 0, "JOIN golden bytes");
    check(beacon_signaling_decode(out, size, &d) && d.type == BeaconSignalingType::JOIN && d.role == BeaconRole::CLIENT &&
              beacon_id_equal(&d.room, &m.room),
          "JOIN round trip");

    const BeaconSignalingType room_only[] = {BeaconSignalingType::LEAVE, BeaconSignalingType::PEER_JOINED,
                                             BeaconSignalingType::LEFT, BeaconSignalingType::NOT_FOUND};
    for (uint32_t i = 0; i < 4; i++)
    {
        m.type = room_only[i];
        size = beacon_signaling_encode(&m, out, sizeof(out));
        check(size == BEACON_SIGNALING_SIZE_ROOM && beacon_signaling_decode(out, size, &d) && d.type == room_only[i],
              "room-only message round trip");
        check(!beacon_signaling_decode(out, size + 1, &d), "a room-only message one byte long is refused");
    }

    m.type = BeaconSignalingType::JOINED;
    m.peer_present = 1;
    size = beacon_signaling_encode(&m, out, sizeof(out));
    check(size == 28 && out[24] == 1 && beacon_signaling_decode(out, size, &d) && d.peer_present == 1, "JOINED");
    out[24] = 2;
    check(!beacon_signaling_decode(out, size, &d), "JOINED with peer_present 2 is refused");
    m.peer_present = 2;
    check(beacon_signaling_encode(&m, out, sizeof(out)) == 0, "JOINED with peer_present 2 doesn't encode");
    m.peer_present = 0;

    m.type = BeaconSignalingType::REFUSED;
    m.reason = BeaconRefusal::ROOMS_FULL;
    size = beacon_signaling_encode(&m, out, sizeof(out));
    check(size == 28 && beacon_signaling_decode(out, size, &d) && d.reason == BeaconRefusal::ROOMS_FULL, "REFUSED");
    out[24] = 3;
    check(!beacon_signaling_decode(out, size, &d), "an unknown refusal reason is refused");

    // SIGNAL: 1-4096 opaque bytes, the length from the message.
    uint8_t blob[BEACON_SIGNALING_MAX_BLOB + 1];
    for (uint32_t i = 0; i < sizeof(blob); i++)
    {
        blob[i] = static_cast<uint8_t>(i * 13);
    }
    m.type = BeaconSignalingType::SIGNAL;
    m.blob = blob;
    const uint32_t blob_sizes[] = {1, 100, BEACON_SIGNALING_MAX_BLOB};
    for (uint32_t i = 0; i < 3; i++)
    {
        m.blob_size = blob_sizes[i];
        size = beacon_signaling_encode(&m, out, sizeof(out));
        check(size == 24 + blob_sizes[i] && beacon_signaling_decode(out, size, &d) &&
                  d.blob_size == blob_sizes[i] && d.blob == out + 24 && memcmp(d.blob, blob, d.blob_size) == 0,
              "SIGNAL round trip");
    }
    m.blob_size = BEACON_SIGNALING_MAX_BLOB + 1;
    check(beacon_signaling_encode(&m, out, sizeof(out)) == 0, "a 4097-byte blob doesn't encode");
    m.blob_size = 0;
    check(beacon_signaling_encode(&m, out, sizeof(out)) == 0, "an empty blob doesn't encode");
    m.blob_size = 10;
    check(beacon_signaling_encode(&m, out, 33) == 0, "SIGNAL that doesn't fit");
    size = beacon_signaling_encode(&m, out, sizeof(out));
    check(!beacon_signaling_decode(out, 24, &d), "SIGNAL without a blob is refused");
    memset(out + size, 0, BEACON_SIGNALING_MAX_SIZE + 1 - size);
    check(!beacon_signaling_decode(out, BEACON_SIGNALING_MAX_SIZE + 1, &d), "SIGNAL over the limit is refused");

    // Header and field rules.
    m.type = BeaconSignalingType::JOIN;
    m.role = BeaconRole::HOST;
    size = beacon_signaling_encode(&m, out, sizeof(out));
    uint8_t bad[28];
    const uint32_t positions[] = {0, 3, 4, 6, 7, 25, 27};
    for (uint32_t i = 0; i < 7; i++)
    {
        memcpy(bad, out, 28);
        bad[positions[i]] = static_cast<uint8_t>(bad[positions[i]] ^ 0x40);
        check(!beacon_signaling_decode(bad, 28, &d), "a JOIN with a bad header or padding byte is refused");
    }
    memcpy(bad, out, 28);
    bad[24] = 3;
    check(!beacon_signaling_decode(bad, 28, &d), "a JOIN with role 3 is refused");
    memcpy(bad, out, 28);
    memset(bad + 8, 0, 16);
    check(!beacon_signaling_decode(bad, 28, &d), "a zero room is refused");
    memcpy(bad, out, 28);
    bad[5] = 9;   // PUNCH: a UDP type
    check(!beacon_signaling_decode(bad, 28, &d), "a UDP type doesn't decode as signaling");
    BeaconMessage udp;
    bad[5] = 16;
    check(!beacon_decode(bad, 28, &udp), "a signaling type doesn't decode as UDP");
    m.room = BeaconId{};
    check(beacon_signaling_encode(&m, out, sizeof(out)) == 0, "a zero room doesn't encode");
}

int main()
{
    test_round_trips();
    test_golden();
    test_header_rejects();
    test_padding_rejects();
    test_field_rejects();
    test_signaling();
    if (g_failures != 0)
    {
        fprintf(stderr, "%u failures\n", g_failures);
        return 1;
    }
    printf("wire: all checks passed\n");
    return 0;
}
