// beacon_stun against RFC 5769's test vectors and the strictness rules in
// beacon_stun.h.

#include "beacon_stun.h"

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

// RFC 5769, 2.1: a request with SOFTWARE, PRIORITY, ICE-CONTROLLED, USERNAME,
// MESSAGE-INTEGRITY and FINGERPRINT (none of them looked at).
static const uint8_t RFC5769_REQUEST[] = {
    0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73,
    0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff,
    0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09,
    0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14,
    0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49,
    0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf,
};
static const uint8_t RFC5769_TRANSACTION[12] = {0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
                                                0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae};

static void test_parse()
{
    uint8_t transaction[BEACON_STUN_TRANSACTION_SIZE] = {};
    check(sizeof(RFC5769_REQUEST) == 108, "RFC 5769 request is 108 bytes");
    check(beacon_stun_looks_like_stun(RFC5769_REQUEST, sizeof(RFC5769_REQUEST)), "the request looks like STUN");
    check(beacon_stun_parse_request(RFC5769_REQUEST, sizeof(RFC5769_REQUEST), transaction) &&
              memcmp(transaction, RFC5769_TRANSACTION, 12) == 0,
          "RFC 5769 request parses, transaction id copied");

    // The bare request browsers send: header only.
    uint8_t bare[20] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    check(beacon_stun_parse_request(bare, sizeof(bare), transaction) && transaction[11] == 12,
          "a header-only request parses");

    const uint8_t mtbc[4] = {'M', 'T', 'B', 'C'};
    check(!beacon_stun_looks_like_stun(mtbc, 4), "\"MTBC\" is not STUN");
    check(!beacon_stun_looks_like_stun(mtbc, 0), "an empty packet is not STUN");

    uint8_t packet[600];
    memcpy(packet, RFC5769_REQUEST, sizeof(RFC5769_REQUEST));
    check(!beacon_stun_parse_request(packet, 107, transaction), "a truncated request is refused");
    check(!beacon_stun_parse_request(packet, 16, transaction), "a packet shorter than the header is refused");

    memcpy(packet, bare, 20);
    packet[1] = 0x11;   // Binding Indication
    check(!beacon_stun_parse_request(packet, 20, transaction), "an indication is refused");
    packet[0] = 0x01;
    packet[1] = 0x01;   // Binding Success Response
    check(!beacon_stun_parse_request(packet, 20, transaction), "a response is refused");
    memcpy(packet, bare, 20);
    packet[1] = 0x03;   // Allocate (TURN)
    check(!beacon_stun_parse_request(packet, 20, transaction), "another method is refused");
    memcpy(packet, bare, 20);
    packet[7] = 0x43;
    check(!beacon_stun_parse_request(packet, 20, transaction), "a wrong magic cookie is refused");

    // Length field vs packet size.
    memcpy(packet, bare, 20);
    packet[3] = 4;
    check(!beacon_stun_parse_request(packet, 20, transaction), "a length past the packet is refused");
    memcpy(packet, RFC5769_REQUEST, sizeof(RFC5769_REQUEST));
    memset(packet + 108, 0, 4);
    check(!beacon_stun_parse_request(packet, 112, transaction), "bytes after the length are refused");

    // Attributes must tile the body exactly.
    memcpy(packet, bare, 20);
    packet[3] = 8;
    const uint8_t attribute[8] = {0x80, 0x22, 0x00, 0x05, 'a', 'b', 'c', 'd'};
    memcpy(packet + 20, attribute, 8);
    check(!beacon_stun_parse_request(packet, 28, transaction), "an attribute whose padding runs past is refused");
    packet[23] = 0x04;
    check(beacon_stun_parse_request(packet, 28, transaction), "the same attribute with 4 bytes parses");
    packet[3] = 4;
    packet[23] = 0x00;
    check(beacon_stun_parse_request(packet, 24, transaction), "an empty attribute parses");
    packet[23] = 0x08;
    check(!beacon_stun_parse_request(packet, 24, transaction), "an attribute longer than the body is refused");

    // Size limits: 548 is the largest, and the size is a multiple of 4.
    memset(packet, 0, sizeof(packet));
    memcpy(packet, bare, 20);
    uint32_t body = BEACON_STUN_MAX_REQUEST_SIZE - 20;
    packet[2] = static_cast<uint8_t>(body >> 8);
    packet[3] = static_cast<uint8_t>(body & 0xff);
    packet[22] = static_cast<uint8_t>((body - 4) >> 8);
    packet[23] = static_cast<uint8_t>((body - 4) & 0xff);
    check(beacon_stun_parse_request(packet, BEACON_STUN_MAX_REQUEST_SIZE, transaction), "548 bytes parse");
    body += 4;
    packet[2] = static_cast<uint8_t>(body >> 8);
    packet[3] = static_cast<uint8_t>(body & 0xff);
    packet[22] = static_cast<uint8_t>((body - 4) >> 8);
    packet[23] = static_cast<uint8_t>((body - 4) & 0xff);
    check(!beacon_stun_parse_request(packet, BEACON_STUN_MAX_REQUEST_SIZE + 4, transaction), "552 bytes are refused");
    memcpy(packet, bare, 20);
    packet[3] = 2;
    check(!beacon_stun_parse_request(packet, 22, transaction), "a size that isn't a multiple of 4 is refused");
}

static void test_encode()
{
    // RFC 5769, 2.2 and 2.3: 192.0.2.1:32853 and
    // 2001:db8:1234:5678:11:2233:4455:6677 port 32853.
    BeaconAddress v4 = {};
    v4.ip[10] = 0xff;
    v4.ip[11] = 0xff;
    v4.ip[12] = 192;
    v4.ip[13] = 0;
    v4.ip[14] = 2;
    v4.ip[15] = 1;
    v4.port = 32853;
    uint8_t out[64];
    size_t size = beacon_stun_encode_response(RFC5769_TRANSACTION, &v4, out, sizeof(out));
    const uint8_t expected_v4[32] = {0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7,
                                     0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x00, 0x20,
                                     0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43};
    check(size == 32 && memcmp(out, expected_v4, 32) == 0, "IPv4 response matches RFC 5769's XOR-MAPPED-ADDRESS");

    BeaconAddress v6 = {};
    const uint8_t ip6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
                             0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    memcpy(v6.ip, ip6, 16);
    v6.port = 32853;
    size = beacon_stun_encode_response(RFC5769_TRANSACTION, &v6, out, sizeof(out));
    const uint8_t expected_v6_attribute[24] = {0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47,
                                               0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79,
                                               0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9};
    check(size == 44 && out[3] == 24 && memcmp(out + 20, expected_v6_attribute, 24) == 0,
          "IPv6 response matches RFC 5769's XOR-MAPPED-ADDRESS");

    check(beacon_stun_encode_response(RFC5769_TRANSACTION, &v6, out, 43) == 0, "too small a buffer gives 0");
    check(beacon_stun_encode_response(RFC5769_TRANSACTION, &v4, out, 32) == 32, "exactly enough room works");
}

int main()
{
    test_parse();
    test_encode();
    if (g_failures != 0)
    {
        fprintf(stderr, "%u failures\n", g_failures);
        return 1;
    }
    printf("stun: all checks passed\n");
    return 0;
}
