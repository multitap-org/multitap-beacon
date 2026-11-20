// libFuzzer target for beacon_stun: any packet either fails to parse or
// gives a transaction id that the response echoes, at the documented size,
// for both address families.

#include "beacon_stun.h"

#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    uint8_t transaction[BEACON_STUN_TRANSACTION_SIZE];
    if (!beacon_stun_parse_request(data, size, transaction))
    {
        return 0;
    }
    // What parsed must have looked like STUN and fit the limits.
    if (!beacon_stun_looks_like_stun(data, size) || size < BEACON_STUN_HEADER_SIZE ||
        size > BEACON_STUN_MAX_REQUEST_SIZE || memcmp(transaction, data + 8, BEACON_STUN_TRANSACTION_SIZE) != 0)
    {
        abort();
    }
    BeaconAddress v4 = {};
    v4.ip[10] = 0xff;
    v4.ip[11] = 0xff;
    v4.ip[12] = data[8];
    v4.port = 1234;
    BeaconAddress v6 = {};
    v6.ip[0] = 0x20;
    v6.ip[15] = data[9];
    v6.port = 4321;
    uint8_t out[64];
    size_t v4_size = beacon_stun_encode_response(transaction, &v4, out, sizeof(out));
    if (v4_size != BEACON_STUN_RESPONSE_IPV4_SIZE || memcmp(out + 8, transaction, BEACON_STUN_TRANSACTION_SIZE) != 0)
    {
        abort();
    }
    size_t v6_size = beacon_stun_encode_response(transaction, &v6, out, sizeof(out));
    if (v6_size != BEACON_STUN_RESPONSE_IPV6_SIZE || memcmp(out + 8, transaction, BEACON_STUN_TRANSACTION_SIZE) != 0)
    {
        abort();
    }
    return 0;
}
