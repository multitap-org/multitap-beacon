// Runs fuzz_stun's entry point without libFuzzer, so every compiler checks it
// in ctest: every byte change of RFC 5769's request, every truncation, and
// random requests with a valid header and random attribute chains.

#include "beacon_stun.h"

#include <cstdio>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static uint64_t next_random(uint64_t* state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static const uint8_t SAMPLE[] = {
    0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73,
    0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff,
    0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09,
    0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14,
    0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49,
    0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf,
};

int main()
{
    uint64_t runs = 0;
    uint8_t packet[BEACON_STUN_MAX_REQUEST_SIZE + 64];
    static constexpr uint8_t BYTE_VALUES[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x7f, 0x80, 0xfe, 0xff};
    for (size_t at = 0; at < sizeof(SAMPLE); at++)
    {
        for (uint32_t v = 0; v < sizeof(BYTE_VALUES); v++)
        {
            memcpy(packet, SAMPLE, sizeof(SAMPLE));
            packet[at] = BYTE_VALUES[v];
            LLVMFuzzerTestOneInput(packet, sizeof(SAMPLE));
            runs++;
        }
    }
    memcpy(packet, SAMPLE, sizeof(SAMPLE));
    memset(packet + sizeof(SAMPLE), 0, 64);
    for (size_t cut = 0; cut <= sizeof(SAMPLE) + 64; cut++)
    {
        LLVMFuzzerTestOneInput(packet, cut);
        runs++;
    }

    uint64_t state = 0x2545f4914f6cdd1dull;
    for (uint32_t i = 0; i < 1000000; i++)
    {
        uint64_t r = next_random(&state);
        size_t size = 20 + 4 * static_cast<size_t>(r % 140);   // up to 576
        for (size_t b = 0; b < size; b++)
        {
            packet[b] = static_cast<uint8_t>(next_random(&state));
        }
        if ((r & 0x100) != 0)
        {
            // A valid header, then attributes with small random lengths.
            packet[0] = 0x00;
            packet[1] = 0x01;
            packet[2] = static_cast<uint8_t>((size - 20) >> 8);
            packet[3] = static_cast<uint8_t>((size - 20) & 0xff);
            packet[4] = 0x21;
            packet[5] = 0x12;
            packet[6] = 0xa4;
            packet[7] = 0x42;
            size_t at = 20;
            while (at + 4 <= size)
            {
                size_t length = static_cast<size_t>(next_random(&state) % 24);
                packet[at + 2] = 0;
                packet[at + 3] = static_cast<uint8_t>(length);
                at += 4 + ((length + 3) & ~static_cast<size_t>(3));
            }
        }
        LLVMFuzzerTestOneInput(packet, size);
        runs++;
    }
    printf("fuzz_stun_replay: %llu inputs, no failures\n", static_cast<unsigned long long>(runs));
    return 0;
}
