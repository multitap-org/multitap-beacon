// Runs the fuzz target without libFuzzer, so every compiler checks it in
// ctest: every single-byte change of a valid message of each type, every
// truncation and extension, and a few million random packets (random bytes,
// and random bodies behind a valid header so the field checks get exercised).

#include "beacon_wire.h"

#include <cstdio>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

// xorshift64: deterministic, so a failure repeats.
static uint64_t next_random(uint64_t* state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static uint32_t valid_packet(uint8_t type, uint8_t* out)
{
    BeaconMessage m = {};
    m.type = static_cast<BeaconType>(type);
    m.nonce = 0x0123456789abcdefull;
    m.cookie[0] = 0x55;
    m.id_count = 3;
    m.ttl_seconds = 60;
    for (uint32_t i = 0; i < 3; i++)
    {
        memset(m.ids[i].bytes, static_cast<int>(i + 1), BEACON_ID_SIZE);
    }
    m.address.ip[15] = 1;
    m.address.port = 55430;
    return beacon_encode(&m, out, BEACON_MAX_MESSAGE_SIZE);
}

int main()
{
    uint64_t runs = 0;
    uint8_t packet[BEACON_MAX_MESSAGE_SIZE + 64];
    uint8_t mutated[BEACON_MAX_MESSAGE_SIZE + 64];
    static constexpr uint8_t BYTE_VALUES[] = {0x00, 0x01, 0x02, 0x08, 0x09, 0x7f, 0x80, 0xfe, 0xff};

    for (uint32_t type = 1; type <= 9; type++)
    {
        uint32_t size = valid_packet(static_cast<uint8_t>(type), packet);
        if (size == 0)
        {
            fprintf(stderr, "FAIL: sample of type %u doesn't encode\n", type);
            return 1;
        }
        memset(packet + size, 0, 64);
        LLVMFuzzerTestOneInput(packet, size);
        runs++;
        for (uint32_t at = 0; at < size; at++)
        {
            for (uint32_t v = 0; v < sizeof(BYTE_VALUES); v++)
            {
                memcpy(mutated, packet, size);
                mutated[at] = BYTE_VALUES[v];
                LLVMFuzzerTestOneInput(mutated, size);
                mutated[at] = static_cast<uint8_t>(packet[at] ^ 0x10);
                LLVMFuzzerTestOneInput(mutated, size);
                runs += 2;
            }
        }
        for (uint32_t cut = 0; cut <= size + 64; cut++)
        {
            LLVMFuzzerTestOneInput(packet, cut);
            runs++;
        }
    }

    // Signaling messages: every byte change of each type and of a SIGNAL, and
    // every truncation.
    static uint8_t signaling[BEACON_SIGNALING_MAX_SIZE + 64];
    static uint8_t signaling_mutated[BEACON_SIGNALING_MAX_SIZE + 64];
    static uint8_t blob[300];
    for (uint32_t i = 0; i < sizeof(blob); i++)
    {
        blob[i] = static_cast<uint8_t>(i);
    }
    for (uint32_t type = 16; type <= 23; type++)
    {
        BeaconSignalingMessage m;
        m.type = static_cast<BeaconSignalingType>(type);
        memset(m.room.bytes, 0x5a, BEACON_ID_SIZE);
        m.role = BeaconRole::CLIENT;
        m.peer_present = 1;
        m.reason = BeaconRefusal::ROOMS_FULL;
        m.blob = blob;
        m.blob_size = sizeof(blob);
        uint32_t size = beacon_signaling_encode(&m, signaling, sizeof(signaling));
        if (size == 0)
        {
            fprintf(stderr, "FAIL: signaling sample of type %u doesn't encode\n", type);
            return 1;
        }
        memset(signaling + size, 0, 64);
        for (uint32_t at = 0; at < size && at < 64; at++)
        {
            for (uint32_t v = 0; v < sizeof(BYTE_VALUES); v++)
            {
                memcpy(signaling_mutated, signaling, size);
                signaling_mutated[at] = BYTE_VALUES[v];
                LLVMFuzzerTestOneInput(signaling_mutated, size);
                runs++;
            }
        }
        for (uint32_t cut = 0; cut <= size + 64; cut++)
        {
            LLVMFuzzerTestOneInput(signaling, cut);
            runs++;
        }
    }

    uint64_t state = 0x9e3779b97f4a7c15ull;
    for (uint32_t i = 0; i < 2000000; i++)
    {
        uint64_t r = next_random(&state);
        size_t size = static_cast<size_t>(r % (BEACON_MAX_MESSAGE_SIZE + 32));
        for (size_t b = 0; b < size; b++)
        {
            packet[b] = static_cast<uint8_t>(next_random(&state));
        }
        if ((r & 0x100) != 0)
        {
            // A valid header of a random type at that type's size, so the
            // random bytes reach the per-type checks.
            uint8_t type = static_cast<uint8_t>(1 + (r >> 16) % 9);
            size = beacon_message_size(type);
            packet[0] = 'M';
            packet[1] = 'T';
            packet[2] = 'B';
            packet[3] = 'C';
            packet[4] = BEACON_VERSION;
            packet[5] = type;
            packet[6] = 0;
            packet[7] = 0;
            // Mostly-zero bodies, or the zero-padding rules refuse everything.
            for (size_t b = 8; b < size; b++)
            {
                if ((next_random(&state) & 3) != 0)
                {
                    packet[b] = 0;
                }
            }
        }
        LLVMFuzzerTestOneInput(packet, size);
        runs++;
    }
    printf("fuzz_replay: %llu inputs, no failures\n", static_cast<unsigned long long>(runs));
    return 0;
}
