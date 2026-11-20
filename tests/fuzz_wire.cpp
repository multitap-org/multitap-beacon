// Fuzz target for the wire decoder (libFuzzer entry point; fuzz_replay.cpp
// drives the same function from a plain main()).
//
// Checks, beyond "doesn't crash": anything decode accepts has exactly the
// size of its type, and encoding it again gives back the same bytes (so
// there's one encoding per message and no byte is ignored).

#include "beacon_wire.h"

#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    BeaconMessage message;
    if (!beacon_decode(data, size, &message))
    {
        return 0;
    }
    if (size != beacon_message_size(static_cast<uint8_t>(message.type)))
    {
        abort();
    }
    uint8_t again[BEACON_MAX_MESSAGE_SIZE];
    uint32_t written = beacon_encode(&message, again, sizeof(again));
    if (written != size || memcmp(again, data, size) != 0)
    {
        abort();
    }
    return 0;
}
