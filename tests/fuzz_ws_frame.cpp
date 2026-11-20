// libFuzzer target for beacon_ws_parse_frame: never reads past `size`, and
// an accepted frame describes itself consistently and within the limits.
// Its payload, framed again by the server's header and re-masked, parses
// back to the same thing.

#include "beacon_ws.h"

#include <cstdlib>
#include <cstring>

static constexpr size_t BUFFER_SIZE = BEACON_WS_MAX_CLIENT_HEADER + BEACON_WS_MAX_PAYLOAD + 64;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static uint8_t buffer[BUFFER_SIZE];
    static uint8_t again[BUFFER_SIZE];
    if (size > BUFFER_SIZE)
    {
        size = BUFFER_SIZE;
    }
    memcpy(buffer, data, size);
    BeaconWsFrame frame;
    BeaconWsParse result = beacon_ws_parse_frame(buffer, size, &frame);
    if (result != BeaconWsParse::OK)
    {
        if (result == BeaconWsParse::INVALID && frame.error_code == 0)
        {
            abort();
        }
        return 0;
    }
    bool control = (static_cast<uint8_t>(frame.opcode) & 0x08u) != 0;
    if (frame.size > size || frame.payload_offset + frame.payload_size != frame.size ||
        frame.payload_size > BEACON_WS_MAX_PAYLOAD || (control && frame.payload_size > 125) ||
        frame.opcode == BeaconWsOpcode::TEXT || frame.opcode == BeaconWsOpcode::CONTINUATION)
    {
        abort();
    }
    // Rebuild it as a client frame with a fixed mask and parse that.
    uint8_t header[BEACON_WS_MAX_SERVER_HEADER];
    size_t header_size = beacon_ws_frame_header(frame.opcode, frame.payload_size, header);
    if (header_size == 0)
    {
        abort();
    }
    header[1] = static_cast<uint8_t>(header[1] | 0x80u);
    const uint8_t mask[4] = {1, 2, 3, 4};
    memcpy(again, header, header_size);
    memcpy(again + header_size, mask, 4);
    for (size_t i = 0; i < frame.payload_size; i++)
    {
        again[header_size + 4 + i] = static_cast<uint8_t>(buffer[frame.payload_offset + i] ^ mask[i & 3u]);
    }
    BeaconWsFrame second;
    if (beacon_ws_parse_frame(again, header_size + 4 + frame.payload_size, &second) != BeaconWsParse::OK ||
        second.opcode != frame.opcode || second.payload_size != frame.payload_size ||
        memcmp(again + second.payload_offset, buffer + frame.payload_offset, frame.payload_size) != 0)
    {
        abort();
    }
    return 0;
}
