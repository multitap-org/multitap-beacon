// libFuzzer target for beacon_ws_parse_handshake: never reads past `size`,
// and an accepted request ends with its blank line, fits the limit, and
// gives a well-formed 101 response.

#include "beacon_ws.h"

#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    BeaconWsHandshake handshake;
    BeaconWsParse result = beacon_ws_parse_handshake(data, size, &handshake);
    if (result != BeaconWsParse::OK)
    {
        return 0;
    }
    if (handshake.size < 4 || handshake.size > size || handshake.size > BEACON_WS_MAX_HANDSHAKE ||
        memcmp(data + handshake.size - 4, "\r\n\r\n", 4) != 0 || memcmp(data, "GET ", 4) != 0 ||
        strlen(handshake.accept) != BEACON_WS_ACCEPT_SIZE)
    {
        abort();
    }
    // The same request parses the same way when cut right after it.
    BeaconWsHandshake again;
    if (beacon_ws_parse_handshake(data, handshake.size, &again) != BeaconWsParse::OK ||
        strcmp(again.accept, handshake.accept) != 0)
    {
        abort();
    }
    char response[256];
    size_t length = beacon_ws_handshake_response(&handshake, response, sizeof(response));
    if (length == 0 || memcmp(response, "HTTP/1.1 101 ", 13) != 0)
    {
        abort();
    }
    return 0;
}
