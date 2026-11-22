// libFuzzer target for beacon_http: the request parser never reads past
// `size`, and an accepted request ends with its blank line and fits the
// limits; the join route and the card upload parser hold their rules on the
// same bytes.

#include "beacon_http.h"

#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    BeaconHttpRequest request;
    if (beacon_http_parse_request(data, size, &request) == BeaconHttpParse::OK)
    {
        if (request.head_size < 4 || request.head_size > size || request.head_size > BEACON_HTTP_MAX_HEAD ||
            memcmp(data + request.head_size - 4, "\r\n\r\n", 4) != 0 || request.target[0] != '/' ||
            strlen(request.target) > BEACON_HTTP_MAX_TARGET || strlen(request.host) > BEACON_HTTP_MAX_HOST ||
            (request.method == BeaconHttpMethod::GET && request.content_length != 0))
        {
            abort();
        }
        BeaconHttpRequest again;
        if (beacon_http_parse_request(data, request.head_size, &again) != BeaconHttpParse::OK ||
            strcmp(again.target, request.target) != 0)
        {
            abort();
        }
        BeaconJoinRoute route;
        if (beacon_http_join_route(request.target, &route) && strlen(route.room) != BEACON_GUEST_ROOM_SIZE)
        {
            abort();
        }
    }
    BeaconCardUpload upload;
    if (beacon_card_parse_upload(data, size, &upload))
    {
        if (upload.png < data || upload.png + upload.png_size != data + size || upload.png_size > BEACON_CARD_MAX_PNG ||
            upload.width == 0 || upload.width > BEACON_CARD_MAX_WIDTH || upload.height == 0 ||
            upload.height > BEACON_CARD_MAX_HEIGHT || strlen(upload.title) == 0 ||
            strlen(upload.title) > BEACON_CARD_MAX_TITLE)
        {
            abort();
        }
        char escaped[BEACON_CARD_MAX_TITLE * 6 + 1];
        if (beacon_html_escape(upload.title, escaped, sizeof(escaped)) == 0 || strchr(escaped, '<') != nullptr)
        {
            abort();
        }
    }
    return 0;
}
