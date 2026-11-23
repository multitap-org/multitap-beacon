#pragma once

// beacon_http: the few plain HTTP requests beacon answers next to its
// WebSocket (PROTOCOL.md, "Guest links"), as pure functions over byte
// buffers (no sockets), so they can be tested and fuzzed alone. beacon_signal
// does the connections.
//
// Guest links: a piccolo streaming to guests makes a link
// https://<beacon>/join/<room>#<token>. The token after the # never reaches
// a server. beacon serves:
// - GET  /join/<room>            the join page: opens piccoletto, and carries
//                                the card's og:title / og:image for chat apps;
// - GET  /join/<room>/card.png   the card's screenshot;
// - POST /join/<room>/card       the host puts the card (title + screenshot),
//                                proving it owns the room with the card key;
// - GET  /join/noise.png         white noise, the picture of a card without a
//                                screenshot (and of a room with no card).
// The room is derived from the card key, and the card key from the token:
//   card key = BLAKE2b-256("multitap guest card v1" || token)   (host side)
//   room     = base32(BLAKE2b-256("multitap guest room v1" || card key)), 13 chars
//   meeting  = BLAKE2b-128("multitap guest v1" || room)         (the signaling room)
// so beacon can check an upload without ever seeing the token, and a card
// lives exactly as long as its guest room.
//
// Strict subset, like the WebSocket handshake: "GET|HEAD|POST <target>
// HTTP/1.1", headers with no folding and no control characters, at most
// BEACON_HTTP_MAX_HEAD bytes; a POST needs Content-Length (no chunked body).

#include "beacon_wire.h"

#include <cstddef>
#include <cstdint>

constexpr size_t BEACON_HTTP_MAX_HEAD = 4096;
constexpr size_t BEACON_HTTP_MAX_TARGET = 256;
constexpr size_t BEACON_HTTP_MAX_HOST = 128;

constexpr uint32_t BEACON_GUEST_ROOM_SIZE = 13;      // base32 characters: 65 bits
constexpr uint32_t BEACON_GUEST_CARD_KEY_SIZE = 32;
constexpr uint32_t BEACON_CARD_MAX_TITLE = 64;       // bytes of UTF-8
constexpr uint32_t BEACON_CARD_MAX_PNG = 256 * 1024;
constexpr uint32_t BEACON_CARD_MAX_WIDTH = 1280;
constexpr uint32_t BEACON_CARD_MAX_HEIGHT = 960;
constexpr uint32_t BEACON_NOISE_WIDTH = 480;           // packaging/join/noise.png
constexpr uint32_t BEACON_NOISE_HEIGHT = 360;
// An upload's body: the card key, the title's length (1 byte), the title, the PNG.
constexpr uint32_t BEACON_CARD_MAX_UPLOAD = BEACON_GUEST_CARD_KEY_SIZE + 1 + BEACON_CARD_MAX_TITLE + BEACON_CARD_MAX_PNG;

enum class BeaconHttpParse : uint8_t
{
    INCOMPLETE,     // valid so far, more bytes needed
    INVALID,
    OK,
};

enum class BeaconHttpMethod : uint8_t
{
    GET,
    HEAD,
    POST,
};

struct BeaconHttpRequest
{
    size_t head_size = 0;                       // bytes up to and including the blank line
    BeaconHttpMethod method = BeaconHttpMethod::GET;
    char target[BEACON_HTTP_MAX_TARGET + 1] = {};
    char host[BEACON_HTTP_MAX_HOST + 1] = {};   // the Host header (empty if none)
    bool upgrade = false;                       // an Upgrade header: a WebSocket handshake
    bool has_content_length = false;
    uint64_t content_length = 0;
    bool has_forwarded = false;                 // as in BeaconWsHandshake
    BeaconAddress forwarded = {};
};

enum class BeaconJoinKind : uint8_t
{
    PAGE,       // /join/<room>
    CARD_PNG,   // /join/<room>/card.png
    CARD_PUT,   // /join/<room>/card
    NOISE,      // /join/noise.png (no room)
};

struct BeaconJoinRoute
{
    BeaconJoinKind kind = BeaconJoinKind::PAGE;
    char room[BEACON_GUEST_ROOM_SIZE + 1] = {};
};

struct BeaconCardUpload
{
    uint8_t card_key[BEACON_GUEST_CARD_KEY_SIZE] = {};
    char title[BEACON_CARD_MAX_TITLE + 1] = {};
    const uint8_t* png = nullptr;               // points into the body; nullptr: no screenshot (only a title)
    uint32_t png_size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
};

// The request head at the start of `data`. INCOMPLETE until the blank line
// arrives (INVALID past BEACON_HTTP_MAX_HEAD bytes).
BeaconHttpParse beacon_http_parse_request(const uint8_t* data, size_t size, BeaconHttpRequest* out);

// A /join/... target (a query string is ignored). False for anything else,
// or a room that isn't 13 lowercase base32 characters.
bool beacon_http_join_route(const char* target, BeaconJoinRoute* out);

// The room for a card key, and the meeting id (signaling room) for a room.
void beacon_guest_room_from_card_key(const uint8_t card_key[BEACON_GUEST_CARD_KEY_SIZE],
                                     char out[BEACON_GUEST_ROOM_SIZE + 1]);
void beacon_guest_meeting_id(const char room[BEACON_GUEST_ROOM_SIZE], BeaconId* out);

// A PNG's size from its signature and IHDR chunk (nothing else is read).
bool beacon_png_size(const uint8_t* data, size_t size, uint32_t* width, uint32_t* height);

// A card upload's body: field rules, a title of valid UTF-8 with no control
// characters, a PNG within the limits, or none (a card with only its title).
bool beacon_card_parse_upload(const uint8_t* body, size_t size, BeaconCardUpload* out);

// Copies `text` into `out` with & < > " ' as entities. Returns the length,
// 0 if it doesn't fit (`out` NUL-terminated either way when capacity > 0).
size_t beacon_html_escape(const char* text, char* out, size_t capacity);

// What the join page shows (beacon_join_page_render).
struct BeaconJoinPage
{
    const char* title = "";
    const char* description = "";
    const char* image_url = "";     // absolute
    uint32_t    image_width = 0;    // its size (og:image:width / height: WhatsApp wants them)
    uint32_t    image_height = 0;
    const char* page_url = "";      // absolute
    bool        ended = false;      // the room's host is gone: Game offline, no buttons
};

// Fills the join page template: {{TITLE}}, {{DESCRIPTION}}, {{IMAGE}},
// {{URL}} (escaped), {{IMAGE_WIDTH}}, {{IMAGE_HEIGHT}}, {{STATE}} ("live" or
// "ended"). Returns the length,
// 0 if it doesn't fit.
size_t beacon_join_page_render(const char* page_template, const BeaconJoinPage* page, char* out, size_t capacity);

// The white noise PNG (packaging/join/noise.png, compiled in).
const uint8_t* beacon_join_noise(size_t* size);

// The built-in join page (used when no --join-page file is given).
const char* beacon_join_page_builtin();

// A whole response head: status line, the given headers, Connection: close,
// Content-Length. Returns the length, 0 if it doesn't fit.
size_t beacon_http_response_head(uint32_t status, const char* content_type, const char* extra_headers,
                                 uint64_t content_length, char* out, size_t capacity);
