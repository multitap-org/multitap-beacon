// beacon_http: see beacon_http.h and PROTOCOL.md ("Guest links").

#include "beacon_http.h"

#include "beacon_join_noise.h"
#include "beacon_join_page.h"

#include <monocypher.h>

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>

// ---------------------------------------------------------------------------
// Text helpers (the same rules as beacon_ws's handshake)
// ---------------------------------------------------------------------------

struct Text
{
    const char* data = nullptr;
    size_t size = 0;
};

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

static bool equal_nocase(Text text, const char* literal)
{
    size_t length = strlen(literal);
    if (text.size != length)
    {
        return false;
    }
    for (size_t i = 0; i < length; i++)
    {
        if (lower(text.data[i]) != lower(literal[i]))
        {
            return false;
        }
    }
    return true;
}

static bool is_ows(char c)
{
    return c == ' ' || c == '\t';
}

static Text trim(Text text)
{
    while (text.size > 0 && is_ows(text.data[0]))
    {
        text.data++;
        text.size--;
    }
    while (text.size > 0 && is_ows(text.data[text.size - 1]))
    {
        text.size--;
    }
    return text;
}

static Text list_last(Text value)
{
    size_t start = value.size;
    while (start > 0 && value.data[start - 1] != ',')
    {
        start--;
    }
    return trim(Text{value.data + start, value.size - start});
}

static bool is_token_char(char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
    {
        return true;
    }
    return c != '\0' && strchr("!#$%&'*+-.^_`|~", c) != nullptr;
}

static bool valid_value_char(uint8_t c)
{
    return c == '\t' || (c >= 0x20 && c != 0x7f);
}

static bool parse_ip(Text value, BeaconAddress* out)
{
    char text[INET6_ADDRSTRLEN + 1];
    if (value.size == 0 || value.size >= sizeof(text))
    {
        return false;
    }
    memcpy(text, value.data, value.size);
    text[value.size] = '\0';
    *out = BeaconAddress{};
    in_addr ip4 = {};
    in6_addr ip6 = {};
    if (inet_pton(AF_INET, text, &ip4) == 1)
    {
        out->ip[10] = 0xff;
        out->ip[11] = 0xff;
        memcpy(out->ip + 12, &ip4, 4);
        return true;
    }
    if (inet_pton(AF_INET6, text, &ip6) == 1)
    {
        memcpy(out->ip, &ip6, 16);
        return true;
    }
    return false;
}

// A Host value as beacon repeats it in URLs: letters, digits, '-', '.', ':'
// (a port) and IPv6 brackets only.
static bool valid_host(Text value)
{
    if (value.size == 0 || value.size > BEACON_HTTP_MAX_HOST)
    {
        return false;
    }
    for (size_t i = 0; i < value.size; i++)
    {
        char c = value.data[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                  c == '.' || c == ':' || c == '[' || c == ']';
        if (!ok)
        {
            return false;
        }
    }
    return true;
}

// Content-Length: digits only, at most 10 of them.
static bool parse_length(Text value, uint64_t* out)
{
    if (value.size == 0 || value.size > 10)
    {
        return false;
    }
    uint64_t length = 0;
    for (size_t i = 0; i < value.size; i++)
    {
        char c = value.data[i];
        if (c < '0' || c > '9')
        {
            return false;
        }
        length = length * 10 + static_cast<uint64_t>(c - '0');
    }
    *out = length;
    return true;
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

BeaconHttpParse beacon_http_parse_request(const uint8_t* data, size_t size, BeaconHttpRequest* out)
{
    *out = BeaconHttpRequest{};
    // Refuse early what can't become a request beacon answers.
    static const char* const METHODS[] = {"GET ", "HEAD ", "POST "};
    bool method_possible = false;
    for (uint32_t i = 0; i < 3; i++)
    {
        size_t length = strlen(METHODS[i]);
        size_t check = size < length ? size : length;
        if (memcmp(data, METHODS[i], check) == 0)
        {
            method_possible = true;
        }
    }
    if (!method_possible)
    {
        return BeaconHttpParse::INVALID;
    }
    size_t limit = size < BEACON_HTTP_MAX_HEAD ? size : BEACON_HTTP_MAX_HEAD;
    size_t end = 0;
    bool found = false;
    for (size_t i = 0; i + 4 <= limit; i++)
    {
        if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n')
        {
            end = i;
            found = true;
            break;
        }
    }
    if (!found)
    {
        return size >= BEACON_HTTP_MAX_HEAD ? BeaconHttpParse::INVALID : BeaconHttpParse::INCOMPLETE;
    }

    const char* text = reinterpret_cast<const char*>(data);
    size_t at = 0;
    bool first = true;
    bool seen_host = false;
    bool seen_length = false;
    bool chunked = false;
    Text forwarded = {};
    bool seen_forwarded = false;
    while (at < end + 2)
    {
        size_t line_end = at;
        while (data[line_end] != '\r' && data[line_end] != '\n')
        {
            line_end++;
        }
        if (data[line_end] != '\r' || data[line_end + 1] != '\n')
        {
            return BeaconHttpParse::INVALID;
        }
        Text line = {text + at, line_end - at};
        at = line_end + 2;
        for (size_t i = 0; i < line.size; i++)
        {
            if (!valid_value_char(static_cast<uint8_t>(line.data[i])))
            {
                return BeaconHttpParse::INVALID;
            }
        }
        if (first)
        {
            // "<METHOD> <target> HTTP/1.1": exactly two spaces, a target
            // starting with '/'.
            first = false;
            size_t method_size = 0;
            if (line.size >= 4 && memcmp(line.data, "GET ", 4) == 0)
            {
                out->method = BeaconHttpMethod::GET;
                method_size = 4;
            }
            else if (line.size >= 5 && memcmp(line.data, "HEAD ", 5) == 0)
            {
                out->method = BeaconHttpMethod::HEAD;
                method_size = 5;
            }
            else if (line.size >= 5 && memcmp(line.data, "POST ", 5) == 0)
            {
                out->method = BeaconHttpMethod::POST;
                method_size = 5;
            }
            else
            {
                return BeaconHttpParse::INVALID;
            }
            static const char VERSION[] = " HTTP/1.1";
            size_t version_size = sizeof(VERSION) - 1;
            if (line.size < method_size + 1 + version_size ||
                memcmp(line.data + line.size - version_size, VERSION, version_size) != 0)
            {
                return BeaconHttpParse::INVALID;
            }
            size_t target_size = line.size - version_size - method_size;
            if (target_size > BEACON_HTTP_MAX_TARGET || line.data[method_size] != '/')
            {
                return BeaconHttpParse::INVALID;
            }
            for (size_t i = 0; i < target_size; i++)
            {
                uint8_t c = static_cast<uint8_t>(line.data[method_size + i]);
                if (c <= 0x20 || c >= 0x7f)
                {
                    return BeaconHttpParse::INVALID;
                }
            }
            memcpy(out->target, line.data + method_size, target_size);
            out->target[target_size] = '\0';
            continue;
        }
        size_t colon = 0;
        while (colon < line.size && line.data[colon] != ':')
        {
            if (!is_token_char(line.data[colon]))
            {
                return BeaconHttpParse::INVALID;
            }
            colon++;
        }
        if (colon == 0 || colon == line.size)
        {
            return BeaconHttpParse::INVALID;
        }
        Text name = {line.data, colon};
        Text value = trim(Text{line.data + colon + 1, line.size - colon - 1});
        if (equal_nocase(name, "host"))
        {
            if (seen_host)
            {
                return BeaconHttpParse::INVALID;
            }
            seen_host = true;
            // An odd Host isn't an error: it just isn't repeated in URLs.
            if (valid_host(value))
            {
                memcpy(out->host, value.data, value.size);
                out->host[value.size] = '\0';
            }
        }
        else if (equal_nocase(name, "upgrade"))
        {
            out->upgrade = true;
        }
        else if (equal_nocase(name, "content-length"))
        {
            if (seen_length || !parse_length(value, &out->content_length))
            {
                return BeaconHttpParse::INVALID;
            }
            seen_length = true;
            out->has_content_length = true;
        }
        else if (equal_nocase(name, "transfer-encoding"))
        {
            chunked = true;
        }
        else if (equal_nocase(name, "x-forwarded-for"))
        {
            forwarded = list_last(value);
            seen_forwarded = true;
        }
    }
    // A body beacon would have to decode: refused (and GET with a body too).
    if (chunked || (out->method != BeaconHttpMethod::POST && out->has_content_length && out->content_length != 0))
    {
        return BeaconHttpParse::INVALID;
    }
    out->head_size = end + 4;
    if (seen_forwarded)
    {
        out->has_forwarded = parse_ip(forwarded, &out->forwarded);
    }
    return BeaconHttpParse::OK;
}

static bool is_base32_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
}

bool beacon_http_join_route(const char* target, BeaconJoinRoute* out)
{
    *out = BeaconJoinRoute{};
    static const char PREFIX[] = "/join/";
    size_t prefix_size = sizeof(PREFIX) - 1;
    if (strncmp(target, PREFIX, prefix_size) != 0)
    {
        return false;
    }
    const char* noise = target + prefix_size;
    if (strncmp(noise, "noise.png", 9) == 0 && (noise[9] == '\0' || noise[9] == '?'))
    {
        out->kind = BeaconJoinKind::NOISE;
        return true;
    }
    const char* room = target + prefix_size;
    for (uint32_t i = 0; i < BEACON_GUEST_ROOM_SIZE; i++)
    {
        if (!is_base32_char(room[i]))
        {
            return false;
        }
    }
    memcpy(out->room, room, BEACON_GUEST_ROOM_SIZE);
    out->room[BEACON_GUEST_ROOM_SIZE] = '\0';
    // What follows the room, up to a query string.
    const char* rest = room + BEACON_GUEST_ROOM_SIZE;
    size_t rest_size = strcspn(rest, "?");
    if (rest_size == 0 || (rest_size == 1 && rest[0] == '/'))
    {
        out->kind = BeaconJoinKind::PAGE;
        return true;
    }
    if (rest_size == 9 && strncmp(rest, "/card.png", 9) == 0)
    {
        out->kind = BeaconJoinKind::CARD_PNG;
        return true;
    }
    if (rest_size == 5 && strncmp(rest, "/card", 5) == 0)
    {
        out->kind = BeaconJoinKind::CARD_PUT;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// The derivations (PROTOCOL.md "Guest links"; frontends-common's net_guest
// computes the same, with the same test vectors)
// ---------------------------------------------------------------------------

static void base32_chars(const uint8_t* data, uint32_t count, char* out)
{
    static const char ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";
    for (uint32_t i = 0; i < count; i++)
    {
        uint32_t bit = i * 5;
        uint32_t byte = bit / 8;
        uint32_t shift = bit % 8;
        uint32_t window = static_cast<uint32_t>(data[byte]) << 8 | data[byte + 1];
        out[i] = ALPHABET[(window >> (11 - shift)) & 31u];
    }
    out[count] = '\0';
}

void beacon_guest_room_from_card_key(const uint8_t card_key[BEACON_GUEST_CARD_KEY_SIZE],
                                     char out[BEACON_GUEST_ROOM_SIZE + 1])
{
    static const char PREFIX[] = "multitap guest room v1";
    uint8_t hash[32];
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, sizeof(hash));
    crypto_blake2b_update(&ctx, reinterpret_cast<const uint8_t*>(PREFIX), sizeof(PREFIX) - 1);
    crypto_blake2b_update(&ctx, card_key, BEACON_GUEST_CARD_KEY_SIZE);
    crypto_blake2b_final(&ctx, hash);
    base32_chars(hash, BEACON_GUEST_ROOM_SIZE, out);
}

void beacon_guest_meeting_id(const char room[BEACON_GUEST_ROOM_SIZE], BeaconId* out)
{
    static const char PREFIX[] = "multitap guest v1";
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, BEACON_ID_SIZE);
    crypto_blake2b_update(&ctx, reinterpret_cast<const uint8_t*>(PREFIX), sizeof(PREFIX) - 1);
    crypto_blake2b_update(&ctx, reinterpret_cast<const uint8_t*>(room), BEACON_GUEST_ROOM_SIZE);
    crypto_blake2b_final(&ctx, out->bytes);
}

// ---------------------------------------------------------------------------
// Cards
// ---------------------------------------------------------------------------

static uint32_t read_u32_be(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 | static_cast<uint32_t>(p[2]) << 8 |
           p[3];
}

bool beacon_png_size(const uint8_t* data, size_t size, uint32_t* width, uint32_t* height)
{
    static const uint8_t SIGNATURE[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    // Signature, then IHDR first: length 13, "IHDR", width, height, ...
    if (size < 8 + 8 + 13 + 4 || memcmp(data, SIGNATURE, 8) != 0 || read_u32_be(data + 8) != 13 ||
        memcmp(data + 12, "IHDR", 4) != 0)
    {
        return false;
    }
    *width = read_u32_be(data + 16);
    *height = read_u32_be(data + 20);
    return true;
}

// Valid UTF-8 (no overlongs, no surrogates, at most U+10FFFF) with no control
// characters (C0, DEL, C1).
static bool valid_title(const uint8_t* text, size_t size)
{
    size_t i = 0;
    while (i < size)
    {
        uint8_t c = text[i];
        uint32_t code = 0;
        size_t extra = 0;
        if (c < 0x80)
        {
            code = c;
        }
        else if (c >= 0xc2 && c <= 0xdf)
        {
            code = c & 0x1fu;
            extra = 1;
        }
        else if (c >= 0xe0 && c <= 0xef)
        {
            code = c & 0x0fu;
            extra = 2;
        }
        else if (c >= 0xf0 && c <= 0xf4)
        {
            code = c & 0x07u;
            extra = 3;
        }
        else
        {
            return false;
        }
        // The continuation bytes are text[i + 1 .. i + extra]: all inside.
        if (extra > 0 && i + extra >= size)
        {
            return false;
        }
        for (size_t k = 1; k <= extra; k++)
        {
            uint8_t next = text[i + k];
            if ((next & 0xc0u) != 0x80u)
            {
                return false;
            }
            code = code << 6 | (next & 0x3fu);
        }
        if ((extra == 2 && code < 0x800) || (extra == 3 && (code < 0x10000 || code > 0x10ffff)) ||
            (code >= 0xd800 && code <= 0xdfff))
        {
            return false;
        }
        if (code < 0x20 || (code >= 0x7f && code <= 0x9f))
        {
            return false;
        }
        i += extra + 1;
    }
    return true;
}

bool beacon_card_parse_upload(const uint8_t* body, size_t size, BeaconCardUpload* out)
{
    *out = BeaconCardUpload{};
    if (size < BEACON_GUEST_CARD_KEY_SIZE + 1 || size > BEACON_CARD_MAX_UPLOAD)
    {
        return false;
    }
    memcpy(out->card_key, body, BEACON_GUEST_CARD_KEY_SIZE);
    size_t title_size = body[BEACON_GUEST_CARD_KEY_SIZE];
    size_t png_at = BEACON_GUEST_CARD_KEY_SIZE + 1 + title_size;
    if (title_size == 0 || title_size > BEACON_CARD_MAX_TITLE || png_at > size)
    {
        return false;
    }
    const uint8_t* title = body + BEACON_GUEST_CARD_KEY_SIZE + 1;
    if (!valid_title(title, title_size))
    {
        return false;
    }
    memcpy(out->title, title, title_size);
    out->title[title_size] = '\0';
    size_t png_size = size - png_at;
    if (png_size == 0)
    {
        return true;   // only a title: the page shows white noise
    }
    if (png_size > BEACON_CARD_MAX_PNG ||
        !beacon_png_size(body + png_at, png_size, &out->width, &out->height) || out->width == 0 ||
        out->height == 0 || out->width > BEACON_CARD_MAX_WIDTH || out->height > BEACON_CARD_MAX_HEIGHT)
    {
        return false;
    }
    out->png = body + png_at;
    out->png_size = static_cast<uint32_t>(png_size);
    return true;
}

// ---------------------------------------------------------------------------
// The page and responses
// ---------------------------------------------------------------------------

size_t beacon_html_escape(const char* text, char* out, size_t capacity)
{
    if (capacity == 0)
    {
        return 0;
    }
    size_t used = 0;
    for (size_t i = 0; text[i] != '\0'; i++)
    {
        const char* entity = nullptr;
        switch (text[i])
        {
            case '&':
                entity = "&amp;";
                break;
            case '<':
                entity = "&lt;";
                break;
            case '>':
                entity = "&gt;";
                break;
            case '"':
                entity = "&quot;";
                break;
            case '\'':
                entity = "&#39;";
                break;
            default:
                break;
        }
        size_t length = entity != nullptr ? strlen(entity) : 1;
        if (used + length >= capacity)
        {
            out[0] = '\0';
            return 0;
        }
        if (entity != nullptr)
        {
            memcpy(out + used, entity, length);
        }
        else
        {
            out[used] = text[i];
        }
        used += length;
    }
    out[used] = '\0';
    return used;
}

const uint8_t* beacon_join_noise(size_t* size)
{
    *size = sizeof(BEACON_JOIN_NOISE);
    return BEACON_JOIN_NOISE;
}

size_t beacon_join_page_render(const char* page_template, const BeaconJoinPage* page, char* out, size_t capacity)
{
    // Every value escaped once, up front (the largest: a description with 64
    // bytes of title, each an entity of 6, or a URL).
    constexpr uint32_t VALUES = 7;
    char values[VALUES][1024];
    char width[16];
    char height[16];
    snprintf(width, sizeof(width), "%u", page->image_width);
    snprintf(height, sizeof(height), "%u", page->image_height);
    const char* raw[VALUES] = {page->title, page->description, page->image_url, page->page_url, width, height,
                               page->ended ? "ended" : "live"};
    for (uint32_t i = 0; i < VALUES; i++)
    {
        if (beacon_html_escape(raw[i], values[i], sizeof(values[i])) == 0 && raw[i][0] != '\0')
        {
            return 0;
        }
    }
    // {{IMAGE_WIDTH}} before {{IMAGE}}: the longer name is tried first.
    static const char* const NAMES[VALUES] = {"{{TITLE}}", "{{DESCRIPTION}}", "{{IMAGE}}", "{{URL}}",
                                              "{{IMAGE_WIDTH}}", "{{IMAGE_HEIGHT}}", "{{STATE}}"};
    static const uint32_t ORDER[VALUES] = {4, 5, 0, 1, 2, 3, 6};
    size_t used = 0;
    const char* at = page_template;
    while (*at != '\0')
    {
        int32_t matched = -1;
        if (at[0] == '{' && at[1] == '{')
        {
            for (uint32_t k = 0; k < VALUES; k++)
            {
                uint32_t i = ORDER[k];
                if (strncmp(at, NAMES[i], strlen(NAMES[i])) == 0)
                {
                    matched = static_cast<int32_t>(i);
                    break;
                }
            }
        }
        const char* piece = at;
        size_t length = 1;
        if (matched >= 0)
        {
            piece = values[matched];
            length = strlen(piece);
            at += strlen(NAMES[matched]);
        }
        else
        {
            at++;
        }
        if (used + length >= capacity)
        {
            return 0;
        }
        memcpy(out + used, piece, length);
        used += length;
    }
    out[used] = '\0';
    return used;
}

const char* beacon_join_page_builtin()
{
    return BEACON_JOIN_PAGE;
}

static const char* status_text(uint32_t status)
{
    switch (status)
    {
        case 200:
            return "OK";
        case 204:
            return "No Content";
        case 400:
            return "Bad Request";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 413:
            return "Content Too Large";
        case 429:
            return "Too Many Requests";
        case 503:
            return "Service Unavailable";
        default:
            return "Error";
    }
}

size_t beacon_http_response_head(uint32_t status, const char* content_type, const char* extra_headers,
                                 uint64_t content_length, char* out, size_t capacity)
{
    char type_line[128] = "";
    if (content_type != nullptr)
    {
        snprintf(type_line, sizeof(type_line), "Content-Type: %s\r\n", content_type);
    }
    int written = snprintf(out, capacity,
                           "HTTP/1.1 %u %s\r\n"
                           "%s"
                           "%s"
                           "X-Content-Type-Options: nosniff\r\n"
                           "Connection: close\r\n"
                           "Content-Length: %llu\r\n"
                           "\r\n",
                           status, status_text(status), type_line, extra_headers != nullptr ? extra_headers : "",
                           static_cast<unsigned long long>(content_length));
    if (written <= 0 || static_cast<size_t>(written) >= capacity)
    {
        return 0;
    }
    return static_cast<size_t>(written);
}
