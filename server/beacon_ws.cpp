// beacon_ws: see beacon_ws.h.

#include "beacon_ws.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>

// ---------------------------------------------------------------------------
// SHA-1 (RFC 3174)
// ---------------------------------------------------------------------------

static uint32_t rotate_left(uint32_t value, uint32_t bits)
{
    return (value << bits) | (value >> (32u - bits));
}

static void sha1_block(uint32_t state[5], const uint8_t block[64])
{
    uint32_t w[80];
    for (uint32_t i = 0; i < 16; i++)
    {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) | (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 8) | block[i * 4 + 3];
    }
    for (uint32_t i = 16; i < 80; i++)
    {
        w[i] = rotate_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    for (uint32_t i = 0; i < 80; i++)
    {
        uint32_t f = 0;
        uint32_t k = 0;
        if (i < 20)
        {
            f = (b & c) | (~b & d);
            k = 0x5A827999u;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        uint32_t temp = rotate_left(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotate_left(b, 30);
        b = a;
        a = temp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void beacon_sha1(const uint8_t* data, size_t size, uint8_t out[BEACON_SHA1_SIZE])
{
    uint32_t state[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
    size_t done = 0;
    while (size - done >= 64)
    {
        sha1_block(state, data + done);
        done += 64;
    }
    // The rest, the 0x80 marker, zeros, and the length in bits (big-endian)
    // in the last 8 bytes: one or two more blocks.
    uint8_t tail[128] = {};
    size_t rest = size - done;
    if (rest > 0)
    {
        memcpy(tail, data + done, rest);
    }
    tail[rest] = 0x80;
    size_t tail_size = rest + 1 + 8 <= 64 ? 64 : 128;
    uint64_t bits = static_cast<uint64_t>(size) * 8u;
    for (uint32_t i = 0; i < 8; i++)
    {
        tail[tail_size - 1 - i] = static_cast<uint8_t>((bits >> (8 * i)) & 0xffu);
    }
    sha1_block(state, tail);
    if (tail_size == 128)
    {
        sha1_block(state, tail + 64);
    }
    for (uint32_t i = 0; i < 5; i++)
    {
        out[i * 4] = static_cast<uint8_t>(state[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 16) & 0xffu);
        out[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 8) & 0xffu);
        out[i * 4 + 3] = static_cast<uint8_t>(state[i] & 0xffu);
    }
}

// ---------------------------------------------------------------------------
// base64 and the accept key
// ---------------------------------------------------------------------------

static const char BASE64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t beacon_base64_encode(const uint8_t* data, size_t size, char* out)
{
    size_t length = 0;
    size_t i = 0;
    while (i + 3 <= size)
    {
        uint32_t group = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8) | data[i + 2];
        out[length++] = BASE64[(group >> 18) & 63u];
        out[length++] = BASE64[(group >> 12) & 63u];
        out[length++] = BASE64[(group >> 6) & 63u];
        out[length++] = BASE64[group & 63u];
        i += 3;
    }
    if (size - i == 1)
    {
        uint32_t group = static_cast<uint32_t>(data[i]) << 16;
        out[length++] = BASE64[(group >> 18) & 63u];
        out[length++] = BASE64[(group >> 12) & 63u];
        out[length++] = '=';
        out[length++] = '=';
    }
    else if (size - i == 2)
    {
        uint32_t group = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
        out[length++] = BASE64[(group >> 18) & 63u];
        out[length++] = BASE64[(group >> 12) & 63u];
        out[length++] = BASE64[(group >> 6) & 63u];
        out[length++] = '=';
    }
    out[length] = '\0';
    return length;
}

static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

void beacon_ws_accept_key(const char key[BEACON_WS_KEY_SIZE], char out[BEACON_WS_ACCEPT_SIZE + 1])
{
    uint8_t input[BEACON_WS_KEY_SIZE + sizeof(WS_GUID) - 1];
    memcpy(input, key, BEACON_WS_KEY_SIZE);
    memcpy(input + BEACON_WS_KEY_SIZE, WS_GUID, sizeof(WS_GUID) - 1);
    uint8_t digest[BEACON_SHA1_SIZE];
    beacon_sha1(input, sizeof(input), digest);
    beacon_base64_encode(digest, sizeof(digest), out);
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

static const char SUBPROTOCOL[] = "multitap-beacon.1";

// A view of part of the request: never NUL-terminated.
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

static bool equal_exact(Text text, const char* literal)
{
    size_t length = strlen(literal);
    return text.size == length && memcmp(text.data, literal, length) == 0;
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

// Whether the comma-separated list `value` has `token` (case-insensitive or exact).
static bool list_has(Text value, const char* token, bool ignore_case)
{
    size_t start = 0;
    while (start <= value.size)
    {
        size_t end = start;
        while (end < value.size && value.data[end] != ',')
        {
            end++;
        }
        Text item = trim(Text{value.data + start, end - start});
        if (ignore_case ? equal_nocase(item, token) : equal_exact(item, token))
        {
            return true;
        }
        start = end + 1;
    }
    return false;
}

// The last item of a comma-separated list.
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
    return strchr("!#$%&'*+-.^_`|~", c) != nullptr && c != '\0';
}

static bool is_base64_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
}

// 16 bytes in base64: 22 characters, the last one carrying 2 bits (so its
// low 4 bits are zero: A, Q, g or w), then "==".
static bool valid_key(Text value)
{
    if (value.size != BEACON_WS_KEY_SIZE || value.data[22] != '=' || value.data[23] != '=')
    {
        return false;
    }
    for (size_t i = 0; i < 22; i++)
    {
        if (!is_base64_char(value.data[i]))
        {
            return false;
        }
    }
    char last = value.data[21];
    return last == 'A' || last == 'Q' || last == 'g' || last == 'w';
}

// A numeric IPv4 or IPv6 address (as X-Forwarded-For has it) into `out`, port 0.
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

// Bytes allowed in a header value (and the request target): visible ASCII,
// space, tab, and obs-text (0x80-0xFF); no other control characters.
static bool valid_value_char(uint8_t c)
{
    return c == '\t' || (c >= 0x20 && c != 0x7f);
}

BeaconWsParse beacon_ws_parse_handshake(const uint8_t* data, size_t size, BeaconWsHandshake* out)
{
    *out = BeaconWsHandshake{};
    // Refuse early what can't become a valid request.
    static const char METHOD[] = "GET ";
    size_t method_check = size < 4 ? size : 4;
    if (memcmp(data, METHOD, method_check) != 0)
    {
        return BeaconWsParse::INVALID;
    }
    size_t limit = size < BEACON_WS_MAX_HANDSHAKE ? size : BEACON_WS_MAX_HANDSHAKE;
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
        return size >= BEACON_WS_MAX_HANDSHAKE ? BeaconWsParse::INVALID : BeaconWsParse::INCOMPLETE;
    }

    // Lines are [start, CR) up to `end` + 2 (the last header's CRLF). A CR or
    // LF anywhere else is refused.
    const char* text = reinterpret_cast<const char*>(data);
    size_t at = 0;
    bool first = true;
    bool seen_host = false;
    bool seen_upgrade = false;
    bool seen_connection = false;
    bool seen_version = false;
    bool seen_key = false;
    bool has_protocol = false;
    Text key = {};
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
            return BeaconWsParse::INVALID;
        }
        Text line = {text + at, line_end - at};
        at = line_end + 2;
        for (size_t i = 0; i < line.size; i++)
        {
            if (!valid_value_char(static_cast<uint8_t>(line.data[i])))
            {
                return BeaconWsParse::INVALID;
            }
        }
        if (first)
        {
            // "GET <target> HTTP/1.1": exactly two spaces, a non-empty target.
            first = false;
            static const char VERSION[] = " HTTP/1.1";
            size_t version_size = sizeof(VERSION) - 1;
            if (line.size < 4 + 1 + version_size ||
                memcmp(line.data + line.size - version_size, VERSION, version_size) != 0)
            {
                return BeaconWsParse::INVALID;
            }
            for (size_t i = 4; i < line.size - version_size; i++)
            {
                uint8_t c = static_cast<uint8_t>(line.data[i]);
                if (c <= 0x20 || c == 0x7f)
                {
                    return BeaconWsParse::INVALID;
                }
            }
            continue;
        }
        // "name: value", the name a token; a line starting with whitespace
        // (obsolete folding) has an empty name and is refused.
        size_t colon = 0;
        while (colon < line.size && line.data[colon] != ':')
        {
            if (!is_token_char(line.data[colon]))
            {
                return BeaconWsParse::INVALID;
            }
            colon++;
        }
        if (colon == 0 || colon == line.size)
        {
            return BeaconWsParse::INVALID;
        }
        Text name = {line.data, colon};
        Text value = trim(Text{line.data + colon + 1, line.size - colon - 1});
        if (equal_nocase(name, "host"))
        {
            if (seen_host || value.size == 0)
            {
                return BeaconWsParse::INVALID;
            }
            seen_host = true;
        }
        else if (equal_nocase(name, "upgrade"))
        {
            if (seen_upgrade || !list_has(value, "websocket", true))
            {
                return BeaconWsParse::INVALID;
            }
            seen_upgrade = true;
        }
        else if (equal_nocase(name, "connection"))
        {
            if (seen_connection || !list_has(value, "upgrade", true))
            {
                return BeaconWsParse::INVALID;
            }
            seen_connection = true;
        }
        else if (equal_nocase(name, "sec-websocket-version"))
        {
            if (seen_version || !equal_exact(value, "13"))
            {
                return BeaconWsParse::INVALID;
            }
            seen_version = true;
        }
        else if (equal_nocase(name, "sec-websocket-key"))
        {
            if (seen_key || !valid_key(value))
            {
                return BeaconWsParse::INVALID;
            }
            seen_key = true;
            key = value;
        }
        else if (equal_nocase(name, "sec-websocket-protocol"))
        {
            // A list, possibly over several headers.
            if (list_has(value, SUBPROTOCOL, false))
            {
                has_protocol = true;
            }
        }
        else if (equal_nocase(name, "x-forwarded-for"))
        {
            // Proxies append: the last header's last address is the one the
            // nearest proxy saw.
            forwarded = list_last(value);
            seen_forwarded = true;
        }
    }
    if (!seen_host || !seen_upgrade || !seen_connection || !seen_version || !seen_key || !has_protocol)
    {
        return BeaconWsParse::INVALID;
    }
    out->size = end + 4;
    beacon_ws_accept_key(key.data, out->accept);
    if (seen_forwarded)
    {
        out->has_forwarded = parse_ip(forwarded, &out->forwarded);
    }
    return BeaconWsParse::OK;
}

size_t beacon_ws_handshake_response(const BeaconWsHandshake* handshake, char* out, size_t capacity)
{
    int written = snprintf(out, capacity,
                           "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: %s\r\n"
                           "Sec-WebSocket-Protocol: %s\r\n"
                           "\r\n",
                           handshake->accept, SUBPROTOCOL);
    if (written <= 0 || static_cast<size_t>(written) >= capacity)
    {
        return 0;
    }
    return static_cast<size_t>(written);
}

size_t beacon_ws_bad_request_response(char* out, size_t capacity)
{
    static const char RESPONSE[] = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    if (capacity < sizeof(RESPONSE))
    {
        return 0;
    }
    memcpy(out, RESPONSE, sizeof(RESPONSE));
    return sizeof(RESPONSE) - 1;
}

size_t beacon_ws_too_many_response(char* out, size_t capacity)
{
    static const char RESPONSE[] = "HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    if (capacity < sizeof(RESPONSE))
    {
        return 0;
    }
    memcpy(out, RESPONSE, sizeof(RESPONSE));
    return sizeof(RESPONSE) - 1;
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

static BeaconWsParse frame_invalid(BeaconWsFrame* out, uint16_t code)
{
    out->error_code = code;
    return BeaconWsParse::INVALID;
}

BeaconWsParse beacon_ws_parse_frame(uint8_t* data, size_t size, BeaconWsFrame* out)
{
    *out = BeaconWsFrame{};
    if (size < 2)
    {
        return BeaconWsParse::INCOMPLETE;
    }
    uint8_t first = data[0];
    uint8_t second = data[1];
    if ((first & 0x80u) == 0 || (first & 0x70u) != 0 || (second & 0x80u) == 0)
    {
        // Fragmented, an extension bit, or not masked.
        return frame_invalid(out, BEACON_WS_CLOSE_PROTOCOL_ERROR);
    }
    uint8_t opcode = first & 0x0fu;
    if (opcode == static_cast<uint8_t>(BeaconWsOpcode::TEXT))
    {
        return frame_invalid(out, BEACON_WS_CLOSE_UNSUPPORTED);
    }
    if (opcode != static_cast<uint8_t>(BeaconWsOpcode::BINARY) && opcode != static_cast<uint8_t>(BeaconWsOpcode::CLOSE) &&
        opcode != static_cast<uint8_t>(BeaconWsOpcode::PING) && opcode != static_cast<uint8_t>(BeaconWsOpcode::PONG))
    {
        return frame_invalid(out, BEACON_WS_CLOSE_PROTOCOL_ERROR);
    }
    bool control = (opcode & 0x08u) != 0;
    size_t length = second & 0x7fu;
    size_t header = 2;
    if (length == 127)
    {
        return frame_invalid(out, BEACON_WS_CLOSE_TOO_BIG);
    }
    if (length == 126)
    {
        if (control)
        {
            return frame_invalid(out, BEACON_WS_CLOSE_PROTOCOL_ERROR);
        }
        if (size < 4)
        {
            return BeaconWsParse::INCOMPLETE;
        }
        length = (static_cast<size_t>(data[2]) << 8) | data[3];
        if (length < 126)
        {
            return frame_invalid(out, BEACON_WS_CLOSE_PROTOCOL_ERROR);
        }
        header = 4;
    }
    if (length > BEACON_WS_MAX_PAYLOAD)
    {
        return frame_invalid(out, BEACON_WS_CLOSE_TOO_BIG);
    }
    if (opcode == static_cast<uint8_t>(BeaconWsOpcode::CLOSE) && length == 1)
    {
        return frame_invalid(out, BEACON_WS_CLOSE_PROTOCOL_ERROR);
    }
    header += 4;
    if (size < header + length)
    {
        return BeaconWsParse::INCOMPLETE;
    }
    const uint8_t* mask = data + header - 4;
    uint8_t* payload = data + header;
    for (size_t i = 0; i < length; i++)
    {
        payload[i] = static_cast<uint8_t>(payload[i] ^ mask[i & 3u]);
    }
    out->opcode = static_cast<BeaconWsOpcode>(opcode);
    out->size = header + length;
    out->payload_offset = header;
    out->payload_size = length;
    if (out->opcode == BeaconWsOpcode::CLOSE && length >= 2)
    {
        out->close_code = static_cast<uint16_t>((static_cast<uint32_t>(payload[0]) << 8) | payload[1]);
    }
    return BeaconWsParse::OK;
}

size_t beacon_ws_frame_header(BeaconWsOpcode opcode, size_t payload_size, uint8_t out[BEACON_WS_MAX_SERVER_HEADER])
{
    bool control = (static_cast<uint8_t>(opcode) & 0x08u) != 0;
    if (payload_size > BEACON_WS_MAX_PAYLOAD || (control && payload_size > 125))
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(0x80u | static_cast<uint8_t>(opcode));
    if (payload_size <= 125)
    {
        out[1] = static_cast<uint8_t>(payload_size);
        return 2;
    }
    out[1] = 126;
    out[2] = static_cast<uint8_t>(payload_size >> 8);
    out[3] = static_cast<uint8_t>(payload_size & 0xffu);
    return 4;
}
