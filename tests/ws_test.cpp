// beacon_ws: SHA-1 (RFC 3174 vectors), base64, the accept key (RFC 6455's
// example), the handshake and frame rules in beacon_ws.h.

#include "beacon_ws.h"

#include <cstdio>
#include <cstring>
#include <string>

static uint32_t g_failures = 0;

static void check(bool ok, const char* what)
{
    if (!ok)
    {
        fprintf(stderr, "FAIL: %s\n", what);
        g_failures++;
    }
}

static std::string hex(const uint8_t* data, size_t size)
{
    static const char DIGITS[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < size; i++)
    {
        out += DIGITS[data[i] >> 4];
        out += DIGITS[data[i] & 15];
    }
    return out;
}

static std::string sha1_hex(const std::string& text)
{
    uint8_t digest[BEACON_SHA1_SIZE];
    beacon_sha1(reinterpret_cast<const uint8_t*>(text.data()), text.size(), digest);
    return hex(digest, sizeof(digest));
}

static void test_sha1_base64()
{
    check(sha1_hex("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA-1 of nothing");
    check(sha1_hex("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d", "SHA-1 of abc");
    check(sha1_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
              "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
          "SHA-1 of the 448-bit vector");
    check(sha1_hex(std::string(1000000, 'a')) == "34aa973cd4c4daa4f61eeb2bdbad27316534016f", "SHA-1 of a million a");
    // Lengths around the padding boundaries (one or two final blocks); the
    // expected values are from Python's hashlib.
    struct Vector
    {
        size_t length;
        const char* digest;
    };
    const Vector boundaries[] = {
        {55, "cef734ba81a024479e09eb5a75b6ddae62e6abf1"}, {56, "901305367c259952f4e7af8323f480d59f81335b"},
        {63, "0ddc4e0cccd9a12850deb5abb0853a4425559fec"}, {64, "bb2fa3ee7afb9f54c6dfb5d021f14b1ffe40c163"},
        {119, "4300320394f7ee239bcdce7d3b8bcee173a0cd5c"}, {120, "ceb2821639c4b6dcb10bce0e522ca2e608ce056d"},
    };
    for (const Vector& v : boundaries)
    {
        check(sha1_hex(std::string(v.length, 'x')) == v.digest, "SHA-1 at a padding boundary");
    }

    char out[64];
    const uint8_t data[] = {'f', 'o', 'o', 'b', 'a', 'r'};
    const char* expected[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
    for (size_t n = 0; n <= 6; n++)
    {
        size_t length = beacon_base64_encode(data, n, out);
        check(length == strlen(expected[n]) && strcmp(out, expected[n]) == 0, "base64 (RFC 4648 vectors)");
    }

    char accept[BEACON_WS_ACCEPT_SIZE + 1];
    beacon_ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==", accept);
    check(strcmp(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0, "RFC 6455's accept key example");
}

static const char CHROME_REQUEST[] =
    "GET /signal HTTP/1.1\r\n"
    "Host: beacon.example.org\r\n"
    "Connection: Upgrade\r\n"
    "Pragma: no-cache\r\n"
    "Cache-Control: no-cache\r\n"
    "User-Agent: Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0\r\n"
    "Upgrade: websocket\r\n"
    "Origin: https://piccoletto.app\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Accept-Encoding: gzip, deflate, br, zstd\r\n"
    "Accept-Language: es-AR,es;q=0.9\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
    "Sec-WebSocket-Protocol: multitap-beacon.1\r\n"
    "\r\n";

static BeaconWsParse parse_text(const std::string& text, BeaconWsHandshake* out)
{
    return beacon_ws_parse_handshake(reinterpret_cast<const uint8_t*>(text.data()), text.size(), out);
}

// CHROME_REQUEST with `from` replaced by `to` (the first occurrence).
static std::string edited(const char* from, const char* to)
{
    std::string text = CHROME_REQUEST;
    size_t at = text.find(from);
    if (at != std::string::npos)
    {
        text.replace(at, strlen(from), to);
    }
    return text;
}

static void test_handshake()
{
    BeaconWsHandshake h;
    std::string chrome = CHROME_REQUEST;
    check(parse_text(chrome, &h) == BeaconWsParse::OK, "a Chrome-like handshake parses");
    check(h.size == chrome.size(), "the handshake size is the whole request");
    check(strcmp(h.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0, "accept key computed");
    check(!h.has_forwarded, "no X-Forwarded-For");

    char response[256];
    size_t size = beacon_ws_handshake_response(&h, response, sizeof(response));
    std::string text(response, size);
    check(text.find("HTTP/1.1 101 Switching Protocols\r\n") == 0, "101 response");
    check(text.find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != std::string::npos, "accept header");
    check(text.find("Sec-WebSocket-Protocol: multitap-beacon.1\r\n") != std::string::npos, "subprotocol header");
    check(text.find("Extensions") == std::string::npos, "no extension accepted");
    check(text.size() >= 4 && text.substr(text.size() - 4) == "\r\n\r\n", "response ends with a blank line");
    check(beacon_ws_handshake_response(&h, response, 20) == 0, "response that doesn't fit gives 0");
    check(beacon_ws_bad_request_response(response, sizeof(response)) > 0 &&
              strncmp(response, "HTTP/1.1 400", 12) == 0,
          "400 response");

    // Bytes after the request (a frame sent early) aren't part of it.
    check(parse_text(chrome + "\x82\x80", &h) == BeaconWsParse::OK && h.size == chrome.size(),
          "bytes after the blank line are left alone");

    // Incomplete until the blank line, invalid past the limit.
    for (size_t cut = 0; cut < chrome.size(); cut += 7)
    {
        check(parse_text(chrome.substr(0, cut), &h) == BeaconWsParse::INCOMPLETE, "a prefix is incomplete");
    }
    std::string huge = "GET / HTTP/1.1\r\nX-Pad: " + std::string(BEACON_WS_MAX_HANDSHAKE, 'a');
    check(parse_text(huge, &h) == BeaconWsParse::INVALID, "more than the limit without a blank line is invalid");
    check(parse_text("POST / HTTP/1.1\r\n", &h) == BeaconWsParse::INVALID, "not GET: invalid at once");
    check(parse_text("GE", &h) == BeaconWsParse::INCOMPLETE, "a prefix of GET is incomplete");

    // Header names in any case, values with extra whitespace and lists.
    std::string lower = "GET / HTTP/1.1\r\nhost: x\r\nupgrade:WebSocket\r\nconnection: keep-alive, Upgrade\r\n"
                        "sec-websocket-version:13\r\nsec-websocket-key:   dGhlIHNhbXBsZSBub25jZQ==  \r\n"
                        "sec-websocket-protocol: chat\r\nSec-WebSocket-Protocol: other, multitap-beacon.1\r\n\r\n";
    check(parse_text(lower, &h) == BeaconWsParse::OK, "lowercase names, lists, split protocol headers");

    // Every required header, refused when missing or wrong.
    struct Case
    {
        const char* from;
        const char* to;
        const char* what;
    };
    const Case cases[] = {
        {"Host: beacon.example.org\r\n", "", "no Host"},
        {"Upgrade: websocket\r\n", "", "no Upgrade"},
        {"Upgrade: websocket", "Upgrade: h2c", "Upgrade not websocket"},
        {"Connection: Upgrade\r\n", "", "no Connection"},
        {"Connection: Upgrade", "Connection: keep-alive", "Connection without upgrade"},
        {"Sec-WebSocket-Version: 13\r\n", "", "no version"},
        {"Sec-WebSocket-Version: 13", "Sec-WebSocket-Version: 8", "version 8"},
        {"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "", "no key"},
        {"dGhlIHNhbXBsZSBub25jZQ==", "dGhlIHNhbXBsZSBub25jZR==", "a key whose last character has stray bits"},
        {"dGhlIHNhbXBsZSBub25jZQ==", "dGhlIHNhbXBsZSBub25jZQ=", "a key of 23 characters"},
        {"dGhlIHNhbXBsZSBub25jZQ==", "dGhlIHNhbXBsZSBub25j*Q==", "a key with a non-base64 character"},
        {"Sec-WebSocket-Protocol: multitap-beacon.1", "Sec-WebSocket-Protocol: multitap-beacon.2", "wrong subprotocol"},
        {"Sec-WebSocket-Protocol: multitap-beacon.1", "Sec-WebSocket-Protocol: MULTITAP-BEACON.1", "subprotocol case"},
        {"Sec-WebSocket-Protocol: multitap-beacon.1\r\n", "", "no subprotocol"},
        {"GET /signal HTTP/1.1", "GET /signal HTTP/1.0", "HTTP/1.0"},
        {"GET /signal HTTP/1.1", "GET  HTTP/1.1", "an empty target"},
        {"GET /signal HTTP/1.1", "GET /a b HTTP/1.1", "a space in the target"},
        {"Pragma: no-cache\r\n", "Pragma: no-cache\r\n continued\r\n", "obsolete line folding"},
        {"Pragma: no-cache\r\n", "Pragma no-cache\r\n", "a header without a colon"},
        {"Pragma: no-cache\r\n", "Pr agma: no-cache\r\n", "a space in a header name"},
        {"Pragma: no-cache\r\n", "Pragma: no\x01" "cache\r\n", "a control character in a value"},
        {"Pragma: no-cache\r\n", "Pragma: no-cache\n", "a bare LF"},
        {"Pragma: no-cache\r\n", "Pragma: no\rcache\r\n", "a bare CR"},
        {"Host: beacon.example.org\r\n", "Host: beacon.example.org\r\nHost: other\r\n", "two Host headers"},
        {"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
         "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "two keys"},
    };
    for (const Case& c : cases)
    {
        check(parse_text(edited(c.from, c.to), &h) == BeaconWsParse::INVALID, c.what);
    }
    // obs-text in a value is allowed.
    check(parse_text(edited("Pragma: no-cache", "Pragma: caf\xc3\xa9"), &h) == BeaconWsParse::OK, "UTF-8 in a value");

    // X-Forwarded-For: the last address of the last header.
    check(parse_text(edited("Pragma: no-cache", "X-Forwarded-For: 198.51.100.7"), &h) == BeaconWsParse::OK &&
              h.has_forwarded && h.forwarded.ip[10] == 0xff && h.forwarded.ip[12] == 198 && h.forwarded.ip[15] == 7,
          "X-Forwarded-For with one IPv4 address");
    check(parse_text(edited("Pragma: no-cache", "X-Forwarded-For: 10.0.0.1, 2001:db8::5"), &h) == BeaconWsParse::OK &&
              h.has_forwarded && h.forwarded.ip[0] == 0x20 && h.forwarded.ip[15] == 5,
          "X-Forwarded-For list: the last one, IPv6");
    check(parse_text(edited("Pragma: no-cache\r\n", "X-Forwarded-For: 1.2.3.4\r\nx-forwarded-for: 5.6.7.8\r\n"), &h) ==
                  BeaconWsParse::OK &&
              h.has_forwarded && h.forwarded.ip[12] == 5,
          "two X-Forwarded-For headers: the last one");
    check(parse_text(edited("Pragma: no-cache", "X-Forwarded-For: unknown"), &h) == BeaconWsParse::OK &&
              !h.has_forwarded,
          "an X-Forwarded-For that isn't an address is ignored");
    check(parse_text(edited("Pragma: no-cache", "X-Forwarded-For: [2001:db8::1]:443"), &h) == BeaconWsParse::OK &&
              !h.has_forwarded,
          "a bracketed address with a port is not taken");
}

// A masked client frame.
static std::string client_frame(uint8_t first, const std::string& payload)
{
    std::string frame;
    frame += static_cast<char>(first);
    if (payload.size() <= 125)
    {
        frame += static_cast<char>(0x80 | payload.size());
    }
    else
    {
        frame += static_cast<char>(0x80 | 126);
        frame += static_cast<char>(payload.size() >> 8);
        frame += static_cast<char>(payload.size() & 0xff);
    }
    const uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
    frame.append(reinterpret_cast<const char*>(mask), 4);
    for (size_t i = 0; i < payload.size(); i++)
    {
        frame += static_cast<char>(payload[i] ^ static_cast<char>(mask[i & 3]));
    }
    return frame;
}

static BeaconWsParse parse_frame(std::string frame, BeaconWsFrame* out, std::string* payload)
{
    BeaconWsParse result =
        beacon_ws_parse_frame(reinterpret_cast<uint8_t*>(frame.data()), frame.size(), out);
    if (result == BeaconWsParse::OK && payload != nullptr)
    {
        *payload = frame.substr(out->payload_offset, out->payload_size);
    }
    return result;
}

static void test_frames()
{
    BeaconWsFrame f;
    std::string payload;
    std::string frame = client_frame(0x82, "hello");
    check(parse_frame(frame, &f, &payload) == BeaconWsParse::OK && f.opcode == BeaconWsOpcode::BINARY &&
              payload == "hello" && f.size == frame.size(),
          "a small binary frame unmasks");
    std::string big(BEACON_WS_MAX_PAYLOAD, 'z');
    big[0] = 'a';
    frame = client_frame(0x82, big);
    check(parse_frame(frame, &f, &payload) == BeaconWsParse::OK && payload == big && f.payload_offset == 8,
          "the largest payload, 16-bit length");
    for (size_t cut = 0; cut < frame.size(); cut += 97)
    {
        check(parse_frame(frame.substr(0, cut), &f, nullptr) == BeaconWsParse::INCOMPLETE, "a partial frame");
    }
    check(parse_frame(frame + "\x82", &f, nullptr) == BeaconWsParse::OK && f.size == frame.size(),
          "the next frame's bytes are left alone");
    check(parse_frame(client_frame(0x82, ""), &f, nullptr) == BeaconWsParse::OK && f.payload_size == 0,
          "an empty binary frame");

    frame = client_frame(0x82, big + "x");
    check(parse_frame(frame, &f, nullptr) == BeaconWsParse::INVALID && f.error_code == BEACON_WS_CLOSE_TOO_BIG,
          "one byte over the payload limit");
    std::string long_form = "\x82\xff";
    check(parse_frame(long_form, &f, nullptr) == BeaconWsParse::INVALID && f.error_code == BEACON_WS_CLOSE_TOO_BIG,
          "the 64-bit length form");
    std::string non_minimal = std::string("\x82\xfe\x00\x05", 4) + "MASK" + "hello";
    check(parse_frame(non_minimal, &f, nullptr) == BeaconWsParse::INVALID, "a 16-bit length under 126");
    check(parse_frame(client_frame(0x81, "hi"), &f, nullptr) == BeaconWsParse::INVALID &&
              f.error_code == BEACON_WS_CLOSE_UNSUPPORTED,
          "a text frame");
    check(parse_frame(client_frame(0x02, "hi"), &f, nullptr) == BeaconWsParse::INVALID &&
              f.error_code == BEACON_WS_CLOSE_PROTOCOL_ERROR,
          "a frame without FIN");
    check(parse_frame(client_frame(0x80, "hi"), &f, nullptr) == BeaconWsParse::INVALID, "a continuation frame");
    check(parse_frame(client_frame(0xc2, "hi"), &f, nullptr) == BeaconWsParse::INVALID, "RSV1 (compression)");
    check(parse_frame(client_frame(0x83, "hi"), &f, nullptr) == BeaconWsParse::INVALID, "a reserved opcode");
    std::string unmasked = "\x82\x02hi";
    check(parse_frame(unmasked, &f, nullptr) == BeaconWsParse::INVALID, "an unmasked frame");

    check(parse_frame(client_frame(0x89, "ping"), &f, &payload) == BeaconWsParse::OK &&
              f.opcode == BeaconWsOpcode::PING && payload == "ping",
          "ping");
    check(parse_frame(client_frame(0x8a, ""), &f, nullptr) == BeaconWsParse::OK && f.opcode == BeaconWsOpcode::PONG,
          "pong");
    check(parse_frame(client_frame(0x89, std::string(126, 'p')), &f, nullptr) == BeaconWsParse::INVALID,
          "a control frame over 125 bytes");
    check(parse_frame(client_frame(0x88, std::string("\x03\xe8" "bye", 5)), &f, nullptr) == BeaconWsParse::OK &&
              f.opcode == BeaconWsOpcode::CLOSE && f.close_code == 1000,
          "close with a code");
    check(parse_frame(client_frame(0x88, ""), &f, nullptr) == BeaconWsParse::OK && f.close_code == 0,
          "close without a code");
    check(parse_frame(client_frame(0x88, "x"), &f, nullptr) == BeaconWsParse::INVALID, "close with 1 byte");

    uint8_t header[BEACON_WS_MAX_SERVER_HEADER];
    check(beacon_ws_frame_header(BeaconWsOpcode::BINARY, 5, header) == 2 && header[0] == 0x82 && header[1] == 5,
          "server header, 7-bit length, unmasked");
    check(beacon_ws_frame_header(BeaconWsOpcode::BINARY, 126, header) == 4 && header[1] == 126 && header[2] == 0 &&
              header[3] == 126,
          "server header, 16-bit length");
    check(beacon_ws_frame_header(BeaconWsOpcode::BINARY, BEACON_WS_MAX_PAYLOAD + 1, header) == 0,
          "server header over the limit");
    check(beacon_ws_frame_header(BeaconWsOpcode::PING, 126, header) == 0, "server control frame over 125");
}

int main()
{
    test_sha1_base64();
    test_handshake();
    test_frames();
    if (g_failures != 0)
    {
        fprintf(stderr, "%u failures\n", g_failures);
        return 1;
    }
    printf("ws: all checks passed\n");
    return 0;
}
