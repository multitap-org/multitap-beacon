#pragma once

// beacon_ws: the WebSocket subset beacon speaks (RFC 6455), as pure functions
// over byte buffers (no sockets), so they can be tested and fuzzed alone.
// beacon_signal does the connections.
//
// Strict subset; anything else is refused:
// - Handshake: "GET <path> HTTP/1.1", headers with no folding and no control
//   characters, at most BEACON_WS_MAX_HANDSHAKE bytes. Required: Host,
//   `Upgrade: websocket`, a Connection list with `upgrade`,
//   `Sec-WebSocket-Version: 13`, a Sec-WebSocket-Key of 24 base64 characters
//   (16 bytes), and the subprotocol `multitap-beacon.1` in
//   Sec-WebSocket-Protocol. The path is ignored (the proxy picks it). Header
//   names are case-insensitive; the ones beacon needs may appear only once.
// - Frames from the client: FIN set (no fragmentation), RSV bits clear (no
//   extensions), masked, opcode binary / close / ping / pong (text and
//   continuation are refused), length in the 7-bit or 16-bit form at its
//   minimal encoding (the 64-bit form is refused), payload at most
//   BEACON_WS_MAX_PAYLOAD; control frames at most 125 bytes, a close payload
//   0 or >= 2 bytes.
// - Frames from beacon: unmasked, FIN set.

#include "beacon_wire.h"

#include <cstddef>
#include <cstdint>

constexpr size_t BEACON_WS_MAX_HANDSHAKE = 4096;
// The largest message: SIGNAL = header (8) + room (16) + blob (4096).
constexpr size_t BEACON_WS_MAX_PAYLOAD = 8 + 16 + 4096;
// Frame header from a client: 2 + 2 (16-bit length) + 4 (mask).
constexpr size_t BEACON_WS_MAX_CLIENT_HEADER = 8;
// Frame header from beacon: 2 + 2 (16-bit length), no mask.
constexpr size_t BEACON_WS_MAX_SERVER_HEADER = 4;
constexpr size_t BEACON_WS_ACCEPT_SIZE = 28;      // base64 of a SHA-1
constexpr size_t BEACON_WS_KEY_SIZE = 24;         // base64 of 16 bytes
constexpr size_t BEACON_SHA1_SIZE = 20;

enum class BeaconWsOpcode : uint8_t
{
    CONTINUATION = 0x0,
    TEXT = 0x1,
    BINARY = 0x2,
    CLOSE = 0x8,
    PING = 0x9,
    PONG = 0xA,
};

// Close codes beacon sends.
constexpr uint16_t BEACON_WS_CLOSE_NORMAL = 1000;
constexpr uint16_t BEACON_WS_CLOSE_GOING_AWAY = 1001;
constexpr uint16_t BEACON_WS_CLOSE_PROTOCOL_ERROR = 1002;
constexpr uint16_t BEACON_WS_CLOSE_UNSUPPORTED = 1003;     // a text frame
constexpr uint16_t BEACON_WS_CLOSE_POLICY = 1008;          // a limit (3b)
constexpr uint16_t BEACON_WS_CLOSE_TOO_BIG = 1009;

enum class BeaconWsParse : uint8_t
{
    INCOMPLETE,     // valid so far, more bytes needed
    INVALID,
    OK,
};

struct BeaconWsHandshake
{
    size_t size = 0;                            // bytes of the request, the final CRLF CRLF included
    char accept[BEACON_WS_ACCEPT_SIZE + 1] = {};  // Sec-WebSocket-Accept for the response
    // The client's address as the proxy saw it: the last address of the last
    // X-Forwarded-For header, if there's one and it parses (beacon decides
    // whether to trust it: --trusted-proxy).
    bool has_forwarded = false;
    BeaconAddress forwarded = {};
};

struct BeaconWsFrame
{
    BeaconWsOpcode opcode = BeaconWsOpcode::BINARY;
    size_t size = 0;                // the whole frame, header included
    size_t payload_offset = 0;      // the payload, already unmasked in place
    size_t payload_size = 0;
    uint16_t close_code = 0;        // in a close frame with a payload (0: none)
    uint16_t error_code = 0;        // INVALID: the close code to answer with
};

// SHA-1 (RFC 3174), only for the handshake's accept key.
void beacon_sha1(const uint8_t* data, size_t size, uint8_t out[BEACON_SHA1_SIZE]);

// Standard base64 with padding. `out` needs 4 * ((size + 2) / 3) + 1 bytes;
// it's NUL-terminated. Returns the length without the NUL.
size_t beacon_base64_encode(const uint8_t* data, size_t size, char* out);

// Sec-WebSocket-Accept for a Sec-WebSocket-Key (RFC 6455, 4.2.2):
// base64(SHA-1(key || "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")).
void beacon_ws_accept_key(const char key[BEACON_WS_KEY_SIZE], char out[BEACON_WS_ACCEPT_SIZE + 1]);

// The client's opening handshake at the start of `data`. INCOMPLETE until the
// blank line arrives (INVALID past BEACON_WS_MAX_HANDSHAKE bytes).
BeaconWsParse beacon_ws_parse_handshake(const uint8_t* data, size_t size, BeaconWsHandshake* out);

// The 101 response for a parsed handshake. Returns its length, 0 if it
// doesn't fit.
size_t beacon_ws_handshake_response(const BeaconWsHandshake* handshake, char* out, size_t capacity);

// The 400 response for a refused handshake (then the connection closes).
size_t beacon_ws_bad_request_response(char* out, size_t capacity);

// One client frame at the start of `data`. On OK the payload is unmasked in
// place (so `data` is changed) and `out` describes it.
BeaconWsParse beacon_ws_parse_frame(uint8_t* data, size_t size, BeaconWsFrame* out);

// A server frame header for `payload_size` bytes. Returns its size (2 or 4),
// 0 if the size is over BEACON_WS_MAX_PAYLOAD (or over 125 for a control frame).
size_t beacon_ws_frame_header(BeaconWsOpcode opcode, size_t payload_size, uint8_t out[BEACON_WS_MAX_SERVER_HEADER]);
