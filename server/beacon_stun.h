#pragma once

// beacon_stun: the one STUN message beacon answers, a Binding Request
// (RFC 5389 / 8489), so browsers can use beacon as their STUN server
// (`stun:<beacon>:55430`). Strict: a request is accepted only if
// - it is 20..BEACON_STUN_MAX_REQUEST_SIZE bytes, a multiple of 4;
// - its type is exactly 0x0001 (Binding Request: indications, responses and
//   other methods are dropped) and it has the magic cookie (old RFC 3489
//   requests have none and are dropped);
// - its length field is the packet size minus the header;
// - its attributes fill the body exactly (each a 4-byte header plus its value
//   padded to 4 bytes, never past the end).
// What the attributes say is never looked at (no authentication: it's public
// STUN). There are no error responses: they would be larger than the request.
//
// The response carries one attribute, XOR-MAPPED-ADDRESS: 32 bytes for an
// IPv4 address (an IPv4-mapped one is answered as IPv4, family 0x01), 44 for
// IPv6.
//
// Telling STUN from beacon's own messages: STUN's first byte has its two top
// bits zero (RFC 7983: 0..3), "MTBC" starts with 0x4D.

#include "beacon_wire.h"

#include <cstddef>
#include <cstdint>

constexpr uint32_t BEACON_STUN_HEADER_SIZE = 20;
constexpr uint32_t BEACON_STUN_MAX_REQUEST_SIZE = 548;
constexpr uint32_t BEACON_STUN_TRANSACTION_SIZE = 12;
constexpr uint32_t BEACON_STUN_RESPONSE_IPV4_SIZE = 32;
constexpr uint32_t BEACON_STUN_RESPONSE_IPV6_SIZE = 44;
constexpr uint32_t BEACON_STUN_MAGIC_COOKIE = 0x2112A442u;

// Whether the packet is STUN-shaped at all (first byte 0..3), so it goes to
// beacon_stun_parse_request() rather than beacon_decode().
bool beacon_stun_looks_like_stun(const uint8_t* data, size_t size);

// A valid Binding Request: copies its transaction id and returns true.
bool beacon_stun_parse_request(const uint8_t* data, size_t size, uint8_t transaction[BEACON_STUN_TRANSACTION_SIZE]);

// The Binding Success Response for `transaction` with `mapped` as
// XOR-MAPPED-ADDRESS. Returns its size, or 0 if `capacity` is too small.
size_t beacon_stun_encode_response(const uint8_t transaction[BEACON_STUN_TRANSACTION_SIZE],
                                   const BeaconAddress* mapped, uint8_t* out, size_t capacity);
