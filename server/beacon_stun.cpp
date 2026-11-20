// beacon_stun: see beacon_stun.h. Integers in STUN are big-endian.

#include "beacon_stun.h"

#include <cstring>

static constexpr uint16_t BINDING_REQUEST = 0x0001;
static constexpr uint16_t BINDING_SUCCESS = 0x0101;
static constexpr uint16_t XOR_MAPPED_ADDRESS = 0x0020;
static constexpr uint8_t FAMILY_IPV4 = 0x01;
static constexpr uint8_t FAMILY_IPV6 = 0x02;

static uint16_t read_u16(const uint8_t* at)
{
    return static_cast<uint16_t>((static_cast<uint32_t>(at[0]) << 8) | at[1]);
}

static uint32_t read_u32(const uint8_t* at)
{
    return (static_cast<uint32_t>(at[0]) << 24) | (static_cast<uint32_t>(at[1]) << 16) |
           (static_cast<uint32_t>(at[2]) << 8) | at[3];
}

static void write_u16(uint8_t* at, uint16_t value)
{
    at[0] = static_cast<uint8_t>(value >> 8);
    at[1] = static_cast<uint8_t>(value & 0xffu);
}

static void write_u32(uint8_t* at, uint32_t value)
{
    at[0] = static_cast<uint8_t>(value >> 24);
    at[1] = static_cast<uint8_t>((value >> 16) & 0xffu);
    at[2] = static_cast<uint8_t>((value >> 8) & 0xffu);
    at[3] = static_cast<uint8_t>(value & 0xffu);
}

bool beacon_stun_looks_like_stun(const uint8_t* data, size_t size)
{
    return size >= 1 && (data[0] & 0xc0u) == 0;
}

bool beacon_stun_parse_request(const uint8_t* data, size_t size, uint8_t transaction[BEACON_STUN_TRANSACTION_SIZE])
{
    if (size < BEACON_STUN_HEADER_SIZE || size > BEACON_STUN_MAX_REQUEST_SIZE || size % 4 != 0)
    {
        return false;
    }
    if (read_u16(data) != BINDING_REQUEST || read_u32(data + 4) != BEACON_STUN_MAGIC_COOKIE ||
        read_u16(data + 2) != size - BEACON_STUN_HEADER_SIZE)
    {
        return false;
    }
    // The attributes must tile the body exactly. Every step moves forward by
    // at least 4 bytes and is checked against the end before it's taken.
    size_t at = BEACON_STUN_HEADER_SIZE;
    while (at < size)
    {
        if (size - at < 4)
        {
            return false;
        }
        size_t length = read_u16(data + at + 2);
        size_t padded = (length + 3u) & ~static_cast<size_t>(3);
        if (padded > size - at - 4)
        {
            return false;
        }
        at += 4 + padded;
    }
    memcpy(transaction, data + 8, BEACON_STUN_TRANSACTION_SIZE);
    return true;
}

size_t beacon_stun_encode_response(const uint8_t transaction[BEACON_STUN_TRANSACTION_SIZE],
                                   const BeaconAddress* mapped, uint8_t* out, size_t capacity)
{
    bool ipv4 = beacon_address_is_ipv4(mapped);
    size_t size = ipv4 ? BEACON_STUN_RESPONSE_IPV4_SIZE : BEACON_STUN_RESPONSE_IPV6_SIZE;
    if (capacity < size)
    {
        return 0;
    }
    memset(out, 0, size);
    write_u16(out, BINDING_SUCCESS);
    write_u16(out + 2, static_cast<uint16_t>(size - BEACON_STUN_HEADER_SIZE));
    write_u32(out + 4, BEACON_STUN_MAGIC_COOKIE);
    memcpy(out + 8, transaction, BEACON_STUN_TRANSACTION_SIZE);

    // XOR-MAPPED-ADDRESS: 0, family, port ^ the cookie's top 16 bits, address
    // ^ the cookie (IPv4) or ^ cookie || transaction id (IPv6).
    uint8_t* attribute = out + BEACON_STUN_HEADER_SIZE;
    write_u16(attribute, XOR_MAPPED_ADDRESS);
    write_u16(attribute + 2, static_cast<uint16_t>(ipv4 ? 8 : 20));
    attribute[5] = ipv4 ? FAMILY_IPV4 : FAMILY_IPV6;
    write_u16(attribute + 6, static_cast<uint16_t>(mapped->port ^ (BEACON_STUN_MAGIC_COOKIE >> 16)));
    // out + 4 .. out + 20 is cookie || transaction id: the XOR key.
    const uint8_t* key = out + 4;
    if (ipv4)
    {
        for (uint32_t i = 0; i < 4; i++)
        {
            attribute[8 + i] = static_cast<uint8_t>(mapped->ip[12 + i] ^ key[i]);
        }
    }
    else
    {
        for (uint32_t i = 0; i < 16; i++)
        {
            attribute[8 + i] = static_cast<uint8_t>(mapped->ip[i] ^ key[i]);
        }
    }
    return size;
}
