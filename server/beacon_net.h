#pragma once

// beacon_net: the server's two UDP sockets (Linux). Each is one dual-stack
// IPv6 socket that also takes IPv4 (as ::ffff:a.b.c.d), unless the bind
// address is an IPv4 one or the machine has no IPv6 (then plain IPv4).

#include "beacon_server.h"

#include <cstdint>
#include <sys/socket.h>

struct BeaconNet
{
    int primary_fd = -1;
    int secondary_fd = -1;          // -1 when the secondary port is off
    int primary_family = 0;         // AF_INET6 or AF_INET
    int secondary_family = 0;
    uint16_t primary_port = 0;      // the bound ports (useful when 0 asked for any)
    uint16_t secondary_port = 0;
    uint64_t send_errors = 0;
    uint64_t oversized = 0;         // packets larger than any message (dropped before decoding)
};

// `bind_address` is a numeric IPv6 or IPv4 address ("::" for every address).
// Port 0 picks a free port; `secondary_port` -1 means no secondary socket.
bool beacon_net_open(BeaconNet* net, const char* bind_address, uint16_t primary_port,
                         int32_t secondary_port);
void beacon_net_close(BeaconNet* net);

// Reads up to `max_packets` waiting packets from one socket (without
// blocking), runs each through the server and sends its replies. Returns how
// many packets it read.
uint32_t beacon_net_drain(BeaconNet* net, BeaconServer* server, uint64_t now_ms,
                              BeaconSocket which, uint32_t max_packets);

// Address conversions (IPv4 becomes ::ffff:a.b.c.d). from_sockaddr fails for
// any family other than AF_INET / AF_INET6; to_sockaddr fails for an IPv6
// address on an IPv4 socket.
bool beacon_address_from_sockaddr(const sockaddr_storage* storage, BeaconAddress* out);
bool beacon_address_to_sockaddr(const BeaconAddress* address, int socket_family, sockaddr_storage* storage,
                                    socklen_t* length);

// CLOCK_MONOTONIC in milliseconds.
uint64_t beacon_now_ms();
