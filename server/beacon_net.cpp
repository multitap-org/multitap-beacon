#include "beacon_net.h"

#include "beacon_log.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <netinet/in.h>
#include <unistd.h>

// Bigger than any message and any STUN request we accept, so anything that
// fills it is known to be oversized (MSG_TRUNC makes recvfrom return the real
// length).
static constexpr size_t RECEIVE_BUFFER_SIZE = 576;
static_assert(RECEIVE_BUFFER_SIZE > BEACON_MAX_MESSAGE_SIZE, "receive buffer");
static_assert(RECEIVE_BUFFER_SIZE > BEACON_STUN_MAX_REQUEST_SIZE, "receive buffer");

uint64_t beacon_now_ms()
{
    timespec now = {};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return static_cast<uint64_t>(now.tv_sec) * 1000u + static_cast<uint64_t>(now.tv_nsec) / 1000000u;
}

bool beacon_address_from_sockaddr(const sockaddr_storage* storage, BeaconAddress* out)
{
    *out = BeaconAddress{};
    if (storage->ss_family == AF_INET6)
    {
        sockaddr_in6 address = {};
        memcpy(&address, storage, sizeof(address));
        memcpy(out->ip, &address.sin6_addr, 16);
        out->port = ntohs(address.sin6_port);
        return true;
    }
    if (storage->ss_family == AF_INET)
    {
        sockaddr_in address = {};
        memcpy(&address, storage, sizeof(address));
        out->ip[10] = 0xff;
        out->ip[11] = 0xff;
        memcpy(out->ip + 12, &address.sin_addr, 4);
        out->port = ntohs(address.sin_port);
        return true;
    }
    return false;
}

bool beacon_address_to_sockaddr(const BeaconAddress* address, int socket_family, sockaddr_storage* storage,
                                    socklen_t* length)
{
    memset(storage, 0, sizeof(*storage));
    if (socket_family == AF_INET6)
    {
        sockaddr_in6 out = {};
        out.sin6_family = AF_INET6;
        out.sin6_port = htons(address->port);
        memcpy(&out.sin6_addr, address->ip, 16);
        memcpy(storage, &out, sizeof(out));
        *length = sizeof(out);
        return true;
    }
    if (socket_family == AF_INET && beacon_address_is_ipv4(address))
    {
        sockaddr_in out = {};
        out.sin_family = AF_INET;
        out.sin_port = htons(address->port);
        memcpy(&out.sin_addr, address->ip + 12, 4);
        memcpy(storage, &out, sizeof(out));
        *length = sizeof(out);
        return true;
    }
    return false;
}

// Opens and binds one socket; returns the fd or -1.
static int open_socket(const char* bind_address, uint16_t port, int* family_out, uint16_t* bound_port)
{
    sockaddr_storage storage = {};
    socklen_t length = 0;
    int family = 0;
    in6_addr ip6 = {};
    in_addr ip4 = {};
    if (inet_pton(AF_INET6, bind_address, &ip6) == 1)
    {
        sockaddr_in6 address = {};
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(port);
        address.sin6_addr = ip6;
        memcpy(&storage, &address, sizeof(address));
        length = sizeof(address);
        family = AF_INET6;
    }
    else if (inet_pton(AF_INET, bind_address, &ip4) == 1)
    {
        sockaddr_in address = {};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr = ip4;
        memcpy(&storage, &address, sizeof(address));
        length = sizeof(address);
        family = AF_INET;
    }
    else
    {
        beacon_log(BeaconLogLevel::error, "bind address '%s' is not a numeric IPv6 or IPv4 address",
                       bind_address);
        return -1;
    }

    int fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 && family == AF_INET6 && errno == EAFNOSUPPORT && strcmp(bind_address, "::") == 0)
    {
        // A machine with IPv6 turned off: serve IPv4 alone.
        beacon_log(BeaconLogLevel::warning, "no IPv6 on this machine: listening on IPv4 only");
        return open_socket("0.0.0.0", port, family_out, bound_port);
    }
    if (fd < 0)
    {
        beacon_log(BeaconLogLevel::error, "socket: %s", strerror(errno));
        return -1;
    }
    if (family == AF_INET6)
    {
        // Dual-stack: IPv4 arrives on this socket as ::ffff:a.b.c.d. Some
        // systems default to IPv6 only, so it's set explicitly.
        int v6only = 0;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0)
        {
            beacon_log(BeaconLogLevel::warning, "IPV6_V6ONLY off failed (%s): IPv4 may not work",
                           strerror(errno));
        }
    }
    // A larger receive buffer rides out bursts while the loop is busy; the
    // kernel caps it at net.core.rmem_max, which is fine.
    int buffer = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer));

    if (bind(fd, reinterpret_cast<const sockaddr*>(&storage), length) != 0)
    {
        beacon_log(BeaconLogLevel::error, "bind to [%s]:%u: %s", bind_address, static_cast<unsigned>(port),
                       strerror(errno));
        close(fd);
        return -1;
    }
    sockaddr_storage bound = {};
    socklen_t bound_length = sizeof(bound);
    BeaconAddress bound_address = {};
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_length) != 0 ||
        !beacon_address_from_sockaddr(&bound, &bound_address))
    {
        beacon_log(BeaconLogLevel::error, "getsockname: %s", strerror(errno));
        close(fd);
        return -1;
    }
    *bound_port = bound_address.port;
    *family_out = family;
    return fd;
}

bool beacon_net_open(BeaconNet* net, const char* bind_address, uint16_t primary_port,
                         int32_t secondary_port, int32_t stun_port)
{
    *net = BeaconNet{};
    net->primary_fd = open_socket(bind_address, primary_port, &net->primary_family, &net->primary_port);
    if (net->primary_fd < 0)
    {
        return false;
    }
    if (secondary_port >= 0)
    {
        net->secondary_fd = open_socket(bind_address, static_cast<uint16_t>(secondary_port), &net->secondary_family,
                                        &net->secondary_port);
        if (net->secondary_fd < 0)
        {
            beacon_net_close(net);
            return false;
        }
    }
    if (stun_port >= 0)
    {
        net->stun_fd = open_socket(bind_address, static_cast<uint16_t>(stun_port), &net->stun_family, &net->stun_port);
        if (net->stun_fd < 0)
        {
            beacon_net_close(net);
            return false;
        }
    }
    return true;
}

void beacon_net_close(BeaconNet* net)
{
    if (net->primary_fd >= 0)
    {
        close(net->primary_fd);
    }
    if (net->secondary_fd >= 0)
    {
        close(net->secondary_fd);
    }
    if (net->stun_fd >= 0)
    {
        close(net->stun_fd);
    }
    *net = BeaconNet{};
}

static int socket_fd(const BeaconNet* net, BeaconSocket which, int* family)
{
    switch (which)
    {
        case BeaconSocket::PRIMARY:
            *family = net->primary_family;
            return net->primary_fd;
        case BeaconSocket::SECONDARY:
            *family = net->secondary_family;
            return net->secondary_fd;
        case BeaconSocket::STUN:
            *family = net->stun_family;
            return net->stun_fd;
    }
    *family = 0;
    return -1;
}

static void send_packet(BeaconNet* net, const BeaconOutPacket* packet)
{
    int family = 0;
    int fd = socket_fd(net, packet->socket, &family);
    sockaddr_storage to = {};
    socklen_t length = 0;
    if (fd < 0 || !beacon_address_to_sockaddr(&packet->to, family, &to, &length))
    {
        net->send_errors++;
        return;
    }
    // A full send buffer drops the packet, as the network could: the peers retry.
    ssize_t sent = sendto(fd, packet->data, packet->size, MSG_DONTWAIT, reinterpret_cast<const sockaddr*>(&to), length);
    if (sent < 0)
    {
        net->send_errors++;
    }
}

uint32_t beacon_net_drain(BeaconNet* net, BeaconServer* server, uint64_t now_ms,
                              BeaconSocket which, uint32_t max_packets)
{
    int family = 0;
    int fd = socket_fd(net, which, &family);
    if (fd < 0)
    {
        return 0;
    }
    uint8_t buffer[RECEIVE_BUFFER_SIZE];
    BeaconOutbox outbox;
    uint32_t handled = 0;
    while (handled < max_packets)
    {
        sockaddr_storage from_storage = {};
        socklen_t from_length = sizeof(from_storage);
        ssize_t got = recvfrom(fd, buffer, sizeof(buffer), MSG_DONTWAIT | MSG_TRUNC,
                               reinterpret_cast<sockaddr*>(&from_storage), &from_length);
        if (got < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            // EAGAIN: nothing left. Anything else (an ICMP error reported on
            // the socket) isn't about the next packet: stop this round.
            break;
        }
        handled++;
        BeaconAddress from = {};
        if (!beacon_address_from_sockaddr(&from_storage, &from))
        {
            continue;
        }
        // With MSG_TRUNC `got` is the real size; one that didn't fit can't be
        // a message, and only the bytes in the buffer may be read.
        size_t size = static_cast<size_t>(got);
        if (size > sizeof(buffer))
        {
            net->oversized++;
            size = 0;
        }
        beacon_server_receive(server, now_ms, which, &from, buffer, size, &outbox);
        for (uint32_t i = 0; i < outbox.count; i++)
        {
            send_packet(net, &outbox.packets[i]);
        }
    }
    return handled;
}
