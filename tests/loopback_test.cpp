// End to end over real UDP sockets on loopback: the server's three dual-stack
// sockets, a fake host on 127.0.0.1 (IPv4, arrives as ::ffff:127.0.0.1) and a
// fake client on ::1 when the machine has IPv6 (127.0.0.1 otherwise).
// Single-threaded: after each send the test lets the server drain its sockets.

#include "beacon_net.h"
#include "beacon_server.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

static uint32_t g_failures = 0;

static void check(bool ok, const char* what)
{
    if (!ok)
    {
        fprintf(stderr, "FAIL: %s\n", what);
        g_failures++;
    }
}

struct Peer
{
    int fd = -1;
    int family = 0;
    BeaconAddress address = {};  // as the server will see it
};

static bool peer_open(Peer* peer, int family)
{
    *peer = Peer{};
    peer->fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (peer->fd < 0)
    {
        return false;
    }
    sockaddr_storage storage = {};
    socklen_t length = 0;
    BeaconAddress loopback = {};
    if (family == AF_INET6)
    {
        loopback.ip[15] = 1;
    }
    else
    {
        loopback.ip[10] = 0xff;
        loopback.ip[11] = 0xff;
        loopback.ip[12] = 127;
        loopback.ip[15] = 1;
    }
    beacon_address_to_sockaddr(&loopback, family, &storage, &length);
    if (bind(peer->fd, reinterpret_cast<const sockaddr*>(&storage), length) != 0)
    {
        close(peer->fd);
        peer->fd = -1;
        return false;
    }
    sockaddr_storage bound = {};
    socklen_t bound_length = sizeof(bound);
    getsockname(peer->fd, reinterpret_cast<sockaddr*>(&bound), &bound_length);
    beacon_address_from_sockaddr(&bound, &peer->address);
    peer->family = family;
    return true;
}

static void peer_close(Peer* peer)
{
    if (peer->fd >= 0)
    {
        close(peer->fd);
    }
    *peer = Peer{};
}

// Sends raw bytes from `peer` to the server's `port` on loopback.
static void peer_send_raw(const Peer* peer, uint16_t port, const uint8_t* data, size_t size)
{
    BeaconAddress server = {};
    if (peer->family == AF_INET6)
    {
        server.ip[15] = 1;
    }
    else
    {
        server.ip[10] = 0xff;
        server.ip[11] = 0xff;
        server.ip[12] = 127;
        server.ip[15] = 1;
    }
    server.port = port;
    sockaddr_storage to = {};
    socklen_t length = 0;
    beacon_address_to_sockaddr(&server, peer->family, &to, &length);
    ssize_t sent = sendto(peer->fd, data, size, 0, reinterpret_cast<const sockaddr*>(&to), length);
    check(sent == static_cast<ssize_t>(size), "peer sends");
}

// Sends `message` from `peer` to the server's `port` on loopback.
static void peer_send(const Peer* peer, uint16_t port, const BeaconMessage* message)
{
    uint8_t packet[BEACON_MAX_MESSAGE_SIZE];
    uint32_t size = beacon_encode(message, packet, sizeof(packet));
    peer_send_raw(peer, port, packet, size);
}

// A STUN Binding Request to `port`, and the XOR-MAPPED-ADDRESS of the answer,
// decoded here independently of beacon_stun (RFC 5389, section 15.2).
static bool stun_exchange(const Peer* peer, BeaconNet* net, BeaconServer* server, uint16_t port, uint8_t seed,
                          BeaconAddress* mapped, size_t* response_size);

// Waits up to a second for one packet the server can read, then drains every socket.
static void server_pump(BeaconNet* net, BeaconServer* server)
{
    pollfd fds[3] = {
        pollfd{.fd = net->primary_fd, .events = POLLIN},
        pollfd{.fd = net->secondary_fd, .events = POLLIN},
        pollfd{.fd = net->stun_fd, .events = POLLIN},
    };
    poll(fds, 3, 1000);
    uint64_t now = beacon_now_ms();
    beacon_net_drain(net, server, now, BeaconSocket::PRIMARY, 64);
    beacon_net_drain(net, server, now, BeaconSocket::SECONDARY, 64);
    beacon_net_drain(net, server, now, BeaconSocket::STUN, 64);
}

static bool stun_exchange(const Peer* peer, BeaconNet* net, BeaconServer* server, uint16_t port, uint8_t seed,
                          BeaconAddress* mapped, size_t* response_size)
{
    uint8_t request[20] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42};
    for (uint32_t i = 8; i < 20; i++)
    {
        request[i] = static_cast<uint8_t>(seed + i);
    }
    peer_send_raw(peer, port, request, sizeof(request));
    server_pump(net, server);
    pollfd fd = {.fd = peer->fd, .events = POLLIN};
    if (poll(&fd, 1, 1000) <= 0)
    {
        return false;
    }
    uint8_t buffer[512];
    ssize_t got = recv(peer->fd, buffer, sizeof(buffer), 0);
    if (got < 32)
    {
        return false;
    }
    *response_size = static_cast<size_t>(got);
    // Success response, same cookie and transaction id, then XOR-MAPPED-ADDRESS.
    if (buffer[0] != 0x01 || buffer[1] != 0x01 || memcmp(buffer + 4, request + 4, 16) != 0 ||
        buffer[20] != 0x00 || buffer[21] != 0x20)
    {
        return false;
    }
    *mapped = BeaconAddress{};
    mapped->port = static_cast<uint16_t>(((buffer[26] << 8) | buffer[27]) ^ 0x2112);
    if (buffer[25] == 0x01 && got == 32)
    {
        mapped->ip[10] = 0xff;
        mapped->ip[11] = 0xff;
        for (uint32_t i = 0; i < 4; i++)
        {
            mapped->ip[12 + i] = static_cast<uint8_t>(buffer[28 + i] ^ buffer[4 + i]);
        }
        return true;
    }
    if (buffer[25] == 0x02 && got == 44)
    {
        for (uint32_t i = 0; i < 16; i++)
        {
            mapped->ip[i] = static_cast<uint8_t>(buffer[28 + i] ^ buffer[4 + i]);
        }
        return true;
    }
    return false;
}

// Waits up to `timeout_ms` for one message on `peer`.
static bool peer_receive(const Peer* peer, int timeout_ms, BeaconMessage* out)
{
    pollfd fd = {.fd = peer->fd, .events = POLLIN};
    if (poll(&fd, 1, timeout_ms) <= 0)
    {
        return false;
    }
    uint8_t buffer[512];
    ssize_t got = recv(peer->fd, buffer, sizeof(buffer), 0);
    if (got <= 0)
    {
        return false;
    }
    return beacon_decode(buffer, static_cast<size_t>(got), out);
}

static BeaconId make_id(uint8_t seed)
{
    BeaconId id;
    for (uint32_t i = 0; i < BEACON_ID_SIZE; i++)
    {
        id.bytes[i] = static_cast<uint8_t>(seed ^ (i * 17));
    }
    return id;
}

int main()
{
    BeaconServerConfig config = {};
    BeaconServer server;
    check(beacon_server_create(&server, &config, beacon_now_ms()), "server creates");
    BeaconNet net;
    if (!beacon_net_open(&net, "::", 0, 0, 0))
    {
        // No IPv6 at all: the IPv4 fallback.
        check(beacon_net_open(&net, "0.0.0.0", 0, 0, 0), "server sockets open");
    }
    bool server_has_ipv6 = net.primary_family == AF_INET6;

    Peer host;
    Peer client;
    check(peer_open(&host, AF_INET), "host socket on 127.0.0.1");
    bool client_ipv6 = server_has_ipv6 && peer_open(&client, AF_INET6);
    if (!client_ipv6)
    {
        check(peer_open(&client, AF_INET), "client socket on 127.0.0.1");
    }
    printf("loopback: server ports %u/%u, client on %s\n", static_cast<unsigned>(net.primary_port),
           static_cast<unsigned>(net.secondary_port), client_ipv6 ? "::1" : "127.0.0.1");

    // BIND on both ports reflects the same address (loopback has no NAT).
    BeaconMessage bind = {};
    bind.type = BeaconType::BIND;
    bind.nonce = 0x1111;
    BeaconMessage r;
    peer_send(&client, net.primary_port, &bind);
    server_pump(&net, &server);
    check(peer_receive(&client, 1000, &r) && r.type == BeaconType::BOUND && r.nonce == 0x1111,
          "BOUND from the primary port");
    check(beacon_address_equal(&r.address, &client.address), "BOUND reflects the client's address");
    bind.nonce = 0x2222;
    peer_send(&client, net.secondary_port, &bind);
    server_pump(&net, &server);
    check(peer_receive(&client, 1000, &r) && r.type == BeaconType::BOUND && r.nonce == 0x2222,
          "BOUND from the secondary port");
    check(beacon_address_equal(&r.address, &client.address), "same address from the secondary port");

    // The host registers: COOKIE first, then REGISTERED.
    BeaconMessage reg = {};
    reg.type = BeaconType::REGISTER;
    reg.nonce = 1;
    reg.id_count = 2;
    reg.ids[0] = make_id(1);
    reg.ids[1] = make_id(2);
    peer_send(&host, net.primary_port, &reg);
    server_pump(&net, &server);
    check(peer_receive(&host, 1000, &r) && r.type == BeaconType::COOKIE, "REGISTER without a cookie: COOKIE");
    memcpy(reg.cookie, r.cookie, BEACON_COOKIE_SIZE);
    reg.nonce = 2;
    peer_send(&host, net.primary_port, &reg);
    server_pump(&net, &server);
    check(peer_receive(&host, 1000, &r) && r.type == BeaconType::REGISTERED && r.id_count == 2,
          "REGISTER with the cookie: REGISTERED, 2 ids");

    // The client meets: both get each other's address.
    BeaconMessage meet = {};
    meet.type = BeaconType::MEET;
    meet.nonce = 0xabcdef;
    meet.ids[0] = make_id(2);
    peer_send(&client, net.primary_port, &meet);
    server_pump(&net, &server);
    BeaconMessage to_client;
    BeaconMessage to_host;
    check(peer_receive(&client, 1000, &to_client) && to_client.type == BeaconType::INTRO,
          "the client gets INTRO");
    check(peer_receive(&host, 1000, &to_host) && to_host.type == BeaconType::INTRO, "the host gets INTRO");
    check(beacon_address_equal(&to_client.address, &host.address), "the client has the host's address");
    check(beacon_address_equal(&to_host.address, &client.address), "the host has the client's address");
    check(to_client.nonce == 0xabcdef && to_host.nonce == 0xabcdef, "both INTROs carry the MEET's nonce");

    // Unknown id: NOT_FOUND, and nothing reaches the host.
    meet.nonce = 0x5555;
    meet.ids[0] = make_id(99);
    peer_send(&client, net.primary_port, &meet);
    server_pump(&net, &server);
    check(peer_receive(&client, 1000, &r) && r.type == BeaconType::NOT_FOUND && r.nonce == 0x5555,
          "an unknown id gets NOT_FOUND");
    check(!peer_receive(&host, 100, &r), "the host hears nothing about an unknown id");

    // A REGISTER with a made-up cookie stores nothing.
    reg.ids[0] = make_id(50);
    reg.id_count = 1;
    memset(reg.cookie, 0x42, BEACON_COOKIE_SIZE);
    peer_send(&client, net.primary_port, &reg);
    server_pump(&net, &server);
    check(peer_receive(&client, 1000, &r) && r.type == BeaconType::COOKIE, "a forged cookie gets COOKIE");
    meet.ids[0] = make_id(50);
    peer_send(&host, net.primary_port, &meet);
    server_pump(&net, &server);
    check(peer_receive(&host, 1000, &r) && r.type == BeaconType::NOT_FOUND, "nothing stored without a cookie");

    // STUN on the primary port and on the STUN-only port: an IPv4 sender gets
    // its IPv4 address (32 bytes), an IPv6 one its IPv6 address (44 bytes).
    BeaconAddress mapped;
    size_t response_size = 0;
    check(stun_exchange(&host, &net, &server, net.primary_port, 1, &mapped, &response_size) &&
              response_size == 32 && beacon_address_equal(&mapped, &host.address),
          "STUN on the primary port answers the IPv4 host with its address");
    check(stun_exchange(&host, &net, &server, net.stun_port, 2, &mapped, &response_size) &&
              beacon_address_equal(&mapped, &host.address),
          "STUN on the STUN-only port");
    check(stun_exchange(&client, &net, &server, net.secondary_port, 3, &mapped, &response_size) &&
              response_size == (client_ipv6 ? 44u : 32u) && beacon_address_equal(&mapped, &client.address),
          "STUN on the secondary port, IPv6 when the client is on ::1");
    // The STUN-only port answers nothing else.
    bind.nonce = 0x3333;
    peer_send(&client, net.stun_port, &bind);
    server_pump(&net, &server);
    check(!peer_receive(&client, 100, &r), "BIND on the STUN-only port gets no reply");

    // An oversized packet and junk get nothing back.
    uint8_t big[1500] = {'M', 'T', 'B', 'C', 1, 1};
    sockaddr_storage to = {};
    socklen_t length = 0;
    BeaconAddress server_address = host.address;
    server_address.port = net.primary_port;
    beacon_address_to_sockaddr(&server_address, AF_INET, &to, &length);
    sendto(host.fd, big, sizeof(big), 0, reinterpret_cast<const sockaddr*>(&to), length);
    server_pump(&net, &server);
    check(!peer_receive(&host, 100, &r), "an oversized packet gets no reply");
    check(net.oversized == 1, "the oversized packet is counted");

    peer_close(&host);
    peer_close(&client);
    beacon_net_close(&net);
    beacon_server_destroy(&server);
    if (g_failures != 0)
    {
        fprintf(stderr, "%u failures\n", g_failures);
        return 1;
    }
    printf("loopback: all checks passed\n");
    return 0;
}
