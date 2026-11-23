// beacon_signal over real TCP sockets on loopback: the handshake, ping /
// pong, the close handshake, protocol errors, rooms (JOIN, PEER_JOINED,
// SIGNAL passed as is, replacement, LEAVE, LEFT on close, NOT_FOUND), room
// limits, rate limits, the per-source limit with X-Forwarded-For, a full
// pool, timeouts, a slow reader. Single-threaded: the test's blocking
// clients alternate with an epoll pump.

#include "beacon_net.h"
#include "beacon_signal.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/epoll.h>
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

struct Harness
{
    BeaconSignal signal;
    int epoll_fd = -1;
    uint64_t now = 1000000;
};

static bool harness_open(Harness* h, const BeaconSignalConfig* config)
{
    h->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    h->now = 1000000;
    return beacon_signal_open(&h->signal, config, "127.0.0.1", 0, h->epoll_fd);
}

static void harness_close(Harness* h)
{
    beacon_signal_close(&h->signal);
    close(h->epoll_fd);
}

// Hands every ready event to the signal module (waits up to `timeout_ms`).
static void pump(Harness* h, int timeout_ms)
{
    epoll_event events[16];
    int ready = epoll_wait(h->epoll_fd, events, 16, timeout_ms);
    for (int i = 0; i < ready; i++)
    {
        uint64_t tag = events[i].data.u64;
        if (tag == BEACON_SIGNAL_TAG_LISTEN)
        {
            beacon_signal_accept(&h->signal, h->now);
        }
        else if (tag >= BEACON_SIGNAL_TAG_FIRST_CONNECTION)
        {
            beacon_signal_event(&h->signal, static_cast<uint32_t>(tag - BEACON_SIGNAL_TAG_FIRST_CONNECTION),
                                events[i].events, h->now);
        }
    }
}

static void pump_a_while(Harness* h)
{
    for (int i = 0; i < 20; i++)
    {
        pump(h, 5);
    }
}

static int client_connect(Harness* h, int receive_buffer)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (receive_buffer > 0)
    {
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer));
    }
    sockaddr_in to = {};
    to.sin_family = AF_INET;
    to.sin_port = htons(h->signal.port);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, reinterpret_cast<const sockaddr*>(&to), sizeof(to)) != 0)
    {
        close(fd);
        return -1;
    }
    pump(h, 100);   // accept
    return fd;
}

static void client_send(Harness* h, int fd, const std::string& bytes)
{
    ssize_t sent = send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL);
    check(sent == static_cast<ssize_t>(bytes.size()), "client sends");
    pump(h, 50);
}

// Reads exactly `size` bytes (pumping the server while waiting), or until
// EOF / `rounds` x 10 ms. Returns what arrived.
static std::string client_read_for(Harness* h, int fd, size_t size, int rounds)
{
    std::string got;
    for (int round = 0; round < rounds && got.size() < size; round++)
    {
        pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 0) <= 0)
        {
            pump(h, 10);
            continue;
        }
        char buffer[16384];
        size_t want = size - got.size() < sizeof(buffer) ? size - got.size() : sizeof(buffer);
        ssize_t n = recv(fd, buffer, want, 0);
        if (n <= 0)
        {
            break;
        }
        got.append(buffer, static_cast<size_t>(n));
    }
    return got;
}

static std::string client_read(Harness* h, int fd, size_t size)
{
    return client_read_for(h, fd, size, 200);
}

// Whether nothing arrives for a little while.
static bool client_quiet(Harness* h, int fd)
{
    return client_read_for(h, fd, 1, 10).empty();
}

// Whether the server closed the connection (EOF within 2 s), reading past
// anything that comes before it.
static bool client_sees_eof(Harness* h, int fd)
{
    for (int round = 0; round < 400; round++)
    {
        pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 0) <= 0)
        {
            pump(h, 5);
            continue;
        }
        char buffer[16384];
        ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
        if (n == 0 || (n < 0 && errno == ECONNRESET))
        {
            return true;
        }
    }
    return false;
}

static std::string request(const char* extra_headers)
{
    return std::string("GET /signal HTTP/1.1\r\n"
                       "Host: localhost\r\n"
                       "Upgrade: websocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                       "Sec-WebSocket-Version: 13\r\n"
                       "Sec-WebSocket-Protocol: multitap-beacon.1\r\n") +
           extra_headers + "\r\n";
}

static const char RESPONSE[] =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
    "Sec-WebSocket-Protocol: multitap-beacon.1\r\n"
    "\r\n";

// Connects and handshakes; returns the socket, or -1 if the server didn't
// answer 101 (then `status` gets the start of what it answered).
static int client_open_with(Harness* h, const char* extra_headers, std::string* status)
{
    int fd = client_connect(h, 0);
    if (fd < 0)
    {
        return -1;
    }
    client_send(h, fd, request(extra_headers));
    std::string response = client_read(h, fd, sizeof(RESPONSE) - 1);
    if (response != RESPONSE)
    {
        if (status != nullptr)
        {
            *status = response.substr(0, 12);
        }
        close(fd);
        return -1;
    }
    return fd;
}

static int client_open(Harness* h)
{
    int fd = client_open_with(h, "", nullptr);
    check(fd >= 0, "the server answers 101 with the accept key and the subprotocol");
    return fd;
}

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
    const char mask[4] = {0x0a, 0x0b, 0x0c, 0x0d};
    frame.append(mask, 4);
    for (size_t i = 0; i < payload.size(); i++)
    {
        frame += static_cast<char>(payload[i] ^ mask[i & 3]);
    }
    return frame;
}

static std::string server_frame(uint8_t first, const std::string& payload)
{
    std::string frame;
    frame += static_cast<char>(first);
    if (payload.size() <= 125)
    {
        frame += static_cast<char>(payload.size());
    }
    else
    {
        frame += static_cast<char>(126);
        frame += static_cast<char>(payload.size() >> 8);
        frame += static_cast<char>(payload.size() & 0xff);
    }
    return frame + payload;
}

static BeaconId room_id(uint8_t seed)
{
    BeaconId id;
    for (uint32_t i = 0; i < BEACON_ID_SIZE; i++)
    {
        id.bytes[i] = static_cast<uint8_t>(seed * 31 + i + 1);
    }
    return id;
}

static std::string encode(const BeaconSignalingMessage* m)
{
    uint8_t bytes[BEACON_SIGNALING_MAX_SIZE];
    uint32_t size = beacon_signaling_encode(m, bytes, sizeof(bytes));
    return std::string(reinterpret_cast<const char*>(bytes), size);
}

static std::string join(uint8_t room, BeaconRole role)
{
    BeaconSignalingMessage m;
    m.type = BeaconSignalingType::JOIN;
    m.room = room_id(room);
    m.role = role;
    return client_frame(0x82, encode(&m));
}

static std::string leave(uint8_t room)
{
    BeaconSignalingMessage m;
    m.type = BeaconSignalingType::LEAVE;
    m.room = room_id(room);
    return client_frame(0x82, encode(&m));
}

static std::string signal_message(uint8_t room, const std::string& blob)
{
    BeaconSignalingMessage m;
    m.type = BeaconSignalingType::SIGNAL;
    m.room = room_id(room);
    m.blob = reinterpret_cast<const uint8_t*>(blob.data());
    m.blob_size = static_cast<uint32_t>(blob.size());
    return encode(&m);
}

// Reads one server binary frame and decodes it; `raw` gets its payload.
static bool read_message(Harness* h, int fd, BeaconSignalingMessage* out, std::string* raw)
{
    std::string head = client_read(h, fd, 2);
    if (head.size() != 2 || static_cast<uint8_t>(head[0]) != 0x82)
    {
        return false;
    }
    size_t length = static_cast<uint8_t>(head[1]);
    if (length == 126)
    {
        std::string extended = client_read(h, fd, 2);
        if (extended.size() != 2)
        {
            return false;
        }
        length = (static_cast<size_t>(static_cast<uint8_t>(extended[0])) << 8) | static_cast<uint8_t>(extended[1]);
    }
    *raw = client_read(h, fd, length);
    return raw->size() == length &&
           beacon_signaling_decode(reinterpret_cast<const uint8_t*>(raw->data()), raw->size(), out);
}

static bool expect(Harness* h, int fd, BeaconSignalingType type, uint8_t room)
{
    BeaconSignalingMessage m;
    std::string raw;
    BeaconId id = room_id(room);
    return read_message(h, fd, &m, &raw) && m.type == type && beacon_id_equal(&m.room, &id);
}

static bool expect_joined(Harness* h, int fd, uint8_t room, uint8_t present)
{
    BeaconSignalingMessage m;
    std::string raw;
    BeaconId id = room_id(room);
    return read_message(h, fd, &m, &raw) && m.type == BeaconSignalingType::JOINED && beacon_id_equal(&m.room, &id) &&
           m.peer_present == present;
}

static void test_websocket_basics()
{
    Harness h;
    BeaconSignalConfig config = {};
    config.max_connections = 4;
    check(harness_open(&h, &config), "signaling listener opens");

    int fd = client_open(&h);
    client_send(&h, fd, client_frame(0x89, "are you there"));
    check(client_read(&h, fd, 15) == server_frame(0x8a, "are you there"), "ping gets pong with its payload");
    client_send(&h, fd, client_frame(0x8a, ""));   // an unsolicited pong is ignored
    client_send(&h, fd, client_frame(0x88, std::string("\x03\xe8", 2)));
    check(client_read(&h, fd, 4) == server_frame(0x88, std::string("\x03\xe8", 2)), "close is echoed with its code");
    check(client_sees_eof(&h, fd), "then the server closes the socket");
    close(fd);

    // Protocol errors close with a code.
    struct Case
    {
        std::string frame;
        uint16_t code;
        const char* what;
    };
    BeaconSignalingMessage joined;
    joined.type = BeaconSignalingType::JOINED;
    joined.room = room_id(1);
    const Case cases[] = {
        {client_frame(0x81, "text"), 1003, "a text frame: close 1003"},
        {std::string("\x82\xff", 2), 1009, "a 64-bit length: close 1009"},
        {std::string("\x82\x02hi", 4), 1002, "an unmasked frame: close 1002"},
        {client_frame(0x82, "not a message"), 1002, "a binary message that isn't a signaling message: 1002"},
        {client_frame(0x82, encode(&joined)), 1002, "a server-only type from a client: 1002"},
    };
    for (const Case& c : cases)
    {
        fd = client_open(&h);
        client_send(&h, fd, c.frame);
        std::string expected = server_frame(0x88, std::string{static_cast<char>(c.code >> 8), static_cast<char>(c.code & 0xff)});
        check(client_read(&h, fd, 4) == expected, c.what);
        check(client_sees_eof(&h, fd), "and the socket closes");
        close(fd);
    }

    // A bad handshake gets 400; TLS on the plain port too.
    fd = client_connect(&h, 0);
    std::string bad = request("");
    bad.replace(bad.find("multitap-beacon.1"), 17, "chat");
    client_send(&h, fd, bad);
    check(client_read(&h, fd, 12) == "HTTP/1.1 400", "no subprotocol: 400");
    check(client_sees_eof(&h, fd), "and the socket closes");
    close(fd);
    fd = client_connect(&h, 0);
    client_send(&h, fd, "\x16\x03\x01");
    check(client_read(&h, fd, 12) == "HTTP/1.1 400", "TLS on the plain port: 400");
    close(fd);
    pump_a_while(&h);
    check(h.signal.stats.open == 0, "every connection was freed");

    // The pool holds 4: the fifth is closed at once.
    int fds[5];
    for (int i = 0; i < 4; i++)
    {
        fds[i] = client_open(&h);
    }
    fds[4] = client_connect(&h, 0);
    check(client_sees_eof(&h, fds[4]), "a connection over the pool is closed");
    check(h.signal.stats.refused_full == 1, "and counted");
    close(fds[4]);

    // Timeouts: one connection in the middle of its handshake, then idle ones.
    close(fds[3]);
    pump(&h, 50);
    fds[3] = client_connect(&h, 0);
    client_send(&h, fds[3], "GET / HTTP/1.1\r\nHost: x\r\n");
    h.now += BEACON_SIGNAL_HANDSHAKE_MS;
    beacon_signal_tick(&h.signal, h.now);
    check(client_sees_eof(&h, fds[3]), "an unfinished handshake times out");
    client_send(&h, fds[0], client_frame(0x89, ""));
    check(client_read(&h, fds[0], 2) == server_frame(0x8a, ""), "a ping keeps a connection alive");
    h.now += BEACON_SIGNAL_IDLE_MS - BEACON_SIGNAL_HANDSHAKE_MS;
    beacon_signal_tick(&h.signal, h.now);
    check(client_read(&h, fds[1], 4) == server_frame(0x88, std::string("\x03\xe9", 2)), "idle: close 1001");
    check(client_sees_eof(&h, fds[1]), "and the socket closes");
    client_send(&h, fds[0], client_frame(0x89, "alive"));
    check(client_read(&h, fds[0], 7) == server_frame(0x8a, "alive"), "the pinged connection is still open");
    for (int i = 0; i < 4; i++)
    {
        close(fds[i]);
    }
    pump_a_while(&h);
    check(h.signal.stats.open == 0, "every connection was freed at the end");
    harness_close(&h);
}

static void test_rooms()
{
    Harness h;
    BeaconSignalConfig config = {};
    config.message_burst = 200;
    check(harness_open(&h, &config), "signaling listener opens");
    int host = client_open(&h);
    int client = client_open(&h);

    client_send(&h, host, join(1, BeaconRole::HOST));
    check(expect_joined(&h, host, 1, 0), "the host joins an empty room");
    client_send(&h, client, join(1, BeaconRole::CLIENT));
    check(expect_joined(&h, client, 1, 1), "the client joins: the host is there");
    check(expect(&h, host, BeaconSignalingType::PEER_JOINED, 1), "the host hears PEER_JOINED");
    check(h.signal.stats.rooms == 1, "one room");

    // SIGNAL is passed along byte for byte, both ways, up to the largest blob.
    std::string offer = signal_message(1, "encrypted offer");
    client_send(&h, client, client_frame(0x82, offer));
    BeaconSignalingMessage m;
    std::string raw;
    check(read_message(&h, host, &m, &raw) && m.type == BeaconSignalingType::SIGNAL && raw == offer,
          "the host gets the client's SIGNAL as is");
    std::string answer = signal_message(1, std::string(BEACON_SIGNALING_MAX_BLOB, 'a'));
    client_send(&h, host, client_frame(0x82, answer));
    check(read_message(&h, client, &m, &raw) && raw == answer, "the client gets the host's largest SIGNAL");

    // The host's keepalive JOIN: JOINED again, nothing for the client.
    client_send(&h, host, join(1, BeaconRole::HOST));
    check(expect_joined(&h, host, 1, 1), "a repeated JOIN refreshes");
    check(client_quiet(&h, client), "the client hears nothing about a refresh");

    // A second client socket for the same side replaces the first.
    int client2 = client_open(&h);
    client_send(&h, client2, join(1, BeaconRole::CLIENT));
    check(expect_joined(&h, client2, 1, 1), "the new client socket joins");
    check(expect(&h, client, BeaconSignalingType::LEFT, 1), "the old one gets LEFT");
    check(expect(&h, host, BeaconSignalingType::PEER_JOINED, 1), "the host hears PEER_JOINED again");
    check(h.signal.stats.replaced == 1, "the replacement is counted");
    client_send(&h, client, client_frame(0x82, offer));
    check(expect(&h, client, BeaconSignalingType::NOT_FOUND, 1), "the replaced socket's SIGNAL: NOT_FOUND");
    check(client_quiet(&h, host), "and it doesn't reach the host");

    // LEAVE: the other side hears LEFT; SIGNAL after it: NOT_FOUND.
    client_send(&h, client2, leave(1));
    check(expect(&h, host, BeaconSignalingType::LEFT, 1), "LEAVE: the host gets LEFT");
    client_send(&h, client2, client_frame(0x82, offer));
    check(expect(&h, client2, BeaconSignalingType::NOT_FOUND, 1), "SIGNAL after LEAVE: NOT_FOUND");
    client_send(&h, host, client_frame(0x82, answer));
    check(expect(&h, host, BeaconSignalingType::NOT_FOUND, 1), "SIGNAL with no client: NOT_FOUND");

    // A client alone in a room: NOT_FOUND (the host is offline).
    client_send(&h, client, join(2, BeaconRole::CLIENT));
    check(expect_joined(&h, client, 2, 0), "a client joins a room with no host");
    client_send(&h, client, client_frame(0x82, signal_message(2, "offer")));
    check(expect(&h, client, BeaconSignalingType::NOT_FOUND, 2), "host offline: NOT_FOUND");
    client_send(&h, client, client_frame(0x82, signal_message(3, "offer")));
    check(expect(&h, client, BeaconSignalingType::NOT_FOUND, 3), "SIGNAL to a room never joined: NOT_FOUND");

    // Closing a socket: the other side hears LEFT; empty rooms are forgotten.
    client_send(&h, client2, join(1, BeaconRole::CLIENT));
    check(expect_joined(&h, client2, 1, 1), "the client joins again");
    check(expect(&h, host, BeaconSignalingType::PEER_JOINED, 1), "the host hears it");
    close(host);
    pump_a_while(&h);
    check(expect(&h, client2, BeaconSignalingType::LEFT, 1), "the host's socket closes: the client gets LEFT");
    check(h.signal.stats.rooms == 2, "rooms 1 (the client) and 2 are left");
    close(client2);
    close(client);
    pump_a_while(&h);
    check(h.signal.stats.rooms == 0 && h.signal.stats.open == 0, "every room and connection was freed");

    // One socket can't hold both sides of a room.
    int both = client_open(&h);
    client_send(&h, both, join(4, BeaconRole::HOST));
    check(expect_joined(&h, both, 4, 0), "host side joined");
    client_send(&h, both, join(4, BeaconRole::CLIENT));
    check(client_read(&h, both, 4) == server_frame(0x88, std::string("\x03\xf0", 2)), "both sides on one socket: 1008");
    close(both);

    // 64 rooms per socket.
    int many = client_open(&h);
    std::string joins;
    for (uint32_t i = 0; i < BEACON_SIGNAL_MAX_ROOMS_PER_CONNECTION; i++)
    {
        joins += join(static_cast<uint8_t>(10 + i), BeaconRole::HOST);
    }
    client_send(&h, many, joins);
    bool all = true;
    for (uint32_t i = 0; i < BEACON_SIGNAL_MAX_ROOMS_PER_CONNECTION; i++)
    {
        all = all && expect_joined(&h, many, static_cast<uint8_t>(10 + i), 0);
    }
    check(all, "64 rooms on one socket");
    client_send(&h, many, join(200, BeaconRole::HOST));
    check(read_message(&h, many, &m, &raw) && m.type == BeaconSignalingType::REFUSED &&
              m.reason == BeaconRefusal::ROOMS_PER_CONNECTION,
          "the 65th: REFUSED, too many rooms on this socket");
    close(many);
    pump_a_while(&h);
    check(h.signal.stats.rooms == 0, "its 64 rooms are forgotten when it closes");
    harness_close(&h);

    // The room table: max_rooms 2.
    config.max_rooms = 2;
    check(harness_open(&h, &config), "signaling listener opens");
    int a = client_open(&h);
    client_send(&h, a, join(1, BeaconRole::HOST) + join(2, BeaconRole::HOST) + join(3, BeaconRole::HOST));
    check(expect_joined(&h, a, 1, 0) && expect_joined(&h, a, 2, 0), "two rooms fit");
    check(read_message(&h, a, &m, &raw) && m.type == BeaconSignalingType::REFUSED &&
              m.reason == BeaconRefusal::ROOMS_FULL,
          "the third: REFUSED, room table full");
    client_send(&h, a, leave(2) + join(3, BeaconRole::HOST));
    check(expect_joined(&h, a, 3, 0), "after a LEAVE there's room again");
    close(a);
    harness_close(&h);
}

static void test_rate_limits()
{
    Harness h;
    BeaconSignalConfig config = {};
    config.message_burst = 5;
    check(harness_open(&h, &config), "signaling listener opens");
    int fd = client_open(&h);
    std::string pings;
    for (int i = 0; i < 6; i++)
    {
        pings += client_frame(0x89, "");
    }
    client_send(&h, fd, pings);
    std::string expected;
    for (int i = 0; i < 5; i++)
    {
        expected += server_frame(0x8a, "");
    }
    expected += server_frame(0x88, std::string("\x03\xf0", 2));
    check(client_read(&h, fd, expected.size()) == expected, "a burst of 5, the sixth message: close 1008");
    close(fd);

    // Bytes: a burst of 8 KiB lets two largest SIGNALs through, not three.
    harness_close(&h);
    config.message_burst = 60;
    config.byte_burst = 8500;
    check(harness_open(&h, &config), "signaling listener opens");
    int host = client_open(&h);
    int client = client_open(&h);
    client_send(&h, host, join(1, BeaconRole::HOST));
    client_send(&h, client, join(1, BeaconRole::CLIENT));
    check(expect_joined(&h, host, 1, 0) && expect_joined(&h, client, 1, 1), "both joined");
    std::string big = client_frame(0x82, signal_message(1, std::string(4000, 'x')));
    client_send(&h, client, big + big + big);
    BeaconSignalingMessage m;
    std::string raw;
    check(expect(&h, host, BeaconSignalingType::PEER_JOINED, 1), "the host heard PEER_JOINED");
    check(read_message(&h, host, &m, &raw) && read_message(&h, host, &m, &raw), "two big SIGNALs pass");
    check(client_read(&h, client, 4) == server_frame(0x88, std::string("\x03\xf0", 2)), "the third: close 1008");
    check(h.signal.stats.rate_limited == 1, "the rate limit is counted");
    close(host);
    close(client);
    harness_close(&h);
}

static void test_sources()
{
    // CIDR parsing and matching.
    BeaconCidr cidr;
    BeaconAddress inside = {};
    inside.ip[10] = 0xff;
    inside.ip[11] = 0xff;
    inside.ip[12] = 172;
    inside.ip[13] = 20;
    inside.ip[14] = 1;
    inside.ip[15] = 2;
    BeaconAddress outside = inside;
    outside.ip[13] = 32;
    check(beacon_cidr_parse("172.16.0.0/12", &cidr) && cidr.prefix == 108, "IPv4 /12 parses (as /108)");
    check(beacon_cidr_contains(&cidr, &inside) && !beacon_cidr_contains(&cidr, &outside), "172.16/12 matching");
    check(beacon_cidr_parse("172.20.1.2", &cidr) && cidr.prefix == 128 && beacon_cidr_contains(&cidr, &inside),
          "a bare IPv4 address is a /32");
    check(beacon_cidr_parse("fd00::/8", &cidr) && cidr.prefix == 8, "IPv6 /8 parses");
    check(!beacon_cidr_parse("172.16.0.0/33", &cidr), "/33 is refused for IPv4");
    check(!beacon_cidr_parse("fd00::/129", &cidr), "/129 is refused");
    check(!beacon_cidr_parse("example.org", &cidr), "a name is refused");
    check(!beacon_cidr_parse("10.0.0.0/", &cidr) && !beacon_cidr_parse("10.0.0.0/8x", &cidr), "a bad prefix");

    // Two connections per source. Behind the (loopback, so trusted) proxy,
    // the source is X-Forwarded-For's address; IPv6 counts by /64.
    Harness h;
    BeaconSignalConfig config = {};
    config.max_connections_per_source = 2;
    check(harness_open(&h, &config), "signaling listener opens");
    std::string status;
    int direct[2] = {client_open(&h), client_open(&h)};
    check(client_open_with(&h, "", &status) < 0 && status == "HTTP/1.1 429", "a third from 127.0.0.1: 429");
    int a1 = client_open_with(&h, "X-Forwarded-For: 198.51.100.1\r\n", nullptr);
    int a2 = client_open_with(&h, "X-Forwarded-For: 10.9.9.9, 198.51.100.1\r\n", nullptr);
    check(a1 >= 0 && a2 >= 0, "two from 198.51.100.1 behind the proxy");
    check(client_open_with(&h, "X-Forwarded-For: 198.51.100.1\r\n", &status) < 0 && status == "HTTP/1.1 429",
          "a third from 198.51.100.1: 429");
    int b1 = client_open_with(&h, "X-Forwarded-For: 198.51.100.2\r\n", nullptr);
    check(b1 >= 0, "another address is its own source");
    int c1 = client_open_with(&h, "X-Forwarded-For: 2001:db8:1:2::1\r\n", nullptr);
    int c2 = client_open_with(&h, "X-Forwarded-For: 2001:db8:1:2::ffff\r\n", nullptr);
    check(c1 >= 0 && c2 >= 0, "two from one IPv6 /64");
    check(client_open_with(&h, "X-Forwarded-For: 2001:db8:1:2:aaaa::1\r\n", &status) < 0 && status == "HTTP/1.1 429",
          "a third from the same /64: 429");
    int d1 = client_open_with(&h, "X-Forwarded-For: 2001:db8:1:3::1\r\n", nullptr);
    check(d1 >= 0, "the next /64 is another source");
    check(h.signal.stats.refused_source == 3, "429s are counted");
    int fds[] = {direct[0], direct[1], a1, a2, b1, c1, c2, d1};
    for (int fd : fds)
    {
        close(fd);
    }
    pump_a_while(&h);
    harness_close(&h);
}

static void test_slow_reader()
{
    // The host stops reading: once its buffers fill, it's closed, and the
    // client gets NOT_FOUND (and LEFT when the host is freed).
    Harness h;
    BeaconSignalConfig config = {};
    config.message_burst = 100000;
    config.messages_per_second = 100000;
    config.byte_burst = 100000000;
    config.bytes_per_second = 100000000;
    check(harness_open(&h, &config), "signaling listener opens");
    int host = client_connect(&h, 4096);
    client_send(&h, host, request(""));
    check(client_read(&h, host, sizeof(RESPONSE) - 1) == RESPONSE, "the host handshakes");
    int client = client_open(&h);
    client_send(&h, host, join(1, BeaconRole::HOST));
    client_send(&h, client, join(1, BeaconRole::CLIENT));
    std::string big = client_frame(0x82, signal_message(1, std::string(4096, 's')));
    bool not_found = false;
    bool left = false;
    for (int i = 0; i < 2000 && !not_found; i++)
    {
        client_send(&h, client, big);
        // Read what the client is sent, looking for NOT_FOUND.
        for (;;)
        {
            pollfd p = {.fd = client, .events = POLLIN};
            if (poll(&p, 1, 0) <= 0)
            {
                break;
            }
            BeaconSignalingMessage m;
            std::string raw;
            if (!read_message(&h, client, &m, &raw))
            {
                break;
            }
            if (m.type == BeaconSignalingType::NOT_FOUND)
            {
                not_found = true;
            }
            if (m.type == BeaconSignalingType::LEFT)
            {
                left = true;
            }
        }
    }
    check(not_found, "a host that doesn't read: the client gets NOT_FOUND");
    check(h.signal.stats.slow_readers >= 1, "the slow reader is counted");
    pump_a_while(&h);
    check(left || expect(&h, client, BeaconSignalingType::LEFT, 1), "and LEFT once the host is dropped");
    check(client_sees_eof(&h, host), "the host's socket is closed");
    close(host);
    close(client);
    harness_close(&h);
}

static std::string guest_signal(uint8_t room, uint8_t guest, const std::string& blob)
{
    BeaconSignalingMessage m;
    m.type = BeaconSignalingType::GUEST_SIGNAL;
    m.room = room_id(room);
    m.guest = guest;
    m.blob = reinterpret_cast<const uint8_t*>(blob.data());
    m.blob_size = static_cast<uint32_t>(blob.size());
    return client_frame(0x82, encode(&m));
}

static bool expect_guest(Harness* h, int fd, BeaconSignalingType type, uint8_t room, uint8_t guest)
{
    BeaconSignalingMessage m;
    std::string raw;
    BeaconId id = room_id(room);
    return read_message(h, fd, &m, &raw) && m.type == type && beacon_id_equal(&m.room, &id) && m.guest == guest;
}

static bool expect_refused(Harness* h, int fd, uint8_t room, BeaconRefusal reason)
{
    BeaconSignalingMessage m;
    std::string raw;
    BeaconId id = room_id(room);
    return read_message(h, fd, &m, &raw) && m.type == BeaconSignalingType::REFUSED && beacon_id_equal(&m.room, &id) &&
           m.reason == reason;
}

static void test_guest_rooms()
{
    Harness h;
    BeaconSignalConfig config = {};
    config.message_burst = 200;
    config.max_connections_per_source = 32;
    check(harness_open(&h, &config), "signaling listener opens");
    int host = client_open(&h);

    // A guest can't open a guest room: the host makes it.
    int early = client_open(&h);
    client_send(&h, early, join(5, BeaconRole::GUEST));
    check(expect(&h, early, BeaconSignalingType::NOT_FOUND, 5), "a guest before the host: NOT_FOUND");
    check(h.signal.stats.rooms == 0, "a guest makes no room");
    BeaconId room5 = room_id(5);
    check(!beacon_signal_guest_room_live(&h.signal, &room5), "no live guest room yet");

    client_send(&h, host, join(5, BeaconRole::GUEST_HOST));
    check(expect_joined(&h, host, 5, 0), "the guest host joins");
    check(beacon_signal_guest_room_live(&h.signal, &room5), "the guest room is live");

    // Eight guests, each with its own index; the ninth is refused.
    int guests[BEACON_SIGNALING_MAX_GUESTS] = {};
    for (uint32_t i = 0; i < BEACON_SIGNALING_MAX_GUESTS; i++)
    {
        guests[i] = client_open(&h);
        client_send(&h, guests[i], join(5, BeaconRole::GUEST));
        check(expect_joined(&h, guests[i], 5, 1), "a guest joins: the host is there");
        check(expect_guest(&h, host, BeaconSignalingType::GUEST_JOINED, 5, static_cast<uint8_t>(i)),
              "the host hears GUEST_JOINED with the guest's index");
    }
    client_send(&h, early, join(5, BeaconRole::GUEST));
    check(expect_refused(&h, early, 5, BeaconRefusal::GUESTS_FULL), "the ninth guest: GUESTS_FULL");

    // A guest's SIGNAL reaches the host with its index, and back.
    client_send(&h, guests[2], client_frame(0x82, signal_message(5, "offer from guest 2")));
    BeaconSignalingMessage m;
    std::string raw;
    check(read_message(&h, host, &m, &raw) && m.type == BeaconSignalingType::GUEST_SIGNAL && m.guest == 2 &&
              std::string(reinterpret_cast<const char*>(m.blob), m.blob_size) == "offer from guest 2",
          "the host gets GUEST_SIGNAL from guest 2");
    check(client_quiet(&h, guests[1]), "the other guests hear nothing");
    std::string big(BEACON_SIGNALING_MAX_GUEST_BLOB, 'b');
    client_send(&h, host, guest_signal(5, 2, big));
    check(read_message(&h, guests[2], &m, &raw) && m.type == BeaconSignalingType::SIGNAL &&
              std::string(reinterpret_cast<const char*>(m.blob), m.blob_size) == big,
          "guest 2 gets the host's largest GUEST_SIGNAL as SIGNAL");
    client_send(&h, guests[4], client_frame(0x82, signal_message(5, std::string(BEACON_SIGNALING_MAX_GUEST_BLOB, 'c'))));
    check(read_message(&h, host, &m, &raw) && m.guest == 4 && m.blob_size == BEACON_SIGNALING_MAX_GUEST_BLOB,
          "a guest's 4092-byte blob fits");

    // A guest that leaves: the host hears GUEST_LEFT, and a signal to it too.
    close(guests[3]);
    check(expect_guest(&h, host, BeaconSignalingType::GUEST_LEFT, 5, 3), "the host hears GUEST_LEFT 3");
    client_send(&h, host, guest_signal(5, 3, "late"));
    check(expect_guest(&h, host, BeaconSignalingType::GUEST_LEFT, 5, 3), "a signal to a gone guest: GUEST_LEFT");
    client_send(&h, early, join(5, BeaconRole::GUEST));
    check(expect_joined(&h, early, 5, 1), "a freed index takes a new guest");
    check(expect_guest(&h, host, BeaconSignalingType::GUEST_JOINED, 5, 3), "it gets index 3");
    guests[3] = early;

    // Plain roles on a guest room and guest roles on a plain room are refused.
    int other = client_open(&h);
    client_send(&h, other, join(5, BeaconRole::CLIENT));
    check(expect_refused(&h, other, 5, BeaconRefusal::ROOM_KIND), "CLIENT on a guest room: ROOM_KIND");
    client_send(&h, other, join(6, BeaconRole::HOST));
    check(expect_joined(&h, other, 6, 0), "a plain room");
    client_send(&h, guests[0], join(6, BeaconRole::GUEST));
    check(expect_refused(&h, guests[0], 6, BeaconRefusal::ROOM_KIND), "GUEST on a plain room: ROOM_KIND");
    client_send(&h, guests[0], join(6, BeaconRole::GUEST_HOST));
    check(expect_refused(&h, guests[0], 6, BeaconRefusal::ROOM_KIND), "GUEST_HOST on a plain room: ROOM_KIND");

    // The host's SIGNAL (no index) in its guest room is a mistake: NOT_FOUND.
    client_send(&h, host, client_frame(0x82, signal_message(5, "who?")));
    check(expect(&h, host, BeaconSignalingType::NOT_FOUND, 5), "the host's plain SIGNAL: NOT_FOUND");

    // The host leaving ends the room: every guest gets LEFT.
    client_send(&h, host, leave(5));
    for (uint32_t i = 0; i < BEACON_SIGNALING_MAX_GUESTS; i++)
    {
        check(expect(&h, guests[i], BeaconSignalingType::LEFT, 5), "a guest gets LEFT when the host leaves");
    }
    check(!beacon_signal_guest_room_live(&h.signal, &room5), "the guest room is gone");
    check(h.signal.stats.rooms == 1, "only the plain room is left");
    client_send(&h, guests[0], client_frame(0x82, signal_message(5, "anyone?")));
    check(expect(&h, guests[0], BeaconSignalingType::NOT_FOUND, 5), "a guest left behind: NOT_FOUND");

    // A guest SIGNAL too big to carry the index closes that guest.
    client_send(&h, host, join(7, BeaconRole::GUEST_HOST));
    check(expect_joined(&h, host, 7, 0), "another guest room");
    client_send(&h, guests[1], join(7, BeaconRole::GUEST));
    check(expect_joined(&h, guests[1], 7, 1), "a guest joins it");
    check(expect_guest(&h, host, BeaconSignalingType::GUEST_JOINED, 7, 0), "index 0");
    client_send(&h, guests[1], client_frame(0x82, signal_message(7, std::string(BEACON_SIGNALING_MAX_BLOB, 'x'))));
    check(client_sees_eof(&h, guests[1]), "a guest's 4096-byte blob closes it");
    check(expect_guest(&h, host, BeaconSignalingType::GUEST_LEFT, 7, 0), "the host hears it left");

    for (uint32_t i = 0; i < BEACON_SIGNALING_MAX_GUESTS; i++)
    {
        close(guests[i]);
    }
    close(other);
    close(host);
    harness_close(&h);
}

static void test_guest_rate()
{
    Harness h;
    BeaconSignalConfig config = {};
    config.message_burst = 200;
    config.max_connections_per_source = 32;
    check(harness_open(&h, &config), "signaling listener opens");
    int host = client_open(&h);
    for (uint8_t room = 10; room < 17; room++)
    {
        client_send(&h, host, join(room, BeaconRole::GUEST_HOST));
        check(expect_joined(&h, host, room, 0), "a guest room");
    }
    // Burst 5: the sixth guest JOIN from one socket is refused; a minute later
    // ten more are allowed (10 a minute, up to the burst).
    int guest = client_open(&h);
    for (uint8_t room = 10; room < 15; room++)
    {
        client_send(&h, guest, join(room, BeaconRole::GUEST));
        check(expect_joined(&h, guest, room, 1), "a guest JOIN within the burst");
    }
    client_send(&h, guest, join(15, BeaconRole::GUEST));
    check(expect_refused(&h, guest, 15, BeaconRefusal::GUEST_RATE), "the sixth guest JOIN: GUEST_RATE");
    client_send(&h, guest, join(10, BeaconRole::GUEST));
    check(expect_joined(&h, guest, 10, 1), "a refresh of a room it's in isn't counted");
    h.now += 6000;
    client_send(&h, guest, join(15, BeaconRole::GUEST));
    check(expect_joined(&h, guest, 15, 1), "six seconds later: one more");
    client_send(&h, guest, join(16, BeaconRole::GUEST));
    check(expect_refused(&h, guest, 16, BeaconRefusal::GUEST_RATE), "and not two");
    close(guest);
    close(host);
    harness_close(&h);
}

// One plain HTTP exchange: sends `request` (in two pieces when `split` is
// set, to cross reads), reads until the server closes.
static std::string http_exchange(Harness* h, const std::string& request, size_t split)
{
    int fd = client_connect(h, 0);
    if (fd < 0)
    {
        return "";
    }
    if (split > 0 && split < request.size())
    {
        client_send(h, fd, request.substr(0, split));
        client_send(h, fd, request.substr(split));
    }
    else
    {
        client_send(h, fd, request);
    }
    std::string got;
    for (int round = 0; round < 2000; round++)
    {
        pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 0) <= 0)
        {
            pump(h, 5);
            continue;
        }
        char buffer[65536];
        ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
        if (n <= 0)
        {
            break;
        }
        got.append(buffer, static_cast<size_t>(n));
    }
    close(fd);
    return got;
}

static std::string http_body(const std::string& response)
{
    size_t at = response.find("\r\n\r\n");
    return at == std::string::npos ? "" : response.substr(at + 4);
}

static std::string fake_png(uint32_t width, uint32_t height, size_t extra)
{
    uint8_t head[33] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 13, 'I', 'H', 'D', 'R'};
    for (uint32_t i = 0; i < 4; i++)
    {
        head[16 + i] = static_cast<uint8_t>(width >> (24 - 8 * i));
        head[20 + i] = static_cast<uint8_t>(height >> (24 - 8 * i));
    }
    std::string png(reinterpret_cast<const char*>(head), sizeof(head));
    for (size_t i = 0; i < extra; i++)
    {
        png += static_cast<char>(i * 7);
    }
    return png;
}

static std::string card_put(const char* room, const uint8_t key[32], const std::string& title, const std::string& png)
{
    std::string body(reinterpret_cast<const char*>(key), 32);
    body += static_cast<char>(title.size());
    body += title;
    body += png;
    return std::string("POST /join/") + room + "/card HTTP/1.1\r\nHost: beacon.example\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n\r\n" + body;
}

static std::string http_get(const char* method, const std::string& target)
{
    return std::string(method) + " " + target + " HTTP/1.1\r\nHost: beacon.example\r\n\r\n";
}

static void test_http_cards()
{
    Harness h;
    BeaconSignalConfig config = {};
    config.message_burst = 200;
    config.max_connections_per_source = 64;
    check(harness_open(&h, &config), "signaling listener opens");

    // The vector from http_test: token "abcdefghijklmnopqrstuvwxyz".
    const char* room = "7hqelxhbgx2e3";
    uint8_t key[32];
    static const char KEY_HEX[] = "08df115380262124acd5de50e376071f05ef0e65857d278af6e0f52d01b4e1c2";
    for (uint32_t i = 0; i < 32; i++)
    {
        unsigned value = 0;
        sscanf(KEY_HEX + i * 2, "%2x", &value);
        key[i] = static_cast<uint8_t>(value);
    }
    uint8_t other_key[32];
    for (uint32_t i = 0; i < 32; i++)
    {
        other_key[i] = static_cast<uint8_t>(i);
    }
    std::string png = fake_png(640, 480, 100000);

    // Unknown room: the page still opens the app, with a plain card.
    std::string page = http_exchange(&h, http_get("GET", std::string("/join/") + room), 0);
    check(page.compare(0, 15, "HTTP/1.1 200 OK") == 0, "the page of an unknown room: 200");
    check(page.find("A piccolo session") != std::string::npos &&
              page.find("https://beacon.example/join/noise.png") != std::string::npos,
          "a plain card, absolute URLs from Host");
    check(page.find("Content-Type: text/html; charset=utf-8") != std::string::npos &&
              page.find("X-Robots-Tag: noindex") != std::string::npos,
          "page headers");
    check(http_exchange(&h, http_get("GET", std::string("/join/") + room + "/card.png"), 0).compare(0, 12, "HTTP/1.1 404") == 0,
          "no card yet: 404");
    check(http_exchange(&h, card_put(room, key, "Zelda", png), 0).compare(0, 12, "HTTP/1.1 404") == 0,
          "an upload before the room is live: 404");

    // The host holds the guest room: uploads are accepted with the right key.
    int host = client_open(&h);
    BeaconSignalingMessage m;
    m.type = BeaconSignalingType::JOIN;
    m.role = BeaconRole::GUEST_HOST;
    beacon_guest_meeting_id(room, &m.room);
    client_send(&h, host, client_frame(0x82, encode(&m)));
    BeaconSignalingMessage reply;
    std::string raw;
    check(read_message(&h, host, &reply, &raw) && reply.type == BeaconSignalingType::JOINED, "the host's guest room");

    check(http_exchange(&h, card_put(room, other_key, "Zelda", png), 0).compare(0, 12, "HTTP/1.1 403") == 0,
          "another key for this room: 403");
    check(http_exchange(&h, card_put("4ecvcngq5gk2z", other_key, "Zelda", png), 0).compare(0, 12, "HTTP/1.1 404") == 0,
          "a room with no live host: 404");
    std::string too_big = std::string("POST /join/") + room +
                          "/card HTTP/1.1\r\nHost: x\r\nContent-Length: " + std::to_string(BEACON_CARD_MAX_UPLOAD + 1) +
                          "\r\n\r\n";
    check(http_exchange(&h, too_big, 0).compare(0, 12, "HTTP/1.1 413") == 0, "an upload over the limit: 413");
    check(http_exchange(&h, card_put(room, key, "", png), 0).compare(0, 12, "HTTP/1.1 400") == 0,
          "an empty title: 400");
    std::string put = card_put(room, key, "Zelda <DX>", png);
    check(http_exchange(&h, put, 120).compare(0, 12, "HTTP/1.1 204") == 0,
          "the host's card, the body in several reads: 204");
    check(h.signal.stats.cards == 1, "one card");

    page = http_exchange(&h, http_get("GET", std::string("/join/") + room), 0);
    check(page.find("<meta property=\"og:title\" content=\"Zelda &lt;DX&gt;\">") != std::string::npos &&
              page.find("https://beacon.example/join/7hqelxhbgx2e3/card.png") != std::string::npos,
          "the page carries the card");
    check(page.find("Playing Zelda &lt;DX&gt; on piccolo") != std::string::npos, "the description names the game");
    std::string noise = http_exchange(&h, http_get("GET", "/join/noise.png"), 0);
    check(noise.compare(0, 15, "HTTP/1.1 200 OK") == 0 && noise.find("Content-Type: image/png") != std::string::npos &&
              http_body(noise).size() > 1000,
          "the white noise PNG");
    std::string card = http_exchange(&h, http_get("GET", std::string("/join/") + room + "/card.png"), 0);
    check(card.find("Content-Type: image/png") != std::string::npos && http_body(card) == png,
          "the card's PNG, byte for byte (larger than the send buffer)");
    std::string head = http_exchange(&h, http_get("HEAD", std::string("/join/") + room + "/card.png"), 0);
    check(head.find("Content-Length: " + std::to_string(png.size())) != std::string::npos && http_body(head).empty(),
          "HEAD: the length, no body");
    check(http_exchange(&h, http_get("GET", "/elsewhere"), 0).compare(0, 12, "HTTP/1.1 404") == 0, "other paths: 404");
    check(http_exchange(&h, http_get("POST", std::string("/join/") + room), 0).compare(0, 12, "HTTP/1.1 404") == 0,
          "POST to the page: 404");

    // Replacing: four a minute per card (the first put counted).
    for (uint32_t i = 0; i < 3; i++)
    {
        check(http_exchange(&h, card_put(room, key, "Zelda " + std::to_string(i), png), 0).compare(0, 12, "HTTP/1.1 204") == 0,
              "a replacement within the rate");
    }
    check(http_exchange(&h, card_put(room, key, "Zelda 4", png), 0).compare(0, 12, "HTTP/1.1 429") == 0,
          "the fifth put in a minute: 429");
    check(strcmp(beacon_signal_card(&h.signal, room)->title, "Zelda 2") == 0, "the last accepted title");

    // The host goes: the card outlives the room for a minute, then it's gone.
    close(host);
    pump_a_while(&h);
    beacon_signal_tick(&h.signal, h.now);
    h.now += BEACON_CARD_ORPHAN_MS - 1000;
    beacon_signal_tick(&h.signal, h.now);
    check(beacon_signal_card(&h.signal, room) != nullptr, "the card waits for the host's reconnect");
    h.now += 2000;
    beacon_signal_tick(&h.signal, h.now);
    check(beacon_signal_card(&h.signal, room) == nullptr && h.signal.stats.cards == 0, "then it's deleted");
    check(http_exchange(&h, http_get("GET", std::string("/join/") + room + "/card.png"), 0).compare(0, 12, "HTTP/1.1 404") == 0,
          "and no longer served");

    // WebSockets still work on the same listener.
    int ws = client_open(&h);
    check(ws >= 0, "a WebSocket after HTTP");
    close(ws);
    harness_close(&h);
}

int main()
{
    test_websocket_basics();
    test_http_cards();
    test_rooms();
    test_guest_rooms();
    test_guest_rate();
    test_rate_limits();
    test_sources();
    test_slow_reader();
    if (g_failures != 0)
    {
        fprintf(stderr, "%u failures\n", g_failures);
        return 1;
    }
    printf("signal: all checks passed\n");
    return 0;
}
