// beacon_signal over real TCP sockets on loopback, step 3a: the handshake,
// echo of binary messages (one frame, split frames, the largest frame),
// ping / pong, the close handshake, protocol errors, a full pool, timeouts.
// Single-threaded: the test's blocking clients alternate with an epoll pump.

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

static int client_connect(Harness* h)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
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
    pump(h, 100);
}

// Reads exactly `size` bytes (pumping the server while waiting), or until
// EOF / 2 s. Returns what arrived.
static std::string client_read(Harness* h, int fd, size_t size)
{
    std::string got;
    for (int round = 0; round < 200 && got.size() < size; round++)
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

// Whether the server closed the connection (EOF within 2 s).
static bool client_sees_eof(Harness* h, int fd)
{
    for (int round = 0; round < 200; round++)
    {
        pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 0) <= 0)
        {
            pump(h, 10);
            continue;
        }
        char buffer[4096];
        ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
        if (n == 0 || (n < 0 && errno == ECONNRESET))
        {
            return true;
        }
    }
    return false;
}

static const char REQUEST[] =
    "GET /signal HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Protocol: multitap-beacon.1\r\n"
    "\r\n";

static const char RESPONSE[] =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
    "Sec-WebSocket-Protocol: multitap-beacon.1\r\n"
    "\r\n";

static int client_open(Harness* h)
{
    int fd = client_connect(h);
    if (fd < 0)
    {
        return -1;
    }
    client_send(h, fd, REQUEST);
    std::string response = client_read(h, fd, sizeof(RESPONSE) - 1);
    check(response == RESPONSE, "the server answers 101 with the accept key and the subprotocol");
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

int main()
{
    Harness h;
    h.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    BeaconSignalConfig config = {};
    config.max_connections = 4;
    check(beacon_signal_open(&h.signal, &config, "127.0.0.1", 0, h.epoll_fd), "signaling listener opens");

    // Echo: one frame, a frame sent a byte at a time, the largest frame.
    int fd = client_open(&h);
    client_send(&h, fd, client_frame(0x82, "hello"));
    check(client_read(&h, fd, 7) == server_frame(0x82, "hello"), "a binary message comes back unmasked");
    std::string split = client_frame(0x82, "split across many TCP segments");
    for (size_t i = 0; i < split.size(); i++)
    {
        client_send(&h, fd, split.substr(i, 1));
    }
    std::string expected = server_frame(0x82, "split across many TCP segments");
    check(client_read(&h, fd, expected.size()) == expected, "a frame sent a byte at a time");
    std::string big(BEACON_WS_MAX_PAYLOAD, 'b');
    big[100] = 'x';
    client_send(&h, fd, client_frame(0x82, big) + client_frame(0x82, "next"));
    expected = server_frame(0x82, big) + server_frame(0x82, "next");
    check(client_read(&h, fd, expected.size()) == expected, "the largest message and one after it in one write");

    // Ping / pong, then the close handshake.
    client_send(&h, fd, client_frame(0x89, "are you there"));
    check(client_read(&h, fd, 15) == server_frame(0x8a, "are you there"), "ping gets pong with its payload");
    client_send(&h, fd, client_frame(0x8a, ""));   // an unsolicited pong is ignored
    client_send(&h, fd, client_frame(0x88, std::string("\x03\xe8", 2)));
    check(client_read(&h, fd, 4) == server_frame(0x88, std::string("\x03\xe8", 2)), "close is echoed with its code");
    check(client_sees_eof(&h, fd), "then the server closes the socket");
    close(fd);

    // Protocol errors close with a code.
    fd = client_open(&h);
    client_send(&h, fd, client_frame(0x81, "text"));
    check(client_read(&h, fd, 4) == server_frame(0x88, std::string("\x03\xeb", 2)), "a text frame: close 1003");
    check(client_sees_eof(&h, fd), "and the socket closes");
    close(fd);
    fd = client_open(&h);
    client_send(&h, fd, std::string("\x82\xff", 2));
    check(client_read(&h, fd, 4) == server_frame(0x88, std::string("\x03\xf1", 2)), "a 64-bit length: close 1009");
    close(fd);
    fd = client_open(&h);
    client_send(&h, fd, std::string("\x82\x02hi", 4));
    check(client_read(&h, fd, 4) == server_frame(0x88, std::string("\x03\xea", 2)), "an unmasked frame: close 1002");
    close(fd);

    // A bad handshake gets 400 and the socket closes.
    fd = client_connect(&h);
    std::string bad = REQUEST;
    bad.replace(bad.find("multitap-beacon.1"), 17, "chat");
    client_send(&h, fd, bad);
    std::string response = client_read(&h, fd, 12);
    check(response == "HTTP/1.1 400", "no subprotocol: 400");
    check(client_sees_eof(&h, fd), "and the socket closes");
    close(fd);
    // A peer that sends junk instead of GET is refused at once.
    fd = client_connect(&h);
    client_send(&h, fd, "\x16\x03\x01");   // a TLS ClientHello: TLS must end at the proxy
    check(client_read(&h, fd, 12) == "HTTP/1.1 400", "TLS on the plain port: 400");
    close(fd);

    // Let the server see every close before counting.
    for (int i = 0; i < 20; i++)
    {
        pump(&h, 10);
    }
    check(h.signal.stats.open == 0, "every connection was freed");

    // The pool holds 4: the fifth is closed at once.
    int fds[5];
    for (int i = 0; i < 4; i++)
    {
        fds[i] = client_open(&h);
    }
    fds[4] = client_connect(&h);
    check(client_sees_eof(&h, fds[4]), "a connection over the pool is closed");
    check(h.signal.stats.refused_full == 1, "and counted");
    close(fds[4]);

    // Timeouts: one connection idle, one in the middle of its handshake.
    close(fds[3]);
    pump(&h, 50);
    fds[3] = client_connect(&h);
    client_send(&h, fds[3], "GET / HTTP/1.1\r\nHost: x\r\n");
    h.now += BEACON_SIGNAL_HANDSHAKE_MS;
    beacon_signal_tick(&h.signal, h.now);
    check(client_sees_eof(&h, fds[3]), "an unfinished handshake times out");
    // fds[0..2] have sent nothing since their handshake.
    client_send(&h, fds[0], client_frame(0x89, ""));
    check(client_read(&h, fds[0], 2) == server_frame(0x8a, ""), "a ping keeps a connection alive");
    h.now += BEACON_SIGNAL_IDLE_MS - BEACON_SIGNAL_HANDSHAKE_MS;
    beacon_signal_tick(&h.signal, h.now);
    check(client_read(&h, fds[1], 4) == server_frame(0x88, std::string("\x03\xe9", 2)), "idle: close 1001");
    check(client_sees_eof(&h, fds[1]), "and the socket closes");
    client_send(&h, fds[0], client_frame(0x82, "alive"));
    check(client_read(&h, fds[0], 7) == server_frame(0x82, "alive"), "the pinged connection is still open");
    for (int i = 0; i < 4; i++)
    {
        close(fds[i]);
    }
    for (int i = 0; i < 20; i++)
    {
        pump(&h, 10);
    }
    check(h.signal.stats.open == 0, "every connection was freed at the end");

    beacon_signal_close(&h.signal);
    close(h.epoll_fd);
    if (g_failures != 0)
    {
        fprintf(stderr, "%u failures\n", g_failures);
        return 1;
    }
    printf("signal: all checks passed\n");
    return 0;
}
