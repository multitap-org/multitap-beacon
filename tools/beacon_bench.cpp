// beacon_bench: how fast the server is (not a test, not run by ctest).
//
//   beacon_bench logic
//       The server logic alone, in this process: BIND, REGISTER and MEET from
//       many different sources, packets per second of CPU.
//   beacon_bench blast PORT SECONDS
//       Sends BINDs as fast as it can to a running server on 127.0.0.1:PORT
//       (start it with a high --rate and --burst) and counts the BOUNDs that
//       come back: what the whole server, syscalls included, answers per second.

#include "beacon_net.h"
#include "beacon_server.h"

#include <arpa/inet.h>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

static BeaconAddress source_address(uint32_t n)
{
    BeaconAddress address = {};
    address.ip[10] = 0xff;
    address.ip[11] = 0xff;
    address.ip[12] = static_cast<uint8_t>(10 + (n >> 24));
    address.ip[13] = static_cast<uint8_t>(n >> 16);
    address.ip[14] = static_cast<uint8_t>(n >> 8);
    address.ip[15] = static_cast<uint8_t>(n);
    address.port = static_cast<uint16_t>(1024 + (n & 0x7fff));
    return address;
}

static BeaconId id_for(uint32_t n)
{
    BeaconId id = {};
    memcpy(id.bytes, &n, sizeof(n));
    id.bytes[15] = 0x5a;
    return id;
}

static double seconds_since(uint64_t start_ms)
{
    return static_cast<double>(beacon_now_ms() - start_ms) / 1000.0;
}

static int bench_logic()
{
    BeaconServerConfig config = {};
    config.max_entries = 1u << 20;
    config.max_sources = 1u << 20;
    BeaconServer server;
    uint64_t now = 1000;
    if (!beacon_server_create(&server, &config, now))
    {
        return 1;
    }
    printf("tables: %" PRIu64 " KiB for %u ids and %u sources (entry %zu bytes, source %zu bytes)\n",
           beacon_server_table_bytes(&server) / 1024, config.max_entries, config.max_sources,
           sizeof(BeaconEntry), sizeof(BeaconSource));
    BeaconOutbox out;
    uint8_t packet[BEACON_MAX_MESSAGE_SIZE];
    static constexpr uint32_t SOURCES = 100000;

    // BIND from 100000 sources, 20 rounds.
    BeaconMessage m = {};
    m.type = BeaconType::BIND;
    uint32_t size = beacon_encode(&m, packet, sizeof(packet));
    uint64_t start = beacon_now_ms();
    uint64_t count = 0;
    for (uint32_t round = 0; round < 20; round++)
    {
        now += 1000;
        for (uint32_t s = 0; s < SOURCES; s++)
        {
            BeaconAddress from = source_address(s);
            beacon_server_receive(&server, now, BeaconSocket::PRIMARY, &from, packet, size, &out);
            count++;
        }
    }
    double elapsed = seconds_since(start);
    printf("BIND:            %10.0f packets/s (%" PRIu64 " packets)\n", static_cast<double>(count) / elapsed, count);

    // REGISTER with 8 ids, valid cookie, from 100000 hosts (800000 ids), 5 rounds.
    start = beacon_now_ms();
    count = 0;
    for (uint32_t round = 0; round < 5; round++)
    {
        now += 1000;
        for (uint32_t s = 0; s < SOURCES; s++)
        {
            BeaconAddress from = source_address(s);
            m = BeaconMessage{};
            m.type = BeaconType::REGISTER;
            m.id_count = 8;
            for (uint32_t i = 0; i < 8; i++)
            {
                m.ids[i] = id_for(s * 8 + i + 1);
            }
            size = beacon_encode(&m, packet, sizeof(packet));
            beacon_server_receive(&server, now, BeaconSocket::PRIMARY, &from, packet, size, &out);
            BeaconMessage cookie;
            beacon_decode(out.packets[0].data, out.packets[0].size, &cookie);
            memcpy(m.cookie, cookie.cookie, BEACON_COOKIE_SIZE);
            size = beacon_encode(&m, packet, sizeof(packet));
            beacon_server_receive(&server, now, BeaconSocket::PRIMARY, &from, packet, size, &out);
            count += 2;
        }
    }
    elapsed = seconds_since(start);
    printf("REGISTER (8 ids): %9.0f packets/s (half without cookie, half storing 8 ids; %u ids stored)\n",
           static_cast<double>(count) / elapsed, server.stats.entries);

    // MEET from other sources for stored ids (two INTROs each).
    start = beacon_now_ms();
    count = 0;
    m = BeaconMessage{};
    m.type = BeaconType::MEET;
    for (uint32_t round = 0; round < 10; round++)
    {
        now += 1000;
        for (uint32_t s = 0; s < SOURCES; s++)
        {
            BeaconAddress from = source_address(SOURCES + s);
            m.ids[0] = id_for(s * 8 + 1 + (round % 8));
            size = beacon_encode(&m, packet, sizeof(packet));
            beacon_server_receive(&server, now, BeaconSocket::PRIMARY, &from, packet, size, &out);
            count++;
        }
    }
    elapsed = seconds_since(start);
    printf("MEET:            %10.0f packets/s (%" PRIu64 " intros)\n", static_cast<double>(count) / elapsed,
           server.stats.intros);

    start = beacon_now_ms();
    beacon_server_tick(&server, now);
    printf("tick (sweep of %zu entry + %zu source slots): %.1f ms\n", server.entries.size(), server.sources.size(),
           seconds_since(start) * 1000.0);
    beacon_server_destroy(&server);
    return 0;
}

static int bench_blast(uint16_t port, uint32_t seconds)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in to = {};
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BeaconMessage m = {};
    m.type = BeaconType::BIND;
    uint8_t packet[BEACON_MAX_MESSAGE_SIZE];
    uint32_t size = beacon_encode(&m, packet, sizeof(packet));
    uint8_t buffer[256];
    uint64_t sent = 0;
    uint64_t received = 0;
    uint64_t in_flight = 0;
    uint64_t start = beacon_now_ms();
    uint64_t end = start + static_cast<uint64_t>(seconds) * 1000u;
    // Keep at most this many requests in flight, so the socket buffers don't
    // just overflow and the count measures the server, not the drops.
    static constexpr uint64_t IN_FLIGHT = 256;
    while (beacon_now_ms() < end)
    {
        while (in_flight < IN_FLIGHT)
        {
            if (sendto(fd, packet, size, 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to)) < 0)
            {
                break;
            }
            sent++;
            in_flight++;
        }
        pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 10) <= 0)
        {
            // Lost packets: open the window again.
            in_flight = 0;
            continue;
        }
        while (recv(fd, buffer, sizeof(buffer), 0) > 0)
        {
            received++;
            if (in_flight > 0)
            {
                in_flight--;
            }
        }
    }
    double elapsed = seconds_since(start);
    printf("blast: %" PRIu64 " sent, ~%.0f replies/s over %.1f s\n", sent, static_cast<double>(received) / elapsed,
           elapsed);
    close(fd);
    return 0;
}

int main(int argc, char** argv)
{
    if (argc >= 2 && strcmp(argv[1], "logic") == 0)
    {
        return bench_logic();
    }
    if (argc >= 4 && strcmp(argv[1], "blast") == 0)
    {
        return bench_blast(static_cast<uint16_t>(atoi(argv[2])), static_cast<uint32_t>(atoi(argv[3])));
    }
    fprintf(stderr, "usage: beacon_bench logic | blast PORT SECONDS\n");
    return 2;
}
