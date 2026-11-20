// beacon: the server program. Reads the command line, opens the sockets
// and runs one loop: poll, drain the sockets, housekeeping once a second,
// counts in the log every --stats-interval seconds. SIGINT / SIGTERM stop it
// (through a signalfd, so there's no signal-handler global).

#include "beacon_log.h"
#include "beacon_net.h"
#include "beacon_server.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <poll.h>
#include <sys/signalfd.h>
#include <unistd.h>

static constexpr uint16_t DEFAULT_PRIMARY_PORT = 55430;
static constexpr uint16_t DEFAULT_SECONDARY_PORT = 55431;
// Packets read from one socket before looking at the others (and the clock) again.
static constexpr uint32_t PACKETS_PER_ROUND = 256;
static constexpr uint64_t TICK_MS = 1000;

struct Options
{
    const char* bind_address = "::";
    uint16_t primary_port = DEFAULT_PRIMARY_PORT;
    uint16_t secondary_port = DEFAULT_SECONDARY_PORT;  // 0 = no secondary socket
    uint32_t stats_interval_seconds = 60;              // 0 = no stats lines
    BeaconServerConfig config = {};
    BeaconLogLevel log_level = BeaconLogLevel::info;
};

static void print_usage(FILE* out)
{
    BeaconServerConfig defaults = {};
    fprintf(out,
            "beacon " BEACON_VERSION_STRING
            ": introduces paired piccolo devices so they can connect directly (UDP hole punching).\n"
            "It never relays traffic. See README.md.\n"
            "\n"
            "Usage: beacon [options]\n"
            "  --bind ADDRESS            numeric IPv6 or IPv4 address to listen on (default ::, every address,\n"
            "                            IPv4 included)\n"
            "  --port N                  primary UDP port (default %u)\n"
            "  --secondary-port N        secondary UDP port for NAT detection, 0 = off (default %u)\n"
            "  --max-entries N           meeting ids kept at once (default %" PRIu32 ")\n"
            "  --max-sources N           source addresses with their own rate limit (default %" PRIu32 ")\n"
            "  --max-ids-per-source N    meeting ids one IPv4 address or IPv6 /64 may register (default %" PRIu32 ")\n"
            "  --rate N                  packets per second per source (default %" PRIu32 ")\n"
            "  --burst N                 packets a source may send at once (default %" PRIu32 ")\n"
            "  --overflow-rate N         packets per second shared by sources that don't fit (default %" PRIu32 ")\n"
            "  --public-address IP       the server's public IPv4 or IPv6 address, for a server behind a NAT\n"
            "                            with port forwarding: senders from private addresses are reported\n"
            "                            with it (give it twice for both families; default: off)\n"
            "  --stats-interval SECONDS  log counts this often, 0 = never (default 60)\n"
            "  --log-level LEVEL         error, warning, info or debug (default info)\n"
            "  --version                 print the version\n"
            "  --help                    this text\n",
            static_cast<unsigned>(DEFAULT_PRIMARY_PORT), static_cast<unsigned>(DEFAULT_SECONDARY_PORT),
            defaults.max_entries, defaults.max_sources, defaults.max_ids_per_source, defaults.rate_per_second,
            defaults.burst, defaults.overflow_rate_per_second);
}

// A decimal number in [min, max], nothing else.
static bool parse_number(const char* name, const char* text, uint32_t min, uint32_t max, uint32_t* out)
{
    if (text == nullptr || text[0] < '0' || text[0] > '9')
    {
        fprintf(stderr, "beacon: %s needs a number\n", name);
        return false;
    }
    errno = 0;
    char* end = nullptr;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == nullptr || *end != '\0' || value < min || value > max)
    {
        fprintf(stderr, "beacon: %s must be a number from %" PRIu32 " to %" PRIu32 "\n", name, min, max);
        return false;
    }
    *out = static_cast<uint32_t>(value);
    return true;
}

// --public-address: a numeric IPv4 address (stored as ::ffff:a.b.c.d) or IPv6 address.
static bool parse_public_address(const char* text, BeaconServerConfig* config)
{
    in_addr ip4 = {};
    in6_addr ip6 = {};
    if (inet_pton(AF_INET, text, &ip4) == 1)
    {
        BeaconAddress address = {};
        address.ip[10] = 0xff;
        address.ip[11] = 0xff;
        memcpy(address.ip + 12, &ip4, 4);
        if (config->has_public_ipv4)
        {
            fprintf(stderr, "beacon: --public-address given twice for IPv4\n");
            return false;
        }
        config->has_public_ipv4 = true;
        config->public_ipv4 = address;
        return true;
    }
    if (inet_pton(AF_INET6, text, &ip6) == 1)
    {
        BeaconAddress address = {};
        memcpy(address.ip, &ip6, 16);
        if (beacon_address_is_ipv4(&address))
        {
            fprintf(stderr, "beacon: give --public-address an IPv4 address as a.b.c.d\n");
            return false;
        }
        if (config->has_public_ipv6)
        {
            fprintf(stderr, "beacon: --public-address given twice for IPv6\n");
            return false;
        }
        config->has_public_ipv6 = true;
        config->public_ipv6 = address;
        return true;
    }
    fprintf(stderr, "beacon: --public-address needs a numeric IPv4 or IPv6 address\n");
    return false;
}

// Returns 0 to run, 1 for an error, 2 when --help or --version was answered.
static int parse_options(int argc, char** argv, Options* options)
{
    for (int i = 1; i < argc; i++)
    {
        const char* name = argv[i];
        const char* value = i + 1 < argc ? argv[i + 1] : nullptr;
        uint32_t number = 0;
        if (strcmp(name, "--help") == 0)
        {
            print_usage(stdout);
            return 2;
        }
        if (strcmp(name, "--version") == 0)
        {
            printf("beacon %s\n", BEACON_VERSION_STRING);
            return 2;
        }
        if (value == nullptr)
        {
            fprintf(stderr, "beacon: unknown option or missing value: %s (see --help)\n", name);
            return 1;
        }
        i++;
        if (strcmp(name, "--bind") == 0)
        {
            options->bind_address = value;
        }
        else if (strcmp(name, "--port") == 0)
        {
            if (!parse_number(name, value, 1, 65535, &number))
            {
                return 1;
            }
            options->primary_port = static_cast<uint16_t>(number);
        }
        else if (strcmp(name, "--secondary-port") == 0)
        {
            if (!parse_number(name, value, 0, 65535, &number))
            {
                return 1;
            }
            options->secondary_port = static_cast<uint16_t>(number);
        }
        else if (strcmp(name, "--max-entries") == 0)
        {
            if (!parse_number(name, value, 1, BEACON_MAX_TABLE_ITEMS, &options->config.max_entries))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--max-sources") == 0)
        {
            if (!parse_number(name, value, 1, BEACON_MAX_TABLE_ITEMS, &options->config.max_sources))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--max-ids-per-source") == 0)
        {
            if (!parse_number(name, value, 1, 65535, &options->config.max_ids_per_source))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--rate") == 0)
        {
            if (!parse_number(name, value, 1, 1000000, &options->config.rate_per_second))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--burst") == 0)
        {
            if (!parse_number(name, value, 1, 1000000, &options->config.burst))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--overflow-rate") == 0)
        {
            if (!parse_number(name, value, 1, 1000000, &options->config.overflow_rate_per_second))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--public-address") == 0)
        {
            if (!parse_public_address(value, &options->config))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--stats-interval") == 0)
        {
            if (!parse_number(name, value, 0, 86400, &options->stats_interval_seconds))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--log-level") == 0)
        {
            if (!beacon_log_parse_level(value, &options->log_level))
            {
                fprintf(stderr, "beacon: --log-level is error, warning, info or debug\n");
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "beacon: unknown option: %s (see --help)\n", name);
            return 1;
        }
    }
    if (options->secondary_port != 0 && options->secondary_port == options->primary_port)
    {
        fprintf(stderr, "beacon: --port and --secondary-port must differ\n");
        return 1;
    }
    return 0;
}

static void log_stats(const BeaconServer* server, const BeaconNet* net, uint32_t seconds)
{
    const BeaconStats* s = &server->stats;
    beacon_log(BeaconLogLevel::info,
                   "last %" PRIu32 " s: %" PRIu64 " packets, %" PRIu64 " bind, %" PRIu64 " register (%" PRIu64
                   " cookie, %" PRIu64 " ids ok, %" PRIu64 " over source limit, %" PRIu64 " table full), %" PRIu64
                   " meet (%" PRIu64 " intro, %" PRIu64 " not found, %" PRIu64 " too soon), dropped %" PRIu64
                   " malformed, %" PRIu64 " unexpected, %" PRIu64 " rate; now %" PRIu32 " ids, %" PRIu32
                   " sources; %" PRIu64 " send errors, %" PRIu64 " oversized in total",
                   seconds, s->packets, s->binds, s->registers, s->cookies_sent, s->ids_accepted,
                   s->ids_refused_source, s->ids_refused_full, s->meets, s->intros, s->not_found, s->intro_limited,
                   s->malformed, s->unexpected, s->rate_limited, s->entries, s->sources, net->send_errors,
                   net->oversized);
}

// Blocks SIGINT and SIGTERM and returns a signalfd that becomes readable when one comes.
static int open_signal_fd()
{
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &signals, nullptr) != 0)
    {
        beacon_log(BeaconLogLevel::error, "sigprocmask: %s", strerror(errno));
        return -1;
    }
    int fd = signalfd(-1, &signals, SFD_NONBLOCK | SFD_CLOEXEC);
    if (fd < 0)
    {
        beacon_log(BeaconLogLevel::error, "signalfd: %s", strerror(errno));
    }
    return fd;
}

static void run(BeaconServer* server, BeaconNet* net, int signal_fd, uint32_t stats_interval_seconds)
{
    uint64_t now = beacon_now_ms();
    uint64_t next_tick = now + TICK_MS;
    uint64_t stats_ms = static_cast<uint64_t>(stats_interval_seconds) * 1000u;
    uint64_t next_stats = now + stats_ms;
    bool running = true;
    while (running)
    {
        pollfd fds[3] = {};
        nfds_t count = 0;
        fds[count++] = pollfd{.fd = signal_fd, .events = POLLIN};
        fds[count++] = pollfd{.fd = net->primary_fd, .events = POLLIN};
        if (net->secondary_fd >= 0)
        {
            fds[count++] = pollfd{.fd = net->secondary_fd, .events = POLLIN};
        }
        now = beacon_now_ms();
        int timeout = next_tick > now ? static_cast<int>(next_tick - now) : 0;
        int ready = poll(fds, count, timeout);
        if (ready < 0 && errno != EINTR)
        {
            beacon_log(BeaconLogLevel::error, "poll: %s", strerror(errno));
            break;
        }
        now = beacon_now_ms();
        if (ready > 0)
        {
            if ((fds[0].revents & POLLIN) != 0)
            {
                signalfd_siginfo info = {};
                ssize_t got = read(signal_fd, &info, sizeof(info));
                if (got == static_cast<ssize_t>(sizeof(info)))
                {
                    beacon_log(BeaconLogLevel::info, "signal %" PRIu32 ": stopping", info.ssi_signo);
                }
                running = false;
            }
            if ((fds[1].revents & POLLIN) != 0)
            {
                beacon_net_drain(net, server, now, BeaconSocket::PRIMARY, PACKETS_PER_ROUND);
            }
            if (count > 2 && (fds[2].revents & POLLIN) != 0)
            {
                beacon_net_drain(net, server, now, BeaconSocket::SECONDARY, PACKETS_PER_ROUND);
            }
        }
        if (now >= next_tick)
        {
            beacon_server_tick(server, now);
            next_tick = now + TICK_MS;
        }
        if (stats_ms != 0 && now >= next_stats)
        {
            log_stats(server, net, stats_interval_seconds);
            beacon_server_stats_reset(server);
            next_stats = now + stats_ms;
        }
    }
}

int main(int argc, char** argv)
{
    Options options = {};
    int parsed = parse_options(argc, argv, &options);
    if (parsed != 0)
    {
        return parsed == 2 ? 0 : 2;
    }
    beacon_log_set_level(options.log_level);

    int signal_fd = open_signal_fd();
    if (signal_fd < 0)
    {
        return 1;
    }
    BeaconServer server;
    if (!beacon_server_create(&server, &options.config, beacon_now_ms()))
    {
        close(signal_fd);
        return 1;
    }
    BeaconNet net;
    int32_t secondary = options.secondary_port == 0 ? -1 : options.secondary_port;
    if (!beacon_net_open(&net, options.bind_address, options.primary_port, secondary))
    {
        beacon_server_destroy(&server);
        close(signal_fd);
        return 1;
    }
    beacon_log(BeaconLogLevel::info,
                   "beacon %s listening on [%s] UDP %u (primary)%s%s, tables %" PRIu64
                   " KiB (%" PRIu32 " ids, %" PRIu32 " sources)",
                   BEACON_VERSION_STRING, options.bind_address, static_cast<unsigned>(net.primary_port),
                   net.secondary_fd >= 0 ? " and secondary port" : ", no secondary port",
                   net.primary_family == AF_INET ? " (IPv4 only)" : "", beacon_server_table_bytes(&server) / 1024,
                   options.config.max_entries, options.config.max_sources);
    if (options.config.has_public_ipv4 || options.config.has_public_ipv6)
    {
        beacon_log(BeaconLogLevel::info, "public address set: senders from private addresses are reported with it");
    }
    if (net.secondary_fd >= 0)
    {
        beacon_log(BeaconLogLevel::info, "secondary port: UDP %u", static_cast<unsigned>(net.secondary_port));
    }

    run(&server, &net, signal_fd, options.stats_interval_seconds);

    if (options.stats_interval_seconds != 0)
    {
        log_stats(&server, &net, options.stats_interval_seconds);
    }
    beacon_net_close(&net);
    beacon_server_destroy(&server);
    close(signal_fd);
    return 0;
}
