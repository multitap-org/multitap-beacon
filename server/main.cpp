// beacon: the server program. Reads the command line, opens the sockets
// and runs one epoll loop: the UDP sockets, the signaling listener and its
// connections, housekeeping once a second, counts in the log every
// --stats-interval seconds. SIGINT / SIGTERM stop it
// (through a signalfd, so there's no signal-handler global).

#include "beacon_log.h"
#include "beacon_net.h"
#include "beacon_server.h"
#include "beacon_signal.h"
#include "beacon_status.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>

static constexpr uint16_t DEFAULT_PRIMARY_PORT = 55430;
static constexpr uint16_t DEFAULT_SECONDARY_PORT = 55431;
static constexpr uint16_t DEFAULT_SIGNAL_PORT = 55432;
// Packets read from one socket before looking at the others (and the clock) again.
static constexpr uint32_t PACKETS_PER_ROUND = 256;
static constexpr uint64_t TICK_MS = 1000;
static constexpr int MAX_EVENTS = 64;

// epoll tags below the signaling ones (beacon_signal.h).
static constexpr uint64_t TAG_SIGNALFD = 1;
static constexpr uint64_t TAG_PRIMARY = 2;
static constexpr uint64_t TAG_SECONDARY = 3;
static constexpr uint64_t TAG_STUN = 4;

struct Options
{
    const char* bind_address = "::";
    uint16_t primary_port = DEFAULT_PRIMARY_PORT;
    uint16_t secondary_port = DEFAULT_SECONDARY_PORT;  // 0 = no secondary socket
    uint16_t stun_port = 0;                            // 0 = no extra STUN socket
    uint32_t stats_interval_seconds = 60;              // 0 = no stats lines
    const char* status_file = nullptr;                 // --status-file, nullptr = none
    const char* signal_bind = "127.0.0.1";             // the WebSocket listener, behind a TLS proxy
    uint16_t signal_port = DEFAULT_SIGNAL_PORT;        // 0 = no signaling
    BeaconSignalConfig signal_config = {};
    BeaconServerConfig config = {};
    BeaconLogLevel log_level = BeaconLogLevel::info;
};

static void print_usage(FILE* out)
{
    BeaconServerConfig defaults = {};
    BeaconSignalConfig signal_defaults = {};
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
            "  --stun-port N             an extra UDP port that answers STUN only, usually 3478; the primary\n"
            "                            and secondary ports answer STUN anyway (default 0 = off)\n"
            "  --max-entries N           meeting ids kept at once (default %" PRIu32 ")\n"
            "  --max-sources N           source addresses with their own rate limit (default %" PRIu32 ")\n"
            "  --max-ids-per-source N    meeting ids one IPv4 address or IPv6 /64 may register (default %" PRIu32 ")\n"
            "  --rate N                  packets per second per source (default %" PRIu32 ")\n"
            "  --burst N                 packets a source may send at once (default %" PRIu32 ")\n"
            "  --overflow-rate N         packets per second shared by sources that don't fit (default %" PRIu32 ")\n"
"  --signal-bind ADDRESS     numeric address for the WebSocket signaling listener (default 127.0.0.1:\n"
            "                            a TLS proxy such as Caddy goes in front)\n"
            "  --signal-port N           its TCP port, 0 = no signaling (default %u)\n"
            "  --max-connections N       signaling connections at once (default %" PRIu32 ")\n"
            "  --max-rooms N             signaling rooms at once (default %" PRIu32 ")\n"
            "  --max-connections-per-source N\n"
            "                            signaling connections from one IPv4 address or IPv6 /64 (default %" PRIu32 ")\n"
            "  --max-cards N             guest link cards kept in memory, 256 KiB each, 0 = no cards\n"
            "                            (default %" PRIu32 ")\n"
            "  --public-url URL          scheme and host for the guest links' absolute URLs, e.g.\n"
            "                            https://beacon.example (default: https:// + the request's Host)\n"
            "  --trusted-proxy IP[/N]    a proxy whose X-Forwarded-For is believed, e.g. a Docker network\n"
            "                            (172.16.0.0/12); loopback always is; up to 8 times\n"
            "  --public-address IP       the server's public IPv4 or IPv6 address, for a server behind a NAT\n"
            "                            with port forwarding: senders from private addresses are reported\n"
            "                            with it (give it twice for both families; default: off)\n"
            "  --stats-interval SECONDS  log counts this often, 0 = never (default 60)\n"
            "  --status-file PATH        write hosts online and introductions in the last hour to this JSON\n"
            "                            file every 10 s, and their history (7 days, 30 days, a year) to\n"
            "                            history.json next to it, for the status page (default: off)\n"
            "  --log-level LEVEL         error, warning, info or debug (default info)\n"
            "  --version                 print the version\n"
            "  --help                    this text\n",
            static_cast<unsigned>(DEFAULT_PRIMARY_PORT), static_cast<unsigned>(DEFAULT_SECONDARY_PORT),
            defaults.max_entries, defaults.max_sources, defaults.max_ids_per_source, defaults.rate_per_second,
            defaults.burst, defaults.overflow_rate_per_second, static_cast<unsigned>(DEFAULT_SIGNAL_PORT),
            signal_defaults.max_connections, signal_defaults.max_rooms, signal_defaults.max_connections_per_source,
            signal_defaults.max_cards);
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
        else if (strcmp(name, "--signal-bind") == 0)
        {
            options->signal_bind = value;
        }
        else if (strcmp(name, "--signal-port") == 0)
        {
            if (!parse_number(name, value, 0, 65535, &number))
            {
                return 1;
            }
            options->signal_port = static_cast<uint16_t>(number);
        }
        else if (strcmp(name, "--max-connections") == 0)
        {
            if (!parse_number(name, value, 1, BEACON_SIGNAL_MAX_CONNECTIONS, &options->signal_config.max_connections))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--max-rooms") == 0)
        {
            if (!parse_number(name, value, 1, 1u << 24, &options->signal_config.max_rooms))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--max-connections-per-source") == 0)
        {
            if (!parse_number(name, value, 1, BEACON_SIGNAL_MAX_CONNECTIONS,
                              &options->signal_config.max_connections_per_source))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--max-cards") == 0)
        {
            if (!parse_number(name, value, 0, 4096, &options->signal_config.max_cards))
            {
                return 1;
            }
        }
        else if (strcmp(name, "--public-url") == 0)
        {
            // Repeated in pages as is: only a plain http(s) origin.
            bool ok = value != nullptr && strlen(value) <= BEACON_MAX_PUBLIC_URL &&
                      (strncmp(value, "https://", 8) == 0 || strncmp(value, "http://", 7) == 0);
            for (size_t k = 0; ok && value[k] != '\0'; k++)
            {
                char c = value[k];
                ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                     strchr("-.:/[]", c) != nullptr;
            }
            if (!ok || value[strlen(value) - 1] == '/')
            {
                fprintf(stderr, "beacon: --public-url needs http(s)://host[:port], no path\n");
                return 1;
            }
            snprintf(options->signal_config.public_url, sizeof(options->signal_config.public_url), "%s", value);
        }
        else if (strcmp(name, "--trusted-proxy") == 0)
        {
            BeaconSignalConfig* signal_config = &options->signal_config;
            if (signal_config->trusted_count >= BEACON_SIGNAL_MAX_TRUSTED)
            {
                fprintf(stderr, "beacon: --trusted-proxy at most %u times\n", BEACON_SIGNAL_MAX_TRUSTED);
                return 1;
            }
            if (!beacon_cidr_parse(value, &signal_config->trusted[signal_config->trusted_count]))
            {
                fprintf(stderr, "beacon: --trusted-proxy needs a numeric address or range (IP or IP/N)\n");
                return 1;
            }
            signal_config->trusted_count++;
        }
        else if (strcmp(name, "--stun-port") == 0)
        {
            if (!parse_number(name, value, 0, 65535, &number))
            {
                return 1;
            }
            options->stun_port = static_cast<uint16_t>(number);
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
        else if (strcmp(name, "--status-file") == 0)
        {
            if (value[0] == '\0')
            {
                fprintf(stderr, "beacon: --status-file needs a path\n");
                return 1;
            }
            options->status_file = value;
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
    if (options->stun_port != 0 &&
        (options->stun_port == options->primary_port || options->stun_port == options->secondary_port))
    {
        fprintf(stderr, "beacon: --stun-port must differ from --port and --secondary-port\n");
        return 1;
    }
    return 0;
}

static void log_signal_stats(BeaconSignal* signal, uint32_t seconds)
{
    const BeaconSignalStats* s = &signal->stats;
    beacon_log(BeaconLogLevel::info,
               "signaling, last %" PRIu32 " s: %" PRIu64 " accepted (%" PRIu64 " pool full, %" PRIu64
               " over source limit), %" PRIu64 " handshakes (%" PRIu64 " bad), %" PRIu64 " joins (%" PRIu64
               " replaced, %" PRIu64 " refused), %" PRIu64 " signals, %" PRIu64 " not found; closed: %" PRIu64
               " rate, %" PRIu64 " protocol, %" PRIu64 " timeout, %" PRIu64 " slow; now %" PRIu32 " open, %" PRIu32
               " rooms",
               seconds, s->accepted, s->refused_full, s->refused_source, s->handshakes, s->bad_handshakes, s->joins,
               s->replaced, s->refused_rooms, s->signals, s->not_found, s->rate_limited, s->protocol_errors,
               s->timeouts, s->slow_readers, s->open, s->rooms);
    beacon_signal_stats_reset(signal);
}

static void log_stats(const BeaconServer* server, const BeaconNet* net, uint32_t seconds)
{
    const BeaconStats* s = &server->stats;
    beacon_log(BeaconLogLevel::info,
                   "last %" PRIu32 " s: %" PRIu64 " packets, %" PRIu64 " bind, %" PRIu64 " stun, %" PRIu64 " register (%" PRIu64
                   " cookie, %" PRIu64 " ids ok, %" PRIu64 " over source limit, %" PRIu64 " table full), %" PRIu64
                   " meet (%" PRIu64 " intro, %" PRIu64 " not found, %" PRIu64 " too soon), dropped %" PRIu64
                   " malformed, %" PRIu64 " unexpected, %" PRIu64 " rate; now %" PRIu32 " ids, %" PRIu32
                   " sources; %" PRIu64 " send errors, %" PRIu64 " oversized in total",
                   seconds, s->packets, s->binds, s->stun, s->registers, s->cookies_sent, s->ids_accepted,
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

static void write_status(BeaconStatus* status, BeaconServer* server, uint64_t now_ms)
{
    beacon_status_update(status, beacon_server_count_hosts(server, now_ms), server->intros_total,
                         beacon_unix_seconds());
}

// Everything the loop drives. `signal` and `status` are nullptr when off.
struct Loop
{
    BeaconServer* server = nullptr;
    BeaconNet* net = nullptr;
    BeaconSignal* signal = nullptr;
    BeaconStatus* status = nullptr;
    int signal_fd = -1;
    int epoll_fd = -1;
    uint32_t stats_interval_seconds = 0;
};

static bool epoll_add(int epoll_fd, int fd, uint64_t tag)
{
    if (fd < 0)
    {
        return true;
    }
    epoll_event event = {};
    event.events = EPOLLIN;
    event.data.u64 = tag;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0)
    {
        beacon_log(BeaconLogLevel::error, "epoll_ctl: %s", strerror(errno));
        return false;
    }
    return true;
}

static void run(Loop* loop)
{
    uint64_t now = beacon_now_ms();
    uint64_t next_tick = now + TICK_MS;
    uint64_t next_status = now + BEACON_STATUS_INTERVAL_MS;
    if (loop->status != nullptr)
    {
        write_status(loop->status, loop->server, now);
    }
    uint64_t stats_ms = static_cast<uint64_t>(loop->stats_interval_seconds) * 1000u;
    uint64_t next_stats = now + stats_ms;
    bool running = true;
    epoll_event events[MAX_EVENTS];
    while (running)
    {
        now = beacon_now_ms();
        int timeout = next_tick > now ? static_cast<int>(next_tick - now) : 0;
        int ready = epoll_wait(loop->epoll_fd, events, MAX_EVENTS, timeout);
        if (ready < 0 && errno != EINTR)
        {
            beacon_log(BeaconLogLevel::error, "epoll_wait: %s", strerror(errno));
            break;
        }
        now = beacon_now_ms();
        for (int i = 0; i < ready; i++)
        {
            uint64_t tag = events[i].data.u64;
            if (tag == TAG_SIGNALFD)
            {
                signalfd_siginfo info = {};
                ssize_t got = read(loop->signal_fd, &info, sizeof(info));
                if (got == static_cast<ssize_t>(sizeof(info)))
                {
                    beacon_log(BeaconLogLevel::info, "signal %" PRIu32 ": stopping", info.ssi_signo);
                }
                running = false;
            }
            else if (tag == TAG_PRIMARY)
            {
                beacon_net_drain(loop->net, loop->server, now, BeaconSocket::PRIMARY, PACKETS_PER_ROUND);
            }
            else if (tag == TAG_SECONDARY)
            {
                beacon_net_drain(loop->net, loop->server, now, BeaconSocket::SECONDARY, PACKETS_PER_ROUND);
            }
            else if (tag == TAG_STUN)
            {
                beacon_net_drain(loop->net, loop->server, now, BeaconSocket::STUN, PACKETS_PER_ROUND);
            }
            else if (tag == BEACON_SIGNAL_TAG_LISTEN && loop->signal != nullptr)
            {
                beacon_signal_accept(loop->signal, now);
            }
            else if (tag >= BEACON_SIGNAL_TAG_FIRST_CONNECTION && loop->signal != nullptr)
            {
                uint64_t index = tag - BEACON_SIGNAL_TAG_FIRST_CONNECTION;
                beacon_signal_event(loop->signal, static_cast<uint32_t>(index), events[i].events, now);
            }
        }
        if (now >= next_tick)
        {
            beacon_server_tick(loop->server, now);
            if (loop->signal != nullptr)
            {
                beacon_signal_tick(loop->signal, now);
            }
            next_tick = now + TICK_MS;
        }
        if (loop->status != nullptr && now >= next_status)
        {
            write_status(loop->status, loop->server, now);
            next_status = now + BEACON_STATUS_INTERVAL_MS;
        }
        if (stats_ms != 0 && now >= next_stats)
        {
            log_stats(loop->server, loop->net, loop->stats_interval_seconds);
            beacon_server_stats_reset(loop->server);
            if (loop->signal != nullptr)
            {
                log_signal_stats(loop->signal, loop->stats_interval_seconds);
            }
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
    int32_t stun = options.stun_port == 0 ? -1 : options.stun_port;
    if (!beacon_net_open(&net, options.bind_address, options.primary_port, secondary, stun))
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
    if (net.stun_fd >= 0)
    {
        beacon_log(BeaconLogLevel::info, "STUN-only port: UDP %u", static_cast<unsigned>(net.stun_port));
    }

    Loop loop;
    loop.server = &server;
    loop.net = &net;
    loop.signal_fd = signal_fd;
    loop.stats_interval_seconds = options.stats_interval_seconds;
    loop.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    bool ready = loop.epoll_fd >= 0 && epoll_add(loop.epoll_fd, signal_fd, TAG_SIGNALFD) &&
                 epoll_add(loop.epoll_fd, net.primary_fd, TAG_PRIMARY) &&
                 epoll_add(loop.epoll_fd, net.secondary_fd, TAG_SECONDARY) &&
                 epoll_add(loop.epoll_fd, net.stun_fd, TAG_STUN);

    BeaconSignal signal;
    if (ready && options.signal_port != 0)
    {
        if (beacon_signal_open(&signal, &options.signal_config, options.signal_bind, options.signal_port,
                               loop.epoll_fd))
        {
            loop.signal = &signal;
            beacon_log(BeaconLogLevel::info,
                       "signaling: WebSocket on [%s] TCP %u, %" PRIu32 " connections, %" PRIu32 " rooms (%" PRIu64
                       " KiB), %" PRIu32 " trusted proxies besides loopback",
                       options.signal_bind, static_cast<unsigned>(signal.port),
                       options.signal_config.max_connections, options.signal_config.max_rooms,
                       beacon_signal_pool_bytes(&signal) / 1024, options.signal_config.trusted_count);
        }
        else
        {
            ready = false;
        }
    }

    BeaconStatus status;
    if (options.status_file != nullptr && beacon_status_open(&status, options.status_file, beacon_unix_seconds()))
    {
        beacon_log(BeaconLogLevel::info, "status file: %s, every %" PRIu64 " s", options.status_file,
                   BEACON_STATUS_INTERVAL_MS / 1000);
        loop.status = &status;
    }

    if (ready)
    {
        run(&loop);
        if (options.stats_interval_seconds != 0)
        {
            log_stats(&server, &net, options.stats_interval_seconds);
            if (loop.signal != nullptr)
            {
                log_signal_stats(loop.signal, options.stats_interval_seconds);
            }
        }
    }
    if (loop.status != nullptr)
    {
        // The bucket in progress, so a restart doesn't leave a hole.
        beacon_status_flush(loop.status, beacon_unix_seconds());
    }
    if (loop.signal != nullptr)
    {
        beacon_signal_close(loop.signal);
    }
    if (loop.epoll_fd >= 0)
    {
        close(loop.epoll_fd);
    }
    beacon_net_close(&net);
    beacon_server_destroy(&server);
    close(signal_fd);
    return ready ? 0 : 1;
}
