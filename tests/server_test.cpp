// Server logic with a fake clock and no sockets: cookies, registration,
// introductions, expiry, limits, rate limits, address families.

#include "beacon_server.h"
#include "beacon_status.h"

#include <cstdio>
#include <cstring>

static uint32_t g_failures = 0;

static void check(bool ok, const char* what)
{
    if (!ok)
    {
        fprintf(stderr, "FAIL: %s\n", what);
        g_failures++;
    }
}

static BeaconId make_id(uint32_t seed)
{
    BeaconId id;
    for (uint32_t i = 0; i < BEACON_ID_SIZE; i++)
    {
        id.bytes[i] = static_cast<uint8_t>((seed >> (8 * (i % 4))) + i + 1);
    }
    return id;
}

static BeaconAddress ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    BeaconAddress address;
    address.ip[10] = 0xff;
    address.ip[11] = 0xff;
    address.ip[12] = a;
    address.ip[13] = b;
    address.ip[14] = c;
    address.ip[15] = d;
    address.port = port;
    return address;
}

static BeaconAddress ipv6(uint8_t last, uint8_t subnet, uint16_t port)
{
    BeaconAddress address;
    address.ip[0] = 0x20;
    address.ip[1] = 0x01;
    address.ip[2] = 0x0d;
    address.ip[3] = 0xb8;
    address.ip[7] = subnet;
    address.ip[15] = last;
    address.port = port;
    return address;
}

struct Fixture
{
    BeaconServer server;
    uint64_t now = 1000000;
    BeaconOutbox out;
};

static bool fixture_create(Fixture* f, const BeaconServerConfig* config)
{
    f->now = 1000000;
    f->out = BeaconOutbox{};
    return beacon_server_create(&f->server, config, f->now);
}

// Sends `message` and checks that every reply is no larger than the request.
static void send_message(Fixture* f, BeaconSocket socket, const BeaconAddress* from,
                         const BeaconMessage* message)
{
    uint8_t packet[BEACON_MAX_MESSAGE_SIZE];
    uint32_t size = beacon_encode(message, packet, sizeof(packet));
    check(size != 0, "test message encodes");
    beacon_server_receive(&f->server, f->now, socket, from, packet, size, &f->out);
    for (uint32_t i = 0; i < f->out.count; i++)
    {
        check(f->out.packets[i].size <= size, "a reply is never larger than its request");
    }
}

static bool reply(const Fixture* f, uint32_t index, BeaconMessage* decoded)
{
    if (index >= f->out.count)
    {
        return false;
    }
    return beacon_decode(f->out.packets[index].data, f->out.packets[index].size, decoded);
}

static BeaconMessage make_register(uint64_t nonce, const uint8_t* cookie, uint32_t first_id, uint8_t count)
{
    BeaconMessage m = {};
    m.type = BeaconType::REGISTER;
    m.nonce = nonce;
    if (cookie != nullptr)
    {
        memcpy(m.cookie, cookie, BEACON_COOKIE_SIZE);
    }
    m.id_count = count;
    for (uint32_t i = 0; i < count; i++)
    {
        m.ids[i] = make_id(first_id + i);
    }
    return m;
}

static BeaconMessage make_meet(uint64_t nonce, uint32_t id)
{
    BeaconMessage m = {};
    m.type = BeaconType::MEET;
    m.nonce = nonce;
    m.ids[0] = make_id(id);
    return m;
}

// REGISTER with no cookie, take the COOKIE, REGISTER again: returns accepted (or -1).
static int32_t register_ids(Fixture* f, const BeaconAddress* host, uint32_t first_id, uint8_t count,
                            uint8_t cookie_out[BEACON_COOKIE_SIZE])
{
    BeaconMessage m = make_register(1, nullptr, first_id, count);
    send_message(f, BeaconSocket::PRIMARY, host, &m);
    BeaconMessage r;
    if (!reply(f, 0, &r) || r.type != BeaconType::COOKIE)
    {
        return -1;
    }
    m = make_register(2, r.cookie, first_id, count);
    send_message(f, BeaconSocket::PRIMARY, host, &m);
    if (!reply(f, 0, &r) || r.type != BeaconType::REGISTERED_REPLY || r.nonce != 2)
    {
        return -1;
    }
    if (cookie_out != nullptr)
    {
        memcpy(cookie_out, r.cookie, BEACON_COOKIE_SIZE);
    }
    return r.id_count;
}

// PRESENCE: which ids are registered, without a meeting (lists' ONLINE / OFFLINE).
static void test_presence()
{
    Fixture f;
    BeaconServerConfig config = {};
    check(fixture_create(&f, &config), "server creates");
    BeaconAddress host = ipv4(203, 0, 113, 1, 40000);
    BeaconAddress client = ipv4(198, 51, 100, 2, 50000);
    check(register_ids(&f, &host, 100, 2, nullptr) == 2, "two ids registered");
    BeaconMessage m = {};
    m.type = BeaconType::PRESENCE;
    m.nonce = 77;
    m.id_count = 3;
    m.ids[0] = make_id(101);
    m.ids[1] = make_id(555);
    m.ids[2] = make_id(100);
    send_message(&f, BeaconSocket::PRIMARY, &client, &m);
    BeaconMessage r;
    check(f.out.count == 1 && reply(&f, 0, &r) && r.type == BeaconType::PRESENT && r.nonce == 77,
          "PRESENCE gets one PRESENT");
    check(r.present == 0x05, "bits for the registered ids only (0 and 2)");
    check(f.server.stats.presences == 1 && f.server.stats.intros == 0, "counted, and nobody was introduced");
    send_message(&f, BeaconSocket::SECONDARY, &client, &m);
    check(f.out.count == 0, "only on the primary socket");
    beacon_server_destroy(&f.server);
}

static void test_bind()
{
    Fixture f;
    BeaconServerConfig config = {};
    check(fixture_create(&f, &config), "server creates");
    BeaconAddress client = ipv4(198, 51, 100, 9, 61000);
    BeaconMessage bind = {};
    bind.type = BeaconType::BIND;
    bind.nonce = 77;
    for (uint32_t s = 0; s < 2; s++)
    {
        BeaconSocket socket = s == 0 ? BeaconSocket::PRIMARY : BeaconSocket::SECONDARY;
        send_message(&f, socket, &client, &bind);
        BeaconMessage r;
        check(f.out.count == 1 && reply(&f, 0, &r), "BIND gets one reply");
        check(r.type == BeaconType::BOUND && r.nonce == 77, "BOUND with the nonce");
        check(beacon_address_equal(&r.address, &client), "BOUND reflects the sender's address");
        check(beacon_address_equal(&f.out.packets[0].to, &client), "BOUND goes to the sender");
        check(f.out.packets[0].socket == socket, "BOUND leaves from the socket BIND came in on");
    }
    beacon_server_destroy(&f.server);
}

static void test_register_and_meet()
{
    Fixture f;
    BeaconServerConfig config = {};
    check(fixture_create(&f, &config), "server creates");
    BeaconAddress host = ipv4(203, 0, 113, 1, 40000);
    BeaconAddress client = ipv4(198, 51, 100, 2, 50000);

    // No cookie: COOKIE only, nothing stored.
    BeaconMessage m = make_register(5, nullptr, 100, 2);
    send_message(&f, BeaconSocket::PRIMARY, &host, &m);
    BeaconMessage r;
    check(f.out.count == 1 && reply(&f, 0, &r) && r.type == BeaconType::COOKIE && r.nonce == 5,
          "REGISTER without a cookie gets COOKIE");
    uint8_t cookie[BEACON_COOKIE_SIZE];
    memcpy(cookie, r.cookie, sizeof(cookie));
    m = make_meet(6, 100);
    send_message(&f, BeaconSocket::PRIMARY, &client, &m);
    check(reply(&f, 0, &r) && r.type == BeaconType::NOT_FOUND, "nothing stored before the cookie");

    // Another address's cookie doesn't work here.
    BeaconAddress other = ipv4(203, 0, 113, 1, 40001);
    m = make_register(7, cookie, 100, 2);
    send_message(&f, BeaconSocket::PRIMARY, &other, &m);
    check(reply(&f, 0, &r) && r.type == BeaconType::COOKIE, "a cookie is bound to its address and port");

    // With the cookie: stored.
    m = make_register(8, cookie, 100, 2);
    send_message(&f, BeaconSocket::PRIMARY, &host, &m);
    check(reply(&f, 0, &r) && r.type == BeaconType::REGISTERED_REPLY, "REGISTER with the cookie is REGISTERED");
    check(r.id_count == 2 && r.ttl_seconds == BEACON_ENTRY_TTL_SECONDS && r.nonce == 8, "REGISTERED fields");
    check(f.server.stats.entries == 2, "two entries stored");

    // The fresh cookie from REGISTERED works for the next refresh.
    m = make_register(9, r.cookie, 100, 2);
    send_message(&f, BeaconSocket::PRIMARY, &host, &m);
    check(reply(&f, 0, &r) && r.type == BeaconType::REGISTERED_REPLY && r.id_count == 2,
          "the fresh cookie works and refreshing doesn't add entries");
    check(f.server.stats.entries == 2, "still two entries");

    // MEET: INTRO to both sides.
    m = make_meet(1234, 101);
    send_message(&f, BeaconSocket::PRIMARY, &client, &m);
    check(f.out.count == 2, "MEET for a registered id sends two packets");
    BeaconMessage to_client;
    BeaconMessage to_host;
    check(reply(&f, 0, &to_client) && reply(&f, 1, &to_host), "both INTROs decode");
    check(to_client.type == BeaconType::INTRO && to_host.type == BeaconType::INTRO, "both are INTRO");
    check(to_client.nonce == 1234 && to_host.nonce == 1234, "both carry the MEET's nonce");
    check(beacon_id_equal(&to_client.ids[0], &m.ids[0]) && beacon_id_equal(&to_host.ids[0], &m.ids[0]),
          "both carry the meeting id");
    check(beacon_address_equal(&f.out.packets[0].to, &client) &&
              beacon_address_equal(&to_client.address, &host),
          "the client gets the host's address");
    check(beacon_address_equal(&f.out.packets[1].to, &host) && beacon_address_equal(&to_host.address, &client),
          "the host gets the client's address");

    // A second MEET right away is dropped; after the interval it works again.
    f.now += 100;
    send_message(&f, BeaconSocket::PRIMARY, &client, &m);
    check(f.out.count == 0, "a MEET within the INTRO interval is dropped");
    f.now += BEACON_INTRO_INTERVAL_MS;
    send_message(&f, BeaconSocket::PRIMARY, &client, &m);
    check(f.out.count == 2, "a MEET after the interval gets INTROs again");

    // Unknown id.
    m = make_meet(55, 999);
    send_message(&f, BeaconSocket::PRIMARY, &client, &m);
    check(f.out.count == 1 && reply(&f, 0, &r) && r.type == BeaconType::NOT_FOUND && r.nonce == 55,
          "an unknown id gets NOT_FOUND");

    // REGISTER and MEET on the secondary port are not answered.
    m = make_meet(56, 100);
    send_message(&f, BeaconSocket::SECONDARY, &client, &m);
    check(f.out.count == 0, "MEET on the secondary port is dropped");
    m = make_register(57, cookie, 100, 1);
    send_message(&f, BeaconSocket::SECONDARY, &host, &m);
    check(f.out.count == 0, "REGISTER on the secondary port is dropped");

    // Reply types sent to the server are dropped.
    m = BeaconMessage{};
    m.type = BeaconType::BOUND;
    m.address = client;
    send_message(&f, BeaconSocket::PRIMARY, &client, &m);
    check(f.out.count == 0, "a BOUND sent to the server is dropped");

    // Garbage.
    uint8_t junk[52] = {'M', 'T', 'B', 'C', 1, 6};
    beacon_server_receive(&f.server, f.now, BeaconSocket::PRIMARY, &client, junk, sizeof(junk), &f.out);
    check(f.out.count == 0, "a MEET with a zero id is dropped");
    beacon_server_receive(&f.server, f.now, BeaconSocket::PRIMARY, &client, junk, 0, &f.out);
    check(f.out.count == 0, "an empty packet is dropped");
    beacon_server_destroy(&f.server);
}

static void test_expiry_and_cookie_age()
{
    Fixture f;
    BeaconServerConfig config = {};
    config.max_ids_per_source = 4;
    check(fixture_create(&f, &config), "server creates");
    BeaconAddress host = ipv4(203, 0, 113, 3, 40000);
    BeaconAddress client = ipv4(198, 51, 100, 3, 50000);
    uint8_t cookie[BEACON_COOKIE_SIZE];
    check(register_ids(&f, &host, 1, 4, cookie) == 4, "four ids registered");
    check(f.server.stats.entries == 4, "four entries");

    // 59 s later: still there. 61 s: gone, and the source's count with them.
    f.now += 59000;
    beacon_server_tick(&f.server, f.now);
    BeaconMessage m = make_meet(1, 1);
    BeaconMessage r;
    send_message(&f, BeaconSocket::PRIMARY, &client, &m);
    check(reply(&f, 0, &r) && r.type == BeaconType::INTRO, "an entry lives 59 s");
    f.now += 2000;
    beacon_server_tick(&f.server, f.now);
    check(f.server.stats.entries == 0, "entries expire after 60 s");
    m = make_meet(2, 2);
    send_message(&f, BeaconSocket::PRIMARY, &client, &m);
    check(reply(&f, 0, &r) && r.type == BeaconType::NOT_FOUND, "an expired id is NOT_FOUND");

    // The cookie from 61 s ago (epoch before last at most... one epoch back) still works.
    BeaconMessage reg = make_register(3, cookie, 10, 4);
    send_message(&f, BeaconSocket::PRIMARY, &host, &reg);
    check(reply(&f, 0, &r) && r.type == BeaconType::REGISTERED_REPLY && r.id_count == 4,
          "a 61 s old cookie still works, and expired entries no longer count against the source");

    // 121 s later without using the fresh one: refused.
    f.now += 121000;
    beacon_server_tick(&f.server, f.now);
    send_message(&f, BeaconSocket::PRIMARY, &host, &reg);
    check(reply(&f, 0, &r) && r.type == BeaconType::COOKIE, "a cookie older than two epochs is refused");
    beacon_server_destroy(&f.server);
}

static void test_limits()
{
    Fixture f;
    BeaconServerConfig config = {};
    config.max_ids_per_source = 10;
    config.max_entries = 14;
    check(fixture_create(&f, &config), "server creates");
    BeaconAddress host = ipv4(203, 0, 113, 4, 40000);
    BeaconAddress same_ip = ipv4(203, 0, 113, 4, 40001);
    BeaconAddress host2 = ipv4(203, 0, 113, 5, 40000);

    check(register_ids(&f, &host, 1, 8, nullptr) == 8, "8 ids accepted");
    check(register_ids(&f, &same_ip, 9, 8, nullptr) == 2, "the per-source limit counts the IPv4 address, not the port");
    check(f.server.stats.ids_refused_source == 6, "6 refused by the source limit");
    check(register_ids(&f, &host2, 100, 8, nullptr) == 4, "the table cap stops the rest");
    check(f.server.stats.entries == 14, "the table holds max_entries");
    beacon_server_destroy(&f.server);

    // IPv6: one /64 is one source.
    check(fixture_create(&f, &config), "server creates");
    BeaconAddress a = ipv6(1, 7, 1000);
    BeaconAddress b = ipv6(2, 7, 1000);
    BeaconAddress c = ipv6(1, 8, 1000);
    check(register_ids(&f, &a, 1, 8, nullptr) == 8, "IPv6 host a: 8 ids");
    check(register_ids(&f, &b, 20, 8, nullptr) == 2, "another address in the same /64 shares the limit");
    check(register_ids(&f, &c, 40, 4, nullptr) == 4, "another /64 has its own limit");
    beacon_server_destroy(&f.server);
}

static void test_rate_limit()
{
    Fixture f;
    BeaconServerConfig config = {};
    config.rate_per_second = 10;
    config.burst = 20;
    check(fixture_create(&f, &config), "server creates");
    BeaconAddress client = ipv4(198, 51, 100, 10, 50000);
    BeaconAddress other = ipv4(198, 51, 100, 11, 50000);
    BeaconMessage bind = {};
    bind.type = BeaconType::BIND;
    uint32_t answered = 0;
    for (uint32_t i = 0; i < 50; i++)
    {
        send_message(&f, BeaconSocket::PRIMARY, &client, &bind);
        answered += f.out.count;
    }
    check(answered == 20, "a source gets its burst, then nothing");
    send_message(&f, BeaconSocket::PRIMARY, &other, &bind);
    check(f.out.count == 1, "another source isn't affected");
    f.now += 500;
    answered = 0;
    for (uint32_t i = 0; i < 50; i++)
    {
        send_message(&f, BeaconSocket::PRIMARY, &client, &bind);
        answered += f.out.count;
    }
    check(answered == 5, "half a second refills half the rate");
    beacon_server_destroy(&f.server);

    // A full source table: newcomers share the overflow bucket.
    config = BeaconServerConfig{};
    config.max_sources = 4;
    config.overflow_rate_per_second = 3;
    check(fixture_create(&f, &config), "server creates");
    for (uint8_t i = 0; i < 4; i++)
    {
        BeaconAddress source = ipv4(10, 0, 0, i, 1000);
        send_message(&f, BeaconSocket::PRIMARY, &source, &bind);
    }
    check(f.server.stats.sources == 4, "four sources in the table");
    answered = 0;
    for (uint8_t i = 10; i < 20; i++)
    {
        BeaconAddress source = ipv4(10, 0, 0, i, 1000);
        send_message(&f, BeaconSocket::PRIMARY, &source, &bind);
        answered += f.out.count;
    }
    check(answered == 3, "sources that don't fit share the overflow bucket");
    // Quiet sources owning nothing leave the table after a while.
    f.now += BEACON_SOURCE_IDLE_MS;
    beacon_server_tick(&f.server, f.now);
    check(f.server.stats.sources == 0, "idle sources are freed");
    beacon_server_destroy(&f.server);
}

static void test_families_and_rebinding()
{
    Fixture f;
    BeaconServerConfig config = {};
    check(fixture_create(&f, &config), "server creates");
    BeaconAddress host4 = ipv4(203, 0, 113, 6, 40000);
    BeaconAddress host6 = ipv6(6, 1, 40000);
    BeaconAddress client4 = ipv4(198, 51, 100, 6, 50000);
    BeaconAddress client6 = ipv6(9, 2, 50000);
    check(register_ids(&f, &host4, 500, 1, nullptr) == 1, "registered over IPv4");
    check(register_ids(&f, &host6, 500, 1, nullptr) == 1, "the same id registered over IPv6");
    check(f.server.stats.entries == 2, "one entry per family");

    BeaconMessage m = make_meet(1, 500);
    BeaconMessage r;
    send_message(&f, BeaconSocket::PRIMARY, &client4, &m);
    check(reply(&f, 0, &r) && beacon_address_equal(&r.address, &host4), "an IPv4 client gets the IPv4 entry");
    send_message(&f, BeaconSocket::PRIMARY, &client6, &m);
    check(reply(&f, 0, &r) && beacon_address_equal(&r.address, &host6), "an IPv6 client gets the IPv6 entry");

    // Only IPv6 registered: an IPv4 client still gets it.
    check(register_ids(&f, &host6, 600, 1, nullptr) == 1, "IPv6-only id");
    m = make_meet(2, 600);
    send_message(&f, BeaconSocket::PRIMARY, &client4, &m);
    check(reply(&f, 0, &r) && r.type == BeaconType::INTRO && beacon_address_equal(&r.address, &host6),
          "the other family is the fallback");

    // NAT rebinding: the host's port changes, the entry follows.
    BeaconAddress host4_moved = ipv4(203, 0, 113, 6, 40999);
    check(register_ids(&f, &host4_moved, 500, 1, nullptr) == 1, "re-registered from a new port");
    check(f.server.stats.entries == 3, "moving doesn't add an entry");
    f.now += BEACON_INTRO_INTERVAL_MS;
    m = make_meet(3, 500);
    send_message(&f, BeaconSocket::PRIMARY, &client4, &m);
    check(reply(&f, 0, &r) && beacon_address_equal(&r.address, &host4_moved), "INTRO gives the new address");

    // Moving to another source moves the count too.
    BeaconAddress host4_new_ip = ipv4(192, 0, 2, 50, 40000);
    check(register_ids(&f, &host4_new_ip, 500, 1, nullptr) == 1, "re-registered from a new IP");
    f.now += 61000;
    beacon_server_tick(&f.server, f.now);
    check(f.server.stats.entries == 0, "all expired");
    f.now += BEACON_SOURCE_IDLE_MS;
    beacon_server_tick(&f.server, f.now);
    check(f.server.stats.sources == 0, "every source's count went back to zero (all sources freed)");
    beacon_server_destroy(&f.server);
}

static void test_public_address()
{
    Fixture f;
    BeaconServerConfig config = {};
    config.has_public_ipv4 = true;
    config.public_ipv4 = ipv4(203, 0, 113, 200, 0);
    config.has_public_ipv6 = true;
    config.public_ipv6 = ipv6(1, 0xff, 0);
    check(fixture_create(&f, &config), "server creates");

    BeaconMessage bind = {};
    bind.type = BeaconType::BIND;
    BeaconMessage r;

    // Private senders are reported with the public address and their own port;
    // the reply still goes to their real address.
    BeaconAddress lan = ipv4(192, 168, 1, 5, 41000);
    send_message(&f, BeaconSocket::PRIMARY, &lan, &bind);
    BeaconAddress expected = ipv4(203, 0, 113, 200, 41000);
    check(reply(&f, 0, &r) && beacon_address_equal(&r.address, &expected), "192.168/16 is reported as public");
    check(beacon_address_equal(&f.out.packets[0].to, &lan), "the BOUND goes to the real address");

    BeaconAddress privates[] = {ipv4(10, 1, 2, 3, 1000), ipv4(172, 20, 0, 1, 1000), ipv4(100, 64, 9, 9, 1000),
                                ipv4(127, 0, 0, 1, 1000), ipv4(169, 254, 1, 1, 1000)};
    for (uint32_t i = 0; i < 5; i++)
    {
        send_message(&f, BeaconSocket::PRIMARY, &privates[i], &bind);
        expected = ipv4(203, 0, 113, 200, 1000);
        check(reply(&f, 0, &r) && beacon_address_equal(&r.address, &expected), "private IPv4 ranges are replaced");
    }
    BeaconAddress publics[] = {ipv4(172, 32, 0, 1, 1000), ipv4(100, 128, 0, 1, 1000), ipv4(198, 51, 100, 1, 1000),
                               ipv4(11, 0, 0, 1, 1000)};
    for (uint32_t i = 0; i < 4; i++)
    {
        send_message(&f, BeaconSocket::PRIMARY, &publics[i], &bind);
        check(reply(&f, 0, &r) && beacon_address_equal(&r.address, &publics[i]), "public IPv4 addresses are kept");
    }

    BeaconAddress ula = {};
    ula.ip[0] = 0xfd;
    ula.ip[15] = 5;
    ula.port = 2000;
    send_message(&f, BeaconSocket::PRIMARY, &ula, &bind);
    expected = ipv6(1, 0xff, 2000);
    check(reply(&f, 0, &r) && beacon_address_equal(&r.address, &expected), "an IPv6 ULA is reported as public IPv6");
    BeaconAddress global6 = ipv6(7, 3, 2000);
    send_message(&f, BeaconSocket::PRIMARY, &global6, &bind);
    check(reply(&f, 0, &r) && beacon_address_equal(&r.address, &global6), "a global IPv6 address is kept");

    // A host on the server's LAN, a client outside.
    BeaconAddress host = ipv4(10, 0, 0, 7, 40000);
    BeaconAddress client = ipv4(198, 51, 100, 9, 50000);
    check(register_ids(&f, &host, 700, 1, nullptr) == 1, "a LAN host registers");
    BeaconMessage m = make_meet(1, 700);
    send_message(&f, BeaconSocket::PRIMARY, &client, &m);
    BeaconMessage to_client;
    BeaconMessage to_host;
    check(f.out.count == 2 && reply(&f, 0, &to_client) && reply(&f, 1, &to_host), "MEET gets two INTROs");
    expected = ipv4(203, 0, 113, 200, 40000);
    check(beacon_address_equal(&to_client.address, &expected), "the client is given the host's public address");
    check(beacon_address_equal(&f.out.packets[1].to, &host), "the host's INTRO goes to its real address");
    check(beacon_address_equal(&to_host.address, &client), "the host is given the client's address");

    // A client on the LAN, the host outside: the host gets the public address.
    BeaconAddress host2 = ipv4(198, 51, 100, 20, 40000);
    BeaconAddress lan_client = ipv4(192, 168, 1, 30, 50001);
    check(register_ids(&f, &host2, 800, 1, nullptr) == 1, "an outside host registers");
    m = make_meet(2, 800);
    send_message(&f, BeaconSocket::PRIMARY, &lan_client, &m);
    check(f.out.count == 2 && reply(&f, 1, &to_host), "MEET from the LAN gets INTROs");
    expected = ipv4(203, 0, 113, 200, 50001);
    check(beacon_address_equal(&to_host.address, &expected), "the host is given the LAN client's public address");

    // The LAN host's entry is owned by its real address: everything frees.
    f.now += 61000;
    beacon_server_tick(&f.server, f.now);
    f.now += BEACON_SOURCE_IDLE_MS;
    beacon_server_tick(&f.server, f.now);
    check(f.server.stats.entries == 0 && f.server.stats.sources == 0, "entries and sources free with a public address");
    beacon_server_destroy(&f.server);

    // Without --public-address nothing is replaced.
    BeaconServerConfig plain = {};
    check(fixture_create(&f, &plain), "server creates");
    send_message(&f, BeaconSocket::PRIMARY, &lan, &bind);
    check(reply(&f, 0, &r) && beacon_address_equal(&r.address, &lan), "without the option a private address is kept");
    beacon_server_destroy(&f.server);
}

// A header-only STUN Binding Request, as browsers send them.
static void stun_request(uint8_t packet[20], uint8_t seed)
{
    const uint8_t header[8] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42};
    memcpy(packet, header, 8);
    for (uint32_t i = 8; i < 20; i++)
    {
        packet[i] = static_cast<uint8_t>(seed + i);
    }
}

static void test_stun()
{
    Fixture f;
    BeaconServerConfig config = {};
    config.rate_per_second = 10;
    config.burst = 5;
    config.has_public_ipv4 = true;
    config.public_ipv4 = ipv4(203, 0, 113, 200, 0);
    check(fixture_create(&f, &config), "server creates");

    uint8_t request[20];
    stun_request(request, 1);
    BeaconAddress client = ipv4(198, 51, 100, 7, 41000);
    BeaconSocket sockets[] = {BeaconSocket::PRIMARY, BeaconSocket::SECONDARY, BeaconSocket::STUN};
    for (uint32_t i = 0; i < 3; i++)
    {
        beacon_server_receive(&f.server, f.now, sockets[i], &client, request, sizeof(request), &f.out);
        check(f.out.count == 1 && f.out.packets[0].size == BEACON_STUN_RESPONSE_IPV4_SIZE &&
                  f.out.packets[0].socket == sockets[i] && beacon_address_equal(&f.out.packets[0].to, &client),
              "STUN is answered on every socket, from that socket");
    }
    uint8_t expected[BEACON_STUN_RESPONSE_IPV6_SIZE];
    check(beacon_stun_encode_response(request + 8, &client, expected, sizeof(expected)) == 32 &&
              memcmp(f.out.packets[0].data, expected, 32) == 0,
          "the response maps the sender's address");

    // IPv6 sender: 44 bytes.
    BeaconAddress client6 = ipv6(4, 4, 42000);
    beacon_server_receive(&f.server, f.now, BeaconSocket::PRIMARY, &client6, request, sizeof(request), &f.out);
    check(f.out.count == 1 && f.out.packets[0].size == BEACON_STUN_RESPONSE_IPV6_SIZE, "IPv6 sender: 44 bytes");

    // --public-address applies: a private sender gets the public IP, its own port.
    BeaconAddress lan = ipv4(192, 168, 1, 9, 43000);
    beacon_server_receive(&f.server, f.now, BeaconSocket::PRIMARY, &lan, request, sizeof(request), &f.out);
    BeaconAddress reported = ipv4(203, 0, 113, 200, 43000);
    check(beacon_stun_encode_response(request + 8, &reported, expected, sizeof(expected)) == 32 &&
              f.out.count == 1 && memcmp(f.out.packets[0].data, expected, 32) == 0 &&
              beacon_address_equal(&f.out.packets[0].to, &lan),
          "a private STUN sender gets the public address, the reply goes to its real one");

    // Malformed STUN is dropped and counted.
    uint64_t malformed = f.server.stats.malformed;
    request[1] = 0x11;
    beacon_server_receive(&f.server, f.now, BeaconSocket::PRIMARY, &client, request, sizeof(request), &f.out);
    check(f.out.count == 0 && f.server.stats.malformed == malformed + 1, "a Binding Indication is dropped");
    request[1] = 0x01;

    // The STUN-only socket answers no beacon message.
    BeaconMessage bind = {};
    bind.type = BeaconType::BIND;
    BeaconAddress other = ipv4(198, 51, 100, 8, 41000);
    send_message(&f, BeaconSocket::STUN, &other, &bind);
    check(f.out.count == 0, "BIND on the STUN-only socket is dropped");

    // Same rate limit as everything else: the client used 3 of its burst of 5.
    uint32_t answered = 0;
    for (uint32_t i = 0; i < 10; i++)
    {
        beacon_server_receive(&f.server, f.now, BeaconSocket::PRIMARY, &client, request, sizeof(request), &f.out);
        answered += f.out.count;
    }
    check(answered == 2, "STUN shares the source's rate limit");
    check(f.server.stats.stun == 7, "answered STUN requests are counted");
    beacon_server_destroy(&f.server);
}

static void test_count_hosts()
{
    Fixture f;
    BeaconServerConfig config = {};
    check(fixture_create(&f, &config), "server creates");
    check(beacon_server_count_hosts(&f.server, f.now) == 0, "no hosts at first");

    // Host A over IPv4 with three ids, and over IPv6 with the same ids: one host.
    BeaconAddress a4 = ipv4(198, 51, 100, 1, 40000);
    BeaconAddress a6 = ipv6(1, 1, 40000);
    check(register_ids(&f, &a4, 100, 3, nullptr) == 3, "A registers over IPv4");
    check(register_ids(&f, &a6, 100, 3, nullptr) == 3, "A registers over IPv6");
    check(beacon_server_count_hosts(&f.server, f.now) == 1, "a dual-stack host counts once");

    // Host B behind the same public IPv4 (another port), host C on IPv6 only.
    BeaconAddress b4 = ipv4(198, 51, 100, 1, 40001);
    BeaconAddress c6 = ipv6(9, 2, 50000);
    check(register_ids(&f, &b4, 200, 1, nullptr) == 1, "B registers");
    check(register_ids(&f, &c6, 300, 2, nullptr) == 2, "C registers");
    check(beacon_server_count_hosts(&f.server, f.now) == 3, "hosts behind one IP count separately");

    // A MEET counts in intros_total, which stats_reset leaves alone.
    BeaconMessage m = make_meet(5, 200);
    BeaconAddress client = ipv4(203, 0, 113, 50, 1234);
    send_message(&f, BeaconSocket::PRIMARY, &client, &m);
    beacon_server_stats_reset(&f.server);
    check(f.server.intros_total == 1, "intros_total counts INTROs and survives stats_reset");

    // Expired entries aren't counted even before the sweep frees them.
    f.now += static_cast<uint64_t>(BEACON_ENTRY_TTL_SECONDS) * 1000u;
    check(beacon_server_count_hosts(&f.server, f.now) == 0, "expired hosts aren't counted");
    beacon_server_destroy(&f.server);
}

static void test_status_file()
{
    char text[160];
    size_t size = beacon_status_format(text, sizeof(text), 12, 40, 1795000000);
    const char* expected = "{\"hosts_online\": 12, \"introductions_last_hour\": 40, \"updated\": 1795000000}\n";
    check(size == strlen(expected) && strcmp(text, expected) == 0, "status JSON format");
    check(beacon_status_format(text, 10, 12, 40, 1795000000) == 0, "status JSON that doesn't fit is refused");

    // Written next to the test binary (ctest runs in the build directory).
    BeaconStatus status;
    check(beacon_status_open(&status, "status_test.json", 1), "status opens");
    // Before the ring is full: since the first sample.
    check(beacon_status_update(&status, 3, 100, 1), "status writes");
    check(beacon_status_update(&status, 3, 105, 2), "status writes again");
    FILE* file = fopen("status_test.json", "rb");
    size_t got = 0;
    if (file != nullptr)
    {
        got = fread(text, 1, sizeof(text) - 1, file);
        fclose(file);
    }
    text[got] = '\0';
    check(strstr(text, "\"introductions_last_hour\": 5,") != nullptr, "introductions since the first sample");
    check(strstr(text, "\"hosts_online\": 3,") != nullptr, "hosts_online is written");
    FILE* temp = fopen("status_test.json.tmp", "rb");
    check(temp == nullptr, "no temporary file left behind");
    if (temp != nullptr)
    {
        fclose(temp);
    }
    // A full ring: the last hour is the last 360 updates.
    for (uint64_t i = 0; i < 1000; i++)
    {
        beacon_status_update(&status, 0, 1000 + i * 2, 3 + i);
    }
    file = fopen("status_test.json", "rb");
    got = 0;
    if (file != nullptr)
    {
        got = fread(text, 1, sizeof(text) - 1, file);
        fclose(file);
    }
    text[got] = '\0';
    check(strstr(text, "\"introductions_last_hour\": 720,") != nullptr, "introductions over the last hour");
    remove("status_test.json");
    remove("history.json");

    BeaconStatus bad;
    check(beacon_status_open(&bad, "/nonexistent-dir/status.json", 1), "status opens a bad path");
    check(!beacon_status_update(&bad, 1, 1, 1), "a write that fails returns false");
    check(bad.failing, "a failing write is remembered (logged once)");
}

static void test_bad_config()
{
    BeaconServer server;
    BeaconServerConfig config = {};
    config.max_entries = 0;
    check(!beacon_server_create(&server, &config, 0), "max_entries 0 is refused");
    config = BeaconServerConfig{};
    config.rate_per_second = 0;
    check(!beacon_server_create(&server, &config, 0), "rate 0 is refused");
}

int main()
{
    test_bind();
    test_register_and_meet();
    test_presence();
    test_expiry_and_cookie_age();
    test_limits();
    test_rate_limit();
    test_families_and_rebinding();
    test_public_address();
    test_stun();
    test_count_hosts();
    test_status_file();
    test_bad_config();
    if (g_failures != 0)
    {
        fprintf(stderr, "%u failures\n", g_failures);
        return 1;
    }
    printf("server: all checks passed\n");
    return 0;
}
