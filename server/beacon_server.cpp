// beacon_server: see beacon_server.h and PROTOCOL.md.

#include "beacon_server.h"

#include "beacon_log.h"
#include "beacon_random.h"

#include <monocypher.h>

#include <cstring>

static constexpr uint32_t NO_SLOT = 0xffffffffu;
static constexpr uint32_t MILLI = 1000;

// ---------------------------------------------------------------------------
// Hashing and sizes
// ---------------------------------------------------------------------------

static uint32_t table_slots_for(uint32_t items)
{
    uint32_t slots = 64;
    while (slots < 2u * items)
    {
        slots *= 2;
    }
    return slots;
}

// Keyed BLAKE2b, so the home slots can't be predicted from outside.
static uint32_t keyed_slot(const BeaconServer* server, const uint8_t* data, size_t size, uint32_t mask)
{
    uint8_t hash[8];
    crypto_blake2b_keyed(hash, sizeof(hash), server->hash_key, sizeof(server->hash_key), data, size);
    uint32_t value = static_cast<uint32_t>(hash[0]) | (static_cast<uint32_t>(hash[1]) << 8) |
                     (static_cast<uint32_t>(hash[2]) << 16) | (static_cast<uint32_t>(hash[3]) << 24);
    return value & mask;
}

// The source a rate limit and the per-source id limit apply to: the whole
// IPv4 address, or the IPv6 /64 (one home or one machine usually gets a whole
// /64, so counting single IPv6 addresses would be no limit at all).
static void source_key(const BeaconAddress* address, uint8_t key[16])
{
    memcpy(key, address->ip, 16);
    if (!beacon_address_is_ipv4(address))
    {
        memset(key + 8, 0, 8);
    }
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

static void cookie_compute(const BeaconServer* server, const BeaconAddress* address, uint64_t epoch,
                           uint8_t cookie[BEACON_COOKIE_SIZE])
{
    // ip (16) | port LE (2) | epoch LE (8), keyed with that epoch's secret.
    uint8_t message[26];
    memcpy(message, address->ip, 16);
    message[16] = static_cast<uint8_t>(address->port & 0xffu);
    message[17] = static_cast<uint8_t>(address->port >> 8);
    for (uint32_t i = 0; i < 8; i++)
    {
        message[18 + i] = static_cast<uint8_t>((epoch >> (8 * i)) & 0xffu);
    }
    const uint8_t* secret = server->secrets[epoch & 1];
    crypto_blake2b_keyed(cookie, BEACON_COOKIE_SIZE, secret, 32, message, sizeof(message));
}

static bool cookie_valid(const BeaconServer* server, const BeaconAddress* address,
                         const uint8_t cookie[BEACON_COOKIE_SIZE])
{
    uint8_t zero[BEACON_COOKIE_SIZE] = {};
    if (crypto_verify16(cookie, zero) == 0)
    {
        return false;
    }
    uint8_t expected[BEACON_COOKIE_SIZE];
    cookie_compute(server, address, server->epoch, expected);
    if (crypto_verify16(cookie, expected) == 0)
    {
        return true;
    }
    if (server->epoch == 0)
    {
        return false;
    }
    cookie_compute(server, address, server->epoch - 1, expected);
    return crypto_verify16(cookie, expected) == 0;
}

// ---------------------------------------------------------------------------
// Token buckets
// ---------------------------------------------------------------------------

static bool bucket_take(uint32_t* tokens_milli, uint64_t* last_ms, uint64_t now_ms, uint32_t rate, uint32_t burst)
{
    uint64_t full = static_cast<uint64_t>(burst) * MILLI;
    if (now_ms > *last_ms)
    {
        // rate tokens per second = rate milli-tokens per ms. The elapsed time is
        // capped so the product can't overflow after a long quiet time.
        uint64_t elapsed = now_ms - *last_ms;
        if (elapsed > 3600000)
        {
            elapsed = 3600000;
        }
        uint64_t tokens = *tokens_milli + elapsed * rate;
        *tokens_milli = static_cast<uint32_t>(tokens > full ? full : tokens);
        *last_ms = now_ms;
    }
    if (*tokens_milli < MILLI)
    {
        return false;
    }
    *tokens_milli -= MILLI;
    return true;
}

// ---------------------------------------------------------------------------
// Source table
// ---------------------------------------------------------------------------

static bool source_reusable(const BeaconSource* source, uint64_t now_ms)
{
    if (source->used == 0)
    {
        return true;
    }
    return source->entries == 0 && now_ms - source->last_ms >= BEACON_SOURCE_IDLE_MS;
}

static uint32_t source_find(const BeaconServer* server, const uint8_t key[16])
{
    uint32_t home = keyed_slot(server, key, 16, server->source_mask);
    for (uint32_t i = 0; i < BEACON_PROBE_WINDOW; i++)
    {
        uint32_t slot = (home + i) & server->source_mask;
        const BeaconSource* source = &server->sources[slot];
        if (source->used != 0 && memcmp(source->key, key, 16) == 0)
        {
            return slot;
        }
    }
    return NO_SLOT;
}

// The slot of this source, created if there's room; NO_SLOT if there isn't.
static uint32_t source_get(BeaconServer* server, uint64_t now_ms, const BeaconAddress* address)
{
    uint8_t key[16];
    source_key(address, key);
    uint32_t found = source_find(server, key);
    if (found != NO_SLOT)
    {
        return found;
    }
    if (server->stats.sources >= server->config.max_sources)
    {
        // Count only: a full table may still hold reusable (idle) slots, and
        // taking one doesn't raise the count.
        bool any_reusable = false;
        uint32_t home = keyed_slot(server, key, 16, server->source_mask);
        for (uint32_t i = 0; i < BEACON_PROBE_WINDOW && !any_reusable; i++)
        {
            const BeaconSource* s = &server->sources[(home + i) & server->source_mask];
            any_reusable = s->used != 0 && source_reusable(s, now_ms);
        }
        if (!any_reusable)
        {
            return NO_SLOT;
        }
    }
    uint32_t home = keyed_slot(server, key, 16, server->source_mask);
    for (uint32_t i = 0; i < BEACON_PROBE_WINDOW; i++)
    {
        uint32_t slot = (home + i) & server->source_mask;
        BeaconSource* source = &server->sources[slot];
        if (source_reusable(source, now_ms))
        {
            if (source->used == 0)
            {
                server->stats.sources++;
            }
            *source = BeaconSource{};
            memcpy(source->key, key, 16);
            source->used = 1;
            source->last_ms = now_ms;
            source->tokens_milli = server->config.burst * MILLI;
            return slot;
        }
    }
    return NO_SLOT;
}

// The entry at `address` stopped being owned by its source.
static void source_release_entry(BeaconServer* server, const BeaconAddress* address)
{
    uint8_t key[16];
    source_key(address, key);
    uint32_t slot = source_find(server, key);
    // A source owning entries is never reused, so it's always found.
    if (slot != NO_SLOT && server->sources[slot].entries > 0)
    {
        server->sources[slot].entries--;
    }
}

// ---------------------------------------------------------------------------
// Meeting table
// ---------------------------------------------------------------------------

static uint32_t entry_home(const BeaconServer* server, const BeaconId* id, uint8_t ipv4)
{
    uint8_t key[BEACON_ID_SIZE + 1];
    memcpy(key, id->bytes, BEACON_ID_SIZE);
    key[BEACON_ID_SIZE] = ipv4;
    return keyed_slot(server, key, sizeof(key), server->entry_mask);
}

static void entry_free(BeaconServer* server, BeaconEntry* entry)
{
    source_release_entry(server, &entry->address);
    *entry = BeaconEntry{};
    server->stats.entries--;
    server->stats.expired++;
}

// Scans the window of (id, family). Expired entries met on the way are freed
// first (between two sweeps an entry may be up to a second past its expiry).
// Returns the live entry's slot or NO_SLOT; `free_slot` (may be nullptr) gets
// the first free slot of the window or NO_SLOT.
static uint32_t entry_scan(BeaconServer* server, uint64_t now_ms, const BeaconId* id, uint8_t ipv4,
                           uint32_t* free_slot)
{
    uint32_t home = entry_home(server, id, ipv4);
    uint32_t found = NO_SLOT;
    uint32_t first_free = NO_SLOT;
    for (uint32_t i = 0; i < BEACON_PROBE_WINDOW; i++)
    {
        uint32_t slot = (home + i) & server->entry_mask;
        BeaconEntry* entry = &server->entries[slot];
        if (entry->used != 0 && entry->expires_ms <= now_ms)
        {
            entry_free(server, entry);
        }
        if (entry->used == 0)
        {
            if (first_free == NO_SLOT)
            {
                first_free = slot;
            }
            continue;
        }
        if (found == NO_SLOT && entry->ipv4 == ipv4 && beacon_id_equal(&entry->id, id))
        {
            found = slot;
        }
    }
    if (free_slot != nullptr)
    {
        *free_slot = first_free;
    }
    return found;
}

// Stores one id for the host at `from`, owned by source slot `source_slot`.
// Returns true if it's stored (new or refreshed).
static bool entry_register(BeaconServer* server, uint64_t now_ms, const BeaconId* id,
                           const BeaconAddress* from, uint32_t source_slot)
{
    uint8_t ipv4 = beacon_address_is_ipv4(from) ? 1 : 0;
    BeaconSource* owner = &server->sources[source_slot];
    uint64_t expires = now_ms + static_cast<uint64_t>(BEACON_ENTRY_TTL_SECONDS) * 1000u;

    uint32_t free_slot = NO_SLOT;
    uint32_t slot = entry_scan(server, now_ms, id, ipv4, &free_slot);
    if (slot != NO_SLOT)
    {
        BeaconEntry* entry = &server->entries[slot];
        if (!beacon_address_equal(&entry->address, from))
        {
            // The host's NAT gave it a new address (or it moved): the entry
            // moves to it, and to its source if that's another one.
            uint8_t old_key[16];
            source_key(&entry->address, old_key);
            if (memcmp(old_key, owner->key, 16) != 0)
            {
                if (owner->entries >= server->config.max_ids_per_source)
                {
                    server->stats.ids_refused_source++;
                    return false;
                }
                source_release_entry(server, &entry->address);
                owner->entries++;
            }
            entry->address = *from;
        }
        entry->expires_ms = expires;
        return true;
    }

    if (server->stats.entries >= server->config.max_entries || free_slot == NO_SLOT)
    {
        server->stats.ids_refused_full++;
        return false;
    }
    if (owner->entries >= server->config.max_ids_per_source)
    {
        server->stats.ids_refused_source++;
        return false;
    }
    BeaconEntry* entry = &server->entries[free_slot];
    *entry = BeaconEntry{};
    entry->id = *id;
    entry->address = *from;
    entry->used = 1;
    entry->ipv4 = ipv4;
    entry->expires_ms = expires;
    owner->entries++;
    server->stats.entries++;
    return true;
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

static void outbox_add(BeaconOutbox* out, BeaconSocket socket, const BeaconAddress* to,
                       const BeaconMessage* message)
{
    if (out->count >= BEACON_MAX_OUT_PACKETS)
    {
        return;
    }
    BeaconOutPacket* packet = &out->packets[out->count];
    packet->size = beacon_encode(message, packet->data, sizeof(packet->data));
    if (packet->size == 0)
    {
        return;
    }
    packet->socket = socket;
    packet->to = *to;
    out->count++;
}

static void handle_bind(BeaconServer* server, BeaconSocket socket, const BeaconAddress* from,
                        const BeaconMessage* request, BeaconOutbox* out)
{
    server->stats.binds++;
    BeaconMessage reply = {};
    reply.type = BeaconType::BOUND;
    reply.nonce = request->nonce;
    reply.address = *from;
    outbox_add(out, socket, from, &reply);
}

static void handle_register(BeaconServer* server, uint64_t now_ms, const BeaconAddress* from,
                            uint32_t source_slot, const BeaconMessage* request, BeaconOutbox* out)
{
    server->stats.registers++;
    BeaconMessage reply = {};
    reply.nonce = request->nonce;
    if (!cookie_valid(server, from, request->cookie))
    {
        server->stats.cookies_sent++;
        reply.type = BeaconType::COOKIE;
        cookie_compute(server, from, server->epoch, reply.cookie);
        outbox_add(out, BeaconSocket::PRIMARY, from, &reply);
        return;
    }

    uint8_t accepted = 0;
    // A sender sharing the overflow bucket has no source slot, so nothing to
    // count its entries in: it can't register until the table has room.
    if (source_slot != NO_SLOT)
    {
        for (uint32_t i = 0; i < request->id_count; i++)
        {
            if (entry_register(server, now_ms, &request->ids[i], from, source_slot))
            {
                accepted++;
            }
        }
    }
    else
    {
        server->stats.ids_refused_full += request->id_count;
    }
    server->stats.ids_accepted += accepted;
    reply.type = BeaconType::REGISTERED;
    reply.id_count = accepted;
    reply.ttl_seconds = BEACON_ENTRY_TTL_SECONDS;
    cookie_compute(server, from, server->epoch, reply.cookie);
    outbox_add(out, BeaconSocket::PRIMARY, from, &reply);
}

static void handle_meet(BeaconServer* server, uint64_t now_ms, const BeaconAddress* from,
                        const BeaconMessage* request, BeaconOutbox* out)
{
    server->stats.meets++;
    // The host's entry of the client's family first: an IPv4 client can't
    // reach an IPv6 address. The other family is still better than nothing.
    uint8_t ipv4 = beacon_address_is_ipv4(from) ? 1 : 0;
    uint32_t slot = entry_scan(server, now_ms, &request->ids[0], ipv4, nullptr);
    if (slot == NO_SLOT)
    {
        slot = entry_scan(server, now_ms, &request->ids[0], ipv4 != 0 ? 0 : 1, nullptr);
    }

    BeaconMessage reply = {};
    reply.nonce = request->nonce;
    reply.ids[0] = request->ids[0];
    if (slot == NO_SLOT)
    {
        server->stats.not_found++;
        reply.type = BeaconType::NOT_FOUND;
        outbox_add(out, BeaconSocket::PRIMARY, from, &reply);
        return;
    }

    BeaconEntry* entry = &server->entries[slot];
    if (entry->last_intro_ms != 0 && now_ms - entry->last_intro_ms < BEACON_INTRO_INTERVAL_MS)
    {
        server->stats.intro_limited++;
        return;
    }
    entry->last_intro_ms = now_ms;
    server->stats.intros++;

    reply.type = BeaconType::INTRO;
    reply.address = entry->address;
    outbox_add(out, BeaconSocket::PRIMARY, from, &reply);
    // The host proved with its cookie that it receives at this address, so
    // this second packet can't be aimed at a third party.
    reply.address = *from;
    outbox_add(out, BeaconSocket::PRIMARY, &entry->address, &reply);
}

void beacon_server_receive(BeaconServer* server, uint64_t now_ms, BeaconSocket socket,
                               const BeaconAddress* from, const uint8_t* data, size_t size,
                               BeaconOutbox* out)
{
    out->count = 0;
    server->stats.packets++;

    // Decoding is cheaper than the rate limit's hash, and garbage gets no
    // reply anyway, so it's dropped before it can take a source slot.
    BeaconMessage request;
    if (from->port == 0 || !beacon_decode(data, size, &request))
    {
        server->stats.malformed++;
        return;
    }

    bool request_type = request.type == BeaconType::BIND ||
                        (socket == BeaconSocket::PRIMARY &&
                         (request.type == BeaconType::REGISTER || request.type == BeaconType::MEET));
    if (!request_type)
    {
        server->stats.unexpected++;
        return;
    }

    uint32_t source_slot = source_get(server, now_ms, from);
    bool allowed = false;
    if (source_slot != NO_SLOT)
    {
        BeaconSource* source = &server->sources[source_slot];
        allowed = bucket_take(&source->tokens_milli, &source->last_ms, now_ms, server->config.rate_per_second,
                              server->config.burst);
    }
    else
    {
        allowed = bucket_take(&server->overflow.tokens_milli, &server->overflow.last_ms, now_ms,
                              server->config.overflow_rate_per_second, server->config.overflow_rate_per_second);
    }
    if (!allowed)
    {
        server->stats.rate_limited++;
        return;
    }

    switch (request.type)
    {
        case BeaconType::BIND:
            handle_bind(server, socket, from, &request, out);
            break;
        case BeaconType::REGISTER:
            handle_register(server, now_ms, from, source_slot, &request, out);
            break;
        case BeaconType::MEET:
            handle_meet(server, now_ms, from, &request, out);
            break;
        default:
            break;
    }
}

// ---------------------------------------------------------------------------
// Lifetime and housekeeping
// ---------------------------------------------------------------------------

bool beacon_server_create(BeaconServer* server, const BeaconServerConfig* config, uint64_t now_ms)
{
    *server = BeaconServer{};
    if (config->max_entries < 1 || config->max_entries > BEACON_MAX_TABLE_ITEMS || config->max_sources < 1 ||
        config->max_sources > BEACON_MAX_TABLE_ITEMS || config->max_ids_per_source < 1 ||
        config->max_ids_per_source > 65535 || config->rate_per_second < 1 || config->burst < 1 ||
        config->burst > 1000000 || config->overflow_rate_per_second < 1 || config->overflow_rate_per_second > 1000000)
    {
        beacon_log(BeaconLogLevel::error, "server configuration out of range");
        return false;
    }
    server->config = *config;
    uint32_t entry_slots = table_slots_for(config->max_entries);
    uint32_t source_slots = table_slots_for(config->max_sources);
    server->entries.resize(entry_slots);
    server->sources.resize(source_slots);
    server->entry_mask = entry_slots - 1;
    server->source_mask = source_slots - 1;
    if (!beacon_random_fill(server->hash_key, sizeof(server->hash_key)) ||
        !beacon_random_fill(server->secrets[0], 32) || !beacon_random_fill(server->secrets[1], 32))
    {
        beacon_server_destroy(server);
        return false;
    }
    server->epoch_started_ms = now_ms;
    server->overflow.last_ms = now_ms;
    server->overflow.tokens_milli = config->overflow_rate_per_second * MILLI;
    return true;
}

void beacon_server_destroy(BeaconServer* server)
{
    crypto_wipe(server->secrets, sizeof(server->secrets));
    crypto_wipe(server->hash_key, sizeof(server->hash_key));
    *server = BeaconServer{};
}

void beacon_server_tick(BeaconServer* server, uint64_t now_ms)
{
    while (now_ms - server->epoch_started_ms >= BEACON_COOKIE_EPOCH_MS)
    {
        // The slot of epoch - 1 becomes epoch + 1's: the previous secret is
        // forgotten, the current one becomes the previous one.
        uint8_t fresh[32];
        if (!beacon_random_fill(fresh, sizeof(fresh)))
        {
            // Keep the old epoch: cookies stay valid a bit longer, nothing breaks.
            break;
        }
        server->epoch++;
        memcpy(server->secrets[server->epoch & 1], fresh, sizeof(fresh));
        crypto_wipe(fresh, sizeof(fresh));
        server->epoch_started_ms += BEACON_COOKIE_EPOCH_MS;
    }

    // A full pass over the meeting table: with the default 131072 slots it's a
    // few hundred microseconds, once a second.
    for (size_t i = 0; i < server->entries.size(); i++)
    {
        BeaconEntry* entry = &server->entries[i];
        if (entry->used != 0 && entry->expires_ms <= now_ms)
        {
            entry_free(server, entry);
        }
    }

    // Then the sources that own nothing and have been quiet: their slots go
    // back to the free pool (and out of the count).
    for (size_t i = 0; i < server->sources.size(); i++)
    {
        BeaconSource* source = &server->sources[i];
        if (source->used != 0 && source_reusable(source, now_ms))
        {
            *source = BeaconSource{};
            server->stats.sources--;
        }
    }
}

void beacon_server_stats_reset(BeaconServer* server)
{
    uint32_t entries = server->stats.entries;
    uint32_t sources = server->stats.sources;
    server->stats = BeaconStats{};
    server->stats.entries = entries;
    server->stats.sources = sources;
}

uint64_t beacon_server_table_bytes(const BeaconServer* server)
{
    return static_cast<uint64_t>(server->entries.size()) * sizeof(BeaconEntry) +
           static_cast<uint64_t>(server->sources.size()) * sizeof(BeaconSource);
}
