// beacon_status: see beacon_status.h.

#include "beacon_status.h"

#include "beacon_log.h"

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>

const char* beacon_status_tier_name(BeaconStatusTier tier)
{
    switch (tier)
    {
    case BeaconStatusTier::week:
        return "week";
    case BeaconStatusTier::month:
        return "month";
    case BeaconStatusTier::year:
        return "year";
    }
    return "week";
}

uint64_t beacon_status_tier_bucket_seconds(BeaconStatusTier tier)
{
    switch (tier)
    {
    case BeaconStatusTier::week:
        return 900;
    case BeaconStatusTier::month:
        return 3600;
    case BeaconStatusTier::year:
        return 86400;
    }
    return 900;
}

uint32_t beacon_status_tier_points(BeaconStatusTier tier)
{
    switch (tier)
    {
    case BeaconStatusTier::week:
        return 672;     // 7 days of 15 minutes
    case BeaconStatusTier::month:
        return 720;     // 30 days of hours
    case BeaconStatusTier::year:
        return 366;     // a year of days, leap years included
    }
    return 672;
}

static BeaconStatusTier tier_at(uint32_t index)
{
    return static_cast<BeaconStatusTier>(index);
}

// How far back a tier's points go.
static uint64_t tier_span_seconds(BeaconStatusTier tier)
{
    return beacon_status_tier_bucket_seconds(tier) * beacon_status_tier_points(tier);
}

// A point is shown while its bucket started less than the span ago.
static bool point_in_span(BeaconStatusTier tier, uint64_t start, uint64_t unix_seconds)
{
    uint64_t span = tier_span_seconds(tier);
    return start <= unix_seconds && unix_seconds - start < span;
}

static void ring_clear(BeaconStatusRing* ring)
{
    ring->count = 0;
    ring->first = 0;
}

static BeaconStatusPoint* ring_newest(BeaconStatusRing* ring, uint32_t capacity)
{
    if (ring->count == 0)
    {
        return nullptr;
    }
    return &ring->points[(ring->first + ring->count - 1) % capacity];
}

// Appends a point; a full ring drops its oldest.
static void ring_push(BeaconStatusRing* ring, uint32_t capacity, const BeaconStatusPoint* point)
{
    if (ring->count < capacity)
    {
        ring->points[(ring->first + ring->count) % capacity] = *point;
        ring->count++;
        return;
    }
    ring->points[ring->first] = *point;
    ring->first = (ring->first + 1) % capacity;
}

static uint32_t saturating_add(uint32_t a, uint64_t b)
{
    uint64_t sum = static_cast<uint64_t>(a) + b;
    return sum > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(sum);
}

// Folds one update into the tier's bucket for `unix_seconds`. Returns true
// if that started a new bucket.
static bool ring_record(BeaconStatusRing* ring, BeaconStatusTier tier, uint32_t hosts, uint64_t introductions,
                        uint64_t unix_seconds)
{
    uint64_t bucket = beacon_status_tier_bucket_seconds(tier);
    uint32_t capacity = beacon_status_tier_points(tier);
    uint64_t start = unix_seconds - unix_seconds % bucket;
    BeaconStatusPoint* newest = ring_newest(ring, capacity);
    // A clock that went back keeps adding to the newest bucket rather than
    // putting points out of order.
    if (newest != nullptr && newest->start >= start)
    {
        if (hosts > newest->hosts)
        {
            newest->hosts = hosts;
        }
        newest->introductions = saturating_add(newest->introductions, introductions);
        return false;
    }
    BeaconStatusPoint point = {
        .start = start,
        .hosts = hosts,
        .introductions = saturating_add(0, introductions),
    };
    ring_push(ring, capacity, &point);
    return true;
}

// --- history.json, written ------------------------------------------------

static void append_text(std::string* out, const char* text)
{
    out->append(text);
}

void beacon_status_format_history(const BeaconStatus* status, uint64_t unix_seconds, std::string* out)
{
    char piece[96];
    out->clear();
    snprintf(piece, sizeof(piece), "{\"updated\": %" PRIu64, unix_seconds);
    append_text(out, piece);
    for (uint32_t t = 0; t < BEACON_STATUS_TIER_COUNT; t++)
    {
        BeaconStatusTier tier = tier_at(t);
        const BeaconStatusRing* ring = &status->rings[t];
        uint32_t capacity = beacon_status_tier_points(tier);
        snprintf(piece, sizeof(piece), ",\n\"%s\": {\"bucket_seconds\": %" PRIu64 ", \"points\": [",
                 beacon_status_tier_name(tier), beacon_status_tier_bucket_seconds(tier));
        append_text(out, piece);
        bool first = true;
        for (uint32_t i = 0; i < ring->count; i++)
        {
            const BeaconStatusPoint* point = &ring->points[(ring->first + i) % capacity];
            if (!point_in_span(tier, point->start, unix_seconds))
            {
                continue;
            }
            snprintf(piece, sizeof(piece), "%s[%" PRIu64 ", %" PRIu32 ", %" PRIu32 "]", first ? "" : ", ",
                     point->start, point->hosts, point->introductions);
            append_text(out, piece);
            first = false;
        }
        append_text(out, "]}");
    }
    append_text(out, "}\n");
}

// --- history.json, read back ----------------------------------------------
// A small strict reader for exactly the shape written above (whitespace
// anywhere between tokens). Nothing else in the file is accepted, so a file
// edited by hand or cut short starts the history over instead of half-loading.

struct Reader
{
    const char* at = nullptr;
    const char* end = nullptr;
};

static void reader_skip_space(Reader* reader)
{
    while (reader->at < reader->end &&
           (*reader->at == ' ' || *reader->at == '\n' || *reader->at == '\r' || *reader->at == '\t'))
    {
        reader->at++;
    }
}

static bool reader_char(Reader* reader, char expected)
{
    reader_skip_space(reader);
    if (reader->at >= reader->end || *reader->at != expected)
    {
        return false;
    }
    reader->at++;
    return true;
}

// A quoted key and its colon: "name":
static bool reader_key(Reader* reader, const char* name)
{
    if (!reader_char(reader, '"'))
    {
        return false;
    }
    size_t length = strlen(name);
    if (static_cast<size_t>(reader->end - reader->at) < length + 1 || memcmp(reader->at, name, length) != 0 ||
        reader->at[length] != '"')
    {
        return false;
    }
    reader->at += length + 1;
    return reader_char(reader, ':');
}

// A non-negative integer without sign, fraction or leading zeros, that fits
// in 64 bits.
static bool reader_number(Reader* reader, uint64_t* value)
{
    reader_skip_space(reader);
    const char* start = reader->at;
    uint64_t number = 0;
    while (reader->at < reader->end && *reader->at >= '0' && *reader->at <= '9')
    {
        uint64_t digit = static_cast<uint64_t>(*reader->at - '0');
        if (number > (UINT64_MAX - digit) / 10)
        {
            return false;
        }
        number = number * 10 + digit;
        reader->at++;
    }
    size_t digits = static_cast<size_t>(reader->at - start);
    if (digits == 0 || (digits > 1 && *start == '0'))
    {
        return false;
    }
    *value = number;
    return true;
}

// [start, hosts, introductions]
static bool reader_point(Reader* reader, uint64_t* start, uint64_t* hosts, uint64_t* introductions)
{
    return reader_char(reader, '[') && reader_number(reader, start) && reader_char(reader, ',') &&
           reader_number(reader, hosts) && reader_char(reader, ',') && reader_number(reader, introductions) &&
           reader_char(reader, ']');
}

// "name": {"bucket_seconds": N, "points": [...]}, keeping the points that
// make sense now.
static bool reader_tier(Reader* reader, BeaconStatusTier tier, BeaconStatusRing* ring, uint64_t unix_seconds)
{
    uint64_t bucket = 0;
    if (!reader_key(reader, beacon_status_tier_name(tier)) || !reader_char(reader, '{') ||
        !reader_key(reader, "bucket_seconds") || !reader_number(reader, &bucket) ||
        bucket != beacon_status_tier_bucket_seconds(tier) || !reader_char(reader, ',') ||
        !reader_key(reader, "points") || !reader_char(reader, '['))
    {
        return false;
    }
    uint32_t capacity = beacon_status_tier_points(tier);
    bool has_previous = false;
    uint64_t previous = 0;
    if (reader_char(reader, ']'))
    {
        return reader_char(reader, '}');
    }
    while (true)
    {
        uint64_t start = 0;
        uint64_t hosts = 0;
        uint64_t introductions = 0;
        if (!reader_point(reader, &start, &hosts, &introductions))
        {
            return false;
        }
        bool ordered = !has_previous || start > previous;
        if (ordered && start % bucket == 0 && point_in_span(tier, start, unix_seconds) && hosts <= UINT32_MAX &&
            introductions <= UINT32_MAX)
        {
            BeaconStatusPoint point = {
                .start = start,
                .hosts = static_cast<uint32_t>(hosts),
                .introductions = static_cast<uint32_t>(introductions),
            };
            ring_push(ring, capacity, &point);
            has_previous = true;
            previous = start;
        }
        if (reader_char(reader, ']'))
        {
            return reader_char(reader, '}');
        }
        if (!reader_char(reader, ','))
        {
            return false;
        }
    }
}

bool beacon_status_parse_history(BeaconStatus* status, const char* text, size_t size, uint64_t unix_seconds)
{
    for (uint32_t t = 0; t < BEACON_STATUS_TIER_COUNT; t++)
    {
        ring_clear(&status->rings[t]);
    }
    Reader reader = {.at = text, .end = text + size};
    uint64_t updated = 0;
    bool ok = reader_char(&reader, '{') && reader_key(&reader, "updated") && reader_number(&reader, &updated);
    for (uint32_t t = 0; ok && t < BEACON_STATUS_TIER_COUNT; t++)
    {
        ok = reader_char(&reader, ',') && reader_tier(&reader, tier_at(t), &status->rings[t], unix_seconds);
    }
    ok = ok && reader_char(&reader, '}');
    reader_skip_space(&reader);
    ok = ok && reader.at == reader.end;
    if (!ok)
    {
        for (uint32_t t = 0; t < BEACON_STATUS_TIER_COUNT; t++)
        {
            ring_clear(&status->rings[t]);
        }
    }
    return ok;
}

// --- Files ----------------------------------------------------------------

// Removes the temporary file without losing the errno of what failed.
static bool fail_and_unlink(const std::string* temp_path)
{
    int saved = errno;
    unlink(temp_path->c_str());
    errno = saved;
    return false;
}

// Writes `text` to `temp_path` and renames it over `path`.
static bool write_file(const std::string* path, const std::string* temp_path, const char* text, size_t size)
{
    int fd = open(temp_path->c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        return false;
    }
    size_t done = 0;
    while (done < size)
    {
        ssize_t wrote = write(fd, text + done, size - done);
        if (wrote < 0 && errno == EINTR)
        {
            continue;
        }
        if (wrote <= 0)
        {
            if (wrote == 0)
            {
                errno = EIO;
            }
            int saved = errno;
            close(fd);
            errno = saved;
            return fail_and_unlink(temp_path);
        }
        done += static_cast<size_t>(wrote);
    }
    if (close(fd) != 0 || rename(temp_path->c_str(), path->c_str()) != 0)
    {
        return fail_and_unlink(temp_path);
    }
    return true;
}

// Logs the first failure and the first success after failures, not every one.
static void note_result(bool ok, bool* failing, const std::string* path)
{
    if (!ok && !*failing)
    {
        beacon_log(BeaconLogLevel::warning, "can't write %s: %s", path->c_str(), strerror(errno));
    }
    else if (ok && *failing)
    {
        beacon_log(BeaconLogLevel::info, "%s written again", path->c_str());
    }
    *failing = !ok;
}

static bool write_history(BeaconStatus* status, uint64_t unix_seconds)
{
    beacon_status_format_history(status, unix_seconds, &status->text);
    bool ok = write_file(&status->history_path, &status->history_temp_path, status->text.data(),
                         status->text.size());
    note_result(ok, &status->history_failing, &status->history_path);
    if (ok)
    {
        status->history_written = true;
        status->history_dirty = false;
    }
    return ok;
}

// Reads history.json back, if there is one.
static void load_history(BeaconStatus* status, uint64_t unix_seconds)
{
    FILE* file = fopen(status->history_path.c_str(), "rb");
    if (file == nullptr)
    {
        return;
    }
    // One byte more than the limit tells a file that's too big from one
    // that fits exactly.
    char* buffer = new char[BEACON_STATUS_HISTORY_MAX_FILE + 1];
    size_t size = fread(buffer, 1, BEACON_STATUS_HISTORY_MAX_FILE + 1, file);
    fclose(file);
    if (size > BEACON_STATUS_HISTORY_MAX_FILE)
    {
        beacon_log(BeaconLogLevel::warning, "%s is too big, history starts over", status->history_path.c_str());
    }
    else if (!beacon_status_parse_history(status, buffer, size, unix_seconds))
    {
        beacon_log(BeaconLogLevel::warning, "%s isn't readable, history starts over",
                   status->history_path.c_str());
    }
    else
    {
        beacon_log(BeaconLogLevel::info, "history read back: %" PRIu32 " / %" PRIu32 " / %" PRIu32 " points",
                   status->rings[0].count, status->rings[1].count, status->rings[2].count);
    }
    delete[] buffer;
}

bool beacon_status_open(BeaconStatus* status, const char* path, uint64_t unix_seconds)
{
    *status = BeaconStatus{};
    if (path == nullptr || path[0] == '\0')
    {
        return false;
    }
    status->path = path;
    status->temp_path = status->path + ".tmp";
    size_t slash = status->path.rfind('/');
    std::string directory = slash == std::string::npos ? std::string() : status->path.substr(0, slash + 1);
    status->history_path = directory + "history.json";
    if (status->history_path == status->path)
    {
        // A status file called history.json: keep the two apart.
        status->history_path = directory + "history-points.json";
    }
    status->history_temp_path = status->history_path + ".tmp";
    status->text.reserve(BEACON_STATUS_HISTORY_MAX_FILE);
    load_history(status, unix_seconds);
    return true;
}

size_t beacon_status_format(char* out, size_t capacity, uint32_t hosts_online, uint64_t introductions_last_hour,
                            uint64_t unix_seconds)
{
    int written = snprintf(out, capacity,
                           "{\"hosts_online\": %" PRIu32 ", \"introductions_last_hour\": %" PRIu64
                           ", \"updated\": %" PRIu64 "}\n",
                           hosts_online, introductions_last_hour, unix_seconds);
    if (written <= 0 || static_cast<size_t>(written) >= capacity)
    {
        return 0;
    }
    return static_cast<size_t>(written);
}

bool beacon_status_update(BeaconStatus* status, uint32_t hosts_online, uint64_t intros_total,
                          uint64_t unix_seconds)
{
    // The ring holds the last HOUR_SAMPLES + 1 values; the oldest one is an
    // hour ago once it's full (before that: since start).
    constexpr uint32_t slots = BEACON_STATUS_HOUR_SAMPLES + 1;
    status->samples[status->next_sample] = intros_total;
    status->next_sample = (status->next_sample + 1) % slots;
    if (status->sample_count < slots)
    {
        status->sample_count++;
    }
    uint32_t oldest = status->sample_count < slots ? 0 : status->next_sample;
    uint64_t last_hour = intros_total - status->samples[oldest];

    // Introductions since the previous update go into the history.
    uint64_t new_intros = 0;
    if (status->has_last_intros && intros_total >= status->last_intros_total)
    {
        new_intros = intros_total - status->last_intros_total;
    }
    status->last_intros_total = intros_total;
    status->has_last_intros = true;
    bool new_bucket = false;
    for (uint32_t t = 0; t < BEACON_STATUS_TIER_COUNT; t++)
    {
        bool started = ring_record(&status->rings[t], tier_at(t), hosts_online, new_intros, unix_seconds);
        if (t == static_cast<uint32_t>(BeaconStatusTier::week) && started)
        {
            new_bucket = true;
        }
    }
    status->history_dirty = true;
    if (new_bucket || !status->history_written)
    {
        write_history(status, unix_seconds);
    }

    char text[160];
    size_t size = beacon_status_format(text, sizeof(text), hosts_online, last_hour, unix_seconds);
    bool ok = size != 0 && write_file(&status->path, &status->temp_path, text, size);
    note_result(ok, &status->failing, &status->path);
    return ok;
}

bool beacon_status_flush(BeaconStatus* status, uint64_t unix_seconds)
{
    if (!status->history_dirty)
    {
        return true;
    }
    return write_history(status, unix_seconds);
}

uint64_t beacon_unix_seconds()
{
    timespec now = {};
    clock_gettime(CLOCK_REALTIME, &now);
    return now.tv_sec > 0 ? static_cast<uint64_t>(now.tv_sec) : 0;
}
