// beacon_status's history: buckets at three resolutions, history.json written
// and read back, and the reader's strictness.

#include "beacon_status.h"

#include <cstdio>
#include <cstring>
#include <string>

static uint32_t g_failures = 0;

static void check(bool ok, const char* what)
{
    if (!ok)
    {
        fprintf(stderr, "FAIL: %s\n", what);
        g_failures++;
    }
}

// A Monday 00:00 UTC, so every tier's bucket starts here.
constexpr uint64_t T0 = 1794873600;

static const BeaconStatusPoint* newest(const BeaconStatus* status, BeaconStatusTier tier)
{
    const BeaconStatusRing* ring = &status->rings[static_cast<uint32_t>(tier)];
    if (ring->count == 0)
    {
        return nullptr;
    }
    uint32_t capacity = beacon_status_tier_points(tier);
    return &ring->points[(ring->first + ring->count - 1) % capacity];
}

static bool read_file(const char* path, std::string* out)
{
    out->clear();
    FILE* file = fopen(path, "rb");
    if (file == nullptr)
    {
        return false;
    }
    char buffer[4096];
    size_t got = 0;
    while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        out->append(buffer, got);
    }
    fclose(file);
    return true;
}

static void test_tiers_and_files()
{
    remove("status_history_test.json");
    remove("history.json");
    BeaconStatus* status = new BeaconStatus;
    check(beacon_status_open(status, "status_history_test.json", T0), "status opens");
    check(status->history_path == "history.json", "history.json goes next to the status file");

    // Within one 15-minute bucket: the peak hosts and the sum of introductions.
    beacon_status_update(status, 3, 100, T0);
    beacon_status_update(status, 7, 104, T0 + 10);
    beacon_status_update(status, 5, 110, T0 + 20);
    const BeaconStatusPoint* week = newest(status, BeaconStatusTier::week);
    check(week != nullptr && week->start == T0 && week->hosts == 7 && week->introductions == 10,
          "a bucket keeps the peak and the sum (the first update only sets the baseline)");
    check(status->rings[0].count == 1, "one week point so far");

    std::string text;
    check(read_file("history.json", &text), "history.json is written on the first update");
    check(text.find("\"week\": {\"bucket_seconds\": 900, \"points\": [[1794873600, 3, 0]]}") != std::string::npos,
          "the first write has the first point");

    // The next 15 minutes: a new week point, the same hour and day.
    beacon_status_update(status, 2, 115, T0 + 900);
    check(status->rings[0].count == 2, "a new week bucket");
    check(status->rings[1].count == 1 && status->rings[2].count == 1, "same hour, same day");
    const BeaconStatusPoint* month = newest(status, BeaconStatusTier::month);
    check(month != nullptr && month->hosts == 7 && month->introductions == 15, "the hour sums both");
    check(read_file("history.json", &text) &&
              text.find("[1794873600, 7, 10], [1794874500, 2, 5]") != std::string::npos,
          "history.json is written again when a week bucket starts");

    // Read back by a new instance: same points.
    BeaconStatus* again = new BeaconStatus;
    check(beacon_status_open(again, "status_history_test.json", T0 + 950), "status opens again");
    check(again->rings[0].count == 2 && again->rings[1].count == 1 && again->rings[2].count == 1,
          "history read back on start");
    const BeaconStatusPoint* back = newest(again, BeaconStatusTier::week);
    check(back != nullptr && back->start == T0 + 900 && back->hosts == 2 && back->introductions == 5,
          "the bucket in progress continues after a restart");
    // The restart's first update only sets the baseline: no introductions
    // counted twice, the peak kept.
    beacon_status_update(again, 1, 50, T0 + 960);
    back = newest(again, BeaconStatusTier::week);
    check(back != nullptr && back->hosts == 2 && back->introductions == 5, "a restart doesn't count twice");

    // flush writes only what changed.
    beacon_status_update(again, 9, 53, T0 + 970);
    check(again->history_dirty, "points changed since the write");
    check(beacon_status_flush(again, T0 + 975) && !again->history_dirty, "flush writes the bucket in progress");
    check(read_file("history.json", &text) && text.find("[1794874500, 9, 8]") != std::string::npos,
          "flush wrote the peak and the new introductions");

    delete again;
    delete status;
    remove("status_history_test.json");
    remove("history.json");
}

static void test_rings_wrap_and_age()
{
    BeaconStatus* status = new BeaconStatus;
    // No file: nothing read back.
    check(beacon_status_open(status, "/nonexistent-dir/status.json", T0), "opens with no history");
    for (uint32_t t = 0; t < BEACON_STATUS_TIER_COUNT; t++)
    {
        check(status->rings[t].count == 0, "rings start empty");
    }
    // Eight days of 15-minute updates: the week ring wraps and keeps 672.
    uint64_t intros = 0;
    for (uint64_t i = 0; i < 8 * 96; i++)
    {
        intros += 2;
        beacon_status_update(status, static_cast<uint32_t>(i % 50), intros, T0 + i * 900);
    }
    check(status->rings[0].count == 672, "the week ring holds 7 days");
    check(status->rings[1].count == 8 * 24, "the month ring has 8 days of hours");
    check(status->rings[2].count == 8, "the year ring has 8 days");
    const BeaconStatusPoint* day = newest(status, BeaconStatusTier::year);
    check(day != nullptr && day->introductions == 96 * 2, "a full day sums 96 updates");

    // Formatting drops what's older than each tier's span.
    uint64_t now = T0 + (8 * 96 - 1) * 900;
    std::string text;
    beacon_status_format_history(status, now, &text);
    BeaconStatus* parsed = new BeaconStatus;
    check(beacon_status_parse_history(parsed, text.data(), text.size(), now), "what's written reads back");
    check(parsed->rings[0].count == 672 && parsed->rings[1].count == 8 * 24 && parsed->rings[2].count == 8,
          "every point round-trips");
    std::string again;
    beacon_status_format_history(parsed, now, &again);
    check(again == text, "the round trip is exact");

    // Thirty-one days later the week and month are gone, the year isn't.
    uint64_t later = now + 31 * 86400ull;
    check(beacon_status_parse_history(parsed, text.data(), text.size(), later), "old file reads");
    check(parsed->rings[0].count == 0 && parsed->rings[1].count == 0 && parsed->rings[2].count == 8,
          "points older than their tier's span are dropped");

    delete parsed;
    delete status;
}

static void test_parser_strict()
{
    BeaconStatus* status = new BeaconStatus;
    const char* good =
        "{\"updated\": 1794874000,\n"
        "\"week\": {\"bucket_seconds\": 900, \"points\": [[1794873600, 4, 1]]},\n"
        "\"month\": {\"bucket_seconds\": 3600, \"points\": []},\n"
        "\"year\": {\"bucket_seconds\": 86400, \"points\": [[1794873600, 4, 1]]}}\n";
    check(beacon_status_parse_history(status, good, strlen(good), T0 + 400), "a good file parses");
    check(status->rings[0].count == 1 && status->rings[1].count == 0 && status->rings[2].count == 1,
          "with its points");

    const char* bad[] = {
        "",
        "{}",
        "{\"updated\": 1}",
        // Wrong bucket size for the tier.
        "{\"updated\": 1, \"week\": {\"bucket_seconds\": 60, \"points\": []},"
        " \"month\": {\"bucket_seconds\": 3600, \"points\": []}, \"year\": {\"bucket_seconds\": 86400, \"points\": []}}",
        // Tiers out of order.
        "{\"updated\": 1, \"month\": {\"bucket_seconds\": 3600, \"points\": []},"
        " \"week\": {\"bucket_seconds\": 900, \"points\": []}, \"year\": {\"bucket_seconds\": 86400, \"points\": []}}",
        // A negative number, a leading zero, a fraction, an overflow.
        "{\"updated\": -1, \"week\": {\"bucket_seconds\": 900, \"points\": []},"
        " \"month\": {\"bucket_seconds\": 3600, \"points\": []}, \"year\": {\"bucket_seconds\": 86400, \"points\": []}}",
        "{\"updated\": 01, \"week\": {\"bucket_seconds\": 900, \"points\": []},"
        " \"month\": {\"bucket_seconds\": 3600, \"points\": []}, \"year\": {\"bucket_seconds\": 86400, \"points\": []}}",
        "{\"updated\": 1.5, \"week\": {\"bucket_seconds\": 900, \"points\": []},"
        " \"month\": {\"bucket_seconds\": 3600, \"points\": []}, \"year\": {\"bucket_seconds\": 86400, \"points\": []}}",
        "{\"updated\": 99999999999999999999, \"week\": {\"bucket_seconds\": 900, \"points\": []},"
        " \"month\": {\"bucket_seconds\": 3600, \"points\": []}, \"year\": {\"bucket_seconds\": 86400, \"points\": []}}",
        // A point with two numbers, a trailing comma, text after the end.
        "{\"updated\": 1, \"week\": {\"bucket_seconds\": 900, \"points\": [[1794873600, 4]]},"
        " \"month\": {\"bucket_seconds\": 3600, \"points\": []}, \"year\": {\"bucket_seconds\": 86400, \"points\": []}}",
        "{\"updated\": 1, \"week\": {\"bucket_seconds\": 900, \"points\": [[1794873600, 4, 1],]},"
        " \"month\": {\"bucket_seconds\": 3600, \"points\": []}, \"year\": {\"bucket_seconds\": 86400, \"points\": []}}",
        "{\"updated\": 1, \"week\": {\"bucket_seconds\": 900, \"points\": []},"
        " \"month\": {\"bucket_seconds\": 3600, \"points\": []}, \"year\": {\"bucket_seconds\": 86400, \"points\": []}} x",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        // Load something first so a failure visibly empties the rings.
        beacon_status_parse_history(status, good, strlen(good), T0 + 400);
        bool ok = beacon_status_parse_history(status, bad[i], strlen(bad[i]), T0 + 400);
        char what[64];
        snprintf(what, sizeof(what), "bad history %zu is refused", i);
        check(!ok, what);
        check(status->rings[0].count == 0 && status->rings[2].count == 0, "a refused file leaves nothing");
    }

    // Parses, but some points are skipped: off a boundary, out of order, from
    // the future, more than 32 bits.
    const char* odd =
        "{\"updated\": 1,\n"
        "\"week\": {\"bucket_seconds\": 900, \"points\": [[1794873601, 1, 1], [1794873600, 2, 2],"
        " [1794873600, 3, 3], [1794874500, 4, 4], [1794999000, 5, 5], [1794875400, 4294967296, 1]]},\n"
        "\"month\": {\"bucket_seconds\": 3600, \"points\": []},\n"
        "\"year\": {\"bucket_seconds\": 86400, \"points\": []}}";
    check(beacon_status_parse_history(status, odd, strlen(odd), T0 + 1000), "odd points still parse");
    check(status->rings[0].count == 2, "only the sensible points are kept");
    delete status;
}

int main()
{
    test_tiers_and_files();
    test_rings_wrap_and_age();
    test_parser_strict();
    if (g_failures != 0)
    {
        fprintf(stderr, "%u failures\n", g_failures);
        return 1;
    }
    printf("status: all checks passed\n");
    return 0;
}
