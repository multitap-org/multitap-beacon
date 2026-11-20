#pragma once

// beacon_status: the --status-file. Every BEACON_STATUS_INTERVAL_MS the
// server writes a small JSON with counts only (no ids, no addresses) for a
// public status page (packaging/status/) served next to it:
//
//     {"hosts_online": 12, "introductions_last_hour": 40, "updated": 1795000000}
//
// Next to it, history.json keeps the same counts over time for the page's
// charts, at three resolutions (BeaconStatusTier). Each point is
// [bucket start (unix seconds), most hosts online in it, introductions in it]:
//
//     {"updated": 1795000000,
//      "week": {"bucket_seconds": 900, "points": [[1794999600, 12, 3], ...]},
//      "month": {"bucket_seconds": 3600, "points": [...]},
//      "year": {"bucket_seconds": 86400, "points": [...]}}
//
// history.json is written when a 15-minute bucket starts and when beacon
// stops (beacon_status_flush), and read back when it starts, so a restart
// keeps the charts. Both files are written to PATH.tmp and renamed over PATH,
// so a reader never sees half of one.

#include <cstddef>
#include <cstdint>
#include <string>

constexpr uint64_t BEACON_STATUS_INTERVAL_MS = 10000;
// One hour of samples, plus the one an hour ago.
constexpr uint32_t BEACON_STATUS_HOUR_SAMPLES = 360;

// The history's resolutions: a week of 15 minutes, 30 days of hours, a year
// of days (UTC days: buckets start at multiples of their size).
enum class BeaconStatusTier : uint32_t
{
    week = 0,
    month = 1,
    year = 2,
};
constexpr uint32_t BEACON_STATUS_TIER_COUNT = 3;
// The largest ring (month: 720 hours).
constexpr uint32_t BEACON_STATUS_MAX_POINTS = 720;
// history.json is about 60 KiB when full; anything much bigger isn't ours.
constexpr size_t BEACON_STATUS_HISTORY_MAX_FILE = 128 * 1024;

const char* beacon_status_tier_name(BeaconStatusTier tier);
uint64_t beacon_status_tier_bucket_seconds(BeaconStatusTier tier);
uint32_t beacon_status_tier_points(BeaconStatusTier tier);

struct BeaconStatusPoint
{
    uint64_t start = 0;             // bucket start, a multiple of the tier's bucket size
    uint32_t hosts = 0;             // the most hosts online seen in the bucket
    uint32_t introductions = 0;     // introductions made in the bucket
};

// One resolution: a ring of points, oldest first from `first`. The newest
// point is the bucket in progress.
struct BeaconStatusRing
{
    BeaconStatusPoint points[BEACON_STATUS_MAX_POINTS];
    uint32_t count = 0;
    uint32_t first = 0;
};

struct BeaconStatus
{
    std::string path;
    std::string temp_path;
    std::string history_path;
    std::string history_temp_path;
    std::string text;               // history.json's text, reused between writes
    // intros_total at every update, oldest overwritten first.
    uint64_t samples[BEACON_STATUS_HOUR_SAMPLES + 1] = {};
    uint32_t sample_count = 0;
    uint32_t next_sample = 0;
    BeaconStatusRing rings[BEACON_STATUS_TIER_COUNT];
    uint64_t last_intros_total = 0; // intros_total at the previous update
    bool has_last_intros = false;
    bool history_written = false;   // history.json written since start
    bool history_dirty = false;     // points changed since history.json was written
    bool failing = false;           // the last status write failed (logged once, not every time)
    bool history_failing = false;   // the same for history.json
};

// `path` is the status file; history.json goes in the same directory and is
// read back if it's there. `unix_seconds` is the wall clock now.
bool beacon_status_open(BeaconStatus* status, const char* path, uint64_t unix_seconds);

// Records `hosts_online` and `intros_total` (the server's counter since
// start) and writes the status file; writes history.json too when a
// 15-minute bucket starts. `unix_seconds` is the wall clock. Returns false if
// the status write failed.
bool beacon_status_update(BeaconStatus* status, uint32_t hosts_online, uint64_t intros_total,
                          uint64_t unix_seconds);

// Writes history.json now if it changed (beacon stopping). Returns false if
// the write failed.
bool beacon_status_flush(BeaconStatus* status, uint64_t unix_seconds);

// The status JSON text into `out`. Returns its length, or 0 if it doesn't fit.
size_t beacon_status_format(char* out, size_t capacity, uint32_t hosts_online, uint64_t introductions_last_hour,
                            uint64_t unix_seconds);

// history.json's text into `out` (replaced): the points still inside their
// tier's span at `unix_seconds`.
void beacon_status_format_history(const BeaconStatus* status, uint64_t unix_seconds, std::string* out);

// Replaces the rings with the points in `text` (history.json as
// beacon_status_format_history writes it). Strict: text in any other shape
// leaves the rings empty and returns false. Points out of order, off a bucket
// boundary, from the future or older than their tier's span are skipped.
bool beacon_status_parse_history(BeaconStatus* status, const char* text, size_t size, uint64_t unix_seconds);

// The current wall clock in seconds (CLOCK_REALTIME).
uint64_t beacon_unix_seconds();
