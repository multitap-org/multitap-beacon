#pragma once

// beacon_status: the --status-file. Every BEACON_STATUS_INTERVAL_MS the
// server writes a small JSON with counts only (no ids, no addresses) for a
// public status page (packaging/status/) served next to it:
//
//     {"hosts_online": 12, "introductions_last_hour": 40, "updated": 1795000000}
//
// The file is written to PATH.tmp and renamed over PATH, so a reader never
// sees half of it.

#include <cstddef>
#include <cstdint>
#include <string>

constexpr uint64_t BEACON_STATUS_INTERVAL_MS = 10000;
// One hour of samples, plus the one an hour ago.
constexpr uint32_t BEACON_STATUS_HOUR_SAMPLES = 360;

struct BeaconStatus
{
    std::string path;
    std::string temp_path;
    // intros_total at every update, oldest overwritten first.
    uint64_t samples[BEACON_STATUS_HOUR_SAMPLES + 1] = {};
    uint32_t sample_count = 0;
    uint32_t next_sample = 0;
    bool failing = false;           // the last write failed (logged once, not every time)
};

bool beacon_status_open(BeaconStatus* status, const char* path);

// Records `intros_total` (the server's counter since start) and writes the
// file. `unix_seconds` is the wall clock. Returns false if the write failed.
bool beacon_status_update(BeaconStatus* status, uint32_t hosts_online, uint64_t intros_total,
                          uint64_t unix_seconds);

// The JSON text into `out`. Returns its length, or 0 if it doesn't fit.
size_t beacon_status_format(char* out, size_t capacity, uint32_t hosts_online, uint64_t introductions_last_hour,
                            uint64_t unix_seconds);

// The current wall clock in seconds (CLOCK_REALTIME).
uint64_t beacon_unix_seconds();
