#pragma once

// Logging for the server: one line per message on stderr (systemd's journal
// and `docker logs` add the time). The server logs counts only: never meeting
// ids, never addresses.

#include <cstdint>

enum class BeaconLogLevel : uint8_t
{
    error,
    warning,
    info,
    debug,
};

// Messages above this level are dropped. Default: info. The level is the only
// global state of the server: every function logs, and passing the level to
// each of them would only add noise.
void beacon_log_set_level(BeaconLogLevel level);

// Parses "error", "warning", "info" or "debug".
bool beacon_log_parse_level(const char* text, BeaconLogLevel* level);

// printf-style; the newline is added.
void beacon_log(BeaconLogLevel level, const char* format, ...) __attribute__((format(printf, 2, 3)));
