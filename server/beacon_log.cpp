#include "beacon_log.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

static BeaconLogLevel g_log_level = BeaconLogLevel::info;

void beacon_log_set_level(BeaconLogLevel level)
{
    g_log_level = level;
}

bool beacon_log_parse_level(const char* text, BeaconLogLevel* level)
{
    if (strcmp(text, "error") == 0)
    {
        *level = BeaconLogLevel::error;
    }
    else if (strcmp(text, "warning") == 0)
    {
        *level = BeaconLogLevel::warning;
    }
    else if (strcmp(text, "info") == 0)
    {
        *level = BeaconLogLevel::info;
    }
    else if (strcmp(text, "debug") == 0)
    {
        *level = BeaconLogLevel::debug;
    }
    else
    {
        return false;
    }
    return true;
}

static const char* level_name(BeaconLogLevel level)
{
    switch (level)
    {
        case BeaconLogLevel::error:
            return "error";
        case BeaconLogLevel::warning:
            return "warning";
        case BeaconLogLevel::info:
            return "info";
        case BeaconLogLevel::debug:
            return "debug";
    }
    return "?";
}

void beacon_log(BeaconLogLevel level, const char* format, ...)
{
    if (static_cast<uint8_t>(level) > static_cast<uint8_t>(g_log_level))
    {
        return;
    }
    char line[512];
    va_list args;
    va_start(args, format);
    vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    fprintf(stderr, "beacon %s: %s\n", level_name(level), line);
    fflush(stderr);
}
