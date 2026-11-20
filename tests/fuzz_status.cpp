// libFuzzer target for history.json's reader: any text either is refused
// (leaving the rings empty) or reads into points that write back and read
// again to exactly the same text.

#include "beacon_status.h"

#include <cstdlib>
#include <string>

// Big structs, kept between runs instead of on the stack.
static BeaconStatus g_first;
static BeaconStatus g_second;
static std::string g_text;
static std::string g_again;

// A fixed "now" inside every tier's span of plausible inputs.
constexpr uint64_t NOW = 1794874000;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    const char* text = reinterpret_cast<const char*>(data);
    if (!beacon_status_parse_history(&g_first, text, size, NOW))
    {
        for (uint32_t t = 0; t < BEACON_STATUS_TIER_COUNT; t++)
        {
            if (g_first.rings[t].count != 0)
            {
                abort();
            }
        }
        return 0;
    }
    for (uint32_t t = 0; t < BEACON_STATUS_TIER_COUNT; t++)
    {
        if (g_first.rings[t].count > beacon_status_tier_points(static_cast<BeaconStatusTier>(t)))
        {
            abort();
        }
    }
    beacon_status_format_history(&g_first, NOW, &g_text);
    if (!beacon_status_parse_history(&g_second, g_text.data(), g_text.size(), NOW))
    {
        abort();
    }
    beacon_status_format_history(&g_second, NOW, &g_again);
    if (g_again != g_text)
    {
        abort();
    }
    return 0;
}
