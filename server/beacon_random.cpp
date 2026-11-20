#include "beacon_random.h"

#include "beacon_log.h"

#include <cerrno>
#include <cstring>
#include <sys/random.h>

bool beacon_random_fill(uint8_t* out, size_t size)
{
    size_t filled = 0;
    while (filled < size)
    {
        ssize_t got = getrandom(out + filled, size - filled, 0);
        if (got < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            beacon_log(BeaconLogLevel::error, "getrandom failed: %s", strerror(errno));
            return false;
        }
        filled += static_cast<size_t>(got);
    }
    return true;
}
