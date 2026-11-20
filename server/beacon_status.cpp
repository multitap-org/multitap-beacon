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

bool beacon_status_open(BeaconStatus* status, const char* path)
{
    *status = BeaconStatus{};
    if (path == nullptr || path[0] == '\0')
    {
        return false;
    }
    status->path = path;
    status->temp_path = status->path + ".tmp";
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

// Removes the temporary file without losing the errno of what failed.
static bool fail_and_unlink(const BeaconStatus* status)
{
    int saved = errno;
    unlink(status->temp_path.c_str());
    errno = saved;
    return false;
}

static bool write_file(const BeaconStatus* status, const char* text, size_t size)
{
    int fd = open(status->temp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
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
            return fail_and_unlink(status);
        }
        done += static_cast<size_t>(wrote);
    }
    if (close(fd) != 0 || rename(status->temp_path.c_str(), status->path.c_str()) != 0)
    {
        return fail_and_unlink(status);
    }
    return true;
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

    char text[160];
    size_t size = beacon_status_format(text, sizeof(text), hosts_online, last_hour, unix_seconds);
    bool ok = size != 0 && write_file(status, text, size);
    if (!ok && !status->failing)
    {
        beacon_log(BeaconLogLevel::warning, "can't write the status file %s: %s", status->path.c_str(),
                   strerror(errno));
    }
    else if (ok && status->failing)
    {
        beacon_log(BeaconLogLevel::info, "status file written again");
    }
    status->failing = !ok;
    return ok;
}

uint64_t beacon_unix_seconds()
{
    timespec now = {};
    clock_gettime(CLOCK_REALTIME, &now);
    return now.tv_sec > 0 ? static_cast<uint64_t>(now.tv_sec) : 0;
}
