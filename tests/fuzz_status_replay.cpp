// Runs fuzz_status's entry point without libFuzzer, so every compiler checks
// it in ctest: every byte of a real history.json changed, every truncation,
// and random byte soup made of the reader's own characters.

#include "beacon_status.h"

#include <cstdio>
#include <cstring>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static uint64_t next_random(uint64_t* state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static const char SAMPLE[] =
    "{\"updated\": 1794874000,\n"
    "\"week\": {\"bucket_seconds\": 900, \"points\": [[1794872700, 3, 0], [1794873600, 7, 10]]},\n"
    "\"month\": {\"bucket_seconds\": 3600, \"points\": [[1794870000, 3, 0], [1794873600, 7, 10]]},\n"
    "\"year\": {\"bucket_seconds\": 86400, \"points\": [[1794787200, 3, 0], [1794873600, 7, 10]]}}\n";

int main()
{
    uint64_t runs = 0;
    size_t length = sizeof(SAMPLE) - 1;
    uint8_t buffer[sizeof(SAMPLE) + 64];
    static constexpr uint8_t BYTE_VALUES[] = {'0', '9', ',', '[', ']', '{', '}', '"', ' ', 'x', 0x00, 0xff};
    for (size_t at = 0; at < length; at++)
    {
        for (uint32_t v = 0; v < sizeof(BYTE_VALUES); v++)
        {
            memcpy(buffer, SAMPLE, length);
            buffer[at] = BYTE_VALUES[v];
            LLVMFuzzerTestOneInput(buffer, length);
            runs++;
        }
    }
    for (size_t cut = 0; cut <= length; cut++)
    {
        memcpy(buffer, SAMPLE, length);
        LLVMFuzzerTestOneInput(buffer, cut);
        runs++;
    }

    static constexpr char ALPHABET[] = "0123456789,[]{}\": \nupdatedweekmonthyearbucket_secondspoints";
    uint64_t state = 0x9e3779b97f4a7c15ull;
    std::string soup;
    for (uint32_t i = 0; i < 200000; i++)
    {
        uint64_t r = next_random(&state);
        size_t size = static_cast<size_t>(r % 200);
        soup.assign(SAMPLE, static_cast<size_t>((r >> 8) % length));
        for (size_t b = 0; b < size; b++)
        {
            soup.push_back(ALPHABET[next_random(&state) % (sizeof(ALPHABET) - 1)]);
        }
        LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(soup.data()), soup.size());
        runs++;
    }
    printf("fuzz_status_replay: %llu runs\n", static_cast<unsigned long long>(runs));
    return 0;
}
