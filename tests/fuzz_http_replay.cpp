// Runs fuzz_http without libFuzzer, so every compiler checks it in ctest:
// every byte change and truncation of valid requests and uploads, then
// random header soups.

#include <cstdint>
#include <cstdio>
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

static uint64_t g_runs = 0;

static void run(const std::string& input)
{
    LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    g_runs++;
}

static void mutate_all(const std::string& sample)
{
    static const char BYTE_VALUES[] = {'\0', '\r', '\n', ' ', ':', '/', '?', '0', '\x7f', '\x80', '\xc0', '\xff'};
    for (size_t at = 0; at < sample.size(); at++)
    {
        for (size_t v = 0; v < sizeof(BYTE_VALUES); v++)
        {
            std::string mutated = sample;
            mutated[at] = BYTE_VALUES[v];
            run(mutated);
        }
        std::string removed = sample;
        removed.erase(at, 1);
        run(removed);
    }
    for (size_t cut = 0; cut <= sample.size(); cut++)
    {
        run(sample.substr(0, cut));
    }
}

static std::string upload()
{
    std::string body(32, '\x11');
    std::string title = "Zelda \xe3\x81\x82 <DX>";
    body += static_cast<char>(title.size());
    body += title;
    const uint8_t png[33] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 13, 'I', 'H', 'D', 'R',
                             0, 0, 2, 0x80, 0, 0, 1, 0xe0, 8, 2};
    body += std::string(reinterpret_cast<const char*>(png), sizeof(png));
    return body;
}

int main()
{
    mutate_all("GET /join/7hqelxhbgx2e3/card.png?x=1 HTTP/1.1\r\nHost: beacon.example:443\r\n"
               "X-Forwarded-For: 10.0.0.1, 2001:db8::7\r\n\r\n");
    mutate_all("POST /join/7hqelxhbgx2e3/card HTTP/1.1\r\nHost: b\r\nContent-Length: 1234\r\n\r\n");
    mutate_all(upload());
    static const char* PIECES[] = {"GET ", "POST ", "HEAD ", "/join/", "7hqelxhbgx2e3", "/card", ".png", " HTTP/1.1",
                                   "\r\n", "Host: x", "Content-Length: 12", "Upgrade: websocket",
                                   "Transfer-Encoding: chunked", ":", " ", "\t", "\r", "\n", "?", "a"};
    uint64_t state = 0x2545f4914f6cdd1dull;
    for (uint32_t i = 0; i < 300000; i++)
    {
        std::string input;
        uint32_t count = static_cast<uint32_t>(next_random(&state) % 24);
        for (uint32_t p = 0; p < count; p++)
        {
            input += PIECES[next_random(&state) % (sizeof(PIECES) / sizeof(PIECES[0]))];
        }
        run(input);
    }
    printf("fuzz_http_replay: %llu runs\n", static_cast<unsigned long long>(g_runs));
    return 0;
}
