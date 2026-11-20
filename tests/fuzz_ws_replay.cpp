// Runs one of the WebSocket fuzz targets (linked in) without libFuzzer, so
// every compiler checks it in ctest. `beacon_fuzz_ws_*_replay handshake`:
// every byte change of a valid request, every truncation, random header
// soups. `... frame`: every byte change of valid frames of each opcode, every
// truncation, random frames with a likely first byte.

#include "beacon_ws.h"

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

static uint64_t g_runs = 0;

static void run(const std::string& input)
{
    LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    g_runs++;
}

static void mutate_all(const std::string& sample)
{
    static const char BYTE_VALUES[] = {'\0', '\r', '\n', ' ', ':', ',', 'A', '=', '\x7f', '\x80', '\xff'};
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

static const char REQUEST[] =
    "GET /signal HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Upgrade: websocket\r\n"
    "Connection: keep-alive, Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Protocol: chat, multitap-beacon.1\r\n"
    "X-Forwarded-For: 10.0.0.1, 2001:db8::7\r\n"
    "\r\n";

static void replay_handshake()
{
    mutate_all(REQUEST);
    static const char* PIECES[] = {"GET / HTTP/1.1\r\n", "Host: x\r\n", "Upgrade: websocket\r\n",
                                   "Connection: Upgrade\r\n", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                                   "Sec-WebSocket-Version: 13\r\n", "Sec-WebSocket-Protocol: multitap-beacon.1\r\n",
                                   "X-Forwarded-For: 1.2.3.4\r\n", "X-Forwarded-For: ,,\r\n", "\r\n", ":",
                                   " ", "\t", "\r", "\n", ",", "a"};
    uint64_t state = 0x9e3779b97f4a7c15ull;
    for (uint32_t i = 0; i < 300000; i++)
    {
        std::string input = "GET ";
        uint32_t count = static_cast<uint32_t>(next_random(&state) % 24);
        for (uint32_t p = 0; p < count; p++)
        {
            input += PIECES[next_random(&state) % (sizeof(PIECES) / sizeof(PIECES[0]))];
        }
        run(input);
    }
}

static std::string client_frame(uint8_t first, const std::string& payload)
{
    std::string frame;
    frame += static_cast<char>(first);
    if (payload.size() <= 125)
    {
        frame += static_cast<char>(0x80 | payload.size());
    }
    else
    {
        frame += static_cast<char>(0x80 | 126);
        frame += static_cast<char>(payload.size() >> 8);
        frame += static_cast<char>(payload.size() & 0xff);
    }
    frame += "\x11\x22\x33\x44";
    frame += payload;
    return frame;
}

static void replay_frame()
{
    mutate_all(client_frame(0x82, "hello"));
    mutate_all(client_frame(0x82, std::string(200, 'p')));
    mutate_all(client_frame(0x88, std::string("\x03\xe8", 2)));
    mutate_all(client_frame(0x89, "ping"));
    mutate_all(client_frame(0x8a, ""));
    run(client_frame(0x82, std::string(BEACON_WS_MAX_PAYLOAD, 'm')));
    run(client_frame(0x82, std::string(BEACON_WS_MAX_PAYLOAD + 1, 'm')));
    uint64_t state = 0x2545f4914f6cdd1dull;
    static const uint8_t FIRST[] = {0x82, 0x88, 0x89, 0x8a, 0x81, 0x80, 0x02, 0xc2, 0x8b};
    for (uint32_t i = 0; i < 1000000; i++)
    {
        uint64_t r = next_random(&state);
        size_t size = static_cast<size_t>(r % 300);
        std::string input(size, '\0');
        for (size_t b = 0; b < size; b++)
        {
            input[b] = static_cast<char>(next_random(&state));
        }
        if (size > 0)
        {
            input[0] = static_cast<char>(FIRST[(r >> 20) % sizeof(FIRST)]);
        }
        if (size >= 6 && (r & 0x100) != 0)
        {
            // Masked, with a 7-bit length that matches what follows.
            size_t length = (size - 6) & 0x7f;
            input[1] = static_cast<char>(0x80 | length);
            input.resize(6 + length);
        }
        run(input);
    }
}

int main(int argc, char** argv)
{
    if (argc != 2 || (strcmp(argv[1], "handshake") != 0 && strcmp(argv[1], "frame") != 0))
    {
        fprintf(stderr, "usage: beacon_fuzz_ws_*_replay handshake|frame (with that target linked in)\n");
        return 2;
    }
    if (strcmp(argv[1], "handshake") == 0)
    {
        replay_handshake();
    }
    else
    {
        replay_frame();
    }
    printf("fuzz_ws_replay %s: %llu inputs, no failures\n", argv[1], static_cast<unsigned long long>(g_runs));
    return 0;
}
