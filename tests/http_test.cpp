// beacon_http: request parsing, join routes, the guest link derivations
// (vectors computed independently with Python's hashlib.blake2b), cards and
// the page.

#include "beacon_http.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static uint32_t g_failures = 0;

static void check(bool ok, const char* what)
{
    if (!ok)
    {
        fprintf(stderr, "FAIL: %s\n", what);
        g_failures++;
    }
}

static BeaconHttpParse parse(const std::string& text, BeaconHttpRequest* out)
{
    return beacon_http_parse_request(reinterpret_cast<const uint8_t*>(text.data()), text.size(), out);
}

static void test_requests()
{
    BeaconHttpRequest r;
    std::string get = "GET /join/7hqelxhbgx2e3 HTTP/1.1\r\nHost: beacon.get-piccolo.app\r\n"
                      "User-Agent: Discordbot\r\nX-Forwarded-For: 10.0.0.1, 203.0.113.9\r\n\r\n";
    check(parse(get, &r) == BeaconHttpParse::OK && r.method == BeaconHttpMethod::GET && r.head_size == get.size() &&
              strcmp(r.target, "/join/7hqelxhbgx2e3") == 0 && strcmp(r.host, "beacon.get-piccolo.app") == 0 &&
              !r.upgrade && r.has_forwarded && r.forwarded.ip[15] == 9,
          "a GET parses");
    for (size_t cut = 0; cut < get.size(); cut++)
    {
        if (parse(get.substr(0, cut), &r) != BeaconHttpParse::INCOMPLETE)
        {
            check(false, "every prefix of a valid GET is INCOMPLETE");
            break;
        }
    }
    check(parse("HEAD /join/7hqelxhbgx2e3/card.png HTTP/1.1\r\nHost: x\r\n\r\n", &r) == BeaconHttpParse::OK &&
              r.method == BeaconHttpMethod::HEAD,
          "a HEAD parses");
    std::string post = "POST /join/7hqelxhbgx2e3/card HTTP/1.1\r\nHost: x\r\nContent-Length: 1234\r\n\r\nbody";
    check(parse(post, &r) == BeaconHttpParse::OK && r.method == BeaconHttpMethod::POST && r.has_content_length &&
              r.content_length == 1234 && r.head_size == post.size() - 4,
          "a POST with Content-Length parses; the body isn't the head");
    check(parse("GET /signal HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n", &r) == BeaconHttpParse::OK &&
              r.upgrade,
          "an Upgrade header is seen (the WebSocket parser takes it)");
    check(parse("GET / HTTP/1.1\r\nHost: <script>\r\n\r\n", &r) == BeaconHttpParse::OK && r.host[0] == '\0',
          "an odd Host is ignored, not repeated");

    const char* bad[] = {
        "PUT /join/7hqelxhbgx2e3 HTTP/1.1\r\n\r\n",
        "GET join HTTP/1.1\r\n\r\n",
        "GET /join/x HTTP/1.0\r\n\r\n",
        "GET /a b HTTP/1.1\r\n\r\n",
        "GET /a HTTP/1.1\r\nBad Header: x\r\n\r\n",
        "GET /a HTTP/1.1\r\n folded: x\r\n\r\n",
        "GET /a HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        "POST /a HTTP/1.1\r\nContent-Length: 12a\r\n\r\n",
        "POST /a HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET /a HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
        "GET /a HTTP/1.1\nHost: x\r\n\r\n",
        "GET /a\x01 HTTP/1.1\r\n\r\n",
    };
    for (uint32_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        if (parse(bad[i], &r) != BeaconHttpParse::INVALID)
        {
            fprintf(stderr, "  case %u\n", i);
            check(false, "a bad request is INVALID");
        }
    }
    std::string huge = "GET /a HTTP/1.1\r\nX: " + std::string(BEACON_HTTP_MAX_HEAD, 'a');
    check(parse(huge, &r) == BeaconHttpParse::INVALID, "a head past the limit is INVALID");
    std::string long_target = "GET /" + std::string(BEACON_HTTP_MAX_TARGET, 'a') + " HTTP/1.1\r\n\r\n";
    check(parse(long_target, &r) == BeaconHttpParse::INVALID, "a target past the limit is INVALID");
}

static void test_routes()
{
    BeaconJoinRoute route;
    check(beacon_http_join_route("/join/7hqelxhbgx2e3", &route) && route.kind == BeaconJoinKind::PAGE &&
              strcmp(route.room, "7hqelxhbgx2e3") == 0,
          "the page");
    check(beacon_http_join_route("/join/7hqelxhbgx2e3/", &route) && route.kind == BeaconJoinKind::PAGE,
          "the page with a slash");
    check(beacon_http_join_route("/join/7hqelxhbgx2e3?utm=x", &route) && route.kind == BeaconJoinKind::PAGE,
          "a query string is ignored");
    check(beacon_http_join_route("/join/7hqelxhbgx2e3/card.png", &route) && route.kind == BeaconJoinKind::CARD_PNG,
          "the card");
    check(beacon_http_join_route("/join/7hqelxhbgx2e3/card", &route) && route.kind == BeaconJoinKind::CARD_PUT,
          "the upload");
    const char* bad[] = {"/join/", "/join/7hqelxhbgx2e", "/join/7HQELXHBGX2E3", "/join/7hqelxhbgx2e1",
                         "/join/7hqelxhbgx2e3x", "/join/7hqelxhbgx2e3/card.jpg", "/status/", "/joinx/7hqelxhbgx2e3",
                         "/join/7hqelxhbgx2e3/../x"};
    for (uint32_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        check(!beacon_http_join_route(bad[i], &route), "not a join route");
    }
}

static void hex_to_bytes(const char* hex, uint8_t* out, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        unsigned value = 0;
        sscanf(hex + i * 2, "%2x", &value);
        out[i] = static_cast<uint8_t>(value);
    }
}

static void test_derivations()
{
    // token "abcdefghijklmnopqrstuvwxyz": card key from net_guest (host side),
    // then room and meeting here.
    uint8_t card_key[32];
    hex_to_bytes("08df115380262124acd5de50e376071f05ef0e65857d278af6e0f52d01b4e1c2", card_key, 32);
    char room[BEACON_GUEST_ROOM_SIZE + 1];
    beacon_guest_room_from_card_key(card_key, room);
    check(strcmp(room, "7hqelxhbgx2e3") == 0, "the room from the card key (vector)");
    BeaconId meeting;
    beacon_guest_meeting_id(room, &meeting);
    uint8_t expected[16];
    hex_to_bytes("cef90bb0d95aa2ae4643af9cab828945", expected, 16);
    check(memcmp(meeting.bytes, expected, 16) == 0, "the meeting id from the room (vector)");
    for (uint32_t i = 0; i < 32; i++)
    {
        card_key[i] = static_cast<uint8_t>(i);
    }
    beacon_guest_room_from_card_key(card_key, room);
    check(strcmp(room, "4ecvcngq5gk2z") == 0, "the room from key 0..31 (vector)");
}

// A minimal PNG head: signature + IHDR (the rest isn't read).
static std::string png(uint32_t width, uint32_t height, size_t extra)
{
    uint8_t head[33] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 13, 'I', 'H', 'D', 'R'};
    for (uint32_t i = 0; i < 4; i++)
    {
        head[16 + i] = static_cast<uint8_t>(width >> (24 - 8 * i));
        head[20 + i] = static_cast<uint8_t>(height >> (24 - 8 * i));
    }
    head[24] = 8;
    head[25] = 2;
    return std::string(reinterpret_cast<const char*>(head), sizeof(head)) + std::string(extra, 'p');
}

static std::string upload(const std::string& title, const std::string& image)
{
    std::string body(32, '\x07');
    body += static_cast<char>(title.size());
    body += title;
    body += image;
    return body;
}

static bool parse_upload(const std::string& body, BeaconCardUpload* out)
{
    return beacon_card_parse_upload(reinterpret_cast<const uint8_t*>(body.data()), body.size(), out);
}

static void test_cards()
{
    BeaconCardUpload u;
    std::string title = "Teenage Mutant Ninja Turtles IV";
    std::string image = png(768, 672, 1000);
    check(parse_upload(upload(title, image), &u) && strcmp(u.title, title.c_str()) == 0 && u.width == 768 &&
              u.height == 672 && u.png_size == image.size() && u.card_key[0] == 7,
          "an upload parses");
    check(parse_upload(upload("ゼルダの伝説 夢をみる島", image), &u), "a UTF-8 title");
    check(parse_upload(upload(std::string(BEACON_CARD_MAX_TITLE, 'a'), png(1280, 960, 0)), &u),
          "the largest title and picture");
    check(parse_upload(upload("a", png(16, 16, BEACON_CARD_MAX_PNG - 33)), &u), "the largest PNG");
    check(!parse_upload(upload("a", png(16, 16, BEACON_CARD_MAX_PNG - 32)), &u), "a PNG over the limit");
    check(!parse_upload(upload("", image), &u), "an empty title");
    check(!parse_upload(upload(std::string(BEACON_CARD_MAX_TITLE + 1, 'a'), image), &u), "a title over the limit");
    check(!parse_upload(upload("a\nb", image), &u), "a control character in the title");
    check(!parse_upload(upload("a\xc2\x85", image), &u), "a C1 control in the title");
    check(!parse_upload(upload("\xc0\xaf", image), &u), "an overlong in the title");
    check(!parse_upload(upload("\xed\xa0\x80", image), &u), "a surrogate in the title");
    check(!parse_upload(upload("ab\xe3\x81", image), &u), "a cut sequence at the title's end");
    check(!parse_upload(upload("a", png(1281, 10, 0)), &u), "too wide");
    check(!parse_upload(upload("a", png(10, 961, 0)), &u), "too tall");
    check(!parse_upload(upload("a", png(0, 10, 0)), &u), "zero wide");
    check(!parse_upload(upload("a", "GIF89a" + std::string(40, 'x')), &u), "not a PNG");
    check(!parse_upload(upload("a", png(10, 10, 0).substr(0, 30)), &u), "a PNG cut short");
    std::string short_title = upload("abc", image);
    short_title[32] = static_cast<char>(200);
    check(!parse_upload(short_title.substr(0, 40), &u), "a title running past the body");
}

static void test_page()
{
    char out[64];
    check(beacon_html_escape("a<b>&\"c'", out, sizeof(out)) == 27 &&
              strcmp(out, "a&lt;b&gt;&amp;&quot;c&#39;") == 0,
          "escaping");
    check(beacon_html_escape("aaaaaaaaaaaa&", out, 14) == 0, "an escape that doesn't fit");

    std::vector<char> page(48 * 1024);
    size_t size = beacon_join_page_render(beacon_join_page_builtin(), "<Zelda> & \"Link\"", "desc",
                                          "https://b.example/join/7hqelxhbgx2e3/card.png",
                                          "https://b.example/join/7hqelxhbgx2e3", page.data(), page.size());
    std::string text(page.data(), size);
    check(size > 0, "the built-in page renders");
    check(text.find("{{") == std::string::npos, "no placeholder is left");
    check(text.find("<Zelda>") == std::string::npos && text.find("&lt;Zelda&gt; &amp; &quot;Link&quot;") != std::string::npos,
          "the title is escaped");
    check(text.find("<meta property=\"og:image\" content=\"https://b.example/join/7hqelxhbgx2e3/card.png\">") !=
              std::string::npos,
          "og:image");
    check(beacon_join_page_render(beacon_join_page_builtin(), "t", "d", "i", "u", page.data(), 100) == 0,
          "a page that doesn't fit");

    char head[512];
    size_t head_size = beacon_http_response_head(404, nullptr, nullptr, 0, head, sizeof(head));
    check(head_size > 0 && strncmp(head, "HTTP/1.1 404 Not Found\r\n", 24) == 0 &&
              strstr(head, "Content-Length: 0\r\n\r\n") != nullptr && strstr(head, "Connection: close") != nullptr,
          "a 404 head");
}

int main()
{
    test_requests();
    test_routes();
    test_derivations();
    test_cards();
    test_page();
    if (g_failures != 0)
    {
        fprintf(stderr, "%u failures\n", g_failures);
        return 1;
    }
    printf("http: all checks passed\n");
    return 0;
}
