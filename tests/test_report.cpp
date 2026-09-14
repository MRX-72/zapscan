#include <chrono>

#include "zapscan/report.hpp"
#include "zapscan/scanner.hpp"
#include "test_harness.hpp"

TEST(parse_ports_single) {
    auto ports = zapscan::parse_ports("80");
    EXPECT_EQ(ports.size(), 1u);
    EXPECT_EQ(ports[0], 80);
}

TEST(parse_ports_range) {
    auto ports = zapscan::parse_ports("1-5");
    EXPECT_EQ(ports.size(), 5u);
    EXPECT_EQ(ports[0], 1);
    EXPECT_EQ(ports[4], 5);
}

TEST(parse_ports_comma_and_range) {
    auto ports = zapscan::parse_ports("22,80-82,443");
    EXPECT_EQ(ports.size(), 5u);
}

TEST(parse_ports_rejects_invalid) {
    EXPECT_TRUE(zapscan::parse_ports("0").empty());
    EXPECT_TRUE(zapscan::parse_ports("70000").empty());
    EXPECT_TRUE(zapscan::parse_ports("abc").empty());
    EXPECT_TRUE(zapscan::parse_ports("80-20").empty());
}

TEST(parse_ports_deduplicates) {
    auto ports = zapscan::parse_ports("80,80,80");
    EXPECT_EQ(ports.size(), 1u);
}

TEST(default_service_known_and_unknown) {
    EXPECT_EQ(zapscan::default_service(22), "ssh");
    EXPECT_EQ(zapscan::default_service(443), "https");
    EXPECT_TRUE(zapscan::default_service(55555).empty());
}

TEST(sanitize_banner_strips_control_chars) {
    std::string dirty = "SSH-2.0-OpenSSH\r\n\x01next\x02";
    auto clean = zapscan::sanitize_banner(dirty, 100);
    EXPECT_TRUE(clean.find('\n') == std::string::npos);
    EXPECT_TRUE(clean.find('?') != std::string::npos);
}

TEST(format_json_is_valid) {
    zapscan::Report report;
    report.target = "127.0.0.1";
    report.started = std::chrono::system_clock::now();
    report.finished = std::chrono::system_clock::now();
    report.result.host = "127.0.0.1";
    report.result.total_scanned = 1;
    report.result.total_open = 1;
    zapscan::PortResult pr;
    pr.port = 22;
    pr.open = true;
    pr.service = "ssh";
    pr.banner = "SSH-2.0\"quoted";
    report.result.ports.push_back(pr);

    auto json = zapscan::format_json(report);
    EXPECT_TRUE(json.find("\"port\": 22") != std::string::npos);
    EXPECT_TRUE(json.find("\\\"quoted") != std::string::npos);
}
TEST(known_ports_matches_service_table) {
    auto ports = zapscan::known_ports();
    EXPECT_FALSE(ports.empty());
    for (auto p : ports) {
        EXPECT_FALSE(zapscan::default_service(p).empty());
    }
}

TEST(format_csv_escapes_fields) {
    zapscan::Report report;
    report.result.host = "127.0.0.1";
    zapscan::PortResult pr;
    pr.port = 22;
    pr.open = true;
    pr.service = "ssh";
    pr.rtt_ms = 3;
    pr.banner = "=HYPERLINK(\"x\"),y";
    report.result.ports.push_back(pr);

    auto csv = zapscan::format_csv(report);
    EXPECT_EQ(csv, std::string("127.0.0.1,22,ssh,3,\"'=HYPERLINK(\"\"x\"\"),y\"\n"));
}
