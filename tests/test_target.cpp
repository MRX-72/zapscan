#include "zapscan/target.hpp"
#include "test_harness.hpp"

TEST(parse_valid_ipv4) {
    uint32_t ip = 0;
    EXPECT_EQ(zapscan::parse_ipv4("192.168.1.10", ip), zapscan::ParseResult::Ok);
    EXPECT_EQ(ip, 0xC0A8010A);
}

TEST(parse_invalid_ipv4) {
    uint32_t ip = 0;
    EXPECT_EQ(zapscan::parse_ipv4("not-an-ip", ip), zapscan::ParseResult::Error);
    EXPECT_EQ(zapscan::parse_ipv4("256.1.1.1", ip), zapscan::ParseResult::Error);
    EXPECT_EQ(zapscan::parse_ipv4("1.2.3", ip), zapscan::ParseResult::Error);
}

TEST(ipv4_roundtrip) {
    uint32_t ip = 0;
    zapscan::parse_ipv4("10.20.30.40", ip);
    EXPECT_EQ(zapscan::ipv4_to_string(ip), "10.20.30.40");
}

TEST(cidr_expansion) {
    zapscan::ParseResult pr;
    uint32_t base = 0;
    zapscan::parse_ipv4("192.168.1.0", base);

    auto hosts = zapscan::expand_cidr(base, 30, pr);
    EXPECT_EQ(pr, zapscan::ParseResult::Ok);
    EXPECT_EQ(hosts.size(), 2u);
    EXPECT_EQ(zapscan::ipv4_to_string(hosts[0]), "192.168.1.1");
    EXPECT_EQ(zapscan::ipv4_to_string(hosts[1]), "192.168.1.2");

    auto too_big = zapscan::expand_cidr(base, 8, pr);
    EXPECT_EQ(pr, zapscan::ParseResult::Error);
    EXPECT_TRUE(too_big.empty());

    // /0 and /1 used to overflow the size guard's int cast.
    for (int prefix : {0, 1}) {
        EXPECT_TRUE(zapscan::expand_cidr(base, prefix, pr).empty());
        EXPECT_EQ(pr, zapscan::ParseResult::Error);
    }
}

TEST(range_expansion) {
    zapscan::ParseResult pr;
    uint32_t start = 0, end = 0;
    zapscan::parse_ipv4("10.0.0.5", start);
    zapscan::parse_ipv4("10.0.0.8", end);

    auto hosts = zapscan::expand_range(start, end, pr);
    EXPECT_EQ(pr, zapscan::ParseResult::Ok);
    EXPECT_EQ(hosts.size(), 4u);

    zapscan::ParseResult bad;
    zapscan::parse_ipv4("10.0.0.9", start);
    auto reversed = zapscan::expand_range(start, end, bad);
    EXPECT_EQ(bad, zapscan::ParseResult::Error);
    EXPECT_TRUE(reversed.empty());
}

TEST(expand_targets_single_ip) {
    zapscan::ParseResult pr;
    auto targets = zapscan::expand_targets("192.168.1.1", pr);
    EXPECT_EQ(pr, zapscan::ParseResult::Ok);
    EXPECT_EQ(targets.size(), 1u);
    EXPECT_EQ(targets[0].label, "192.168.1.1");
}

TEST(expand_targets_comma_list) {
    zapscan::ParseResult pr;
    auto targets = zapscan::expand_targets("192.168.1.1,10.0.0.5", pr);
    EXPECT_EQ(pr, zapscan::ParseResult::Ok);
    EXPECT_EQ(targets.size(), 2u);
}

TEST(expand_targets_rejects_garbage) {
    zapscan::ParseResult pr;
    auto targets = zapscan::expand_targets("::::", pr);
    EXPECT_EQ(pr, zapscan::ParseResult::Error);
    EXPECT_TRUE(targets.empty());
}

TEST(expand_targets_short_range) {
    zapscan::ParseResult pr;
    auto targets = zapscan::expand_targets("192.168.1.5-20", pr);
    EXPECT_EQ(pr, zapscan::ParseResult::Ok);
    EXPECT_EQ(targets.size(), 16u);
    EXPECT_EQ(targets.front().label, "192.168.1.5");
    EXPECT_EQ(targets.back().label, "192.168.1.20");

    auto full = zapscan::expand_targets("10.0.0.1-10.0.0.3", pr);
    EXPECT_EQ(pr, zapscan::ParseResult::Ok);
    EXPECT_EQ(full.size(), 3u);

    for (const char* bad : {"192.168.1.5-256", "192.168.1.5-4", "192.168.1.5-", "192.168.1.5-1x"}) {
        EXPECT_TRUE(zapscan::expand_targets(bad, pr).empty());
        EXPECT_EQ(pr, zapscan::ParseResult::Error);
    }
}
