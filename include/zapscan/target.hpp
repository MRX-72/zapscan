#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace zapscan {

struct Target {
    uint32_t ip;
    std::string label;
};

enum class ParseResult : int {
    Ok = 0,
    Error = 1,
};

// One CIDR block or range. 4096 admits a /20 but not a /19.
constexpr int kMaxHostsPerToken = 4096;
// One spec before repeats are dropped, and one whole run after.
constexpr int kMaxTotalHosts = 1 << 16;

ParseResult parse_ipv4(const std::string& text, uint32_t& out);
std::string ipv4_to_string(uint32_t ip);

std::vector<uint32_t> expand_cidr(uint32_t base, int prefix, ParseResult& result);
std::vector<uint32_t> expand_range(uint32_t start, uint32_t end, ParseResult& result);

// Expands a comma-separated spec of IPs, hostnames, CIDR blocks, and ranges.
// Any bad token fails the whole spec; so does exceeding kMaxTotalHosts.
std::vector<Target> expand_targets(const std::string& spec, ParseResult& result);

// Drops repeats of an identical (ip, label) pair, keeping first-seen order.
// The same address under two different labels is not a repeat.
std::vector<Target> dedupe_targets(const std::vector<Target>& targets);

}  // namespace zapscan