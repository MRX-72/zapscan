#include "zapscan/target.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <algorithm>
#include <limits>
#include <sstream>

namespace zapscan {

ParseResult parse_ipv4(const std::string& text, uint32_t& out) {
    struct in_addr addr {};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1) {
        return ParseResult::Error;
    }
    out = ntohl(addr.s_addr);
    return ParseResult::Ok;
}

std::string ipv4_to_string(uint32_t ip) {
    struct in_addr addr {};
    addr.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN] = {0};
    return inet_ntop(AF_INET, &addr, buf, sizeof(buf));
}

std::vector<uint32_t> expand_cidr(uint32_t base, int prefix, ParseResult& result) {
    result = ParseResult::Ok;
    std::vector<uint32_t> hosts;
    if (prefix < 0 || prefix > 32) {
        result = ParseResult::Error;
        return hosts;
    }
    uint32_t mask = prefix == 0 ? 0 : (~0u << (32 - prefix));
    uint32_t network = base & mask;
    uint64_t count = prefix == 0 ? 0x100000000ULL : (1ULL << (32 - prefix));
    if (count > static_cast<uint64_t>(kMaxHostsPerToken)) {
        result = ParseResult::Error;
        return hosts;
    }
    if (prefix <= 30) {
        network += 1;  // skip network address
        count -= 2;    // skip broadcast as well
    }
    for (uint64_t i = 0; i < count; ++i) {
        hosts.push_back(network + static_cast<uint32_t>(i));
    }
    return hosts;
}

std::vector<uint32_t> expand_range(uint32_t start, uint32_t end, ParseResult& result) {
    result = ParseResult::Ok;
    std::vector<uint32_t> hosts;
    if (start > end) {
        result = ParseResult::Error;
        return hosts;
    }
    uint64_t count = static_cast<uint64_t>(end) - start + 1;
    if (count > kMaxHostsPerToken) {
        result = ParseResult::Error;
        return hosts;
    }
    hosts.reserve(static_cast<size_t>(count));
    for (uint32_t ip = start; ip != end; ++ip) {
        hosts.push_back(ip);
    }
    hosts.push_back(end);
    return hosts;
}

static std::vector<uint32_t> resolve_hostname(const std::string& hostname) {
    std::vector<uint32_t> out;
    struct addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0) {
        return out;
    }
    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            auto* sa = reinterpret_cast<struct sockaddr_in*>(ai->ai_addr);
            out.push_back(ntohl(sa->sin_addr.s_addr));
        }
    }
    freeaddrinfo(res);
    return out;
}

std::vector<Target> expand_targets(const std::string& spec, ParseResult& result) {
    result = ParseResult::Ok;
    std::vector<Target> targets;

    std::stringstream ss(spec);
    std::string token;
    while (std::getline(ss, token, ',')) {
        if (token.empty()) {
            continue;
        }
        size_t slash = token.find('/');
        if (slash != std::string::npos) {
            uint32_t base = 0;
            if (parse_ipv4(token.substr(0, slash), base) != ParseResult::Ok) {
                result = ParseResult::Error;
                return {};
            }
            std::string prefix_text = token.substr(slash + 1);
            if (prefix_text.empty() || prefix_text.size() > 2 ||
                prefix_text.find_first_not_of("0123456789") != std::string::npos) {
                result = ParseResult::Error;
                return {};
            }
            int prefix = std::stoi(prefix_text);
            auto hosts = expand_cidr(base, prefix, result);
            if (result != ParseResult::Ok) {
                return {};
            }
            for (uint32_t ip : hosts) {
                targets.push_back(Target{ip, ipv4_to_string(ip)});
            }
            continue;
        }

        size_t dash = token.find('-');
        uint32_t start = 0, end = 0;
        // Only an IPv4 before the dash makes a range; "my-host" is a hostname.
        if (dash != std::string::npos && token.rfind('-') == dash &&
            parse_ipv4(token.substr(0, dash), start) == ParseResult::Ok) {
            std::string tail = token.substr(dash + 1);
            if (!tail.empty() && tail.size() <= 3 &&
                tail.find_first_not_of("0123456789") == std::string::npos) {
                // Short form 192.168.1.5-20: tail replaces the last octet.
                int octet = std::stoi(tail);
                if (octet > 255) {
                    result = ParseResult::Error;
                    return {};
                }
                end = (start & ~0xFFu) | static_cast<uint32_t>(octet);
            } else if (parse_ipv4(tail, end) != ParseResult::Ok) {
                result = ParseResult::Error;
                return {};
            }
            auto hosts = expand_range(start, end, result);
            if (result != ParseResult::Ok) {
                return {};
            }
            for (uint32_t ip : hosts) {
                targets.push_back(Target{ip, ipv4_to_string(ip)});
            }
            continue;
        }

        uint32_t single = 0;
        if (parse_ipv4(token, single) == ParseResult::Ok) {
            targets.push_back(Target{single, token});
            continue;
        }

        auto resolved = resolve_hostname(token);
        if (resolved.empty()) {
            result = ParseResult::Error;
            return {};
        }
        for (uint32_t ip : resolved) {
            targets.push_back(Target{ip, token});
        }
    }

    if (targets.empty() || targets.size() > static_cast<size_t>(kMaxTotalHosts)) {
        result = ParseResult::Error;
        return {};
    }
    return targets;
}

}  // namespace zapscan