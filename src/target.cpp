#include "zapscan/target.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <sstream>
#include <string>
#include <vector>

namespace zapscan {

namespace {

// Bare decimal only: no sign, whitespace, or padding. Returns -1 otherwise.
int to_number(const std::string& text) {
    if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos) {
        return -1;
    }
    try {
        return std::stoi(text);
    } catch (const std::out_of_range&) {
        return -1;
    }
}

std::vector<uint32_t> resolve_hostname(const std::string& hostname) {
    std::vector<uint32_t> addresses;

    struct addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* head = nullptr;
    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &head) != 0) {
        return addresses;
    }
    for (struct addrinfo* ai = head; ai != nullptr; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            auto* addr = reinterpret_cast<struct sockaddr_in*>(ai->ai_addr);
            addresses.push_back(ntohl(addr->sin_addr.s_addr));
        }
    }
    freeaddrinfo(head);
    return addresses;
}

// Expanded addresses carry their own textual form as the label.
void append_expanded(const std::vector<uint32_t>& addresses, std::vector<Target>& out) {
    for (uint32_t ip : addresses) {
        out.push_back(Target{ip, ipv4_to_string(ip)});
    }
}

// "192.168.1.0/24"; the caller guarantees the token contains a slash.
bool append_cidr(const std::string& token, std::vector<Target>& out) {
    size_t slash = token.find('/');
    std::string address = token.substr(0, slash);
    std::string prefix_text = token.substr(slash + 1);

    uint32_t base = 0;
    int prefix = to_number(prefix_text);
    // Prefixes are one or two digits; "033", "+24", and spaces are rejected.
    if (prefix < 0 || prefix_text.size() > 2 ||
        parse_ipv4(address, base) != ParseResult::Ok) {
        return false;
    }

    ParseResult sub = ParseResult::Ok;
    auto hosts = expand_cidr(base, prefix, sub);
    if (sub != ParseResult::Ok) {
        return false;
    }
    append_expanded(hosts, out);
    return true;
}

// "192.168.1.5-20" or "10.0.0.1-10.0.0.3"; start is the IPv4 before the dash.
bool append_range(uint32_t start, const std::string& tail, std::vector<Target>& out) {
    uint32_t end = 0;
    int last_octet = to_number(tail);
    if (last_octet >= 0 && tail.size() <= 3) {
        // Short form: the tail replaces the last octet.
        if (last_octet > 255) {
            return false;
        }
        end = (start & ~0xFFu) | static_cast<uint32_t>(last_octet);
    } else if (parse_ipv4(tail, end) != ParseResult::Ok) {
        return false;
    }

    ParseResult sub = ParseResult::Ok;
    auto hosts = expand_range(start, end, sub);
    if (sub != ParseResult::Ok) {
        return false;
    }
    append_expanded(hosts, out);
    return true;
}

// A literal IP, or a hostname resolved to every address it has.
bool append_single(const std::string& token, std::vector<Target>& out) {
    uint32_t ip = 0;
    if (parse_ipv4(token, ip) == ParseResult::Ok) {
        out.push_back(Target{ip, token});
        return true;
    }

    auto addresses = resolve_hostname(token);
    if (addresses.empty()) {
        return false;
    }
    for (uint32_t resolved : addresses) {
        out.push_back(Target{resolved, token});
    }
    return true;
}

bool append_token(const std::string& token, std::vector<Target>& out) {
    if (token.find('/') != std::string::npos) {
        return append_cidr(token, out);
    }

    // Only an IPv4 before a single dash makes a range; "my-host" is a hostname.
    size_t dash = token.find('-');
    uint32_t start = 0;
    if (dash != std::string::npos && token.rfind('-') == dash &&
        parse_ipv4(token.substr(0, dash), start) == ParseResult::Ok) {
        return append_range(start, token.substr(dash + 1), out);
    }

    return append_single(token, out);
}

}  // namespace

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
    if (prefix < 0 || prefix > 32) {
        result = ParseResult::Error;
        return {};
    }

    uint32_t mask = prefix == 0 ? 0u : ~0u << (32 - prefix);
    uint64_t host_count = 1ULL << (32 - prefix);
    if (host_count > static_cast<uint64_t>(kMaxHostsPerToken)) {
        result = ParseResult::Error;
        return {};
    }

    uint32_t network = base & mask;
    if (prefix <= 30) {
        network += 1;      // skip the network address
        host_count -= 2;   // and the broadcast address
    }

    std::vector<uint32_t> hosts;
    hosts.reserve(static_cast<size_t>(host_count));
    for (uint64_t i = 0; i < host_count; ++i) {
        hosts.push_back(network + static_cast<uint32_t>(i));
    }

    result = ParseResult::Ok;
    return hosts;
}

std::vector<uint32_t> expand_range(uint32_t start, uint32_t end, ParseResult& result) {
    if (start > end) {
        result = ParseResult::Error;
        return {};
    }
    uint64_t count = static_cast<uint64_t>(end) - start + 1;
    if (count > static_cast<uint64_t>(kMaxHostsPerToken)) {
        result = ParseResult::Error;
        return {};
    }

    std::vector<uint32_t> hosts;
    hosts.reserve(static_cast<size_t>(count));
    for (uint32_t ip = start; ip != end; ++ip) {
        hosts.push_back(ip);
    }
    hosts.push_back(end);  // the loop stops one short, avoiding overflow at UINT32_MAX

    result = ParseResult::Ok;
    return hosts;
}

std::vector<Target> expand_targets(const std::string& spec, ParseResult& result) {
    result = ParseResult::Ok;
    std::vector<Target> targets;

    std::stringstream stream(spec);
    std::string token;
    while (std::getline(stream, token, ',')) {
        if (token.empty()) {
            continue;
        }
        // Any invalid token rejects the whole spec, so typos fail loudly.
        if (!append_token(token, targets)) {
            result = ParseResult::Error;
            return {};
        }
    }

    if (targets.empty() || targets.size() > static_cast<size_t>(kMaxTotalHosts)) {
        result = ParseResult::Error;
        return {};
    }
    return targets;
}

}  // namespace zapscan
