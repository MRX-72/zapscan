#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace zapscan {

struct ScanOptions {
    int concurrency = 128;
    int connect_timeout_ms = 1500;
    bool grab_banners = true;
    bool resolve_hosts = false;
};

struct PortResult {
    uint16_t port;
    bool open;
    std::string service;
    std::string banner;
    int rtt_ms;
};

struct HostResult {
    std::string host;
    uint32_t ip = 0;
    std::vector<PortResult> ports;
    int total_scanned = 0;
    int total_open = 0;
};

std::vector<uint16_t> parse_ports(const std::string& spec);
std::vector<uint16_t> known_ports();
std::string default_service(uint16_t port);

HostResult scan_host(const std::string& host, const std::vector<uint16_t>& ports,
                     const ScanOptions& opts);

}  // namespace zapscan