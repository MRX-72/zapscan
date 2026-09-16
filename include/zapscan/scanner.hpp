#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "zapscan/target.hpp"

namespace zapscan {

struct ScanOptions {
    int concurrency = 128;
    int connect_timeout_ms = 1500;
    bool grab_banners = true;
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
    // Probes that failed locally (e.g. EMFILE) and so could not be scanned.
    int total_errors = 0;
};

std::vector<uint16_t> parse_ports(const std::string& spec);
std::vector<uint16_t> known_ports();
std::string default_service(uint16_t port);

// Scans every (target, port) pair with one shared pool of opts.concurrency workers.
// Results are in the same order as targets; each target's ip is scanned, label copied.
std::vector<HostResult> scan_hosts(const std::vector<Target>& targets,
                                   const std::vector<uint16_t>& ports, const ScanOptions& opts);

// Single-target convenience wrapper around scan_hosts.
HostResult scan_host(const Target& target, const std::vector<uint16_t>& ports,
                     const ScanOptions& opts);

}  // namespace zapscan