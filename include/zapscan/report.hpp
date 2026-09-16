#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "zapscan/scanner.hpp"

namespace zapscan {

struct Report {
    std::chrono::system_clock::time_point started;
    std::chrono::system_clock::time_point finished;
    HostResult result;
};

std::string format_text(const Report& report);
std::string format_json(const Report& report);
// One row per open port, no header; prepend kCsvHeader once.
constexpr const char* kCsvHeader = "host,ip,port,service,rtt_ms,banner\n";
std::string format_csv(const Report& report);
std::string sanitize_banner(const std::string& raw, size_t max_bytes);

}  // namespace zapscan