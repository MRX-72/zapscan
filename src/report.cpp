#include "zapscan/report.hpp"

#include <arpa/inet.h>

#include <cctype>
#include <iomanip>
#include <sstream>

namespace zapscan {

namespace {

std::string timestamp(const std::chrono::system_clock::time_point& tp) {
    auto t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm {};
    localtime_r(&t, &tm);
    char buf[32] = {0};
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

std::string duration_ms(const Report& report) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  report.finished - report.started)
                  .count();
    return std::to_string(ms) + " ms";
}

std::string json_escape(const std::string& in) {
    std::ostringstream out;
    for (char c : in) {
        switch (c) {
            case '"':  out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(c)) << std::dec;
                } else {
                    out << c;
                }
        }
    }
    return out.str();
}

std::string csv_field(std::string in) {
    // Banners are remote-controlled: neutralize spreadsheet formulas.
    if (!in.empty() && (in[0] == '=' || in[0] == '+' || in[0] == '-' || in[0] == '@')) {
        in.insert(0, 1, '\'');
    }
    if (in.find_first_of(",\"") == std::string::npos) {
        return in;
    }
    std::string out = "\"";
    for (char c : in) {
        out += c;
        if (c == '"') {
            out += '"';
        }
    }
    return out + "\"";
}

}  // namespace

std::string sanitize_banner(const std::string& raw, size_t max_bytes) {
    std::string out;
    out.reserve(raw.size());
    for (char c : raw) {
        if (c == '\r' || c == '\n') {
            continue;
        }
        if (std::isprint(static_cast<unsigned char>(c)) || c == ' ') {
            out.push_back(c);
        } else {
            out.push_back('?');
        }
        if (out.size() >= max_bytes) {
            break;
        }
    }
    return out;
}

std::string format_text(const Report& report) {
    std::ostringstream out;
    out << "zapscan " << report.target << " [" << timestamp(report.started) << "]\n";
    out << std::setfill('-') << std::setw(78) << "" << std::setfill(' ') << "\n";

    const auto& result = report.result;
    if (result.ports.empty()) {
        out << "No open ports found (scanned " << result.total_scanned << ").\n";
    } else {
        out << "PORT      STATE   SERVICE        RTT     BANNER\n";
        for (const auto& p : result.ports) {
            out << std::setw(5) << p.port << "/tcp"
                << "   open   "
                << std::left << std::setw(13) << (p.service.empty() ? "-" : p.service)
                << std::right << std::setw(6) << p.rtt_ms << "ms   "
                << (p.banner.empty() ? "" : sanitize_banner(p.banner, 80))
                << "\n";
        }
    }

    out << std::setfill('-') << std::setw(78) << "" << std::setfill(' ') << "\n";
    out << "Scanned " << result.total_scanned << " ports, " << result.total_open
        << " open, in " << duration_ms(report) << "\n";
    return out.str();
}

std::string format_json(const Report& report) {
    const auto& result = report.result;
    std::ostringstream out;
    out << "{\n";
    out << "  \"target\": \"" << json_escape(result.host) << "\",\n";
    out << "  \"started\": \"" << timestamp(report.started) << "\",\n";
    out << "  \"finished\": \"" << timestamp(report.finished) << "\",\n";
    out << "  \"ports\": [\n";
    for (size_t i = 0; i < result.ports.size(); ++i) {
        const auto& p = result.ports[i];
        out << "    {\"port\": " << p.port << ", \"state\": \"open\", \"service\": \""
            << json_escape(p.service) << "\", \"rtt_ms\": " << p.rtt_ms << ", \"banner\": \""
            << json_escape(sanitize_banner(p.banner, 512)) << "\"}";
        out << (i + 1 < result.ports.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
    return out.str();
}

std::string format_csv(const Report& report) {
    const auto& result = report.result;
    std::ostringstream out;
    for (const auto& p : result.ports) {
        out << csv_field(result.host) << "," << p.port << "," << csv_field(p.service) << ","
            << p.rtt_ms << "," << csv_field(sanitize_banner(p.banner, 512)) << "\n";
    }
    return out.str();
}

}  // namespace zapscan