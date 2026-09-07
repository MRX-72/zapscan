#include <arpa/inet.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "zapscan/report.hpp"
#include "zapscan/scanner.hpp"
#include "zapscan/target.hpp"

namespace {

constexpr const char* kVersion = "3.0.0";

void usage() {
    std::cout
        << "zapscan v" << kVersion
        << " - parallel TCP port scanner\n\n"
        << "Usage: zapscan [options] <target...>\n\n"
        << "Targets may be IPs, hostnames, CIDR blocks (192.168.1.0/24),\n"
        << "ranges (192.168.1.5-20), or comma-separated lists.\n\n"
        << "Options:\n"
        << "  -p, --ports <spec>     Ports to scan (default: 1-1024)\n"
        << "                         e.g. 80,443 or 1-1000 or 22,80,443-900\n"
        << "  -c, --concurrency <n>   Concurrent connections (default: 128)\n"
        << "  -t, --timeout <ms>      Connect timeout in ms (default: 1500)\n"
        << "      --no-banners        Disable banner grabbing\n"
        << "  -j, --json              Emit JSON output\n"
        << "  -o, --output <file>     Write report to file\n"
        << "  -h, --help              Show this help\n"
        << "  -v, --version           Show version\n";
}

struct Config {
    std::vector<std::string> targets;
    std::string ports = "1-1024";
    int concurrency = 128;
    int timeout_ms = 1500;
    bool banners = true;
    bool json = false;
    std::string output_file;
};

bool parse_int(const std::string& s, int& out) {
    try {
        size_t pos = 0;
        int parsed = std::stoi(s, &pos);
        if (pos != s.size() || parsed <= 0) {
            return false;
        }
        out = parsed;
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_args(int argc, char** argv, Config& cfg) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            usage();
            std::exit(0);
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "zapscan " << kVersion << "\n";
            std::exit(0);
        } else if (arg == "-p" || arg == "--ports") {
            if (i + 1 >= argc) return false;
            cfg.ports = argv[++i];
        } else if (arg == "-c" || arg == "--concurrency") {
            if (i + 1 >= argc || !parse_int(argv[++i], cfg.concurrency)) return false;
        } else if (arg == "-t" || arg == "--timeout") {
            if (i + 1 >= argc || !parse_int(argv[++i], cfg.timeout_ms)) return false;
        } else if (arg == "--no-banners") {
            cfg.banners = false;
        } else if (arg == "-j" || arg == "--json") {
            cfg.json = true;
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) return false;
            cfg.output_file = argv[++i];
        } else if (!arg.empty() && arg[0] == '-' && arg.size() > 1) {
            std::cerr << "zapscan: unknown option '" << arg << "'\n";
            return false;
        } else {
            cfg.targets.push_back(arg);
        }
    }
    return !cfg.targets.empty();
}

int write_output(const std::string& path, const std::string& data) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) {
        std::cerr << "zapscan: cannot write '" << path << "'\n";
        return 1;
    }
    f << data;
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    Config cfg;
    if (!parse_args(argc, argv, cfg)) {
        usage();
        return 2;
    }

    auto ports = zapscan::parse_ports(cfg.ports);
    if (ports.empty()) {
        std::cerr << "zapscan: no valid ports parsed from '" << cfg.ports << "'\n";
        return 2;
    }

    zapscan::ScanOptions opts;
    opts.concurrency = cfg.concurrency;
    opts.connect_timeout_ms = cfg.timeout_ms;
    opts.grab_banners = cfg.banners;

    std::ostringstream report_stream;

    for (const auto& target_spec : cfg.targets) {
        zapscan::ParseResult pr;
        auto targets = zapscan::expand_targets(target_spec, pr);
        if (pr != zapscan::ParseResult::Ok) {
            std::cerr << "zapscan: invalid target '" << target_spec << "'\n";
            return 2;
        }

        for (const auto& target : targets) {
            auto started = std::chrono::system_clock::now();
            auto result = zapscan::scan_host(target.label, ports, opts);
            auto finished = std::chrono::system_clock::now();

            zapscan::Report report;
            report.target = target_spec;
            report.started = started;
            report.finished = finished;
            report.result = std::move(result);

            report_stream << (cfg.json ? zapscan::format_json(report)
                                       : zapscan::format_text(report));
            if (!cfg.json) {
                report_stream << "\n";
            }
        }
    }

    std::string output = report_stream.str();
    if (!cfg.output_file.empty()) {
        return write_output(cfg.output_file, output);
    }
    std::cout << output;
    return 0;
}