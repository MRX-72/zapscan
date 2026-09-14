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
        << "  -F, --fast              Scan only well-known service ports (overrides -p)\n"
        << "  -iL, --input-list <file> Read targets from file, one per line (# comments)\n"
        << "  -c, --concurrency <n>   Concurrent connections (default: 128)\n"
        << "  -t, --timeout <ms>      Connect timeout in ms (default: 1500)\n"
        << "      --no-banners        Disable banner grabbing\n"
        << "  -j, --json              Emit JSON output\n"
        << "      --csv               Emit CSV output\n"
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
    bool fast = false;
    bool json = false;
    bool csv = false;
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

bool read_target_file(const std::string& path, std::vector<std::string>& targets) {
    std::ifstream f(path);
    if (!f) {
        std::cerr << "zapscan: cannot read '" << path << "'\n";
        return false;
    }
    std::string line;
    while (std::getline(f, line)) {
        line = line.substr(0, line.find('#'));
        auto first = line.find_first_not_of(" \t\r");
        if (first == std::string::npos) {
            continue;
        }
        targets.push_back(line.substr(first, line.find_last_not_of(" \t\r") - first + 1));
    }
    return true;
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
        } else if (arg == "-F" || arg == "--fast") {
            cfg.fast = true;
        } else if (arg == "-iL" || arg == "--input-list") {
            if (i + 1 >= argc || !read_target_file(argv[++i], cfg.targets)) return false;
        } else if (arg == "-j" || arg == "--json") {
            cfg.json = true;
        } else if (arg == "--csv") {
            cfg.csv = true;
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
    if (cfg.json && cfg.csv) {
        std::cerr << "zapscan: --json and --csv are mutually exclusive\n";
        return false;
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

    auto ports = cfg.fast ? zapscan::known_ports() : zapscan::parse_ports(cfg.ports);
    if (ports.empty()) {
        std::cerr << "zapscan: invalid port spec '" << cfg.ports << "'\n";
        return 2;
    }

    zapscan::ScanOptions opts;
    opts.concurrency = cfg.concurrency;
    opts.connect_timeout_ms = cfg.timeout_ms;
    opts.grab_banners = cfg.banners;

    std::ostringstream report_stream;
    int probe_errors = 0;
    if (cfg.csv) {
        report_stream << zapscan::kCsvHeader;
    }
    // JSON is always one array of per-host objects, so the output parses as a whole.
    bool first_json = true;
    if (cfg.json) {
        report_stream << "[\n";
    }

    // Expand and validate every target before any socket is opened.
    std::vector<std::string> specs;  // parallel to targets: the argument each came from
    std::vector<zapscan::Target> targets;
    for (const auto& target_spec : cfg.targets) {
        zapscan::ParseResult pr;
        auto expanded = zapscan::expand_targets(target_spec, pr);
        if (pr != zapscan::ParseResult::Ok) {
            std::cerr << "zapscan: invalid target '" << target_spec << "'\n";
            return 2;
        }
        for (auto& target : expanded) {
            specs.push_back(target_spec);
            targets.push_back(std::move(target));
        }
    }

    // All hosts share one worker pool, so every report carries the whole run's times.
    auto started = std::chrono::system_clock::now();
    auto results = zapscan::scan_hosts(targets, ports, opts);
    auto finished = std::chrono::system_clock::now();

    for (size_t i = 0; i < results.size(); ++i) {
        probe_errors += results[i].total_errors;

        zapscan::Report report;
        report.target = specs[i];
        report.started = started;
        report.finished = finished;
        report.result = std::move(results[i]);

        if (cfg.json) {
            if (!first_json) {
                report_stream.seekp(-1, std::ios_base::end);  // "}\n" -> "},\n"
                report_stream << ",\n";
            }
            report_stream << zapscan::format_json(report);
            first_json = false;
        } else if (cfg.csv) {
            report_stream << zapscan::format_csv(report);
        } else {
            report_stream << zapscan::format_text(report) << "\n";
        }
    }

    if (cfg.json) {
        report_stream << "]\n";
    }
    std::string output = report_stream.str();
    if (!cfg.output_file.empty()) {
        if (write_output(cfg.output_file, output) != 0) {
            return 1;
        }
    } else {
        std::cout << output;
    }
    if (probe_errors > 0) {
        std::cerr << "zapscan: warning: " << probe_errors
                  << " probe(s) failed locally (e.g. too many open files); results are"
                     " incomplete. Lower -c or raise 'ulimit -n'.\n";
        return 3;
    }
    return 0;
}