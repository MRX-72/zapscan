#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
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
        << "  -p, --ports <spec>       Ports to scan (default: 1-1024)\n"
        << "                           e.g. 80,443 or 1-1000 or 22,80,443-900\n"
        << "  -F, --fast               Scan only well-known service ports (overrides -p)\n"
        << "  -iL, --input-list <file> Read targets from file, one per line (# comments)\n"
        << "  -c, --concurrency <n>    Concurrent connections (default: 128)\n"
        << "  -t, --timeout <ms>       Connect timeout in ms (default: 1500)\n"
        << "      --no-banners         Disable banner grabbing\n"
        << "  -j, --json               Emit JSON output\n"
        << "      --csv                Emit CSV output\n"
        << "  -o, --output <file>      Write report to file\n"
        << "  -h, --help               Show this help\n"
        << "  -v, --version            Show version\n";
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

bool parse_int(const std::string& text, int& out) {
    try {
        size_t pos = 0;
        int parsed = std::stoi(text, &pos);
        if (pos != text.size() || parsed <= 0) {
            return false;
        }
        out = parsed;
        return true;
    } catch (...) {
        return false;
    }
}

// Consumes the next argv element; false when the option has no value.
bool take_value(int argc, char** argv, int& i, std::string& value) {
    if (i + 1 >= argc) {
        return false;
    }
    value = argv[++i];
    return true;
}

std::string trim(const std::string& text) {
    auto first = text.find_first_not_of(" \t\r");
    if (first == std::string::npos) {
        return "";
    }
    auto last = text.find_last_not_of(" \t\r");
    return text.substr(first, last - first + 1);
}

bool read_target_file(const std::string& path, std::vector<std::string>& targets) {
    std::ifstream file(path);
    if (!file) {
        std::cerr << "zapscan: cannot read '" << path << "'\n";
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        std::string entry = trim(line.substr(0, line.find('#')));
        if (!entry.empty()) {
            targets.push_back(entry);
        }
    }
    return true;
}

bool parse_args(int argc, char** argv, Config& cfg) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        std::string value;

        if (arg == "-h" || arg == "--help") {
            usage();
            std::exit(0);
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "zapscan " << kVersion << "\n";
            std::exit(0);
        } else if (arg == "-p" || arg == "--ports") {
            if (!take_value(argc, argv, i, value)) return false;
            cfg.ports = value;
        } else if (arg == "-c" || arg == "--concurrency") {
            if (!take_value(argc, argv, i, value) || !parse_int(value, cfg.concurrency)) {
                return false;
            }
        } else if (arg == "-t" || arg == "--timeout") {
            if (!take_value(argc, argv, i, value) || !parse_int(value, cfg.timeout_ms)) {
                return false;
            }
        } else if (arg == "--no-banners") {
            cfg.banners = false;
        } else if (arg == "-F" || arg == "--fast") {
            cfg.fast = true;
        } else if (arg == "-iL" || arg == "--input-list") {
            if (!take_value(argc, argv, i, value) || !read_target_file(value, cfg.targets)) {
                return false;
            }
        } else if (arg == "-j" || arg == "--json") {
            cfg.json = true;
        } else if (arg == "--csv") {
            cfg.csv = true;
        } else if (arg == "-o" || arg == "--output") {
            if (!take_value(argc, argv, i, value)) return false;
            cfg.output_file = value;
        } else if (arg.size() > 1 && arg[0] == '-') {
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

// Expands and validates every target before any socket is opened.
bool expand_all_targets(const std::vector<std::string>& specs,
                        std::vector<zapscan::Target>& targets) {
    for (const auto& spec : specs) {
        zapscan::ParseResult pr;
        auto expanded = zapscan::expand_targets(spec, pr);
        if (pr != zapscan::ParseResult::Ok) {
            std::cerr << "zapscan: invalid target '" << spec << "'\n";
            return false;
        }
        for (auto& target : expanded) {
            targets.push_back(std::move(target));
        }
    }
    return true;
}

zapscan::Report make_report(const zapscan::HostResult& result,
                            std::chrono::system_clock::time_point started,
                            std::chrono::system_clock::time_point finished) {
    zapscan::Report report;
    report.started = started;
    report.finished = finished;
    report.result = result;
    return report;
}

// Each object ends with a newline; between objects that newline becomes ",\n".
std::string join_json_objects(const std::vector<std::string>& objects) {
    std::string out = "[\n";
    for (size_t i = 0; i < objects.size(); ++i) {
        std::string object = objects[i];
        if (i + 1 < objects.size()) {
            object.replace(object.size() - 1, 1, ",\n");
        }
        out += object;
    }
    out += "]\n";
    return out;
}

// Renders the whole run in the requested format, from one header to one footer.
std::string format_output(const std::vector<zapscan::HostResult>& results, const Config& cfg,
                          std::chrono::system_clock::time_point started,
                          std::chrono::system_clock::time_point finished) {
    if (cfg.json) {
        std::vector<std::string> objects;
        objects.reserve(results.size());
        for (const auto& result : results) {
            objects.push_back(zapscan::format_json(make_report(result, started, finished)));
        }
        return join_json_objects(objects);
    }

    std::ostringstream out;
    if (cfg.csv) {
        out << zapscan::kCsvHeader;
    }
    for (const auto& result : results) {
        zapscan::Report report = make_report(result, started, finished);
        if (cfg.csv) {
            out << zapscan::format_csv(report);
        } else {
            out << zapscan::format_text(report) << "\n";
        }
    }
    return out.str();
}

int write_output(const std::string& path, const std::string& data) {
    std::ofstream file(path, std::ios::trunc);
    if (!file) {
        std::cerr << "zapscan: cannot write '" << path << "'\n";
        return 1;
    }
    file << data;
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

    std::vector<zapscan::Target> targets;
    if (!expand_all_targets(cfg.targets, targets)) {
        return 2;
    }

    zapscan::ScanOptions opts;
    opts.concurrency = cfg.concurrency;
    opts.connect_timeout_ms = cfg.timeout_ms;
    opts.grab_banners = cfg.banners;

    // All hosts share one worker pool, so every report carries the whole run's times.
    auto started = std::chrono::system_clock::now();
    auto results = zapscan::scan_hosts(targets, ports, opts);
    auto finished = std::chrono::system_clock::now();

    std::string output = format_output(results, cfg, started, finished);
    if (cfg.output_file.empty()) {
        std::cout << output;
    } else if (write_output(cfg.output_file, output) != 0) {
        return 1;
    }

    int probe_errors = 0;
    for (const auto& result : results) {
        probe_errors += result.total_errors;
    }
    if (probe_errors > 0) {
        std::cerr << "zapscan: warning: " << probe_errors
                  << " probe(s) failed locally (e.g. too many open files); results are"
                     " incomplete. Lower -c or raise 'ulimit -n'.\n";
        return 3;
    }
    return 0;
}
