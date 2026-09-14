#include "zapscan/scanner.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

namespace zapscan {

namespace {

const std::map<uint16_t, std::string>& service_table() {
    static const std::map<uint16_t, std::string> table = {
        {21, "ftp"},      {22, "ssh"},        {23, "telnet"},     {25, "smtp"},
        {53, "domain"},   {80, "http"},       {110, "pop3"},      {111, "rpcbind"},
        {135, "msrpc"},   {139, "netbios-ssn"},{143, "imap"},     {443, "https"},
        {445, "microsoft-ds"}, {465, "smtps"}, {587, "submission"},{631, "ipp"},
        {873, "rsync"},   {993, "imaps"},     {995, "pop3s"},     {1433, "ms-sql-s"},
        {1521, "oracle"}, {2049, "nfs"},      {3306, "mysql"},    {3389, "ms-wbt-server"},
        {5432, "postgresql"}, {5900, "vnc-server"}, {6379, "redis"}, {8080, "http-proxy"},
        {8443, "https-alt"},
    };
    return table;
}

}  // namespace

std::vector<uint16_t> known_ports() {
    std::vector<uint16_t> ports;
    for (const auto& entry : service_table()) {
        ports.push_back(entry.first);
    }
    return ports;
}

std::string default_service(uint16_t port) {
    auto it = service_table().find(port);
    return it == service_table().end() ? "" : it->second;
}

namespace {

// Digits only, 1-65535; returns 0 on anything else.
int parse_port_number(const std::string& s) {
    if (s.empty() || s.size() > 5 || s.find_first_not_of("0123456789") != std::string::npos) {
        return 0;
    }
    int value = std::stoi(s);
    return value <= 65535 ? value : 0;
}

}  // namespace

// Any invalid token rejects the whole spec (empty result), so typos fail loudly.
std::vector<uint16_t> parse_ports(const std::string& spec) {
    std::vector<uint16_t> ports;
    std::set<uint16_t> seen;
    if (spec.empty() || spec.back() == ',') {
        return {};
    }

    std::stringstream ss(spec);
    std::string token;
    while (std::getline(ss, token, ',')) {
        size_t dash = token.find('-');
        int lo = parse_port_number(token.substr(0, dash));
        int hi = dash == std::string::npos ? lo : parse_port_number(token.substr(dash + 1));
        if (lo == 0 || hi == 0 || lo > hi) {
            return {};
        }
        for (int p = lo; p <= hi; ++p) {
            if (seen.insert(static_cast<uint16_t>(p)).second) {
                ports.push_back(static_cast<uint16_t>(p));
            }
        }
    }
    return ports;
}

namespace {

int rtt_ms(const std::chrono::steady_clock::time_point& start) {
    auto now = std::chrono::steady_clock::now();
    return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count());
}

struct ConnectResult {
    bool open;
    int err;
    int rtt;
    bool local_error;  // this machine couldn't probe; says nothing about the port
    int fd = -1;       // connected socket, only when open and keep_open was requested
};

bool is_local_error(int err) {
    return err == EMFILE || err == ENFILE || err == ENOBUFS || err == ENOMEM ||
           err == EAGAIN || err == EADDRNOTAVAIL || err == EINTR;
}

ConnectResult try_connect(uint32_t ip, uint16_t port, int timeout_ms, bool keep_open) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return {false, errno, 0, true};
    }

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip);

    auto start = std::chrono::steady_clock::now();

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        if (!keep_open) {
            close(fd);
        }
        return {true, 0, rtt_ms(start), false, keep_open ? fd : -1};
    }
    if (errno != EINPROGRESS) {
        int saved = errno;
        close(fd);
        return {false, saved, rtt_ms(start), is_local_error(saved)};
    }

    struct pollfd pfd {};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    int pres = poll(&pfd, 1, timeout_ms);
    if (pres <= 0) {
        int saved = pres == 0 ? ETIMEDOUT : errno;
        close(fd);
        return {false, saved, rtt_ms(start), pres < 0};
    }

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
    bool open = (pfd.revents & POLLOUT) && so_error == 0;
    int rtt = rtt_ms(start);
    if (open && keep_open) {
        return {true, 0, rtt, false, fd};
    }
    close(fd);
    return {open, so_error, rtt, false};
}

// Reads from an already-connected non-blocking socket, then closes it.
std::string read_banner(int fd, int timeout_ms) {
    std::string banner;
    char buf[512];
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (banner.size() < 2048) {
        auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remain <= 0) {
            break;
        }
        struct pollfd pfd {};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int pres = poll(&pfd, 1, static_cast<int>(remain));
        if (pres <= 0) {
            break;
        }
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
        banner.append(buf, static_cast<size_t>(n));
    }
    close(fd);
    return banner;
}

}  // namespace

std::vector<HostResult> scan_hosts(const std::vector<Target>& targets,
                                   const std::vector<uint16_t>& ports, const ScanOptions& opts) {
    std::vector<HostResult> results(targets.size());
    for (size_t h = 0; h < targets.size(); ++h) {
        results[h].host = targets[h].label;
        results[h].ip = targets[h].ip;
        results[h].total_scanned = static_cast<int>(ports.size());
    }

    // One pool over every (host, port) pair. Ports are the outer loop so load is
    // spread across hosts instead of hammering one host at a time.
    const size_t total = targets.size() * ports.size();
    std::atomic<size_t> next{0};
    std::vector<std::future<void>> futures;
    std::mutex mu;

    size_t workers = std::min<size_t>(opts.concurrency, total);
    for (size_t w = 0; w < workers; ++w) {
        futures.emplace_back(std::async(std::launch::async, [&]() {
            for (;;) {
                size_t idx = next.fetch_add(1);
                if (idx >= total) {
                    break;
                }
                size_t h = idx % targets.size();
                const uint32_t ip = targets[h].ip;
                uint16_t port = ports[idx / targets.size()];

                auto conn = try_connect(ip, port, opts.connect_timeout_ms, opts.grab_banners);
                // Local exhaustion is usually transient while other workers release fds.
                for (int attempt = 1; conn.local_error && attempt <= 20; ++attempt) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    conn = try_connect(ip, port, opts.connect_timeout_ms, opts.grab_banners);
                }
                if (conn.local_error) {
                    std::lock_guard<std::mutex> lock(mu);
                    results[h].total_errors++;
                    continue;
                }
                if (!conn.open) {
                    continue;
                }

                PortResult pr;
                pr.port = port;
                pr.open = true;
                pr.service = default_service(port);
                pr.rtt_ms = conn.rtt;

                if (conn.fd >= 0) {
                    pr.banner = read_banner(conn.fd, 800);
                }

                std::lock_guard<std::mutex> lock(mu);
                results[h].ports.push_back(std::move(pr));
                results[h].total_open++;
            }
        }));
    }
    for (auto& f : futures) {
        f.get();
    }

    for (auto& result : results) {
        std::sort(result.ports.begin(), result.ports.end(),
                  [](const PortResult& a, const PortResult& b) { return a.port < b.port; });
    }
    return results;
}

HostResult scan_host(const Target& target, const std::vector<uint16_t>& ports,
                     const ScanOptions& opts) {
    return scan_hosts({target}, ports, opts)[0];
}

}  // namespace zapscan