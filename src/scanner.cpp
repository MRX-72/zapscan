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

std::vector<uint16_t> parse_ports(const std::string& spec) {
    std::vector<uint16_t> ports;
    std::set<uint16_t> seen;

    std::stringstream ss(spec);
    std::string token;
    while (std::getline(ss, token, ',')) {
        size_t dash = token.find('-');
        if (dash != std::string::npos) {
            int lo, hi;
            char* end1, *end2;
            lo = static_cast<int>(strtol(token.substr(0, dash).c_str(), &end1, 10));
            hi = static_cast<int>(strtol(token.substr(dash + 1).c_str(), &end2, 10));
            if (*end1 != '\0' || *end2 != '\0' || lo < 1 || hi < 1 || lo > 65535 ||
                hi > 65535 || lo > hi) {
                continue;
            }
            for (int p = lo; p <= hi; ++p) {
                if (seen.insert(static_cast<uint16_t>(p)).second) {
                    ports.push_back(static_cast<uint16_t>(p));
                }
            }
        } else {
            char* end;
            long single = strtol(token.c_str(), &end, 10);
            if (*end != '\0' || single < 1 || single > 65535) {
                continue;
            }
            if (seen.insert(static_cast<uint16_t>(single)).second) {
                ports.push_back(static_cast<uint16_t>(single));
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
};

ConnectResult try_connect(uint32_t ip, uint16_t port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return {false, errno, 0};
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
        close(fd);
        return {true, 0, rtt_ms(start)};
    }
    if (errno != EINPROGRESS) {
        int saved = errno;
        close(fd);
        return {false, saved, rtt_ms(start)};
    }

    struct pollfd pfd {};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    int pres = poll(&pfd, 1, timeout_ms);
    if (pres <= 0) {
        int saved = pres == 0 ? ETIMEDOUT : errno;
        close(fd);
        return {false, saved, rtt_ms(start)};
    }

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
    bool open = (pfd.revents & POLLOUT) && so_error == 0;
    close(fd);
    return {open, so_error, rtt_ms(start)};
}

std::string grab_banner(uint32_t ip, uint16_t port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return "";
    }

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip);

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return "";
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

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

HostResult scan_host(const Target& target, const std::vector<uint16_t>& ports,
                     const ScanOptions& opts) {
    const uint32_t ip = target.ip;

    HostResult result;
    result.host = target.label;
    result.ip = ip;
    result.total_scanned = static_cast<int>(ports.size());

    std::atomic<size_t> next{0};
    std::vector<std::future<void>> futures;
    std::mutex mu;

    size_t workers = std::min<size_t>(opts.concurrency, ports.size());
    if (workers == 0) {
        return result;
    }

    for (size_t w = 0; w < workers; ++w) {
        futures.emplace_back(std::async(std::launch::async, [&, ip]() {
            for (;;) {
                size_t idx = next.fetch_add(1);
                if (idx >= ports.size()) {
                    break;
                }
                uint16_t port = ports[idx];

                auto conn = try_connect(ip, port, opts.connect_timeout_ms);
                if (!conn.open) {
                    continue;
                }

                PortResult pr;
                pr.port = port;
                pr.open = true;
                pr.service = default_service(port);
                pr.rtt_ms = conn.rtt;

                if (opts.grab_banners) {
                    pr.banner = grab_banner(ip, port, 800);
                }

                std::lock_guard<std::mutex> lock(mu);
                result.ports.push_back(std::move(pr));
                result.total_open++;
            }
        }));
    }
    for (auto& f : futures) {
        f.get();
    }

    std::sort(result.ports.begin(), result.ports.end(),
              [](const PortResult& a, const PortResult& b) { return a.port < b.port; });
    return result;
}

}  // namespace zapscan