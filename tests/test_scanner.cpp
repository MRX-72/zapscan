#include <arpa/inet.h>

#include <chrono>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <thread>

#include "zapscan/report.hpp"
#include "zapscan/scanner.hpp"
#include "zapscan/target.hpp"
#include "test_harness.hpp"

namespace {

int listen_on_port(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

zapscan::Target get_local_loopback() {
    return {0x7F000001, "127.0.0.1"};
}

}  // namespace

TEST(scan_open_and_closed_port) {
    int fd = listen_on_port(31234);
    EXPECT_NE(fd, -1);

    zapscan::ScanOptions opts;
    opts.grab_banners = false;
    auto result = zapscan::scan_host(get_local_loopback(), {31234, 39999}, opts);

    EXPECT_EQ(result.total_scanned, 2);
    EXPECT_EQ(result.total_open, 1);
    EXPECT_EQ(result.ports.size(), 1u);
    if (!result.ports.empty()) {
        EXPECT_EQ(result.ports[0].port, 31234);
    }
    close(fd);
}

TEST(scan_multiple_open_ports) {
    int fd1 = listen_on_port(31235);
    int fd2 = listen_on_port(31236);
    EXPECT_NE(fd1, -1);
    EXPECT_NE(fd2, -1);

    zapscan::ScanOptions opts;
    opts.grab_banners = false;
    auto result = zapscan::scan_host(get_local_loopback(), {31235, 31236}, opts);

    EXPECT_EQ(result.total_open, 2);
    EXPECT_EQ(result.ports.size(), 2u);
    close(fd1);
    close(fd2);
}

TEST(request_pacing_does_not_reorder_open_ports) {
    int fd1 = listen_on_port(31240);
    int fd2 = listen_on_port(31241);
    int fd3 = listen_on_port(31242);

    zapscan::ScanOptions opts;
    opts.grab_banners = false;
    auto result = zapscan::scan_host(get_local_loopback(), {31242, 31240, 31241}, opts);

    EXPECT_EQ(result.total_open, 3);
    EXPECT_EQ(result.ports[0].port, 31240);
    EXPECT_EQ(result.ports[1].port, 31241);
    EXPECT_EQ(result.ports[2].port, 31242);
    close(fd1);
    close(fd2);
    close(fd3);
}
TEST(scan_uses_resolved_ip_not_label) {
    int fd = listen_on_port(31250);
    EXPECT_NE(fd, -1);

    zapscan::ScanOptions opts;
    opts.grab_banners = false;
    // Label is unresolvable: the scan must use target.ip, not look up the name again.
    zapscan::Target target{0x7F000001, "multi-a.invalid"};
    auto result = zapscan::scan_host(target, {31250}, opts);

    EXPECT_EQ(result.host, "multi-a.invalid");
    EXPECT_EQ(result.ip, 0x7F000001u);
    EXPECT_EQ(result.total_open, 1);
    close(fd);
}

TEST(local_socket_errors_are_counted_not_reported_closed) {
    int fd = listen_on_port(31260);
    EXPECT_NE(fd, -1);

    // Cap the fd limit at the next free descriptor so every socket() fails with EMFILE.
    struct rlimit saved {};
    getrlimit(RLIMIT_NOFILE, &saved);
    int next_free = dup(0);
    close(next_free);
    struct rlimit tight = saved;
    tight.rlim_cur = static_cast<rlim_t>(next_free);
    setrlimit(RLIMIT_NOFILE, &tight);

    zapscan::ScanOptions opts;
    opts.grab_banners = false;
    opts.concurrency = 1;
    auto result = zapscan::scan_host(get_local_loopback(), {31260}, opts);

    setrlimit(RLIMIT_NOFILE, &saved);

    EXPECT_EQ(result.total_open, 0);
    EXPECT_EQ(result.total_errors, 1);
    close(fd);
}

TEST(scan_grabs_banner_from_probe_connection) {
    int fd = listen_on_port(31270);
    EXPECT_NE(fd, -1);
    // Greet each connection; the banner must come from the connection the probe opened.
    std::thread server([fd]() {
        int client = accept(fd, nullptr, nullptr);
        if (client >= 0) {
            const char greeting[] = "SSH-2.0-test\r\n";
            send(client, greeting, sizeof(greeting) - 1, 0);
            close(client);
        }
    });

    zapscan::ScanOptions opts;
    auto result = zapscan::scan_host(get_local_loopback(), {31270}, opts);
    server.join();

    EXPECT_EQ(result.total_open, 1);
    if (!result.ports.empty()) {
        EXPECT_EQ(result.ports[0].banner, "SSH-2.0-test\r\n");
    }
    close(fd);
}
