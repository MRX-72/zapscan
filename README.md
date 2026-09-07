# zapscan

A parallel, native TCP port scanner written in C++17. No shelling out to nmap —
connections, timeouts, and banner grabs run directly over BSD sockets.

## Why this exists

Port scanners are usually either nmap wrappers (`system("nmap ...")`) or a
single blocking loop that scans one port at a time. This one is neither: it
opens a bounded pool of worker threads, connects asynchronously with `poll()`,
and scans in parallel with predictable concurrency.

## Features

- **Native TCP connect scan** — non-blocking `connect()` + `poll()`, no external tools
- **Deterministic concurrency** — bounded worker pool, configurable via `-c`
- **Banner grabbing** — reads service banners on open ports (disable with `--no-banners`)
- **Rich target parsing** — single IPs, hostnames, CIDR blocks, ranges, comma lists
- **Rich port parsing** — `80`, `1-1000`, `22,80,443-900`, deduplication
- **Text + JSON output** — human-readable report or machine-parsable JSON
- **File output** — `-o` writes the report to a file, `--json` + `-o` for pipeline use
- **Safe by construction** — no shell interpolation anywhere; input is parsed, validated, and bounds-checked

## Build

```bash
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build        # run tests
./build/zapscan --version
```

Only needs a C++17 compiler and CMake. No dependencies.

## Usage

```
zapscan [options] <target...>

Targets may be IPs, hostnames, CIDR blocks (192.168.1.0/24),
ranges (192.168.1.5-20), or comma-separated lists.

Options:
  -p, --ports <spec>     Ports to scan (default: 1-1024)
                         e.g. 80,443 or 1-1000 or 22,80,443-900
  -c, --concurrency <n>   Concurrent connections (default: 128)
  -t, --timeout <ms>      Connect timeout in ms (default: 1500)
      --no-banners        Disable banner grabbing
  -j, --json              Emit JSON output
  -o, --output <file>     Write report to file
  -h, --help              Show help
  -v, --version           Show version
```

### Examples

```bash
zapscan 192.168.1.1
zapscan -p 22,80,443 192.168.1.1
zapscan -p 1-1024 -c 256 scanme.nmap.org
zapscan -j -o report.json 10.0.0.0/24
zapscan --no-banners -t 3000 db.internal.example.com
```

### Text output

```
PORT      STATE   SERVICE        RTT     BANNER
80/tcp    open    http                0ms
443/tcp   open    https               0ms   Server: nginx
```

### JSON output

```json
{
  "target": "192.168.1.1",
  "ports": [
    {"port": 22, "state": "open", "service": "ssh", "rtt_ms": 1, "banner": "SSH-2.0-OpenSSH"}
  ]
}
```

## How it works

1. Targets and port lists are expanded and validated up front. Bad input is
   rejected before a single connection is made — no partial runs.
2. A fixed pool of worker threads pulls (host, port) pairs from an atomic
   work-queue index.
3. Each connection is made non-blocking and awaited with `poll()` for the
   configured timeout. An open port is one whose connect completes without
   `SO_ERROR`.
4. On open ports, the tool optionally reconnects and reads a banner for up to
   800 ms, bounded to 2 KB.
5. Results are collected under a mutex and sorted by port so output order is
   deterministic regardless of completion order.

Windows is not supported (POSIX sockets); macOS and Linux are.

## Why no SYN scan

SYN scans require raw sockets and root. A connect scan is the classic fallback:
it completes the handshake, which is exactly what banner grabbing needs anyway.
Privileged raw-socket scanning is a distinct feature, not a hidden omission.

## Project layout

```
include/zapscan/   public headers (target, scanner, report)
src/               implementation
tests/             unit + integration tests (dependency-free harness)
```

## Development

- `-Wall -Wextra -Wpedantic` enabled for all targets
- Debug builds can enable ASan/UBSan: `-DZAPSCAN_ENABLE_SANITIZERS=ON`
- Tests run locally via `ctest`, and in CI on macOS and Linux
- Sanitizer runs are part of CI

## License

MIT