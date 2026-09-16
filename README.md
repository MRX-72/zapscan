<div align="center">

# zapscan

[![CI](https://github.com/MRX-72/zapscan/actions/workflows/ci.yml/badge.svg)](https://github.com/MRX-72/zapscan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)](https://en.cppreference.com/w/cpp/17)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)]()

<br>

</div>

A parallel TCP port scanner in C++17. Connections, timeouts, and banner grabs
run directly over BSD sockets — no shelling out to `nmap`, no external
dependencies, no interpreter in the middle.

```bash
zapscan -p 22,80,443 192.168.1.10
```

## Table of contents

- [Why zapscan](#why-zapscan)
- [Features](#features)
- [Building](#building)
- [Usage](#usage)
- [Examples](#examples)
- [Output formats](#output-formats)
- [How it works](#how-it-works)
- [Design decisions](#design-decisions)
- [Project layout](#project-layout)
- [Development](#development)
- [Security & responsible use](#security--responsible-use)
- [License](#license)

## Why zapscan

Port scanners typically fall into two camps: wrappers that shell out to
`nmap`, and single-threaded loops that probe one port at a time. The first
adds a heavyweight dependency and stringly-typed shell commands; the second is
dramatically slow on anything larger than a single host.

zapscan is neither. It is a self-contained scanner with a bounded pool of
worker threads, non-blocking `connect()`, and `poll()`-based timeouts — fast
enough to sweep a `/24` in seconds, small enough to build in one command, and
safe enough that it never touches a shell.

## Features

- **Native TCP connect scan** — non-blocking `connect()` awaited via `poll()`, no external tools
- **Bounded concurrency** — a fixed worker pool you control with `-c`; no thread explosion
- **Banner grabbing** — reads service banners on open ports (disable per-run with `--no-banners`)
- **Flexible targets** — single IPs, hostnames, CIDR blocks, ranges, comma-separated lists, or a file via `-iL`
- **Flexible ports** — `80`, `1-1000`, `22,80,443-900`, with deduplication, or `-F` for well-known service ports only
- **Text, JSON, and CSV output** — readable reports, machine-parsable JSON, or spreadsheet-ready CSV
- **File output** — `-o` writes any report format to a file for pipelines and logs
- **Fail-fast parsing** — invalid targets and port specs are rejected before a single connection
- **Safe by construction** — all input is parsed, validated, and bounds-checked; no shell interpolation anywhere

## Building

Requires:

- A C++17 compiler (GCC, Clang)
- CMake 3.16 or newer
- POSIX sockets (macOS or Linux)

```bash
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build
./build/zapscan --version
```

Install system-wide (optional):

```bash
cmake --install build
```

To run the test suite with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DZAPSCAN_ENABLE_SANITIZERS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## Usage

```
zapscan v3.0.0 - parallel TCP port scanner

Usage: zapscan [options] <target...>

Targets may be IPs, hostnames, CIDR blocks (192.168.1.0/24),
ranges (192.168.1.5-20), or comma-separated lists.

Options:
  -p, --ports <spec>       Ports to scan (default: 1-1024)
                           e.g. 80,443 or 1-1000 or 22,80,443-900
  -F, --fast               Scan only well-known service ports (overrides -p)
  -iL, --input-list <file> Read targets from file, one per line (# comments)
  -c, --concurrency <n>    Concurrent connections (default: 128)
  -t, --timeout <ms>       Connect timeout in ms (default: 1500)
      --no-banners         Disable banner grabbing
  -j, --json               Emit JSON output
      --csv                Emit CSV output
  -o, --output <file>      Write report to file
  -h, --help               Show this help
  -v, --version            Show version
```

### Exit codes

| Code | Meaning                              |
|------|--------------------------------------|
| 0    | Scan completed (open or not)         |
| 1    | Output file could not be written     |
| 2    | Invalid arguments, target, or ports  |
| 3    | Scan incomplete: some probes failed locally (e.g. too many open files) |

## Examples

```bash
# Single host, default ports 1-1024
zapscan 192.168.1.1

# Specific ports
zapscan -p 22,80,443 192.168.1.1

# A broad range with higher concurrency
zapscan -p 1-1024 -c 256 scanme.nmap.org

# Whole subnet, JSON to a file
zapscan -j -o report.json 10.0.0.0/24

# Well-known ports on every host listed in a file, as CSV
zapscan -F --csv -o report.csv -iL hosts.txt

# Fast sweep of a range, no banner grabbing
zapscan --no-banners -t 3000 192.168.1.5-20
```

## Output formats

### Text

```
zapscan 127.0.0.1 [2026-09-07 14:25:36]
------------------------------------------------------------------------------
PORT      STATE   SERVICE        RTT     BANNER
31251/tcp   open   -                 0ms   SSH-2.0-OpenSSH_9.6 TEST
------------------------------------------------------------------------------
Scanned 1 ports, 1 open, in 0 ms
```

### JSON (`-j`)

```json
[
{
  "target": "127.0.0.1",
  "ip": "127.0.0.1",
  "started": "2026-09-07 14:25:36",
  "finished": "2026-09-07 14:25:36",
  "ports": [
    {"port": 31251, "state": "open", "service": "", "rtt_ms": 0, "banner": "SSH-2.0-OpenSSH_9.6 TEST"}
  ]
}
]
```

The output is always a single JSON array with one object per scanned host, even
when only one host is scanned.

### CSV (`--csv`)

```
host,ip,port,service,rtt_ms,banner
127.0.0.1,127.0.0.1,22,ssh,0,SSH-2.0-OpenSSH_9.6
```

One header row, then one row per open port across all hosts. A hostname that
resolves to several addresses gets separate rows per `ip`. Fields with commas
or quotes are quoted, and cells starting with `= + - @` get a leading `'` so
spreadsheets don't run them as formulas.

Banners are sanitized to printable characters and truncated (80 bytes in text,
512 bytes in JSON and CSV). Non-printable bytes render as `?`.

## How it works

1. **Validate first** — targets and port specs are expanded and checked before
   any socket is created. Invalid input aborts the run entirely; no partial scans.
2. **Feed the pool** — a single fixed pool of worker threads, shared by all
   hosts, pulls `(host, port)` pairs from a shared atomic work index. Pairs are
   interleaved across hosts, so a slow or unresponsive host doesn't hold up the others.
   Every report shows the start and end time of the whole run.
3. **Connect non-blocking** — each probe opens a socket, returns immediately from
   `connect()`, and awaits readiness with `poll()` up to the configured timeout.
   A port is open if the connect completes without `SO_ERROR`.
4. **Grab banners** — on open ports, reads the banner from the probe's own
   connection for up to 800 ms, bounded to 2 KB. No second connection is made.
5. **Report deterministically** — results are collected under a mutex and sorted
   by port, so output order is stable regardless of completion order.

## Design decisions

### Why a connect scan, not a SYN scan

A `connect()` scan completes the TCP handshake, which is exactly what banner
grabbing requires. SYN scanning needs raw sockets and privileges, and it
produces results separate from the banner-grabbing pass. Getting correct,
verified results with zero privileges is more useful than an unverified
half-open probe. Privileged scanning is a potential future direction, not a
hidden omission.

### Why C++17

Single self-contained static binary, no runtime to ship, POSIX sockets with no
abstraction layer, and `-Wall -Wextra -Wpedantic` hygiene. At this scope there
is no reason to pull in a framework.

### Why no interdependency on nmap

No `system()` calls, no parsing of another tool's output, no version skew. The
scanner's behavior is defined by its own source, tested by its own tests.

## Project layout

```
include/zapscan/   public headers (target, scanner, report)
src/               implementation
tests/             dependency-free test harness + unit/integration tests
.github/workflows/ CI
```

## Development

- Compiler flags: `-Wall -Wextra -Wpedantic` (all targets), `/W4` on MSVC
- Tests run via `ctest`, on macOS and Linux in CI, with a dedicated
  ASan/UBSan job
- The integration tests bind real listening sockets on loopback and verify
  results against them — no mocking of the network layer
- CMake options: `ZAPSCAN_BUILD_TESTS` (default ON),
  `ZAPSCAN_ENABLE_SANITIZERS` (Debug-only, default OFF)

## Security & responsible use

Port scanning active services is probing. Only scan networks and hosts you own
or are explicitly authorized to test. Unauthorized scanning may violate laws,
policies, or acceptable-use terms where you operate. Use zapscan responsibly
and within your authorization.

## License

[MIT](LICENSE) © [MRX-72](https://github.com/MRX-72)