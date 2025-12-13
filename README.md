<h1 align="center">Zapscan v2.0</h1>
<p align="center">
  <b>Advanced Port Scanner & Reconnaissance Tool</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C++17-blue.svg" alt="Language">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20|%20macOS-lightgrey.svg" alt="Platform">
</p>

---

**Zapscan** is a powerful, C++ based CLI tool that wraps Nmap to provide a user-friendly and aesthetically pleasing interface for network reconnaissance. It simplifies complex Nmap flags into easy-to-remember commands while adding features like input sanitization, logging, and automated dependency checks.

## 🚀 Features

- **⚡ Fast & Optimized**: Built with C++17 for speed and efficiency.
- **🛡️ Secure**: Input sanitization prevents command injection vulnerabilities.
- **📋 Logging System**: Automatically save scan results to timestamped log files.
- **🔍 15+ Scan Modes**:
  - **Aggressive Scan**: Complete OS, service, and script detection.
  - **Stealth/No-Ping**: Scan hosts that block ping requests.
  - **Vulnerability**: Check for common vulnerabilities (if scripts available).
  - **UDP & Traceroute**: Deep network analysis options.
- **🛠️ Easy Build**: Ships with `CMake` support and a one-click `setup.sh`.

## 📦 Installation

### Option 1: Quick Setup (Linux/macOS)
```bash
git clone https://github.com/MRX-72/zapscan.git
cd zapscan
bash setup.sh
```

### Option 2: Manual Compile
Requirements: `cmake`, `g++`, `nmap`.
```bash
mkdir build && cd build
cmake ..
make
sudo make install
```

## 💻 Usage

Syntax: `zap <flags> <target>`

### 🔥 Popular Commands

| Goal | Command | Description |
| :--- | :--- | :--- |
| **Quick Check** | `zap -Fz <target>` | Scans top 100 common ports. |
| **Full Recon** | `zap -Az <target>` | OS detect, version scan, script scan, traceroute. |
| **Save Logs** | `zap -Lz -Az <target>` | Saves output to `zapscan_YYYYMMDD.log`. |
| **Bypass Ping** | `zap -Pnz <target>` | Scans hosts that block ICMP ping. |
| **All-in-One** | `zap -All <target>` | The most comprehensive scan mode available. |

### 🚩 Complete Flag List

| Flag | Nmap Equivalent | Function |
| :--- | :--- | :--- |
| `-Az` | `-A` | Aggressive Scan (OS/Version/Script/Trace) |
| `-Fz` | `-F` | Fast Scan (Top 100 ports) |
| `-Bz` | *(default)* | Basic Scan (Top 1000 ports) |
| `-Oz` | `-O` | Operating System Detection |
| `-sVz` | `-sV` | Service Version Detection |
| `-sCz` | `-sC` | Default Script Scan |
| `-Pnz` | `-Pn` | No-Ping / Treat Host as Online |
| `-Uz` | `-sU` | UDP Scan (Note: Slow) |
| `-Trz` | `--traceroute` | Trace path to host |
| `-Whois` | `whois` | Domain/IP Whois Lookup |
| `-Dz` | `dns-brute` | DNS Enumeration Script |
| `-T4z` | `-T4` | Aggressive Timing Template |
| `-Gz` | `ping` | Simple Ping Check |
| `-Sz <p>` | `-p <p>` | Scan Specific Port |
| `-Rz` | `-p <start>-<end>`| Interactive Range Scan |

## 🤝 Contributing

Contributions are welcome! Please fork the repository and submit a pull request.
1. Fork it.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---
<p align="center">
  Created by <a href="https://github.com/MRX-72">MRX-72</a>
</p>
