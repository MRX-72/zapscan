#!/bin/bash

echo "[*] Zapscan Setup Started..."

# Function to check command existence
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for Nmap
if ! command_exists nmap; then
    echo "[!] Nmap is not installed. Installing..."
    if command_exists apt-get; then
        sudo apt-get update && sudo apt-get install -y nmap
    elif command_exists yum; then
        sudo yum install -y nmap
    elif command_exists brew; then
        brew install nmap
    else
        echo "[!] Clean install failed. Please install nmap manually."
        exit 1
    fi
else
    echo "[+] Nmap is already installed."
fi

# Check for g++ or clang
if ! command_exists g++ && ! command_exists clang++; then
    echo "[!] No C++ compiler found. Installing g++..."
    sudo apt-get install -y g++ || echo "[!] Failed to install compiler."
fi

# Build
echo "[*] Building Zapscan..."

if command_exists cmake; then
    echo "[+] CMake found. Using CMake build system..."
    mkdir -p build
    cd build
    cmake ..
    cmake --build .
    # Move binary to root or path
    sudo cp zap /usr/local/bin/zap 2>/dev/null || cp zap ../zap
    cd ..
    echo "[+] Built successfully."
else
    echo "[*] CMake not found. Falling back to g++..."
    g++ -std=c++17 Zapscan.cpp -o zap
    echo "[+] Built successfully."
    echo "[*] Moving to /usr/local/bin (requires sudo)..."
    sudo mv zap /usr/local/bin/zap || echo "[!] Failed to move binary. You can run it locally with ./zap"
fi

echo ""
echo "-----------------------------------"
echo "Zapscan Installed Successfully!"
echo "Type 'zap --help' to get started."
echo "-----------------------------------"
