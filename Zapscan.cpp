#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <chrono>
#include <ctime>
#include <cstdlib>
#include <fstream>
#include <algorithm>
#include <regex>
#include <iomanip>

using namespace std;

class ZapScanner {
private:
    string target;
    string command;
    bool loggingEnabled;
    string logFileName;

    // Helper to get current date/time string
    string getCurrentDateTime() {
        auto now = chrono::system_clock::to_time_t(chrono::system_clock::now());
        string s(30, '\0');
        strftime(&s[0], s.size(), "%Y-%m-%d %H:%M:%S", localtime(&now));
        return s.substr(0, strlen(s.c_str()));
    }

    // Helper to sanitize input (basic check)
    bool isValidTarget(const string& t) {
        // Allow IP addresses, hostnames, and basics.
        // Simple regex for alphanumeric, dots, dashes.
        regex re("^[a-zA-Z0-9.-]+$");
        return regex_match(t, re);
    }

    void log(const string& message) {
        if (loggingEnabled) {
            ofstream logFile;
            logFile.open(logFileName, ios::app);
            if (logFile.is_open()) {
                logFile << message << endl;
                logFile.close();
            }
        }
    }

    void executeCommand(const string& cmdDescription, const string& cmd) {
        displayHeader();
        cout << "-> Target: " << target << endl;
        cout << "-> Action: " << cmdDescription << endl;
        cout << "-> Start : " << getCurrentDateTime() << endl;
        cout << string(40, '-') << endl;

        string fullCmd = cmd;
        if (loggingEnabled) {
             fullCmd += " | tee -a " + logFileName;
        }

        auto start = chrono::system_clock::now();
        
        // Security Note: In a real enterprise app, we'd use execv, but for this simpler
        // tool with sanitized input, system() is acceptable with warnings.
        int ret = system(fullCmd.c_str());

        auto end = chrono::system_clock::now();
        chrono::duration<double> elapsed = end - start;

        cout << string(40, '-') << endl;
        cout << "-> End   : " << getCurrentDateTime() << endl;
        cout << "-> Time  : " << elapsed.count() << "s" << endl;
        
        if (ret != 0) {
            cout << "[!] Command executed with errors or returned non-zero exit code." << endl;
        }

        if (loggingEnabled) {
            log("\n--- Scan Completed [" + cmdDescription + "] ---\n");
        }
    }

    void displayHeader() {
        // system("clear"); // Optional: clear screen or not? User might prefer scrolling.
        cout << "\n";
        cout << "         #########################\n";
        cout << "         #                       #\n";
        cout << "         #  Zapscan:   v2.0      #\n";
        cout << "         #  Github:    MRX-72    #\n";
        cout << "         #                       #\n";
        cout << "         #########################\n";
        cout << "\n";
    }

public:
    ZapScanner() : loggingEnabled(false) {
        // Generate a log filename based on time
        auto now = chrono::system_clock::to_time_t(chrono::system_clock::now());
        char buf[100];
        strftime(buf, sizeof(buf), "zapscan_%Y%m%d_%H%M%S.log", localtime(&now));
        logFileName = string(buf);
    }

    void setTarget(const string& t) {
        if (isValidTarget(t)) {
            target = t;
        } else {
            cerr << "[!] Invalid target format. Only alphanumeric, dots, and dashes allowed." << endl;
            exit(1);
        }
    }

    void enableLogging() {
        loggingEnabled = true;
        cout << "[+] Logging enabled. Output will be saved to " << logFileName << endl;
    }

    void showHelp() {
        cout << R"(
Zapscan v2.0 - Advanced Port Scanner & Recon Tool
Usage: zap [options] <target>

Options:
  -Az       Aggressive Scan (OS, Version, Script, Traceroute)
  -Fz       Fast Scan (Top 100 ports)
  -Bz       Basic Scan (Top 1000 ports)
  -Oz       OS Detection
  -sVz      Version Detection
  -Pnz      No Ping Scan (Treat all hosts as online)
  -Uz       UDP Scan (Warning: Slow)
  -Trz      Traceroute
  -sCz      Script Scan (Default scripts)
  -Vz       Vulnerability Scan (Custom port list)
  -Whois    Whois Lookup
  -Dz       DNS Enumeration (dns-brute)
  -T4z      Aggressive Timing (Nmap -T4)
  -All      Comprehensive Scan (Aggressive + All Ports)
  -Gz       Ping Check
  -Sz       Specific Port (Usage: zap -Sz <port> <target>)
  -Rz       Range Scan (Interactive)
  
  -Lz       Enable logging to file
  --help    Show this help message

Examples:
  zap -Fz scanme.nmap.org
  zap -Az 192.168.1.1
  zap -Lz -Fz scanme.nmap.org
        )" << endl;
    }

    // --- Scan Implementations ---

    void fastScan() {
        executeCommand("Fast Scan", "nmap -F " + target);
    }

    void basicScan() {
        executeCommand("Basic Scan", "nmap " + target);
    }

    void aggressiveScan() {
        executeCommand("Aggressive Scan", "nmap -A " + target);
    }

    void osScan() {
        executeCommand("OS Detection", "nmap -O " + target);
    }

    void versionScan() {
        executeCommand("Version Detection", "nmap -sV " + target);
    }

    void noPingScan() {
        executeCommand("No Ping Scan", "nmap -Pn " + target);
    }

    void udpScan() {
        cout << "[!] UDP Scans can be very slow." << endl;
        executeCommand("UDP Scan", "nmap -sU " + target);
    }

    void traceroute() {
        executeCommand("Traceroute", "nmap --traceroute " + target);
    }

    void scriptScan() {
        executeCommand("Script Scan", "nmap -sC " + target);
    }

    void whois() {
        executeCommand("Whois Lookup", "whois " + target);
    }

    void dnsEnum() {
        executeCommand("DNS Enumeration", "nmap --script dns-brute " + target);
    }

    void timingScan() {
        executeCommand("Aggressive Timing Scan", "nmap -T4 " + target);
    }

    void comprehensiveScan() {
        executeCommand("Comprehensive Scan", "nmap -p- -A -T4 " + target);
    }

    void pingCheck() {
        executeCommand("Ping Check", "ping -c 3 " + target);
    }

    void vulnScan() {
        // Defined in original code as a specific list of ports
        string ports = "20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080";
        executeCommand("Vulnerability Port Scan", "nmap -p " + ports + " --script vuln " + target);
    }

    void specificScan(const string& port) {
        executeCommand("Specific Port Scan (" + port + ")", "nmap -p " + port + " " + target);
    }

    void rangeScan() {
        int startPort, endPort;
        cout << "[?] Enter Start Port: ";
        if (!(cin >> startPort)) {
             cerr << "Invalid input" << endl; return;
        }
        cout << "[?] Enter End Port: ";
        if (!(cin >> endPort)) {
             cerr << "Invalid input" << endl; return;
        }
        
        executeCommand("Range Scan (" + to_string(startPort) + "-" + to_string(endPort) + ")", 
            "nmap -p " + to_string(startPort) + "-" + to_string(endPort) + " " + target);
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "[!] Syntax: zap [options] <target>" << endl;
        cerr << "[!] Try 'zap --help' for more information." << endl;
        return 1;
    }

    ZapScanner scanner;
    string command = argv[1];
    
    // Check for help immediately
    if (command == "--help" || command == "-h") {
        scanner.showHelp();
        return 0;
    }

    // Handle args
    // Basic argument parsing logic
    // We expect: zap <flag> [port/optional] <target>
    // Or if logging is enabled: zap -Lz <flag> <target>

    // Let's implement a simple loop to find flags and target.
    // Constraints according to requirements: Keep it simple.
    
    // New logic: 
    // If first arg is -Lz, enable logging and shift.
    int argIndex = 1;
    if (string(argv[argIndex]) == "-Lz") {
        scanner.enableLogging();
        argIndex++;
        if (argIndex >= argc) {
             cerr << "[!] Missing command/target after -Lz" << endl;
             return 1;
        }
        command = argv[argIndex];
    }

    // Special case: Range scan might not need target immediately if interactive? 
    // But our logic stores target differently.
    // Let's assume the LAST argument is the target for most commands, 
    // unless it's a specific flag structure.

    if (command == "-Rz") {
        // Range scan interactive
        // We still need a target.
        if (argIndex + 1 < argc) {
            scanner.setTarget(argv[argIndex + 1]);
            scanner.rangeScan();
        } else {
             cerr << "[!] Missing target. Usage: zap -Rz <target>" << endl;
             return 1;
        }
        return 0;
    }
    
    if (command == "-Sz") {
        if (argIndex + 2 < argc) {
            string port = argv[argIndex + 1];
            scanner.setTarget(argv[argIndex + 2]);
            scanner.specificScan(port);
        } else {
            cerr << "[!] Missing args. Usage: zap -Sz <port> <target>" << endl;
            return 1;
        }
        return 0;
    }

    // General case: zap <flag> <target>
    if (argIndex + 1 >= argc) {
        cerr << "[!] Missing target." << endl;
        return 1;
    }

    scanner.setTarget(argv[argIndex + 1]);

    if (command == "-Fz") scanner.fastScan();
    else if (command == "-Bz") scanner.basicScan();
    else if (command == "-Az") scanner.aggressiveScan();
    else if (command == "-Oz") scanner.osScan();
    else if (command == "-sVz") scanner.versionScan();
    else if (command == "-Pnz") scanner.noPingScan();
    else if (command == "-Uz") scanner.udpScan();
    else if (command == "-Trz") scanner.traceroute();
    else if (command == "-sCz") scanner.scriptScan();
    else if (command == "-Vz") scanner.vulnScan();
    else if (command == "-Whois") scanner.whois();
    else if (command == "-Dz") scanner.dnsEnum();
    else if (command == "-T4z") scanner.timingScan();
    else if (command == "-All") scanner.comprehensiveScan();
    else if (command == "-Gz") scanner.pingCheck();
    else {
        cerr << "[!] Unknown command: " << command << endl;
        scanner.showHelp();
        return 1;
    }

    return 0;
}
