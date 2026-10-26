#include "memguard/core/types.hpp"
#include "memguard/core/process.hpp"
#include "memguard/core/memory_scanner.hpp"
#include "memguard/core/entropy.hpp"
#include "memguard/report/console_reporter.hpp"
#include "memguard/report/json_reporter.hpp"
#include <iostream>
#include <span>
#include <vector>
#include <string>
#include <string_view>
#include <fstream>
#include <iomanip>

namespace {

void print_help() {
    std::cout << R"(MemGuard - Windows Process Memory & Anti-Tamper Forensics Scanner
Usage:
  memguard scan --pid <PID> [options]
  memguard scan --name <process_name> [options]
  memguard list
  memguard entropy <text_string>
  memguard entropy --file <path>
  memguard rules
  memguard --help

Options:
  --pid <pid>             Target Process ID to inspect
  --name <process.exe>    Target process by executable name
  --no-hooks              Skip inline API hook detection
  --no-entropy            Skip Shannon entropy calculation
  --min-entropy <float>   Threshold for suspicious entropy (default: 7.10)
  --min-severity <level>  Filter: INFO, LOW, MEDIUM, HIGH, CRITICAL (default: LOW)
  --dump <directory>      Dump suspicious payload buffers to folder
  --json <file_path>      Save structured scan report to JSON file
  --no-color              Disable ANSI colors in console output
  -h, --help              Show this help message
)";
}

void print_rules() {
    std::cout << R"(
Catalog of MemGuard Detection Rules:
--------------------------------------------------------------------------------------
ID      SEVERITY   CATEGORY            DESCRIPTION
--------------------------------------------------------------------------------------
MG-001  CRITICAL   MemoryInjection     Unbacked PE Header in Private Memory (Reflective DLL / Hollowed)
MG-002  HIGH       MemoryProtection    Private Executable-Writable Memory Region (RWX)
MG-003  MEDIUM     MemoryInjection     Unbacked Executable Memory Page (Private RX)
MG-004  HIGH       PayloadAnalysis     High Shannon Entropy Buffer (>7.1 bits, Packed/Encrypted)
MG-005  HIGH       Tampering           Tampered / Writable Module Code Section (.text patch)
MG-006  CRITICAL   ApiHooking          Inline API Hook / Syscall Trampoline into Unbacked Memory
--------------------------------------------------------------------------------------
)";
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help();
        return 0;
    }

    std::string command = argv[1];
    if (command == "--help" || command == "-h" || command == "help") {
        print_help();
        return 0;
    }

    if (command == "rules") {
        print_rules();
        return 0;
    }

    memguard::ScanConfig config;
    bool use_color = true;

    if (command == "list") {
        memguard::ConsoleReporter reporter(use_color);
        reporter.print_banner();
        auto procs = memguard::Process::enumerate_processes();
        reporter.print_process_list(procs);
        return 0;
    }

    if (command == "entropy") {
        if (argc < 3) {
            std::cerr << "[-] Error: provide a string or --file <path> to calculate entropy.\n";
            return 1;
        }
        std::string arg2 = argv[2];
        std::vector<std::uint8_t> data;
        if (arg2 == "--file" && argc >= 4) {
            std::ifstream file(argv[3], std::ios::binary);
            if (!file) {
                std::cerr << "[-] Failed to open file: " << argv[3] << "\n";
                return 1;
            }
            data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        } else {
            data.assign(arg2.begin(), arg2.end());
        }

        const double ent = memguard::EntropyCalculator::calculate(data);
        auto classification = memguard::EntropyCalculator::classify(ent, data.size());
        std::cout << "\n[Entropy Analysis]\n";
        std::cout << "  Input Size     : " << data.size() << " bytes\n";
        std::cout << "  Shannon Entropy: " << std::fixed << std::setprecision(4) << ent << " / 8.0000 bits\n";
        std::cout << "  Classification : " << memguard::EntropyCalculator::class_to_string(classification) << "\n\n";
        return 0;
    }

    if (command == "scan") {
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--pid" && i + 1 < argc) {
                config.target_pid = static_cast<std::uint32_t>(std::stoul(argv[++i]));
            } else if (arg == "--name" && i + 1 < argc) {
                config.target_name = argv[++i];
            } else if (arg == "--no-hooks") {
                config.scan_hooks = false;
            } else if (arg == "--no-entropy") {
                config.scan_entropy = false;
            } else if (arg == "--min-entropy" && i + 1 < argc) {
                config.min_entropy_threshold = std::stod(argv[++i]);
            } else if (arg == "--min-severity" && i + 1 < argc) {
                config.min_severity = memguard::string_to_severity(argv[++i]);
            } else if (arg == "--dump" && i + 1 < argc) {
                config.dump_suspicious = true;
                config.dump_directory = argv[++i];
            } else if (arg == "--json" && i + 1 < argc) {
                config.json_output_path = argv[++i];
            } else if (arg == "--no-color") {
                use_color = false;
            } else if (arg == "--help" || arg == "-h") {
                print_help();
                return 0;
            }
        }

        memguard::ConsoleReporter reporter(use_color);
        reporter.print_banner();

        // Elevate privileges if possible
        if (!memguard::Process::enable_debug_privilege()) {
            std::cout << "[*] Note: SeDebugPrivilege could not be acquired (run as Administrator for full system process access).\n";
        }

        if (config.target_pid == 0 && !config.target_name.empty()) {
            auto pid_opt = memguard::Process::find_pid_by_name(config.target_name);
            if (!pid_opt.has_value()) {
                std::cerr << "[-] Error: Process '" << config.target_name << "' not found.\n";
                return 1;
            }
            config.target_pid = pid_opt.value();
        }

        if (config.target_pid == 0) {
            std::cerr << "[-] Error: You must specify --pid <PID> or --name <process_name> to scan.\n";
            return 1;
        }

        std::cout << "[*] Attaching to target PID " << config.target_pid << "...\n";
        memguard::Process process(config.target_pid);
        if (!process.is_valid()) {
            std::cerr << "[-] Error: Failed to open process (Access Denied or Invalid PID).\n";
            return 2;
        }

        std::cout << "[*] Scanning virtual address space and memory regions...\n";
        memguard::MemoryScanner scanner(process, config);
        auto result = scanner.scan();

        reporter.print_scan_summary(result);
        reporter.print_findings(result);
        if (config.scan_hooks) {
            reporter.print_hooks(result);
        }

        if (!config.json_output_path.empty()) {
            if (memguard::JsonReporter::write_to_file(result, config.json_output_path)) {
                std::cout << "[+] Exported JSON report to: " << config.json_output_path << "\n";
            } else {
                std::cerr << "[-] Failed to write JSON report to: " << config.json_output_path << "\n";
            }
        }

        // Return non-zero exit code if Critical or High severity findings exist
        bool has_high_findings = false;
        for (const auto& f : result.findings) {
            if (f.severity >= memguard::Severity::High) has_high_findings = true;
        }
        for (const auto& h : result.hooks) {
            if (h.severity >= memguard::Severity::High) has_high_findings = true;
        }

        return has_high_findings ? 1 : 0;
    }

    print_help();
    return 0;
}
