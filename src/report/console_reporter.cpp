#include "memguard/report/console_reporter.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

namespace memguard {

namespace {

constexpr const char* COLOR_RESET   = "\033[0m";
constexpr const char* COLOR_BOLD    = "\033[1m";
constexpr const char* COLOR_DIM     = "\033[2m";
constexpr const char* COLOR_RED     = "\033[31m";
constexpr const char* COLOR_GREEN   = "\033[32m";
constexpr const char* COLOR_YELLOW  = "\033[33m";
constexpr const char* COLOR_BLUE    = "\033[34m";
constexpr const char* COLOR_MAGENTA = "\033[35m";
constexpr const char* COLOR_CYAN    = "\033[36m";
constexpr const char* COLOR_WHITE   = "\033[37m";

std::string format_bytes(std::size_t bytes) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    if (bytes >= 1024ULL * 1024ULL * 1024ULL) {
        oss << (static_cast<double>(bytes) / (1024ULL * 1024ULL * 1024ULL)) << " GB";
    } else if (bytes >= 1024ULL * 1024ULL) {
        oss << (static_cast<double>(bytes) / (1024ULL * 1024ULL)) << " MB";
    } else if (bytes >= 1024ULL) {
        oss << (static_cast<double>(bytes) / 1024ULL) << " KB";
    } else {
        oss << bytes << " B";
    }
    return oss.str();
}

} // namespace

ConsoleReporter::ConsoleReporter(bool use_color) : use_color_(use_color) {}

const char* ConsoleReporter::severity_color(Severity sev) const noexcept {
    if (!use_color_) return "";
    switch (sev) {
        case Severity::Critical: return "\033[1;31m"; // Bold Red
        case Severity::High:     return "\033[31m";   // Red
        case Severity::Medium:   return "\033[33m";   // Yellow
        case Severity::Low:      return "\033[36m";   // Cyan
        case Severity::Info:     return "\033[37m";   // White
        default:                 return "";
    }
}

const char* ConsoleReporter::reset_color() const noexcept {
    return use_color_ ? COLOR_RESET : "";
}

void ConsoleReporter::print_banner() const {
    if (use_color_) std::cout << COLOR_CYAN << COLOR_BOLD;
    std::cout << R"(
    __  ___                ______                         __
   /  |/  /___  ____ ___  / ____/_  ______ _________  ___/ /
  / /|_/ / __ \/ __ `__ \/ / __/ / / / __ `/ ___/ _ \/ __  / 
 / /  / /  __/ / / / / / / /_/ / /_/ / /_/ / /  /  __/ /_/ /  
/_/  /_/\___/_/ /_/ /_/\/\____/\__,_/\__,_/_/   \___/\__,_/   
)";
    if (use_color_) std::cout << COLOR_RESET;
    std::cout << " Windows Process Memory & Anti-Tamper Forensics Scanner (C++20)\n";
    std::cout << " Zero External Dependencies • Shannon Entropy • Unbacked Executable & Hook Detection\n\n";
}

void ConsoleReporter::print_scan_summary(const ScanResult& result) const {
    std::cout << "======================================================================\n";
    std::cout << (use_color_ ? COLOR_BOLD : "") << " TARGET PROCESS SUMMARY" << reset_color() << "\n";
    std::cout << "----------------------------------------------------------------------\n";
    std::cout << "  Process Name    : " << result.target_process.name << " (PID: " << result.target_process.pid << ")\n";
    std::cout << "  Architecture    : " << (result.target_process.is_64bit ? "x64 (64-bit)" : "x86 (32-bit)") << "\n";
    if (!result.target_process.path.empty()) {
        std::cout << "  Image Path      : " << result.target_process.path << "\n";
    }
    std::cout << "  Memory Scanned  : " << format_bytes(result.target_process.total_memory_scanned)
              << " across " << result.total_regions_checked << " virtual regions\n";
    std::cout << "  Scan Duration   : " << result.duration.count() << " ms\n";
    std::cout << "  Executable Pages: " << result.executable_regions_count << "\n";
    std::cout << "  Detections      : " << severity_color(result.findings.empty() && result.hooks.empty() ? Severity::Low : Severity::Critical)
              << (result.findings.size() + result.hooks.size()) << " anomaly triggers" << reset_color() << "\n";
    std::cout << "======================================================================\n\n";
}

void ConsoleReporter::print_findings(const ScanResult& result) const {
    if (result.findings.empty()) {
        std::cout << (use_color_ ? COLOR_GREEN : "") << "[+] No suspicious unbacked or modified memory regions detected." << reset_color() << "\n\n";
        return;
    }

    std::cout << (use_color_ ? COLOR_BOLD : "") << "--- [ MEMORY ANOMALIES & INJECTIONS ] --------------------------------\n" << reset_color();

    for (std::size_t i = 0; i < result.findings.size(); ++i) {
        const auto& f = result.findings[i];
        std::cout << "\n[" << (i + 1) << "] "
                  << severity_color(f.severity) << "[" << severity_to_string(f.severity) << "]" << reset_color()
                  << " " << (use_color_ ? COLOR_BOLD : "") << f.rule_id << ": " << f.title << reset_color() << "\n";
        std::cout << "    Address  : 0x" << std::hex << std::uppercase << f.address << std::dec << "\n";
        std::cout << "    Size     : " << format_bytes(f.size) << " (" << f.size << " bytes)\n";
        if (f.entropy > 0.01) {
            std::cout << "    Entropy  : " << std::fixed << std::setprecision(3) << f.entropy << " / 8.000 bits\n";
        }
        std::cout << "    Details  : " << f.description << "\n";
        if (!f.extra_info.empty()) {
            std::cout << "    Metadata : " << (use_color_ ? COLOR_DIM : "") << f.extra_info << reset_color() << "\n";
        }
    }
    std::cout << "\n";
}

void ConsoleReporter::print_hooks(const ScanResult& result) const {
    if (result.hooks.empty()) {
        std::cout << (use_color_ ? COLOR_GREEN : "") << "[+] No inline API hooks or modified system syscalls detected." << reset_color() << "\n\n";
        return;
    }

    std::cout << (use_color_ ? COLOR_BOLD : "") << "--- [ INLINE API HOOKS & SYSCALL TRAMPOLINES ] -----------------------\n" << reset_color();

    for (std::size_t i = 0; i < result.hooks.size(); ++i) {
        const auto& h = result.hooks[i];
        std::cout << "\n[" << (i + 1) << "] "
                  << severity_color(h.severity) << "[" << severity_to_string(h.severity) << "]" << reset_color()
                  << " " << (use_color_ ? COLOR_BOLD : "") << h.module_name << "!" << h.function_name << reset_color() << "\n";
        std::cout << "    Address  : 0x" << std::hex << std::uppercase << h.memory_address << std::dec << "\n";
        std::cout << "    Hook Type: " << (use_color_ ? COLOR_YELLOW : "") << h.hook_type << reset_color() << "\n";
        if (h.target_address != 0) {
            std::cout << "    Target   : 0x" << std::hex << std::uppercase << h.target_address << std::dec << "\n";
        }
        std::cout << "    Bytes    : ";
        for (std::uint8_t b : h.patched_bytes) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
        }
        std::cout << std::dec << "\n";
    }
    std::cout << "\n";
}

void ConsoleReporter::print_process_list(const std::vector<ProcessInfo>& processes) const {
    std::cout << (use_color_ ? COLOR_BOLD : "") << std::left
              << std::setw(10) << "PID"
              << std::setw(35) << "PROCESS NAME"
              << reset_color() << "\n";
    std::cout << "--------------------------------------------------\n";
    for (const auto& p : processes) {
        std::cout << std::left
                  << std::setw(10) << p.pid
                  << std::setw(35) << p.name << "\n";
    }
    std::cout << "\nTotal processes: " << processes.size() << "\n";
}

} // namespace memguard
