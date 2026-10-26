#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <string_view>
#include <chrono>

namespace memguard {

enum class Severity : uint8_t {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

[[nodiscard]] constexpr std::string_view severity_to_string(Severity sev) noexcept {
    switch (sev) {
        case Severity::Info:     return "INFO";
        case Severity::Low:      return "LOW";
        case Severity::Medium:   return "MEDIUM";
        case Severity::High:     return "HIGH";
        case Severity::Critical: return "CRITICAL";
        default:                 return "UNKNOWN";
    }
}

[[nodiscard]] constexpr Severity string_to_severity(std::string_view s) noexcept {
    if (s == "INFO" || s == "info") return Severity::Info;
    if (s == "LOW" || s == "low") return Severity::Low;
    if (s == "MEDIUM" || s == "medium" || s == "MED" || s == "med") return Severity::Medium;
    if (s == "HIGH" || s == "high") return Severity::High;
    if (s == "CRITICAL" || s == "critical" || s == "CRIT" || s == "crit") return Severity::Critical;
    return Severity::Low;
}

struct MemoryRegion {
    std::uintptr_t base_address{0};
    std::size_t region_size{0};
    std::uint32_t state{0};
    std::uint32_t protect{0};
    std::uint32_t alloc_protect{0};
    std::uint32_t type{0};
    std::string mapped_module;
    bool is_executable{false};
    bool is_writable{false};
    bool is_private{false};
};

struct Finding {
    std::string rule_id;
    Severity severity{Severity::Info};
    std::string title;
    std::string description;
    std::uintptr_t address{0};
    std::size_t size{0};
    double entropy{0.0};
    std::string extra_info;
};

struct HookFinding {
    std::string module_name;
    std::string function_name;
    std::uintptr_t memory_address{0};
    std::vector<std::uint8_t> original_bytes;
    std::vector<std::uint8_t> patched_bytes;
    std::string hook_type; // e.g. "JMP Rel32", "JMP QWORD [RIP+x]", "MOV RAX + JMP RAX"
    std::uintptr_t target_address{0};
    Severity severity{Severity::High};
};

struct ProcessInfo {
    std::uint32_t pid{0};
    std::string name;
    std::string path;
    bool is_64bit{true};
    std::size_t memory_working_set{0};
    std::size_t scanned_regions{0};
    std::size_t total_memory_scanned{0};
};

struct ScanConfig {
    std::uint32_t target_pid{0};
    std::string target_name;
    bool scan_hooks{true};
    bool scan_entropy{true};
    double min_entropy_threshold{7.10}; // Shannon entropy > 7.1 out of 8.0 usually indicates encrypted/packed data
    Severity min_severity{Severity::Low};
    bool dump_suspicious{false};
    std::string dump_directory{"./dumps"};
    std::string json_output_path;
};

struct ScanResult {
    ProcessInfo target_process;
    std::chrono::system_clock::time_point timestamp;
    std::chrono::milliseconds duration{0};
    std::vector<Finding> findings;
    std::vector<HookFinding> hooks;
    std::size_t total_regions_checked{0};
    std::size_t executable_regions_count{0};
    std::size_t suspicious_regions_count{0};
};

} // namespace memguard
