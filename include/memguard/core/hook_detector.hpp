#pragma once

#include "memguard/core/types.hpp"
#include "memguard/core/process.hpp"
#include <vector>
#include <string>

namespace memguard {

class HookDetector {
public:
    explicit HookDetector(Process& process);

    /// Scan target process ntdll.dll and kernel32.dll for inline hooks and trampolines
    [[nodiscard]] std::vector<HookFinding> scan_critical_hooks();

    /// Analyzes raw bytes of a function prologue to determine if it is an inline hook
    struct HookAnalysisResult {
        bool is_hooked{false};
        std::string hook_type;
        std::uintptr_t target_address{0};
    };

    [[nodiscard]] static HookAnalysisResult analyze_prologue(std::span<const std::uint8_t> bytes, std::uintptr_t function_addr) noexcept;

private:
    Process& process_;

    std::vector<HookFinding> scan_module_hooks(const std::string& module_name, const std::vector<std::string>& functions_to_check);
};

} // namespace memguard
