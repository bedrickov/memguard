#include "memguard/core/hook_detector.hpp"
#include <span>
#include <array>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace memguard {

HookDetector::HookDetector(Process& process) : process_(process) {}

HookDetector::HookAnalysisResult HookDetector::analyze_prologue(
    std::span<const std::uint8_t> bytes,
    std::uintptr_t function_addr) noexcept
{
    HookAnalysisResult result;
    if (bytes.size() < 5) return result;

    // Pattern 1: E9 xx xx xx xx -> JMP rel32 (Classic inline hook)
    if (bytes[0] == 0xE9) {
        std::int32_t rel_offset = 0;
        std::memcpy(&rel_offset, &bytes[1], sizeof(rel_offset));
        result.is_hooked = true;
        result.hook_type = "JMP Rel32 (Inline JMP)";
        result.target_address = function_addr + 5 + rel_offset;
        return result;
    }

    // Pattern 2: FF 25 xx xx xx xx -> JMP QWORD PTR [RIP + offset]
    if (bytes.size() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25) {
        std::int32_t rel_offset = 0;
        std::memcpy(&rel_offset, &bytes[2], sizeof(rel_offset));
        result.is_hooked = true;
        result.hook_type = "JMP Indirect [RIP+rel32]";
        result.target_address = function_addr + 6 + rel_offset;
        return result;
    }

    // Pattern 3: 48 B8 <imm64> FF E0 -> MOV RAX, imm64; JMP RAX (x64 64-bit absolute hook)
    if (bytes.size() >= 12 && bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0) {
        std::uint64_t target = 0;
        std::memcpy(&target, &bytes[2], sizeof(target));
        result.is_hooked = true;
        result.hook_type = "MOV RAX, imm64 + JMP RAX";
        result.target_address = static_cast<std::uintptr_t>(target);
        return result;
    }

    // Pattern 4: 48 B8 <imm64> 50 C3 -> MOV RAX, imm64; PUSH RAX; RET
    if (bytes.size() >= 12 && bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0x50 && bytes[11] == 0xC3) {
        std::uint64_t target = 0;
        std::memcpy(&target, &bytes[2], sizeof(target));
        result.is_hooked = true;
        result.hook_type = "MOV RAX, imm64 + PUSH RAX + RET";
        result.target_address = static_cast<std::uintptr_t>(target);
        return result;
    }

    // Pattern 5: 68 <imm32> C3 -> PUSH imm32; RET (x86 push-return hook)
    if (bytes.size() >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3) {
        std::uint32_t target = 0;
        std::memcpy(&target, &bytes[1], sizeof(target));
        result.is_hooked = true;
        result.hook_type = "PUSH imm32 + RET";
        result.target_address = static_cast<std::uintptr_t>(target);
        return result;
    }

    // Pattern 6: CC -> INT3 (Software Breakpoint)
    if (bytes[0] == 0xCC) {
        result.is_hooked = true;
        result.hook_type = "INT3 Software Breakpoint";
        result.target_address = 0;
        return result;
    }

    return result;
}

std::vector<HookFinding> HookDetector::scan_critical_hooks() {
    std::vector<HookFinding> findings;

    // Critical NT syscalls frequently hooked by rootkits, malware or EDRs
    static const std::vector<std::string> ntdll_funcs = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtCreateThreadEx",
        "NtQueueApcThread",
        "NtOpenProcess",
        "NtTerminateProcess",
        "NtSuspendProcess",
        "NtResumeProcess",
        "NtQueryInformationProcess",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection"
    };

    auto ntdll_hooks = scan_module_hooks("ntdll.dll", ntdll_funcs);
    findings.insert(findings.end(), ntdll_hooks.begin(), ntdll_hooks.end());

    static const std::vector<std::string> kernel32_funcs = {
        "VirtualAllocEx",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "LoadLibraryA",
        "LoadLibraryW"
    };

    auto k32_hooks = scan_module_hooks("kernel32.dll", kernel32_funcs);
    findings.insert(findings.end(), k32_hooks.begin(), k32_hooks.end());

    return findings;
}

#ifdef _WIN32
std::vector<HookFinding> HookDetector::scan_module_hooks(
    const std::string& module_name,
    const std::vector<std::string>& functions_to_check)
{
    std::vector<HookFinding> results;
    HMODULE local_mod = GetModuleHandleA(module_name.c_str());
    if (!local_mod) {
        local_mod = LoadLibraryA(module_name.c_str());
    }
    if (!local_mod) return results;

    // Find module in remote process
    const auto& remote_modules = process_.modules();
    std::uintptr_t remote_mod_base = 0;
    for (const auto& mod : remote_modules) {
        if (mod.name == module_name || mod.name == (module_name + ".dll")) {
            remote_mod_base = mod.base_address;
            break;
        }
    }

    // On Windows, system DLLs (ntdll, kernel32) are relocated to the same virtual base in all processes in the same boot session
    // If not found in module list yet, fallback to local base
    if (remote_mod_base == 0) {
        remote_mod_base = reinterpret_cast<std::uintptr_t>(local_mod);
    }

    const std::uintptr_t local_base = reinterpret_cast<std::uintptr_t>(local_mod);

    for (const auto& func_name : functions_to_check) {
        FARPROC local_proc = GetProcAddress(local_mod, func_name.c_str());
        if (!local_proc) continue;

        const std::uintptr_t offset = reinterpret_cast<std::uintptr_t>(local_proc) - local_base;
        const std::uintptr_t remote_func_addr = remote_mod_base + offset;

        // Read 16 bytes of function prologue from remote process
        std::array<std::uint8_t, 16> code_bytes{};
        std::size_t read_bytes = process_.read_memory_into(remote_func_addr, code_bytes.data(), code_bytes.size());
        if (read_bytes < 5) continue;

        auto analysis = analyze_prologue(std::span<const std::uint8_t>(code_bytes.data(), read_bytes), remote_func_addr);
        if (analysis.is_hooked) {
            HookFinding finding;
            finding.module_name = module_name;
            finding.function_name = func_name;
            finding.memory_address = remote_func_addr;
            finding.hook_type = analysis.hook_type;
            finding.target_address = analysis.target_address;
            finding.patched_bytes.assign(code_bytes.begin(), code_bytes.begin() + read_bytes);
            finding.severity = Severity::High;

            // Check if hooked into unbacked memory (higher severity!)
            auto target_mod = process_.module_from_address(analysis.target_address);
            if (!target_mod.has_value() && analysis.target_address != 0) {
                finding.severity = Severity::Critical;
                finding.hook_type += " -> Points to UNBACKED / PRIVATE memory!";
            }
            results.push_back(std::move(finding));
        }
    }

    return results;
}
#else
std::vector<HookFinding> HookDetector::scan_module_hooks(
    const std::string&,
    const std::vector<std::string>&)
{
    return {};
}
#endif

} // namespace memguard
