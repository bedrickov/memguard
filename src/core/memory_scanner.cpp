#include "memguard/core/memory_scanner.hpp"
#include "memguard/core/hook_detector.hpp"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

namespace memguard {

namespace fs = std::filesystem;

MemoryScanner::MemoryScanner(Process& process, ScanConfig config)
    : process_(process), config_(std::move(config)) {}

bool MemoryScanner::contains_pe_header(std::span<const std::uint8_t> buffer) noexcept {
    if (buffer.size() < 0x200) return false;
    // Check 'MZ' signature (0x4D, 0x5A)
    if (buffer[0] != 0x4D || buffer[1] != 0x5A) return false;

    // e_lfanew is at offset 0x3C
    std::uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, &buffer[0x3C], sizeof(e_lfanew));
    if (e_lfanew + 4 > buffer.size()) return false;

    // Check 'PE\0\0' (0x50, 0x45, 0x00, 0x00)
    return buffer[e_lfanew] == 0x50 &&
           buffer[e_lfanew + 1] == 0x45 &&
           buffer[e_lfanew + 2] == 0x00 &&
           buffer[e_lfanew + 3] == 0x00;
}

std::string MemoryScanner::protection_to_string(std::uint32_t protect) noexcept {
#ifdef _WIN32
    std::string s;
    const DWORD base = protect & 0xFF;
    switch (base) {
        case PAGE_NOACCESS:          s = "NOACCESS"; break;
        case PAGE_READONLY:          s = "READONLY"; break;
        case PAGE_READWRITE:         s = "READWRITE"; break;
        case PAGE_WRITECOPY:         s = "WRITECOPY"; break;
        case PAGE_EXECUTE:           s = "EXECUTE"; break;
        case PAGE_EXECUTE_READ:      s = "EXECUTE_READ"; break;
        case PAGE_EXECUTE_READWRITE: s = "EXECUTE_READWRITE"; break;
        case PAGE_EXECUTE_WRITECOPY: s = "EXECUTE_WRITECOPY"; break;
        default:                     s = "PAGE_UNKNOWN"; break;
    }
    if (protect & PAGE_GUARD)        s += "+GUARD";
    if (protect & PAGE_NOCACHE)      s += "+NOCACHE";
    if (protect & PAGE_WRITECOMBINE) s += "+WRITECOMBINE";
    return s;
#else
    return "PAGE_UNKNOWN";
#endif
}

std::string MemoryScanner::type_to_string(std::uint32_t type) noexcept {
#ifdef _WIN32
    switch (type) {
        case MEM_IMAGE:   return "MEM_IMAGE";
        case MEM_MAPPED:  return "MEM_MAPPED";
        case MEM_PRIVATE: return "MEM_PRIVATE";
        default:          return "UNKNOWN";
    }
#else
    return "UNKNOWN";
#endif
}

std::vector<Finding> MemoryScanner::analyze_region(const MemoryRegion& region) {
    std::vector<Finding> findings;

    // Skip uncommitted, guard, or no-access pages to avoid access violations
#ifdef _WIN32
    if ((region.state & MEM_COMMIT) == 0 ||
        (region.protect & PAGE_GUARD) != 0 ||
        (region.protect & PAGE_NOACCESS) != 0) {
        return findings;
    }
#endif

    const bool is_rwx = (region.protect & 0xFF) == PAGE_EXECUTE_READWRITE;
    const bool is_rx = (region.protect & 0xFF) == PAGE_EXECUTE_READ || (region.protect & 0xFF) == PAGE_EXECUTE;
    const bool is_executable = is_rwx || is_rx || ((region.protect & 0xFF) == PAGE_EXECUTE_WRITECOPY);

    // Read a sample for inspection
    const std::size_t sample_size = std::min<std::size_t>(region.region_size, 65536);
    std::vector<std::uint8_t> sample = process_.read_memory(region.base_address, sample_size);

    if (sample.empty()) {
        return findings;
    }

    const double entropy = EntropyCalculator::calculate(sample);

    // Rule MG-001: PE Header in unmapped / private memory (Reflective DLL / Process Hollowing)
    if (region.is_private && contains_pe_header(sample)) {
        Finding f;
        f.rule_id = "MG-001";
        // If executable, this is an active reflective code injection (CRITICAL)
        // If non-executable, this is an inactive staged payload or memory cache (MEDIUM)
        f.severity = is_executable ? Severity::Critical : Severity::Medium;
        f.title = is_executable ? "Active In-Memory PE / Reflective DLL (Executable)"
                                : "Staged Unbacked PE Image in Private Memory";
        f.description = is_executable
            ? "Detected valid DOS/PE executable headers in private executable memory page (active injection)."
            : "Detected valid DOS/PE header in private non-executable data allocation (staged artifact).";
        f.address = region.base_address;
        f.size = region.region_size;
        f.entropy = entropy;
        f.extra_info = "Protection: " + protection_to_string(region.protect) + ", Size: " + std::to_string(region.region_size) + " bytes";
        findings.push_back(std::move(f));
    }

    // Rule MG-002: Private Executable-Writable Memory (RWX)
    if (region.is_private && is_rwx) {
        Finding f;
        f.rule_id = "MG-002";
        f.severity = Severity::High;
        f.title = "Private Executable & Writable Memory Region (RWX)";
        f.description = "Memory region has PAGE_EXECUTE_READWRITE in private allocation (classic shellcode / JIT / hook trampoline target).";
        f.address = region.base_address;
        f.size = region.region_size;
        f.entropy = entropy;
        f.extra_info = "Type: " + type_to_string(region.type) + ", Protection: " + protection_to_string(region.protect);
        findings.push_back(std::move(f));
    }

    // Rule MG-003: Unbacked Executable Memory (RX without module backing)
    if (region.is_private && is_rx && region.mapped_module.empty() && !contains_pe_header(sample)) {
        Finding f;
        f.rule_id = "MG-003";
        f.severity = Severity::Medium;
        f.title = "Unbacked Executable Memory Page (Private RX)";
        f.description = "Executable code page is private and not mapped to any valid PE module on disk.";
        f.address = region.base_address;
        f.size = region.region_size;
        f.entropy = entropy;
        f.extra_info = "Type: " + type_to_string(region.type) + ", Protection: " + protection_to_string(region.protect);
        findings.push_back(std::move(f));
    }

    // Rule MG-004: High Shannon Entropy in Executable or Private Memory
    if (config_.scan_entropy && entropy >= config_.min_entropy_threshold && sample.size() >= 512) {
        Finding f;
        f.rule_id = "MG-004";
        f.severity = is_executable ? Severity::High : Severity::Medium;
        f.title = "High-Entropy Memory Payload (Compressed / Encrypted Beacon)";
        f.description = "Shannon entropy of memory buffer exceeds threshold, indicating packed code or encrypted payload.";
        f.address = region.base_address;
        f.size = region.region_size;
        f.entropy = entropy;
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << "Entropy: " << entropy << " / 8.00 bits (Threshold: " << config_.min_entropy_threshold << ")";
        f.extra_info = oss.str();
        findings.push_back(std::move(f));
    }

    // Rule MG-005: Writable Code Section in Legitimate PE Image
    if (!region.is_private && region.type == MEM_IMAGE && is_rwx) {
        Finding f;
        f.rule_id = "MG-005";
        f.severity = Severity::High;
        f.title = "Tampered / Writable Module Code Section";
        f.description = "Executable section in mapped DLL/EXE was granted write permissions (potential unhooking or inline patch).";
        f.address = region.base_address;
        f.size = region.region_size;
        f.entropy = entropy;
        f.extra_info = "Module: " + region.mapped_module + ", Protection: " + protection_to_string(region.protect);
        findings.push_back(std::move(f));
    }

    if (config_.dump_suspicious) {
        for (const auto& finding : findings) {
            if (finding.severity >= Severity::High) {
                dump_payload_if_configured(finding, sample);
            }
        }
    }

    return findings;
}

void MemoryScanner::dump_payload_if_configured(const Finding& finding, std::span<const std::uint8_t> data) {
    try {
        fs::create_directories(config_.dump_directory);
        std::ostringstream filename;
        filename << config_.dump_directory << "/dump_"
                 << process_.pid() << "_0x" << std::hex << finding.address << "_" << finding.rule_id << ".bin";
        std::ofstream out(filename.str(), std::ios::binary);
        if (out) {
            out.write(reinterpret_cast<const char*>(data.data()), data.size());
        }
    } catch (...) {
        // Silently ignore filesystem errors during dump
    }
}

ScanResult MemoryScanner::scan() {
    ScanResult result;
    auto start_time = std::chrono::steady_clock::now();
    result.timestamp = std::chrono::system_clock::now();

    result.target_process.pid = process_.pid();
    result.target_process.name = process_.name();
    result.target_process.path = process_.path();
    result.target_process.is_64bit = process_.is_64bit();

    scan_regions(result);

    if (config_.scan_hooks) {
        scan_hooks(result);
    }

    auto end_time = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    return result;
}

void MemoryScanner::scan_regions(ScanResult& result) {
#ifdef _WIN32
    if (!process_.native_handle()) return;

    HANDLE hProcess = static_cast<HANDLE>(process_.native_handle());
    std::uintptr_t current_address = 0;
    MEMORY_BASIC_INFORMATION mbi{};

    std::size_t total_scanned = 0;
    const std::uintptr_t max_user_address = process_.is_64bit() ? 0x7FFFFFFEFFFFULL : 0x7FFEFFFFULL;

    while (current_address < max_user_address &&
           VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(current_address), &mbi, sizeof(mbi)) != 0) {

        ++result.total_regions_checked;

        if (mbi.State == MEM_COMMIT) {
            MemoryRegion region;
            region.base_address = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            region.region_size = mbi.RegionSize;
            region.state = mbi.State;
            region.protect = mbi.Protect;
            region.alloc_protect = mbi.AllocationProtect;
            region.type = mbi.Type;

            const DWORD p = mbi.Protect & 0xFF;
            region.is_executable = (p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
                                    p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY);
            region.is_writable = (p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
                                  p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY);
            region.is_private = (mbi.Type == MEM_PRIVATE);

            if (region.is_executable) {
                ++result.executable_regions_count;
            }

            auto mod = process_.module_from_address(region.base_address);
            if (mod.has_value()) {
                region.mapped_module = mod->name;
            }

            auto findings = analyze_region(region);
            for (auto& f : findings) {
                if (f.severity >= config_.min_severity) {
                    ++result.suspicious_regions_count;
                    result.findings.push_back(std::move(f));
                }
            }

            total_scanned += region.region_size;
            if (progress_cb_) {
                progress_cb_(current_address, total_scanned);
            }
        }

        // Advance to next region
        std::uintptr_t next_address = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next_address <= current_address) {
            break; // Overflow guard
        }
        current_address = next_address;
    }

    result.target_process.total_memory_scanned = total_scanned;
    result.target_process.scanned_regions = result.total_regions_checked;
#endif
}

void MemoryScanner::scan_hooks(ScanResult& result) {
    HookDetector detector(process_);
    auto hook_findings = detector.scan_critical_hooks();
    for (auto& hook : hook_findings) {
        if (hook.severity >= config_.min_severity) {
            result.hooks.push_back(std::move(hook));
        }
    }
}

} // namespace memguard
