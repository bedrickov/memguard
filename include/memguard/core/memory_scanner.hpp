#pragma once

#include "memguard/core/types.hpp"
#include "memguard/core/process.hpp"
#include "memguard/core/entropy.hpp"
#include <vector>
#include <functional>

namespace memguard {

class MemoryScanner {
public:
    explicit MemoryScanner(Process& process, ScanConfig config = {});

    /// Run full memory audit on target process
    [[nodiscard]] ScanResult scan();

    /// Progress callback signature: (current_address, total_scanned_bytes)
    using ProgressCallback = std::function<void(std::uintptr_t current_address, std::size_t scanned_bytes)>;
    void set_progress_callback(ProgressCallback cb) { progress_cb_ = std::move(cb); }

    /// Inspect a specific memory region for anomalies
    [[nodiscard]] std::vector<Finding> analyze_region(const MemoryRegion& region);

    /// Check if a memory buffer begins with an unmapped PE header (MZ + PE signature)
    [[nodiscard]] static bool contains_pe_header(std::span<const std::uint8_t> buffer) noexcept;

    /// Convert Win32 memory protection constants to human-readable string (e.g. "PAGE_EXECUTE_READWRITE")
    [[nodiscard]] static std::string protection_to_string(std::uint32_t protect) noexcept;

    /// Convert Win32 memory type constants to human-readable string (e.g. "MEM_PRIVATE", "MEM_IMAGE")
    [[nodiscard]] static std::string type_to_string(std::uint32_t type) noexcept;

private:
    Process& process_;
    ScanConfig config_;
    ProgressCallback progress_cb_;

    void scan_regions(ScanResult& result);
    void scan_hooks(ScanResult& result);
    void dump_payload_if_configured(const Finding& finding, std::span<const std::uint8_t> data);
};

} // namespace memguard
