#pragma once

#include "memguard/core/types.hpp"
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <cstdint>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace memguard {

struct ModuleEntry {
    std::string name;
    std::string path;
    std::uintptr_t base_address{0};
    std::size_t size{0};
};

class Process {
public:
    explicit Process(std::uint32_t pid);
    ~Process();

    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    Process(Process&& other) noexcept;
    Process& operator=(Process&& other) noexcept;

    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] std::uint32_t pid() const noexcept { return pid_; }
    [[nodiscard]] const std::string& name() const noexcept { return name_; }
    [[nodiscard]] const std::string& path() const noexcept { return path_; }
    [[nodiscard]] bool is_64bit() const noexcept { return is_64bit_; }
    [[nodiscard]] void* native_handle() const noexcept { return handle_; }

    /// Enable SeDebugPrivilege in current access token
    static bool enable_debug_privilege() noexcept;

    /// Enumerate all active processes currently running on the system
    [[nodiscard]] static std::vector<ProcessInfo> enumerate_processes();

    /// Find PID by process name (e.g. "explorer.exe", "discord.exe")
    [[nodiscard]] static std::optional<std::uint32_t> find_pid_by_name(std::string_view process_name);

    /// Refresh and enumerate loaded modules in the target process
    [[nodiscard]] const std::vector<ModuleEntry>& modules();

    /// Find which module contains the specified address (if any)
    [[nodiscard]] std::optional<ModuleEntry> module_from_address(std::uintptr_t address);

    /// Read raw memory bytes from target process safely
    [[nodiscard]] std::vector<std::uint8_t> read_memory(std::uintptr_t address, std::size_t size) const;

    /// Read raw memory into existing buffer, returning actual bytes read
    std::size_t read_memory_into(std::uintptr_t address, void* buffer, std::size_t size) const noexcept;

private:
    void init_process_metadata();
    void refresh_modules();

    std::uint32_t pid_{0};
    void* handle_{nullptr};
    std::string name_;
    std::string path_;
    bool is_64bit_{true};
    std::vector<ModuleEntry> cached_modules_;
    bool modules_cached_{false};
};

} // namespace memguard
