#include "memguard/core/process.hpp"

#ifdef _WIN32
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <algorithm>

namespace memguard {

namespace {

std::string wide_to_utf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::string get_filename_only(const std::string& path) {
    auto pos = path.find_last_of("\\/");
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

bool string_iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

} // namespace

bool Process::enable_debug_privilege() noexcept {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }

    BOOL success = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(token);
    return success && (err != ERROR_NOT_ALL_ASSIGNED);
}

Process::Process(std::uint32_t pid) : pid_(pid) {
    handle_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!handle_) {
        // Fallback with just QUERY_LIMITED_INFORMATION if access is restricted
        handle_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    }
    if (handle_) {
        init_process_metadata();
    }
}

Process::~Process() {
    if (handle_) {
        CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
}

Process::Process(Process&& other) noexcept
    : pid_(other.pid_),
      handle_(other.handle_),
      name_(std::move(other.name_)),
      path_(std::move(other.path_)),
      is_64bit_(other.is_64bit_),
      cached_modules_(std::move(other.cached_modules_)),
      modules_cached_(other.modules_cached_) {
    other.handle_ = nullptr;
    other.pid_ = 0;
}

Process& Process::operator=(Process&& other) noexcept {
    if (this != &other) {
        if (handle_) {
            CloseHandle(static_cast<HANDLE>(handle_));
        }
        pid_ = other.pid_;
        handle_ = other.handle_;
        name_ = std::move(other.name_);
        path_ = std::move(other.path_);
        is_64bit_ = other.is_64bit_;
        cached_modules_ = std::move(other.cached_modules_);
        modules_cached_ = other.modules_cached_;

        other.handle_ = nullptr;
        other.pid_ = 0;
    }
    return *this;
}

bool Process::is_valid() const noexcept {
    return handle_ != nullptr;
}

void Process::init_process_metadata() {
    wchar_t buf[MAX_PATH * 2]{0};
    DWORD size = sizeof(buf) / sizeof(wchar_t);

    if (QueryFullProcessImageNameW(static_cast<HANDLE>(handle_), 0, buf, &size)) {
        path_ = wide_to_utf8(std::wstring(buf, size));
        name_ = get_filename_only(path_);
    } else {
        name_ = "pid:" + std::to_string(pid_);
    }

    BOOL is_wow64 = FALSE;
    if (IsWow64Process(static_cast<HANDLE>(handle_), &is_wow64)) {
        is_64bit_ = !is_wow64;
    }
}

void Process::refresh_modules() {
    cached_modules_.clear();
    modules_cached_ = true;

    if (!handle_) return;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                ModuleEntry entry;
                entry.name = wide_to_utf8(me.szModule);
                entry.path = wide_to_utf8(me.szExePath);
                entry.base_address = reinterpret_cast<std::uintptr_t>(me.modBaseAddr);
                entry.size = me.modBaseSize;
                cached_modules_.push_back(std::move(entry));
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }

    // Fallback using EnumProcessModules if toolhelp yielded empty or was blocked
    if (cached_modules_.empty()) {
        HMODULE mods[1024];
        DWORD cb_needed = 0;
        if (EnumProcessModulesEx(static_cast<HANDLE>(handle_), mods, sizeof(mods), &cb_needed, LIST_MODULES_ALL)) {
            const DWORD count = cb_needed / sizeof(HMODULE);
            for (DWORD i = 0; i < count; ++i) {
                MODULEINFO mi{};
                if (GetModuleInformation(static_cast<HANDLE>(handle_), mods[i], &mi, sizeof(mi))) {
                    wchar_t mod_name[MAX_PATH]{0};
                    wchar_t mod_path[MAX_PATH * 2]{0};
                    GetModuleBaseNameW(static_cast<HANDLE>(handle_), mods[i], mod_name, MAX_PATH);
                    GetModuleFileNameExW(static_cast<HANDLE>(handle_), mods[i], mod_path, MAX_PATH * 2);

                    ModuleEntry entry;
                    entry.name = wide_to_utf8(mod_name);
                    entry.path = wide_to_utf8(mod_path);
                    entry.base_address = reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll);
                    entry.size = mi.SizeOfImage;
                    cached_modules_.push_back(std::move(entry));
                }
            }
        }
    }
}

const std::vector<ModuleEntry>& Process::modules() {
    if (!modules_cached_) {
        refresh_modules();
    }
    return cached_modules_;
}

std::optional<ModuleEntry> Process::module_from_address(std::uintptr_t address) {
    const auto& mods = modules();
    for (const auto& mod : mods) {
        if (address >= mod.base_address && address < (mod.base_address + mod.size)) {
            return mod;
        }
    }
    return std::nullopt;
}

std::vector<std::uint8_t> Process::read_memory(std::uintptr_t address, std::size_t size) const {
    std::vector<std::uint8_t> buffer(size);
    std::size_t bytes_read = read_memory_into(address, buffer.data(), size);
    buffer.resize(bytes_read);
    return buffer;
}

std::size_t Process::read_memory_into(std::uintptr_t address, void* buffer, std::size_t size) const noexcept {
    if (!handle_ || !buffer || size == 0) return 0;
    SIZE_T bytes_read = 0;
    if (ReadProcessMemory(static_cast<HANDLE>(handle_), reinterpret_cast<LPCVOID>(address), buffer, size, &bytes_read)) {
        return static_cast<std::size_t>(bytes_read);
    }
    return 0;
}

std::vector<ProcessInfo> Process::enumerate_processes() {
    std::vector<ProcessInfo> results;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return results;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0) continue; // Skip idle
            ProcessInfo info;
            info.pid = pe.th32ProcessID;
            info.name = wide_to_utf8(pe.szExeFile);
            results.push_back(std::move(info));
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return results;
}

std::optional<std::uint32_t> Process::find_pid_by_name(std::string_view process_name) {
    auto procs = enumerate_processes();
    for (const auto& p : procs) {
        if (string_iequals(p.name, process_name)) {
            return p.pid;
        }
    }
    return std::nullopt;
}

} // namespace memguard

#else
// Non-windows stub implementation for cross-platform builds/CI
namespace memguard {
bool Process::enable_debug_privilege() noexcept { return true; }
Process::Process(std::uint32_t pid) : pid_(pid) {}
Process::~Process() = default;
Process::Process(Process&&) noexcept = default;
Process& Process::operator=(Process&&) noexcept = default;
bool Process::is_valid() const noexcept { return true; }
void Process::init_process_metadata() {}
void Process::refresh_modules() {}
const std::vector<ModuleEntry>& Process::modules() { return cached_modules_; }
std::optional<ModuleEntry> Process::module_from_address(std::uintptr_t) { return std::nullopt; }
std::vector<std::uint8_t> Process::read_memory(std::uintptr_t, std::size_t size) const { return std::vector<std::uint8_t>(size, 0); }
std::size_t Process::read_memory_into(std::uintptr_t, void*, std::size_t size) const noexcept { return size; }
std::vector<ProcessInfo> Process::enumerate_processes() { return {}; }
std::optional<std::uint32_t> Process::find_pid_by_name(std::string_view) { return std::nullopt; }
}
#endif
