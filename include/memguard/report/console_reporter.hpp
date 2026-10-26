#pragma once

#include "memguard/core/types.hpp"

namespace memguard {

class ConsoleReporter {
public:
    explicit ConsoleReporter(bool use_color = true);

    void print_banner() const;
    void print_scan_summary(const ScanResult& result) const;
    void print_findings(const ScanResult& result) const;
    void print_hooks(const ScanResult& result) const;
    void print_process_list(const std::vector<ProcessInfo>& processes) const;

private:
    bool use_color_{true};

    [[nodiscard]] const char* severity_color(Severity sev) const noexcept;
    [[nodiscard]] const char* reset_color() const noexcept;
};

} // namespace memguard
