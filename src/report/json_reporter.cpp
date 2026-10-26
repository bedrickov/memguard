#include "memguard/report/json_reporter.hpp"
#include <sstream>
#include <iomanip>
#include <fstream>

namespace memguard {

std::string JsonReporter::escape_json(std::string_view s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) <= 0x1f) {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

std::string JsonReporter::serialize(const ScanResult& result) {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"version\": \"1.0.0\",\n";
    oss << "  \"engine\": \"MemGuard\",\n";
    oss << "  \"duration_ms\": " << result.duration.count() << ",\n";
    oss << "  \"process\": {\n";
    oss << "    \"pid\": " << result.target_process.pid << ",\n";
    oss << "    \"name\": \"" << escape_json(result.target_process.name) << "\",\n";
    oss << "    \"path\": \"" << escape_json(result.target_process.path) << "\",\n";
    oss << "    \"is_64bit\": " << (result.target_process.is_64bit ? "true" : "false") << ",\n";
    oss << "    \"total_scanned_bytes\": " << result.target_process.total_memory_scanned << ",\n";
    oss << "    \"total_regions_checked\": " << result.total_regions_checked << ",\n";
    oss << "    \"executable_regions\": " << result.executable_regions_count << "\n";
    oss << "  },\n";

    // Findings
    oss << "  \"findings\": [\n";
    for (std::size_t i = 0; i < result.findings.size(); ++i) {
        const auto& f = result.findings[i];
        oss << "    {\n";
        oss << "      \"rule_id\": \"" << escape_json(f.rule_id) << "\",\n";
        oss << "      \"severity\": \"" << severity_to_string(f.severity) << "\",\n";
        oss << "      \"title\": \"" << escape_json(f.title) << "\",\n";
        oss << "      \"description\": \"" << escape_json(f.description) << "\",\n";
        oss << "      \"address\": \"0x" << std::hex << f.address << std::dec << "\",\n";
        oss << "      \"size\": " << f.size << ",\n";
        oss << "      \"entropy\": " << std::fixed << std::setprecision(4) << f.entropy << ",\n";
        oss << "      \"extra_info\": \"" << escape_json(f.extra_info) << "\"\n";
        oss << "    }" << (i + 1 < result.findings.size() ? "," : "") << "\n";
    }
    oss << "  ],\n";

    // Hooks
    oss << "  \"hooks\": [\n";
    for (std::size_t i = 0; i < result.hooks.size(); ++i) {
        const auto& h = result.hooks[i];
        oss << "    {\n";
        oss << "      \"module\": \"" << escape_json(h.module_name) << "\",\n";
        oss << "      \"function\": \"" << escape_json(h.function_name) << "\",\n";
        oss << "      \"address\": \"0x" << std::hex << h.memory_address << std::dec << "\",\n";
        oss << "      \"hook_type\": \"" << escape_json(h.hook_type) << "\",\n";
        oss << "      \"target_address\": \"0x" << std::hex << h.target_address << std::dec << "\",\n";
        oss << "      \"severity\": \"" << severity_to_string(h.severity) << "\"\n";
        oss << "    }" << (i + 1 < result.hooks.size() ? "," : "") << "\n";
    }
    oss << "  ]\n";
    oss << "}\n";

    return oss.str();
}

bool JsonReporter::write_to_file(const ScanResult& result, const std::string& file_path) {
    std::ofstream out(file_path);
    if (!out) return false;
    out << serialize(result);
    return true;
}

} // namespace memguard
