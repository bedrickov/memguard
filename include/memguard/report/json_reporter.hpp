#pragma once

#include "memguard/core/types.hpp"
#include <string>

namespace memguard {

class JsonReporter {
public:
    [[nodiscard]] static std::string serialize(const ScanResult& result);
    static bool write_to_file(const ScanResult& result, const std::string& file_path);

private:
    static std::string escape_json(std::string_view s);
};

} // namespace memguard
