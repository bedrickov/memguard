#include "memguard/core/entropy.hpp"
#include <cmath>
#include <numeric>
#include <algorithm>

namespace memguard {

std::array<std::size_t, 256> EntropyCalculator::byte_distribution(std::span<const std::uint8_t> data) noexcept {
    std::array<std::size_t, 256> counts{};
    for (std::uint8_t byte : data) {
        ++counts[byte];
    }
    return counts;
}

double EntropyCalculator::calculate(std::span<const std::uint8_t> data) noexcept {
    if (data.empty()) {
        return 0.0;
    }

    const auto counts = byte_distribution(data);
    const double total_size = static_cast<double>(data.size());
    double entropy = 0.0;

    for (std::size_t count : counts) {
        if (count > 0) {
            const double p = static_cast<double>(count) / total_size;
            entropy -= p * std::log2(p);
        }
    }

    // Numerical precision clamp
    return std::clamp(entropy, 0.0, 8.0);
}

double EntropyCalculator::calculate(const std::uint8_t* data, std::size_t size) noexcept {
    if (data == nullptr || size == 0) {
        return 0.0;
    }
    return calculate(std::span<const std::uint8_t>(data, size));
}

EntropyCalculator::ContentClass EntropyCalculator::classify(double entropy, std::size_t size) noexcept {
    if (size == 0 || entropy < 0.2) {
        return ContentClass::ZeroPadded;
    }
    if (entropy < 4.8) {
        return ContentClass::TextOrAscii;
    }
    if (entropy < 6.85) {
        return ContentClass::NativeCode;
    }
    return ContentClass::PackedOrEncrypted;
}

const char* EntropyCalculator::class_to_string(ContentClass classification) noexcept {
    switch (classification) {
        case ContentClass::ZeroPadded:       return "Zero / Homogeneous";
        case ContentClass::TextOrAscii:      return "Text / Structured";
        case ContentClass::NativeCode:       return "Native Machine Code";
        case ContentClass::PackedOrEncrypted: return "Encrypted / Packed Payload";
        default:                             return "Unknown";
    }
}

} // namespace memguard
