#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include <array>
#include <span>

namespace memguard {

class EntropyCalculator {
public:
    /// Calculates standard Shannon entropy in bits per byte (0.0 to 8.0)
    [[nodiscard]] static double calculate(std::span<const std::uint8_t> data) noexcept;

    /// Calculates Shannon entropy for a raw pointer and length
    [[nodiscard]] static double calculate(const std::uint8_t* data, std::size_t size) noexcept;

    /// Generates full 256-byte frequency distribution
    [[nodiscard]] static std::array<std::size_t, 256> byte_distribution(std::span<const std::uint8_t> data) noexcept;

    /// Estimates data classification based on entropy & byte diversity
    enum class ContentClass {
        ZeroPadded,    // Mostly 0x00 or repetitive single byte
        TextOrAscii,   // Low entropy (1.0 - 4.5), printable characters
        NativeCode,    // Medium entropy (4.8 - 6.6), x86/x64 opcodes with standard distribution
        PackedOrEncrypted // High entropy (7.1 - 8.0), indistinguishable from pseudo-random
    };

    [[nodiscard]] static ContentClass classify(double entropy, std::size_t size) noexcept;
    [[nodiscard]] static const char* class_to_string(ContentClass classification) noexcept;
};

} // namespace memguard
