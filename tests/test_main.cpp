#include "memguard/core/entropy.hpp"
#include "memguard/core/hook_detector.hpp"
#include "memguard/core/memory_scanner.hpp"
#include "memguard/core/types.hpp"
#include "memguard/report/json_reporter.hpp"
#include <iostream>
#include <vector>
#include <cassert>
#include <cmath>
#include <random>
#include <numeric>
#include <cstring>

namespace {

int g_tests_run = 0;
int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "  [FAIL] " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define RUN_TEST(fn) \
    do { \
        g_tests_run++; \
        std::cout << "[RUN] " << #fn << "...\n"; \
        fn(); \
    } while (0)

} // namespace

void test_entropy_zero_and_empty() {
    TEST_ASSERT(memguard::EntropyCalculator::calculate({}) == 0.0, "Empty span must yield 0.0 entropy");
    
    std::vector<std::uint8_t> all_zeros(1024, 0x00);
    TEST_ASSERT(memguard::EntropyCalculator::calculate(all_zeros) == 0.0, "All zeros must yield 0.0 entropy");

    std::vector<std::uint8_t> repeated(500, 0xAA);
    TEST_ASSERT(memguard::EntropyCalculator::calculate(repeated) == 0.0, "Single repeated byte must yield 0.0 entropy");
}

void test_entropy_maximum() {
    // 256 unique bytes with equal frequency must yield exactly 8.0 bits
    std::vector<std::uint8_t> uniform(256 * 10);
    for (std::size_t i = 0; i < uniform.size(); ++i) {
        uniform[i] = static_cast<std::uint8_t>(i % 256);
    }
    double ent = memguard::EntropyCalculator::calculate(uniform);
    TEST_ASSERT(std::abs(ent - 8.0) < 0.0001, "Uniform byte distribution must yield 8.0 entropy");
}

void test_entropy_classification() {
    std::string text = "The quick brown fox jumps over the lazy dog. Production systems engineering.";
    std::vector<std::uint8_t> text_bytes(text.begin(), text.end());
    double text_ent = memguard::EntropyCalculator::calculate(text_bytes);
    TEST_ASSERT(text_ent > 3.0 && text_ent < 5.0, "English text entropy should be between 3.0 and 5.0");
    auto cls = memguard::EntropyCalculator::classify(text_ent, text_bytes.size());
    TEST_ASSERT(cls == memguard::EntropyCalculator::ContentClass::TextOrAscii, "Text must be classified as TextOrAscii");

    // Random bytes -> PackedOrEncrypted
    std::mt19937 rng(42);
    std::vector<std::uint8_t> random_bytes(2048);
    for (auto& b : random_bytes) {
        b = static_cast<std::uint8_t>(rng() & 0xFF);
    }
    double rand_ent = memguard::EntropyCalculator::calculate(random_bytes);
    TEST_ASSERT(rand_ent > 7.5, "Random buffer should have entropy > 7.5");
    auto rand_cls = memguard::EntropyCalculator::classify(rand_ent, random_bytes.size());
    TEST_ASSERT(rand_cls == memguard::EntropyCalculator::ContentClass::PackedOrEncrypted, "Random bytes must be classified as PackedOrEncrypted");
}

void test_hook_detector_prologues() {
    // 1. Clean Windows Syscall stub: 4C 8B D1 B8 18 00 00 00 (mov r10, rcx; mov eax, 18h)
    std::array<std::uint8_t, 16> clean_stub = {
        0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00,
        0x0F, 0x05, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90
    };
    auto clean_res = memguard::HookDetector::analyze_prologue(clean_stub, 0x7FFF0000);
    TEST_ASSERT(!clean_res.is_hooked, "Clean syscall stub must not be detected as hooked");

    // 2. Inline JMP Rel32: E9 20 10 00 00
    std::array<std::uint8_t, 16> jmp_hook = {
        0xE9, 0x20, 0x10, 0x00, 0x00, 0x90, 0x90, 0x90
    };
    auto jmp_res = memguard::HookDetector::analyze_prologue(jmp_hook, 0x7FFF0000);
    TEST_ASSERT(jmp_res.is_hooked, "E9 opcode must be detected as inline hook");
    TEST_ASSERT(jmp_res.target_address == (0x7FFF0000 + 5 + 0x1020), "Target address calculation must be correct");

    // 3. Indirect JMP: FF 25 00 00 00 00
    std::array<std::uint8_t, 16> indirect_jmp = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00
    };
    auto ind_res = memguard::HookDetector::analyze_prologue(indirect_jmp, 0x7FFF0000);
    TEST_ASSERT(ind_res.is_hooked, "FF 25 must be detected as indirect JMP hook");

    // 4. MOV RAX, imm64 + JMP RAX: 48 B8 [0x1122334455667788] FF E0
    std::array<std::uint8_t, 16> mov_jmp = {
        0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xFF, 0xE0
    };
    auto mov_res = memguard::HookDetector::analyze_prologue(mov_jmp, 0x7FFF0000);
    TEST_ASSERT(mov_res.is_hooked, "MOV RAX + JMP RAX must be detected");
    TEST_ASSERT(mov_res.target_address == 0x1122334455667788ULL, "Absolute 64-bit target address must match");

    // 5. INT3 Breakpoint: CC
    std::array<std::uint8_t, 8> int3_hook = { 0xCC, 0x90, 0x90, 0x90 };
    auto int3_res = memguard::HookDetector::analyze_prologue(int3_hook, 0x7FFF0000);
    TEST_ASSERT(int3_res.is_hooked, "0xCC must be detected as INT3 breakpoint");
}

void test_pe_header_validator() {
    // Valid minimal PE header layout
    std::vector<std::uint8_t> valid_pe(1024, 0);
    valid_pe[0] = 0x4D; // 'M'
    valid_pe[1] = 0x5A; // 'Z'
    // e_lfanew at 0x3C pointing to 0x80
    std::uint32_t pe_offset = 0x80;
    std::memcpy(&valid_pe[0x3C], &pe_offset, sizeof(pe_offset));
    // PE signature at 0x80
    valid_pe[0x80] = 'P';
    valid_pe[0x81] = 'E';
    valid_pe[0x82] = 0x00;
    valid_pe[0x83] = 0x00;

    TEST_ASSERT(memguard::MemoryScanner::contains_pe_header(valid_pe), "Constructed PE header must pass validation");

    // Corrupted PE signature
    valid_pe[0x81] = 'X';
    TEST_ASSERT(!memguard::MemoryScanner::contains_pe_header(valid_pe), "Corrupted PE signature must fail validation");

    // Corrupted MZ
    valid_pe[0] = 0x00;
    TEST_ASSERT(!memguard::MemoryScanner::contains_pe_header(valid_pe), "Corrupted MZ must fail validation");
}

void test_severity_conversion() {
    TEST_ASSERT(memguard::severity_to_string(memguard::Severity::Critical) == "CRITICAL", "Critical string must match");
    TEST_ASSERT(memguard::severity_to_string(memguard::Severity::High) == "HIGH", "High string must match");
    TEST_ASSERT(memguard::string_to_severity("CRITICAL") == memguard::Severity::Critical, "Parse CRITICAL must succeed");
    TEST_ASSERT(memguard::string_to_severity("high") == memguard::Severity::High, "Parse lowercase high must succeed");
}

void test_json_serialization() {
    memguard::ScanResult result;
    result.target_process.pid = 1337;
    result.target_process.name = "malware_test.exe";
    result.target_process.is_64bit = true;
    result.total_regions_checked = 150;
    result.executable_regions_count = 12;

    memguard::Finding f;
    f.rule_id = "MG-002";
    f.severity = memguard::Severity::High;
    f.title = "RWX Test";
    f.description = "Test Description";
    f.address = 0x140001000;
    f.size = 4096;
    f.entropy = 6.42;
    result.findings.push_back(f);

    std::string json = memguard::JsonReporter::serialize(result);
    TEST_ASSERT(json.find("\"engine\": \"MemGuard\"") != std::string::npos, "JSON must contain engine tag");
    TEST_ASSERT(json.find("\"pid\": 1337") != std::string::npos, "JSON must contain correct PID");
    TEST_ASSERT(json.find("\"MG-002\"") != std::string::npos, "JSON must contain rule ID");
}

int main() {
    std::cout << "========================================\n";
    std::cout << "       MemGuard C++20 Test Suite        \n";
    std::cout << "========================================\n\n";

    RUN_TEST(test_entropy_zero_and_empty);
    RUN_TEST(test_entropy_maximum);
    RUN_TEST(test_entropy_classification);
    RUN_TEST(test_hook_detector_prologues);
    RUN_TEST(test_pe_header_validator);
    RUN_TEST(test_severity_conversion);
    RUN_TEST(test_json_serialization);

    std::cout << "\n----------------------------------------\n";
    std::cout << "Tests run: " << g_tests_run << " | Failures: " << g_tests_failed << "\n";
    if (g_tests_failed == 0) {
        std::cout << "ALL TESTS PASSED!\n";
        return 0;
    } else {
        std::cerr << "SOME TESTS FAILED!\n";
        return 1;
    }
}
