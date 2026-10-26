cmake_minimum_required(VERSION 3.20)
project(memguard VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler optimization and warnings
if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /EHsc /O2)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O3)
endif()

# Core static library
add_library(memguard_core STATIC
    src/core/entropy.cpp
    src/core/process.cpp
    src/core/memory_scanner.cpp
    src/core/hook_detector.cpp
    src/report/console_reporter.cpp
    src/report/json_reporter.cpp
)

target_include_directories(memguard_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(WIN32)
    target_link_libraries(memguard_core PUBLIC psapi advapi32)
endif()

# CLI Executable
add_executable(memguard src/cli/main.cpp)
target_link_libraries(memguard PRIVATE memguard_core)

# Unit Tests Executable
enable_testing()
add_executable(memguard_tests tests/test_main.cpp)
target_link_libraries(memguard_tests PRIVATE memguard_core)

add_test(NAME UnitTests COMMAND memguard_tests)
