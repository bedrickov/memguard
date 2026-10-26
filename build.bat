@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo        Building MemGuard (C++20 Forensic Scanner)
echo ========================================================

if "%1"=="clean" (
    echo Cleaning build directory...
    if exist build rmdir /s /q build
    echo Clean complete.
    exit /b 0
)

if not exist build (
    cmake -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release
    if %errorlevel% neq 0 (
        echo CMake configuration failed.
        exit /b 1
    )
)

cmake --build build --config Release -j
if %errorlevel% neq 0 (
    echo Build failed.
    exit /b 1
)

echo Build succeeded!
if "%1"=="test" (
    echo Running unit tests...
    build\memguard_tests.exe
)
