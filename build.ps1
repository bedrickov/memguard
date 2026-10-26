param (
    [switch]$Test,
    [switch]$Clean,
    [string]$Config = "Release"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
$BuildDir = Join-Path $ProjectRoot "build"

if ($Clean) {
    if (Test-Path $BuildDir) {
        Write-Host "Cleaning $BuildDir..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $BuildDir
    }
    Write-Host "Clean complete." -ForegroundColor Green
    exit 0
}

Write-Host "=== MemGuard Build Pipeline ===" -ForegroundColor Cyan

if (-not (Test-Path $BuildDir)) {
    Write-Host "Configuring CMake with Ninja..." -ForegroundColor DarkGray
    cmake -B $BuildDir -G "Ninja" -DCMAKE_BUILD_TYPE=$Config
}

Write-Host "Compiling binaries ($Config)..." -ForegroundColor DarkGray
cmake --build $BuildDir --config $Config -j

Write-Host "Build finished successfully!" -ForegroundColor Green

if ($Test) {
    Write-Host "`nRunning Test Suite..." -ForegroundColor Cyan
    $TestExe = Join-Path $BuildDir "memguard_tests.exe"
    if (Test-Path $TestExe) {
        & $TestExe
    } else {
        Write-Error "Test executable not found: $TestExe"
    }
}
