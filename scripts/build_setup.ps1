param(
    [switch]$SkipPortable
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host "[INFO] $Message"
}

function Get-RepoRoot {
    Split-Path -Parent $PSScriptRoot
}

function Get-CargoVersion([string]$CargoTomlPath) {
    $content = Get-Content -Raw -LiteralPath $CargoTomlPath
    $match = [regex]::Match($content, '(?m)^version\s*=\s*"([^"]+)"')
    if (-not $match.Success) {
        throw "Cannot read package version from Cargo.toml"
    }
    $match.Groups[1].Value
}

function Resolve-Iscc {
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $candidates = @(
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe",
        "C:\Program Files (x86)\Inno Setup 5\ISCC.exe",
        "C:\Program Files\Inno Setup 5\ISCC.exe"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

$repoRoot = Get-RepoRoot
$cargoToml = Join-Path $repoRoot "Cargo.toml"
$portableDir = Join-Path $repoRoot "dist\EXE_Analyzer"
$issPath = Join-Path $repoRoot "installer\metsuki_installer.iss"

if (-not $SkipPortable) {
    Write-Step "Building portable package first"
    & (Join-Path $repoRoot "build_portable.cmd")
    if ($LASTEXITCODE -ne 0) {
        throw "Portable build failed with exit code $LASTEXITCODE"
    }
}

if (-not (Test-Path -LiteralPath $portableDir)) {
    throw "Portable folder was not found: $portableDir"
}

if (-not (Test-Path -LiteralPath (Join-Path $portableDir "exe_tester_web_gui.exe"))) {
    throw "Portable UI binary is missing from dist\EXE_Analyzer"
}

if (-not (Test-Path -LiteralPath (Join-Path $portableDir ".engine\analyzer_core.exe"))) {
    throw "Portable analysis engine is missing from dist\EXE_Analyzer\.engine"
}

if (-not (Test-Path -LiteralPath $issPath)) {
    throw "Installer script was not found: $issPath"
}

$iscc = Resolve-Iscc
if (-not $iscc) {
    throw "Inno Setup compiler (ISCC.exe) was not found. Install Inno Setup 6 or add ISCC.exe to PATH."
}

$version = Get-CargoVersion $cargoToml
Write-Step "Compiling installer with Inno Setup"
Write-Step "ISCC: $iscc"
Write-Step "Version: $version"

Push-Location (Split-Path -Parent $issPath)
try {
    & $iscc "/DMyAppVersion=$version" "metsuki_installer.iss"
    if ($LASTEXITCODE -ne 0) {
        throw "ISCC failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

$setupPath = Join-Path $repoRoot ("dist\Metsuki_EXE_Analyzer_Setup_{0}.exe" -f $version)
if (-not (Test-Path -LiteralPath $setupPath)) {
    throw "Installer build finished without expected output: $setupPath"
}

Write-Host ""
Write-Host "====================================================="
Write-Host "Setup package ready:"
Write-Host $setupPath
Write-Host "====================================================="
Write-Host ""
