param(
    [switch]$Sign,
    [switch]$SkipSetup
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

function Get-FileSha256([string]$Path) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

$repoRoot = Get-RepoRoot
$cargoToml = Join-Path $repoRoot "Cargo.toml"
$portableCmd = Join-Path $repoRoot "build_portable.cmd"
$setupPs1 = Join-Path $PSScriptRoot "build_setup.ps1"
$distDir = Join-Path $repoRoot "dist"
$portableDir = Join-Path $distDir "EXE_Analyzer"
$version = Get-CargoVersion $cargoToml

Write-Step "Building portable artifacts"
& $portableCmd
if ($LASTEXITCODE -ne 0) {
    throw "Portable build failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path -LiteralPath $portableDir)) {
    throw "Portable output folder is missing: $portableDir"
}

if (-not $SkipSetup) {
    Write-Step "Building installer artifacts"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $setupPs1 -SkipPortable
    if ($LASTEXITCODE -ne 0) {
        throw "Setup build failed with exit code $LASTEXITCODE"
    }
}

$hashTargets = New-Object System.Collections.Generic.List[string]
$portableExe = Join-Path $portableDir "exe_tester_web_gui.exe"
$engineExe = Join-Path $portableDir ".engine\analyzer_core.exe"

foreach ($path in @($portableExe, $engineExe)) {
    if (Test-Path -LiteralPath $path) {
        $hashTargets.Add($path)
    }
}

$setupExe = Join-Path $distDir ("Metsuki_EXE_Analyzer_Setup_{0}.exe" -f $version)
if (Test-Path -LiteralPath $setupExe) {
    $hashTargets.Add($setupExe)
}

$hashFile = Join-Path $portableDir "SHA256SUMS.txt"
$hashLines = foreach ($path in $hashTargets) {
    $hash = Get-FileSha256 $path
    $relative = Resolve-Path -LiteralPath $path | ForEach-Object {
        $_.Path.Substring($repoRoot.Length).TrimStart('\')
    }
    "{0} *{1}" -f $hash, $relative
}
Set-Content -LiteralPath $hashFile -Value $hashLines -Encoding utf8

$precheckFile = Join-Path $portableDir "SECURITY_PRECHECK.txt"
$precheck = @(
    "Metsuki EXE Analyzer release precheck",
    "version=$version",
    "timestamp_utc=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
    "portable_exists=$([bool](Test-Path -LiteralPath $portableExe))",
    "engine_exists=$([bool](Test-Path -LiteralPath $engineExe))",
    "setup_exists=$([bool](Test-Path -LiteralPath $setupExe))",
    "sign_requested=$Sign",
    "status=ok"
)
Set-Content -LiteralPath $precheckFile -Value $precheck -Encoding utf8

if ($Sign) {
    Write-Warning "Code signing was requested, but no signing integration is configured in this repository yet."
}

Write-Host ""
Write-Host "====================================================="
Write-Host "Release artifacts ready:"
Write-Host "Portable: $portableDir"
if (Test-Path -LiteralPath $setupExe) {
    Write-Host "Setup:    $setupExe"
}
Write-Host "Hashes:   $hashFile"
Write-Host "Precheck: $precheckFile"
Write-Host "====================================================="
Write-Host ""
