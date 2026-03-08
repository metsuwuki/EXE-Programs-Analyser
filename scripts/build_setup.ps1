param(
    [switch]$SkipPortable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $PSScriptRoot
Set-Location $scriptRoot

if (-not $SkipPortable) {
    Write-Host "[1/3] Build portable package..."
    & "$scriptRoot\build_portable.cmd"
    if ($LASTEXITCODE -ne 0) {
        throw "build_portable.cmd failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Host "[1/3] Using existing portable package in dist\\EXE_Analyzer..."
}

$distPath = Join-Path $scriptRoot "dist\EXE_Analyzer"
if (-not (Test-Path -LiteralPath $distPath)) {
    throw "Portable package folder not found: $distPath"
}

$cargoToml = Join-Path $scriptRoot "Cargo.toml"
$appVersion = "0.1.0"
if (Test-Path -LiteralPath $cargoToml) {
    $content = Get-Content -LiteralPath $cargoToml -Raw
    $m = [regex]::Match($content, '(?m)^version\s*=\s*"([^"]+)"')
    if ($m.Success) {
        $appVersion = $m.Groups[1].Value
    }
}

function Resolve-Iscc {
    if ($env:ISCC_EXE -and (Test-Path -LiteralPath $env:ISCC_EXE)) {
        return $env:ISCC_EXE
    }

    $cmd = Get-Command "iscc.exe" -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:LocalAppData "Programs\Inno Setup 6\ISCC.exe")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    return ($candidates | Select-Object -First 1)
}

$iscc = Resolve-Iscc
if (-not $iscc) {
    throw "Inno Setup Compiler (ISCC.exe) not found. Install from https://jrsoftware.org/isdl.php"
}

$issPath = Join-Path $scriptRoot "installer\Metsuki_EXE_Analyzer.iss"
if (-not (Test-Path -LiteralPath $issPath)) {
    throw "Installer script not found: $issPath"
}

Write-Host "[2/3] Building setup installer..."
$isccArgs = @(
    "/Qp",
    "/DMyAppVersion=$appVersion",
    "/DMyDistDir=$distPath",
    "/DMyOutputDir=$(Join-Path $scriptRoot 'dist')",
    $issPath
)
& $iscc @isccArgs
if ($LASTEXITCODE -ne 0) {
    throw "ISCC failed with exit code $LASTEXITCODE"
}

Write-Host "[3/3] Done."
Write-Host "Setup ready: $scriptRoot\dist\Metsuki_EXE_Analyzer_Setup_$appVersion.exe"
exit 0
