param(
    [string]$PortableDir = "dist/EXE_Analyzer"
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path $PortableDir
$guiExe = Join-Path $root "exe_tester_web_gui.exe"
$engineExe = Join-Path $root ".engine\\analyzer_core.exe"
$cliExe = Join-Path $root ".engine\\analyzer_core.exe"
$hashFile = Join-Path $root "SHA256SUMS.txt"
$precheckFile = Join-Path $root "SECURITY_PRECHECK.txt"

Write-Host "Portable root: $root"

$required = @(
    @{ Path = $guiExe; Label = "GUI executable" },
    @{ Path = $engineExe; Label = "Analyzer engine" }
)

foreach ($item in $required) {
    if (-not (Test-Path $item.Path)) {
        throw "$($item.Label) is missing: $($item.Path)"
    }
    Write-Host "[ok] $($item.Label): $($item.Path)"
}

if (Test-Path $hashFile) {
    Write-Host "[ok] Hash manifest: $hashFile"
} else {
    Write-Host "[info] Optional hash manifest not present in portable-only build: $hashFile"
}

if (Test-Path $precheckFile) {
    Write-Host "[ok] Security precheck: $precheckFile"
} else {
    Write-Host "[info] Optional security precheck not present in portable-only build: $precheckFile"
}

$previousPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$help = & $cliExe --help 2>&1 | Out-String
$exitCode = $LASTEXITCODE
$ErrorActionPreference = $previousPreference
if ($exitCode -ne 0) {
    throw "Analyzer engine --help failed with exit code $exitCode"
}

Write-Host "[ok] Analyzer engine responds to --help"
Write-Host ""
Write-Host "Portable verification completed successfully."
