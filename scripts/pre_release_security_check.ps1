param(
    [string]$DistPath = ".\dist\EXE_Analyzer",
    [string]$HashFileName = "SHA256SUMS.txt",
    [string]$ReportFileName = "SECURITY_PRECHECK.txt",
    [switch]$SkipDefender
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$distAbs = Resolve-Path $DistPath -ErrorAction Stop
$distDir = $distAbs.Path

$hashPath = Join-Path $distDir $HashFileName
$reportPath = Join-Path $distDir $ReportFileName

$hashLines = @()
$exeFiles = Get-ChildItem -Path $distDir -Filter *.exe -File -Recurse
foreach ($file in $exeFiles) {
    $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
    $relative = $file.FullName.Substring($distDir.Length).TrimStart('\\')
    $hashLines += ("{0} *{1}" -f $hash.Hash, $relative)
}

Set-Content -Path $hashPath -Value $hashLines -Encoding UTF8

$defenderStatus = "SKIPPED"
$defenderDetails = "Defender scan skipped by flag or unavailable"

if (-not $SkipDefender) {
    $hasDefenderCmd = Get-Command Start-MpScan -ErrorAction SilentlyContinue
    if ($hasDefenderCmd) {
        try {
            Start-MpScan -ScanType CustomScan -ScanPath $distDir
            $defenderStatus = "OK"
            $defenderDetails = "Microsoft Defender custom scan completed"
        }
        catch {
            $defenderStatus = "FAILED"
            $defenderDetails = $_.Exception.Message
        }
    }
    else {
        $defenderStatus = "UNAVAILABLE"
        $defenderDetails = "Start-MpScan command not available"
    }
}

$report = @()
$report += "Metsuki EXE Analyzer - Security Precheck"
$utcNow = (Get-Date).ToUniversalTime().ToString("o")
$report += "Timestamp (UTC): $utcNow"
$report += "Dist: $distDir"
$report += ""
$report += "Defender: $defenderStatus"
$report += "Details: $defenderDetails"
$report += ""
$report += "SHA256:" 
$report += $hashLines

Set-Content -Path $reportPath -Value $report -Encoding UTF8

Write-Host "[OK] Hashes: $hashPath"
Write-Host "[OK] Report: $reportPath"
