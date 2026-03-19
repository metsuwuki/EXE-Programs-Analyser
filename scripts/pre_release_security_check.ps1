param(
<<<<<<< HEAD
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
=======
	[string]$DistPath = ".\dist\EXE_Analyzer"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$DistFull = (Resolve-Path (Join-Path $RepoRoot $DistPath)).Path

if (-not (Test-Path $DistFull)) { Write-Error "[ERROR] Dist path not found: $DistFull"; exit 1 }

Write-Host "[INFO] Generating SHA256 sums in $DistFull"
$hashFile = Join-Path $DistFull "SHA256SUMS.txt"
Get-ChildItem -Path $DistFull -Recurse -File | ForEach-Object {
	$rel = $_.FullName.Substring($DistFull.Length).TrimStart('\')
	$h = Get-FileHash -Algorithm SHA256 -Path $_.FullName
	"{0}  {1}" -f $h.Hash, $rel
} | Sort-Object | Set-Content -Encoding UTF8 $hashFile

Write-Host "[INFO] Creating SECURITY_PRECHECK.txt"
$preFile = Join-Path $DistFull "SECURITY_PRECHECK.txt"
@(
	"Security precheck generated: $(Get-Date -Format o)"
	"Files scanned: $(Get-ChildItem -Path $DistFull -Recurse -File | Measure-Object | Select-Object -ExpandProperty Count)"
	"SHA256 manifest: SHA256SUMS.txt"
	"Notes: If you need an AV pre-scan, submit SHA256s to vendor."
) | Set-Content -Encoding UTF8 $preFile

# Попытка запустить Windows Defender quick scan на папку (если доступно)
$mpcmdPaths = @(
	"$env:ProgramFiles\Windows Defender\MpCmdRun.exe",
	"$env:ProgramFiles(x86)\Windows Defender\MpCmdRun.exe",
	"C:\Program Files\Windows Defender\MpCmdRun.exe",
	"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe"
)
$mpcmd = $mpcmdPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($mpcmd) {
	Write-Host "[INFO] Found MpCmdRun: $mpcmd - attempting quick scan of $DistFull (may require elevated privileges)"
	try {
		& $mpcmd -Scan -ScanType 3 -File $DistFull | Out-Null
		Write-Host "[INFO] MpCmdRun invoked (result non-fatal)."
	} catch {
		Write-Warning "[WARN] MpCmdRun invocation failed: $_"
	}
} else {
	Write-Host "[INFO] MpCmdRun not found, skipping AV pre-scan."
}

Write-Host "[INFO] Pre-release security check complete."
exit 0
>>>>>>> 4eb762c97ad4a0321ba84566b2eef38064581585
