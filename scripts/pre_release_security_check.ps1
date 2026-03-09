param(
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
