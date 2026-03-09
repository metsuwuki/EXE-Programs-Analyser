param(
	[switch]$Sign,
	[switch]$SkipSetup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Push-Location $ScriptDir
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
Pop-Location

# 1) Build portable (batch)
Write-Host "[1/4] Building portable package..."
$bp = Join-Path $RepoRoot "build_portable.cmd"
if (-not (Test-Path $bp)) { Throw "build_portable.cmd not found." }
$proc = Start-Process -FilePath $bp -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -ne 0) { Throw "build_portable.cmd failed with exit code $($proc.ExitCode)" }

# 2) Pre-release security check
Write-Host "[2/4] Running pre-release security check..."
$pre = Join-Path $RepoRoot "scripts\pre_release_security_check.ps1"
if (-not (Test-Path $pre)) { Throw "pre_release_security_check.ps1 not found." }
& powershell -NoProfile -ExecutionPolicy Bypass -File $pre -DistPath ".\dist\EXE_Analyzer"
if ($LASTEXITCODE -ne 0) { Throw "pre_release_security_check failed." }

# 3) Build setup (unless skipped)
if (-not $SkipSetup) {
	Write-Host "[3/4] Building setup installer (Inno Setup required)..."
	$bs = Join-Path $RepoRoot "build_setup.cmd"
	if (-not (Test-Path $bs)) { Write-Warning "build_setup.cmd not found; skipping setup build." } else {
		& cmd /c `"$bs --skip-portable`"
		if ($LASTEXITCODE -ne 0) { Write-Warning "build_setup.cmd returned non-zero (installer may be missing)." }
	}
} else {
	Write-Host "[3/4] Skipped setup build by request."
}

# 4) Optional signing
if ($Sign) {
	Write-Host "[4/4] Signing artifacts (if signtool available)..."
	$sign = Join-Path $RepoRoot "scripts\sign_artifacts.ps1"
	if (-not (Test-Path $sign)) { Write-Warning "sign_artifacts.ps1 not found; skipping signing." } else {
		& powershell -NoProfile -ExecutionPolicy Bypass -File $sign -DistPath ".\dist" 
		if ($LASTEXITCODE -ne 0) { Write-Warning "sign_artifacts.ps1 returned non-zero." }
	}
} else {
	Write-Host "[4/4] Signing skipped (use -Sign to enable)."
}

Write-Host "[DONE] Release artifacts prepared in dist\*"
exit 0
