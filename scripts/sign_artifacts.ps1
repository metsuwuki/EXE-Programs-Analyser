param(
	[string]$DistPath = ".\dist",
	[string]$TimestampUrl = "http://timestamp.digicert.com",
	[switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$DistFull = (Resolve-Path (Join-Path $RepoRoot $DistPath)).Path

if (-not (Test-Path $DistFull)) { Write-Error "[ERROR] Dist path not found: $DistFull"; exit 1 }

# Найти signtool.exe
$signtool = $env:SIGNTOOL
if (-not $signtool) {
	$possible = @(
		"$env:ProgramFiles (x86)\Windows Kits\10\bin\x64\signtool.exe",
		"$env:ProgramFiles\Windows Kits\10\bin\x64\signtool.exe",
		"signtool.exe"
	)
	foreach ($p in $possible) {
		if (Test-Path $p) { $signtool = $p; break }
		try { if (Get-Command $p -ErrorAction SilentlyContinue) { $signtool = (Get-Command $p).Path; break } } catch {}
	}
}
if (-not $signtool) {
	Write-Warning "[WARN] signtool.exe not found in PATH or common kit locations. Skipping signing."
	exit 0
}
Write-Host "[INFO] Using signtool: $signtool"

# Опции подписи: /fd SHA256 /tr timestamp /td SHA256 /a (automatic cert selection)
$files = Get-ChildItem -Path $DistFull -Recurse -File -Include *.exe,*.dll | Sort-Object FullName
if ($files.Count -eq 0) { Write-Host "[INFO] No .exe/.dll files found to sign."; exit 0 }

foreach ($f in $files) {
	try {
		$auth = Get-AuthenticodeSignature -FilePath $f.FullName -ErrorAction SilentlyContinue
		if ($auth -and $auth.Status -eq 'Valid' -and -not $Force) {
			Write-Host "[SKIP] Already signed (valid): $($f.FullName)"
			continue
		}
		Write-Host "[SIGN] $($f.FullName)"
		$arg = @("sign","/fd","SHA256","/a","/tr",$TimestampUrl,"/td","SHA256",$f.FullName)
		$proc = Start-Process -FilePath $signtool -ArgumentList $arg -NoNewWindow -Wait -PassThru
		if ($proc.ExitCode -ne 0) { Write-Warning "[WARN] signtool failed for $($f.FullName) with exit code $($proc.ExitCode)" }
	} catch {
		Write-Warning "[WARN] Exception signing $($f.FullName): $_"
	}
}

Write-Host "[INFO] Signing step complete."
exit 0
