param(
    [switch]$SkipPortable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Путь к корню репо
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")

function New-InstallerBrandingAssets {
	param(
		[Parameter(Mandatory = $true)]
		[string]$RepositoryRoot
	)

	$logoPath = Join-Path $RepositoryRoot "logo.png"
	if (-not (Test-Path $logoPath)) {
		Write-Warning "[WARN] logo.png not found, using default Inno Setup images."
		return
	}

	$assetsDir = Join-Path $RepositoryRoot "installer\assets"
	$largeBmp = Join-Path $assetsDir "wizard_large.bmp"
	$smallBmp = Join-Path $assetsDir "wizard_small.bmp"
	New-Item -ItemType Directory -Path $assetsDir -Force | Out-Null

	Add-Type -AssemblyName System.Drawing
	$logo = [System.Drawing.Image]::FromFile($logoPath)
	try {
		# Main left-side wizard image (164x314)
		$largeWidth = 164
		$largeHeight = 314
		$largeCanvas = New-Object System.Drawing.Bitmap($largeWidth, $largeHeight, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
		$largeGraphics = [System.Drawing.Graphics]::FromImage($largeCanvas)
		try {
			$largeGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
			$largeGraphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
			$largeGraphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

			$rect = New-Object System.Drawing.Rectangle(0, 0, $largeWidth, $largeHeight)
			$bgBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
				$rect,
				[System.Drawing.Color]::FromArgb(245, 248, 255),
				[System.Drawing.Color]::FromArgb(214, 227, 255),
				90.0
			)
			$largeGraphics.FillRectangle($bgBrush, $rect)
			$bgBrush.Dispose()

			$accentBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(85, 71, 122, 210))
			$largeGraphics.FillEllipse($accentBrush, -36, 228, 210, 120)
			$accentBrush.Dispose()

			$maxLogoWidth = 120.0
			$maxLogoHeight = 120.0
			$scale = [Math]::Min($maxLogoWidth / [double]$logo.Width, $maxLogoHeight / [double]$logo.Height)
			$drawLogoWidth = [int][Math]::Round([double]$logo.Width * $scale)
			$drawLogoHeight = [int][Math]::Round([double]$logo.Height * $scale)
			$logoX = [int](($largeWidth - $drawLogoWidth) / 2)
			$logoY = 64
			$largeGraphics.DrawImage($logo, $logoX, $logoY, $drawLogoWidth, $drawLogoHeight)
		} finally {
			$largeGraphics.Dispose()
		}
		$largeCanvas.Save($largeBmp, [System.Drawing.Imaging.ImageFormat]::Bmp)
		$largeCanvas.Dispose()

		# Small top-right wizard image (55x55)
		$smallWidth = 55
		$smallHeight = 55
		$smallCanvas = New-Object System.Drawing.Bitmap($smallWidth, $smallHeight, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
		$smallGraphics = [System.Drawing.Graphics]::FromImage($smallCanvas)
		try {
			$smallGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
			$smallGraphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
			$smallRect = New-Object System.Drawing.Rectangle(0, 0, $smallWidth, $smallHeight)
			$smallBgBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
				$smallRect,
				[System.Drawing.Color]::FromArgb(236, 244, 255),
				[System.Drawing.Color]::FromArgb(201, 219, 255),
				120.0
			)
			$smallGraphics.FillRectangle($smallBgBrush, $smallRect)
			$smallBgBrush.Dispose()

			$smallScale = [Math]::Min(34.0 / [double]$logo.Width, 34.0 / [double]$logo.Height)
			$smallLogoWidth = [int][Math]::Round([double]$logo.Width * $smallScale)
			$smallLogoHeight = [int][Math]::Round([double]$logo.Height * $smallScale)
			$smallLogoX = [int](($smallWidth - $smallLogoWidth) / 2)
			$smallLogoY = [int](($smallHeight - $smallLogoHeight) / 2)
			$smallGraphics.DrawImage($logo, $smallLogoX, $smallLogoY, $smallLogoWidth, $smallLogoHeight)
		} finally {
			$smallGraphics.Dispose()
		}
		$smallCanvas.Save($smallBmp, [System.Drawing.Imaging.ImageFormat]::Bmp)
		$smallCanvas.Dispose()
	} finally {
		$logo.Dispose()
	}

	Write-Host "[INFO] Branding assets updated: $assetsDir"
}

function Ensure-ValidSetupIcon {
	param(
		[Parameter(Mandatory = $true)]
		[string]$RepositoryRoot
	)

	$iconPath = Join-Path $RepositoryRoot "icon.ico"
	$logoPath = Join-Path $RepositoryRoot "logo.png"

	$isValidIcon = $false
	if (Test-Path $iconPath) {
		Add-Type -AssemblyName System.Drawing
		try {
			$icon = New-Object System.Drawing.Icon($iconPath)
			$icon.Dispose()
			$isValidIcon = $true
		} catch {
			Write-Warning "[WARN] icon.ico is not a valid ICO file, regenerating from logo.png"
		}
	}

	if ($isValidIcon) {
		Write-Host "[INFO] Setup icon is valid: $iconPath"
		return
	}

	if (-not (Test-Path $logoPath)) {
		Write-Error "[ERROR] Cannot generate icon.ico: logo.png not found"
		exit 1
	}

	if (-not ("Win32.NativeMethods" -as [type])) {
		Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
public static extern bool DestroyIcon(System.IntPtr hIcon);
'@
	}

	Add-Type -AssemblyName System.Drawing
	$logo = $null
	$bmp = $null
	$logo = [System.Drawing.Image]::FromFile($logoPath)
	try {
		$size = 256
		$bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
		$g = [System.Drawing.Graphics]::FromImage($bmp)
		try {
			$g.Clear([System.Drawing.Color]::Transparent)
			$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
			$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic

			$max = 220.0
			$scale = [Math]::Min($max / [double]$logo.Width, $max / [double]$logo.Height)
			$w = [int][Math]::Round([double]$logo.Width * $scale)
			$h = [int][Math]::Round([double]$logo.Height * $scale)
			$x = [int](($size - $w) / 2)
			$y = [int](($size - $h) / 2)
			$g.DrawImage($logo, $x, $y, $w, $h)
		} finally {
			$g.Dispose()
		}

		$hIcon = $bmp.GetHicon()
		try {
			$icon = [System.Drawing.Icon]::FromHandle($hIcon)
			$fs = [System.IO.File]::Open($iconPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
			try {
				$icon.Save($fs)
			} finally {
				$fs.Dispose()
				$icon.Dispose()
			}
		} finally {
			[Win32.NativeMethods]::DestroyIcon($hIcon) | Out-Null
		}

		Write-Host "[INFO] Generated fallback icon.ico from logo.png"
	} finally {
		if ($bmp) { $bmp.Dispose() }
		if ($logo) { $logo.Dispose() }
	}
}

function Assert-PortablePayload {
	param(
		[Parameter(Mandatory = $true)]
		[string]$RepositoryRoot
	)

	$portableRoot = Join-Path $RepositoryRoot "dist\EXE_Analyzer"
	if (-not (Test-Path $portableRoot)) {
		Write-Error "[ERROR] Portable payload not found: $portableRoot. Run build_portable.cmd first or remove --skip-portable."
		exit 1
	}

	$requiredFiles = @(
		(Join-Path $portableRoot "exe_tester_gui.exe"),
		(Join-Path $portableRoot ".engine\analyzer_core.exe")
	)

	$missing = @()
	foreach ($file in $requiredFiles) {
		if (-not (Test-Path $file)) {
			$missing += $file
		}
	}

	if ($missing.Count -gt 0) {
		Write-Error "[ERROR] Portable payload is incomplete. Missing required files:`n$($missing -join "`n")"
		exit 1
	}

	Write-Host "[INFO] Portable payload validated: $portableRoot"
}

function Get-CargoPackageVersion {
	param(
		[Parameter(Mandatory = $true)]
		[string]$CargoTomlPath
	)

	if (-not (Test-Path $CargoTomlPath)) {
		Write-Warning "[WARN] Cargo.toml not found; using version 0.1.0"
		return "0.1.0"
	}

	$content = Get-Content $CargoTomlPath -Raw
	$packageBlock = [regex]::Match($content, '(?ms)^\[package\]\s*(?<body>.*?)(^\[|\z)')
	if ($packageBlock.Success) {
		$versionMatch = [regex]::Match($packageBlock.Groups['body'].Value, '(?m)^\s*version\s*=\s*"(?<ver>[^"]+)"')
		if ($versionMatch.Success) {
			return $versionMatch.Groups['ver'].Value.Trim()
		}
	}

	# Fallback for non-standard Cargo.toml layout.
	$fallback = [regex]::Match($content, '(?m)^\s*version\s*=\s*"(?<ver>[^"]+)"')
	if ($fallback.Success) {
		return $fallback.Groups['ver'].Value.Trim()
	}

	Write-Warning "[WARN] Could not parse version from Cargo.toml; using version 0.1.0"
	return "0.1.0"
}

# Если не пропущено — попытаться собрать портативный пакет сначала
if (-not $SkipPortable) {
	Write-Host "[INFO] Building portable package first..."
	$buildPortable = Join-Path $RepoRoot "build_portable.cmd"
	if (Test-Path $buildPortable) {
		$proc = Start-Process -FilePath $buildPortable -NoNewWindow -Wait -PassThru
		if ($proc.ExitCode -ne 0) { Write-Error "[ERROR] build_portable.cmd failed with exit code $($proc.ExitCode)"; exit 1 }
	} else {
		Write-Warning "[WARN] build_portable.cmd not found, skipping portable build."
	}
}

Assert-PortablePayload -RepositoryRoot $RepoRoot

# Найти ISCC.exe (Inno Setup Compiler)
$iscc = $env:ISCC_EXE
if (-not $iscc) {
	$userLocalIscc = Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"
	$possible = @(
		$userLocalIscc,
		"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
		"C:\Program Files\Inno Setup 6\ISCC.exe",
		"ISCC.exe"
	)
	foreach ($p in $possible) {
		try {
			if (Test-Path $p) {
				$iscc = (Resolve-Path $p).Path
				break
			}
			$cmd = Get-Command $p -ErrorAction SilentlyContinue
			if ($cmd) {
				$iscc = $cmd.Path
				break
			}
		} catch {}
	}
}
if (-not $iscc) {
	Write-Error "[ERROR] ISCC.exe not found. Install Inno Setup or set ISCC_EXE environment variable."
	exit 1
}
Write-Host "[INFO] Using ISCC: $iscc"

# Прочитать версию из Cargo.toml
$cargoPath = Join-Path $RepoRoot "Cargo.toml"
$version = Get-CargoPackageVersion -CargoTomlPath $cargoPath
$outputBaseName = "Metsuki_EXE_Analyzer_Setup_$version"
Write-Host "[INFO] Installer version: $version"

# Путь к .iss
$iss = Join-Path $RepoRoot "installer\metsuki_installer.iss"
if (-not (Test-Path $iss)) { Write-Error "[ERROR] Installer script not found: $iss"; exit 1 }

# Убедиться, что icon.ico валидна для SetupIconFile
Ensure-ValidSetupIcon -RepositoryRoot $RepoRoot

# Обновить изображения мастера установки из logo.png
New-InstallerBrandingAssets -RepositoryRoot $RepoRoot

# Вызов ISCC с определением переменной MyAppVersion, вывод в dist
$distDir = Join-Path $RepoRoot "dist"
if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir | Out-Null }

$argList = "/O`"$distDir`" /DMyAppVersion=`"$version`" /DSetupOutputBaseFilename=`"$outputBaseName`" `"$iss`""
Write-Host "[INFO] Running ISCC $argList"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $iscc
$psi.Arguments = $argList
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$proc = [System.Diagnostics.Process]::Start($psi)
$stdout = $proc.StandardOutput.ReadToEnd()
$stderr = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()
Write-Host $stdout
if ($proc.ExitCode -ne 0) {
	Write-Error "[ERROR] ISCC failed:`n$stderr"
	exit $proc.ExitCode
}

$expectedSetup = Join-Path $distDir ("$outputBaseName.exe")
if (-not (Test-Path $expectedSetup)) {
	$fallback = Get-ChildItem -Path $distDir -Filter "*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
	if ($null -ne $fallback) {
		Write-Warning "[WARN] Expected installer name not found, using latest executable artifact: $($fallback.FullName)"
		$expectedSetup = $fallback.FullName
	} else {
		Write-Error "[ERROR] ISCC finished but no installer executable was produced in: $distDir"
		exit 1
	}
}

$canonicalSetup = Join-Path $distDir "Setup.exe"
if ((Resolve-Path $expectedSetup).Path -ne (Resolve-Path $canonicalSetup -ErrorAction SilentlyContinue | ForEach-Object { $_.Path })) {
	Copy-Item -Path $expectedSetup -Destination $canonicalSetup -Force
	Write-Host "[INFO] Canonical installer alias updated: $canonicalSetup"
}

Write-Host "[INFO] Installer built successfully: $expectedSetup"
exit 0
