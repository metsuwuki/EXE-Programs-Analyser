# Metsuki EXE Analyzer

<p align="center">
	Windows-focused executable analysis toolkit with a desktop WebView UI, CLI automation support, and profile-driven security checks.
</p>

<p align="center">
	<img alt="Rust" src="https://img.shields.io/badge/Rust-1.77+-CE422B?logo=rust&logoColor=white">
	<img alt="UI" src="https://img.shields.io/badge/UI-WebView2%20Desktop-0EA5E9?logo=windows-terminal&logoColor=white">
	<img alt="CLI" src="https://img.shields.io/badge/CLI-exe__tester-2E8B57">
	<img alt="Platform" src="https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white">
</p>

---

## ✨ Features

- 🔎 PE integrity checks: sections, entropy, imports, mitigations, overlay indicators
- 🧪 Runtime scenarios with timing diagnostics and evidence timeline
- 📊 Structured findings with score and severity breakdown
- 🧩 Security-Lab profiles with custom module selection
- 🌐 Localization: English, Russian, Ukrainian, German
- 🖥 Desktop host (`exe_tester_web_gui.exe`) + automation-ready CLI (`exe_tester`)

---

## 📦 What Is Included

- `exe_tester_web_gui.exe`: desktop WebView-based UI host
- `.engine/analyzer_core.exe`: internal analysis engine used by desktop app
- `exe_tester` bin: CLI entrypoint for automation and local testing

---

## 🧭 Analysis Modes

- `MIN`: safer default profile
- `PENTEST`: deeper checks, requires explicit confirmation

---

## 🚀 Quick Start

### End users

1. Open portable folder: `dist/EXE_Analyzer`
2. Run: `exe_tester_web_gui.exe`

Rust/Cargo are not required for end users.

### Development

Build all binaries:

```powershell
cargo build --release --bins
```

Run desktop UI:

```powershell
cargo run --bin exe_tester_web_gui
```

Run CLI engine in MIN mode:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --mode-min --timeout 4 --runs 6 --out-dir logs
```

Run CLI engine in PENTEST mode:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --mode-pentest --confirm-extended-tests --timeout 4 --runs 8 --out-dir logs
```

---

## 🏗 Build & Packaging

Build portable package:

```powershell
build_portable.cmd
```

Build installer:

```powershell
build_setup.cmd
```

Build installer from existing portable output:

```powershell
build_setup.cmd --skip-portable
```

Recommended release pipeline:

```powershell
release_artifacts.cmd
```

---

## 📁 Output Locations

- Portable bundle: `dist/EXE_Analyzer`
- Installer: `dist/Metsuki_EXE_Analyzer_Setup_<version>.exe`
- Security manifests:
	- `dist/EXE_Analyzer/SHA256SUMS.txt`
	- `dist/EXE_Analyzer/SECURITY_PRECHECK.txt`

---

## 🛡 Security Docs

- Module matrix and profile behavior: `SECURITY_LAB_MODULES.md`
- Security and false-positive guidance: `SECURITY.md`

---

## 🧱 Repository Notes

- Keep source and scripts in Git: `src/`, `scripts/`, `installer/`, `webui/`, `assets/`
- Do not commit generated outputs: `target/`, `dist/`, runtime logs

<p align="center"><sub>Made by Metsuwuki</sub></p>

