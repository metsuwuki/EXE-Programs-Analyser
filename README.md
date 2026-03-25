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

## 👨‍💻 What It Can Actually Do (No Buzzwords)

- Takes your `.exe` through a 4-phase pipeline: static checks, runtime scenarios, security modules, and a final report.
- Static analysis is more than "is this a PE": it inspects sections, imports, mitigations (ASLR/DEP/CFG), suspicious patterns, and risk indicators.
- Runtime analysis stresses the target with intentionally rough inputs: empty stdin, noisy stdin, long args, unicode, shell-like symbols, broken paths, clean env.
- Tracks useful engineering metrics: exit codes, timeouts, duration (p50/p95), run stability, and flakiness.
- Produces structured findings with severity + score, so results are readable in UI and easy to consume in CI/automation.
- Supports both `MIN` and `PENTEST` modes: quick/safe when needed, deeper/aggressive when required.
- Security Lab modules can be enabled by profile or manually: PE rules, ASM heuristics, taint/dataflow, runtime trace, fuzzing, regression checks.
- Includes both a desktop UI for hands-on work and a CLI for scripts/pipelines, no forced trade-off.
- Includes a teacher/audit batch flow: provide an assignment JSON, get bulk analysis, summary JSON/CSV, and rerun cmd.
- Ships as both a portable build and a setup installer, so you can run it instantly or deploy it properly.

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
