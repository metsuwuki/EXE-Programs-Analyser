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
- ⚡ Power profiles (BASIC / AUDIT / PENTEST / EXTREME) with pre-tuned defaults
- 🌐 Localization: English, Russian, Ukrainian, German
- 🖥 Desktop host (`exe_tester_web_gui.exe`) + automation-ready CLI (`exe_tester`)

---

## 👨‍💻 What It Can Actually Do

- Takes your `.exe` through a 4-phase pipeline: static checks, runtime scenarios, security modules, and a final report.
- Static analysis inspects sections, imports, mitigations (ASLR/DEP/CFG), suspicious patterns, and risk indicators.
- Runtime analysis stresses the target with intentionally rough inputs: empty stdin, noisy stdin, long args, unicode, shell-like symbols, broken paths, clean env.
- Tracks useful engineering metrics: exit codes, timeouts, duration (p50/p95), run stability, and flakiness.
- Produces structured findings with severity + score: readable in the UI and easy to consume in CI/automation.
- Supports `MIN` and `PENTEST` analysis modes — quick/safe when needed, deeper/aggressive when required.
- Security-Lab modules can be enabled by profile or manually: PE rules, ASM heuristics, taint/dataflow, runtime trace, fuzzing, regression checks.
- Includes both a desktop UI for hands-on work and a CLI for scripts/pipelines.
- Includes a teacher/audit batch flow: provide an assignment JSON, get bulk analysis with summary JSON/CSV and a ready rerun cmd.
- Ships as both a portable build and a setup installer.

---

## 📦 What Is Included

| File | Description |
|---|---|
| `exe_tester_web_gui.exe` | Desktop WebView-based UI host |
| `.engine/analyzer_core.exe` | Internal analysis engine (hidden folder, used by the desktop app) |
| `exe_tester` | CLI entrypoint for automation and local testing |

---

## 🧭 Analysis Modes

| Mode | Verdict | Lab profile | Notes |
|---|---|---|---|
| `MIN` | BALANCED | standard | Safe default, no explicit opt-in required |
| `PENTEST` | STRICT | aggressive | Deeper checks; `--mode-pentest` enables opt-in automatically |

---

## ⚡ Power Profiles

Power profiles pre-configure runs, timeout, analysis mode, verdict mode, and sandbox level in one flag.
Individual flags (`--runs`, `--timeout`, `--strict`, `--sandbox-profile`) always override profile defaults.

| Profile | Mode | Verdict | Runs | Timeout | Sandbox |
|---|---|---|---|---|---|
| `BASIC` | MIN | BALANCED | 4 | 4 s | limited |
| `AUDIT` | MIN | BALANCED | 8 | 5 s | limited |
| `PENTEST` | PENTEST | STRICT | 10 | 6 s | isolated |
| `EXTREME` | PENTEST | STRICT | 12 | 8 s | isolated |

---

## 🚀 Quick Start

### End users

1. Open the portable folder: `dist/EXE_Analyzer`
2. Run: `exe_tester_web_gui.exe`

Rust/Cargo are not required for end users.

### Development

Build all binaries:

```powershell
cargo build --release --bins
```

Run the desktop UI:

```powershell
cargo run --bin exe_tester_web_gui
```

Run the CLI — MIN mode:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --mode-min --runs 6 --timeout 4 --out-dir logs
```

Run the CLI — PENTEST mode (extended tests are enabled automatically):

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --mode-pentest --out-dir logs
```

Run the CLI — using a power profile:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --power-profile AUDIT --out-dir logs
```

---

## 🔧 CLI Reference

```
exe_tester <target.exe> [options]
```

| Flag | Values | Default | Description |
|---|---|---|---|
| `--mode-min` | — | ✓ | MIN mode, BALANCED verdict, standard lab profile |
| `--mode-pentest` | — | | PENTEST mode, STRICT verdict, aggressive lab, opt-in auto-enabled |
| `--mode` | `min` / `pentest` | `min` | Value-based alternative to `--mode-min` / `--mode-pentest` |
| `--power-profile` | `BASIC` `AUDIT` `PENTEST` `EXTREME` | `BASIC` | Pre-tuned profile that sets mode, runs, timeout, sandbox |
| `--runs` | integer ≥ 1 | 4 | Number of runtime scenario runs |
| `--timeout` | integer ≥ 1 | 4 | Per-run timeout in seconds |
| `--strict` | — | | Force STRICT verdict mode |
| `--balanced` | — | | Force BALANCED verdict mode |
| `--sandbox-profile` | `limited` `isolated` `none` | `limited` | Runtime sandbox isolation level |
| `--out-dir` | path | `logs` | Output directory for reports |
| `--export-md` | — | | Export Markdown report alongside JSON |
| `--export-html` | — | | Export HTML report alongside JSON |
| `--export-format` | `json` `md` `html` `both` | `json` | Shorthand export selector |
| `--only-scenario` | name | | Run a single named scenario only |
| `--assignment` | path | | Assignment JSON for teacher/audit batch flow |
| `--audit-dir` | path | | Directory of EXE targets for batch audit |
| `--lab-profile` | `standard` `aggressive` | `standard` | Security-Lab module profile |
| `--modules` | `id1,id2,...` | | Override active modules (comma-separated IDs) |
| `--no-security-lab` | — | | Disable Security-Lab entirely |
| `--list-lab-modules` | — | | Print module status table and exit |
| `--confirm-extended-tests` | — | | Explicit opt-in for PENTEST/extended checks |
| `--fuzz-engine` | `native` `libafl` | `native` | Fuzzing engine selection |

---

## 🏗 Build & Packaging

Build portable package:

```powershell
build_portable.cmd
```

Build installer (runs portable build first, then Inno Setup):

```powershell
build_setup.cmd
```

Build installer from an already-built portable output:

```powershell
build_setup.cmd --skip-portable
```

Full release pipeline — portable + installer + hash manifest:

```powershell
release_artifacts.cmd
```

With code signing:

```powershell
release_artifacts.cmd --sign
```

Skip the installer step:

```powershell
release_artifacts.cmd --skip-setup
```

---

## 📁 Output Locations

| Path | Contents |
|---|---|
| `dist/EXE_Analyzer/` | Portable bundle |
| `dist/Metsuki_EXE_Analyzer_Setup_<version>.exe` | Installer |
| `dist/EXE_Analyzer/SHA256SUMS.txt` | Release hash manifest |
| `dist/EXE_Analyzer/SECURITY_PRECHECK.txt` | Pre-release security check log |
| `logs/` | Analysis reports (JSON; optional MD/HTML) |

Settings are stored at `%APPDATA%\Metsuki\exe_analyzer\settings.json`.

---

## 🛡 Security Docs

- Module matrix and profile behavior: `SECURITY_LAB_MODULES.md`
- Security and false-positive guidance: `SECURITY.md`

---

## 🧱 Repository Notes

- Keep source and scripts in Git: `src/`, `scripts/`, `installer/`, `webui/`, `assets/`
- Do not commit generated outputs: `target/`, `dist/`, runtime logs
