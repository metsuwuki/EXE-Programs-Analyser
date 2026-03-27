# Metsuki EXE Analyzer

<p align="center">
  Windows EXE triage and runtime diagnostics for fast first-pass analysis.
</p>

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-1.77+-CE422B?logo=rust&logoColor=white">
  <img alt="UI" src="https://img.shields.io/badge/UI-WebView2%20Desktop-0EA5E9?logo=windows-terminal&logoColor=white">
  <img alt="CLI" src="https://img.shields.io/badge/CLI-exe__tester-2E8B57">
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white">
</p>

---

## What It Is

Metsuki EXE Analyzer is a Windows-focused tool for inspecting `.exe` files, running practical runtime scenarios, and generating reviewable reports.

It is built for:

- QA engineers validating packaged desktop builds
- security reviewers doing fast executable triage
- support and release teams collecting reproducible evidence
- power users who want a local EXE analysis dashboard plus CLI automation

---

## What It Is Not

- It is not an antivirus.
- It does not promise a reliable malware verdict.
- It is not a replacement for deep reverse engineering or full sandbox research.
- It is not positioned as a source-code analyzer in the main product workflow.

---

## Core Value

- EXE-first workflow: choose a Windows executable, run analysis, review findings
- PE-focused checks: sections, entropy, imports, mitigations, signatures, overlay indicators
- runtime diagnostics: scenario runs, timing, exit codes, timeouts, stdout/stderr evidence
- structured output: JSON reports with optional Markdown and HTML exports
- desktop UI for hands-on use and CLI for scripting
- portable bundle and installer packaging

---

## User-Facing Modes

The product exposes two simple analysis modes in the GUI:

- `STANDARD`: the recommended first pass for most EXE reviews
- `DEEP`: a broader rerun for harder cases or when you want more runtime coverage

CLI mapping:

- `STANDARD` maps to `MIN`
- `DEEP` maps to `PENTEST`

---

## Power Profiles

Power profiles are presets for runs, timeout, mode, and sandbox level.

| Profile | User meaning | CLI mode | Runs | Timeout | Sandbox |
|---|---|---|---|---|---|
| `BASIC` | quick local pass | `MIN` | 4 | 4 s | limited |
| `AUDIT` | steadier review pass | `MIN` | 8 | 5 s | limited |
| `PENTEST` | deeper strict pass | `PENTEST` | 10 | 6 s | isolated |
| `EXTREME` | deeper rerun preset, not a separate magic mode | `PENTEST` | 12 | 8 s | isolated |

---

## Quick Start

### End Users

1. Open `dist/EXE_Analyzer`
2. Run `exe_tester_web_gui.exe`
3. Choose a Windows `.exe`
4. Pick `STANDARD` or `DEEP`
5. Run analysis and review the report

Rust or Cargo are not required for end users.

### Developers

Build all binaries:

```powershell
cargo build --release --bins
```

Run the desktop UI:

```powershell
cargo run --bin exe_tester_web_gui
```

Run the CLI:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --mode-min --runs 6 --timeout 4 --out-dir logs
```

Run the deeper CLI pass:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --mode-pentest --out-dir logs
```

Use a power profile:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --power-profile AUDIT --out-dir logs
```

---

## CLI Reference

```text
exe_tester <target.exe> [options]
```

Main supported target: Windows `.exe`

The CLI now rejects non-EXE targets in the primary workflow.

| Flag | Values | Default | Description |
|---|---|---|---|
| `--mode-min` | - | yes | first-pass EXE analysis |
| `--mode-pentest` | - |  | deeper EXE analysis |
| `--mode` | `min` / `pentest` | `min` | value-based alternative to the mode flags |
| `--power-profile` | `BASIC` `AUDIT` `PENTEST` `EXTREME` | `BASIC` | preset for mode, runs, timeout, and sandbox |
| `--runs` | integer >= 1 | 4 | number of runtime scenario runs |
| `--timeout` | integer >= 1 | 4 | per-run timeout in seconds |
| `--strict` | - |  | force STRICT verdict mode |
| `--balanced` | - |  | force BALANCED verdict mode |
| `--sandbox-profile` | `limited` `isolated` `none` | `limited` | runtime isolation level |
| `--out-dir` | path | `logs` | output directory for reports |
| `--export-md` | - |  | export Markdown report |
| `--export-html` | - |  | export HTML report |
| `--export-format` | `json` `md` `html` `both` | `json` | shorthand export selector |
| `--only-scenario` | name |  | rerun one runtime scenario |
| `--assignment` | path |  | assignment JSON for batch audit flow |
| `--audit-dir` | path |  | directory of EXE targets for batch audit |
| `--lab-profile` | `standard` `aggressive` | `standard` | internal security-lab preset for EXE analysis |
| `--modules` | `id1,id2,...` |  | override active module IDs |
| `--no-security-lab` | - |  | disable security-lab modules |
| `--list-lab-modules` | - |  | print module status table and exit |
| `--confirm-extended-tests` | - |  | explicit opt-in for extended checks |
| `--fuzz-engine` | `native` `libafl` | `native` | fuzzing engine selection |

---

## Output

| Path | Contents |
|---|---|
| `dist/EXE_Analyzer/` | portable bundle |
| `dist/Metsuki_EXE_Analyzer_Setup_<version>.exe` | installer |
| `dist/EXE_Analyzer/SHA256SUMS.txt` | release hash manifest |
| `dist/EXE_Analyzer/SECURITY_PRECHECK.txt` | pre-release check log |
| `logs/` | analysis reports |

Settings are stored at `%APPDATA%\Metsuki\exe_analyzer\settings.json`.

---

## Build And Packaging

Build portable package:

```powershell
build_portable.cmd
```

Build installer:

```powershell
build_setup.cmd
```

Build release artifacts:

```powershell
release_artifacts.cmd
```

Verify a portable bundle:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify_portable.ps1
```

Note for maintainers:
`build_setup.cmd` requires Inno Setup (`ISCC.exe`) to be installed locally.

---

## Security Notes

- `SECURITY.md`: release integrity and false-positive handling
- `SECURITY_LAB_MODULES.md`: supported EXE-oriented lab modules and presets

---

## Repository Notes

- Keep source and build scripts in version control: `src/`, `installer/`, `scripts/`, `webui/`, `assets/`
- Do not commit generated outputs such as `target/`, `dist/`, or runtime logs
