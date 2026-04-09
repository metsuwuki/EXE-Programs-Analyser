# Metsuki EXE Analyzer

<p align="center">
  Windows EXE triage, runtime diagnostics, and debugger orchestration for fast first-pass analysis.
</p>

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-1.77+-CE422B?logo=rust&logoColor=white">
  <img alt="UI" src="https://img.shields.io/badge/UI-WebView2%20Desktop-0EA5E9?logo=windows-terminal&logoColor=white">
  <img alt="CLI" src="https://img.shields.io/badge/CLI-exe__tester-2E8B57">
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white">
</p>

---

## What It Is

Metsuki EXE Analyzer is a Windows-first desktop and CLI tool for reviewing `.exe` targets, exercising runtime scenarios, and collecting structured evidence in one place.

It is built for:

- QA engineers validating packaged desktop builds
- security reviewers doing fast executable triage
- support and release teams collecting reproducible evidence
- power users who want a local EXE analysis dashboard plus CLI automation

---

## What It Is Not

- It is not an antivirus.
- It does not promise a trustworthy malware verdict.
- It is not a replacement for reverse engineering, a VM lab, or a full EDR sandbox.
- Its `isolated` profile is a stronger local runtime harness, not a full container or virtual machine.

---

## Core Value

- EXE-first workflow: choose a Windows executable, run analysis, review findings
- PE-focused checks: headers, sections, entropy, mitigations, imports, signatures, overlays
- runtime diagnostics: scenario runs, timing, exit codes, timeouts, stdout/stderr evidence
- structured output: JSON reports with optional Markdown and HTML exports
- desktop UI for hands-on use and CLI for scripting, batch audit, and exports
- built-in reports, runtime, debugger, settings, and repro-bundle flows

---

## Desktop Workflow

The desktop application centers around five views:

- `Home`: target selection, power profile, sandbox profile, run controls, KPIs
- `Reports`: previous report loading, findings review, log access, export, report close
- `Runtime`: per-scenario timeline, stdout/stderr previews, timeout and exit evidence
- `Debugger`: DAP-based launch preparation and debugger workbench integration
- `Settings`: language, appearance, defaults, analyzer path, diagnostics

Additional user-facing behavior:

- first-run welcome screen before the main workspace is initialized
- persisted settings in `%APPDATA%\\Metsuki\\exe_analyzer\\settings.json`
- interface localization for English, Russian, Ukrainian, and German
- runtime report export to Markdown and HTML through the desktop UI
- hidden `pentest` visual layer for the strict analysis profile

---

## Power Profiles

Power profiles are presets for analysis mode, verdict mode, runs, timeout, and sandbox level.

| Profile | User meaning | Analysis mode | Verdict mode | Runs | Timeout | Sandbox |
|---|---|---|---|---|---|---|
| `BASIC` | default local pass | `MIN` | `BALANCED` | 4 | 5 s | `limited` |
| `AUDIT` | steadier review pass | `MIN` | `BALANCED` | 2 | 4 s | `limited` |
| `PENTEST` | strict extended pass | `PENTEST` | `STRICT` | 16 | 10 s | `isolated` |

`PENTEST` requires explicit confirmation before extended checks are enabled in the GUI or CLI.

---

## Sandbox Profiles

Runtime scenarios support three local execution profiles:

| Profile | Meaning |
|---|---|
| `limited` | normal harnessing plus redirected runtime environment |
| `isolated` | `limited` plus Windows Job Object limits, kill-on-close, memory caps, and active-process cap |
| `none` | direct launch without sandbox restrictions |

The sandbox layer redirects runtime paths such as `TEMP`, `HOME`, `APPDATA`, and `LOCALAPPDATA` into the run workspace so the target does not write into the normal user profile during instrumented runs.

---

## Quick Start

### End Users

1. Open `dist/EXE_Analyzer`
2. Run `exe_tester_web_gui.exe`
3. Choose a Windows `.exe`
4. Pick `BASIC`, `AUDIT`, or `PENTEST`
5. Run analysis and review the report, runtime, and exports

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
cargo run --bin exe_tester -- "C:\path\to\app.exe" --mode-min --runs 4 --timeout 5 --out-dir logs
```

Run the strict pass:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --mode-pentest --confirm-extended-tests --out-dir logs
```

Use a power profile:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --power-profile AUDIT --out-dir logs
```

List available runtime scenarios:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --list-scenarios
```

---

## CLI Reference

```text
exe_tester <target.exe> [options]
```

Main supported target: Windows `.exe`

The primary workflow rejects non-EXE targets.

| Flag | Values | Default | Description |
|---|---|---|---|
| `--mode-min` | - | yes | first-pass EXE analysis |
| `--mode-pentest` | - |  | strict extended EXE analysis |
| `--mode` | `min` / `pentest` | `min` | value-based alternative to the mode flags |
| `--power-profile` | `BASIC` `AUDIT` `PENTEST` | `BASIC` | preset for mode, verdict, runs, timeout, and sandbox |
| `--runs` | integer >= 1 | profile-based | number of runtime scenario runs |
| `--timeout` | integer >= 1 | profile-based | per-run timeout in seconds |
| `--strict` | - |  | force `STRICT` verdict mode |
| `--balanced` | - | profile-based | force `BALANCED` verdict mode |
| `--sandbox-profile` | `limited` `isolated` `none` | profile-based | runtime isolation level |
| `--out-dir` | path | `logs` | output directory for reports |
| `--export-md` | - |  | export Markdown report |
| `--export-html` | - |  | export HTML report |
| `--export-format` | `json` `md` `html` `both` | `json` | shorthand export selector |
| `--only-scenario` | name |  | rerun one runtime scenario |
| `--list-scenarios` | - |  | print runtime scenario catalog and exit |
| `--assignment` | path |  | assignment JSON for teacher or audit flow |
| `--audit-dir` | path |  | directory of EXE targets for batch audit |
| `--lab-profile` | `standard` `aggressive` | `standard` | security-lab preset |
| `--modules` | `id1,id2,...` | profile-based | override active module IDs |
| `--no-security-lab` | - |  | disable security-lab module layer |
| `--list-lab-modules` | - |  | print module catalog and exit |
| `--confirm-extended-tests` | - |  | explicit opt-in for extended checks |
| `--fuzz-engine` | `native` `libafl` | `native` | fuzzing engine selection |

---

## Output

| Path | Contents |
|---|---|
| `logs/` | analysis reports and runtime artifacts |
| `dist/EXE_Analyzer/` | portable bundle |
| `dist/Metsuki_EXE_Analyzer_Setup_<version>.exe` | installer |
| `dist/EXE_Analyzer/SHA256SUMS.txt` | release hash manifest |
| `dist/EXE_Analyzer/SECURITY_PRECHECK.txt` | pre-release check log |

Desktop settings are stored at `%APPDATA%\\Metsuki\\exe_analyzer\\settings.json`.

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

## Documentation Map

- `REPORT_FORMAT.md`: report schema and compatibility notes
- `SECURITY_LAB_MODULES.md`: security-lab module catalog and profile behavior
- `SECURITY.md`: release integrity, reporting policy, and endpoint-security notes
- `LICENSE`: repository license text

---

## License

This repository is licensed under the MIT License. See `LICENSE`.

---

## Repository Notes

- Keep source and build scripts in version control: `src/`, `installer/`, `scripts/`, `webui/`, `assets/`
- Do not commit generated outputs such as `target/`, `dist/`, or runtime logs
