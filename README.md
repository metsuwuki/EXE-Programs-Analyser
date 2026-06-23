# EXE Analyzer

<p align="center">
  Executable QA, Safety & Release Readiness Analyzer for Windows desktop and console applications.
</p>

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-1.77+-CE422B?logo=rust&logoColor=white">
  <img alt="UI" src="https://img.shields.io/badge/UI-WebView2%20Desktop-0EA5E9?logo=windows-terminal&logoColor=white">
  <img alt="Desktop" src="https://img.shields.io/badge/App-GUI--only-2E8B57">
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white">
</p>

---

## What It Is

EXE Analyzer is a Windows-first Executable QA, Safety & Release Readiness Analyzer. It reviews `.exe` targets, selects runtime expectations by application kind, compares reports, and collects structured evidence in one place.

It is built for:

- QA engineers validating packaged desktop builds
- security reviewers doing fast executable triage
- support and release teams collecting reproducible evidence
- power users who want a local EXE analysis dashboard without extra terminal plumbing

---

## What It Is Not

- It is not an antivirus.
- It does not promise a trustworthy malware verdict.
- It is not a replacement for reverse engineering, a VM lab, or a full EDR sandbox.
- Its `isolated` profile is a stronger local runtime harness, not a full container or virtual machine.
- Verdicts indicate detected risk or QA readiness, not proof of maliciousness.

---

## Core Value

- EXE-first workflow: choose a Windows executable, run analysis, review findings
- PE-focused checks: headers, sections, entropy, mitigations, imports, signatures, overlays
- application-kind detection for GUI, console, installer, service-like, and unknown targets
- GUI-aware runtime checks: visible window detection, responsiveness sampling, and graceful close
- real signature trust checks: PE certificate table parsing plus native `WinVerifyTrust` validation on Windows
- runtime diagnostics: scenario runs, timing, exit codes, timeouts, stdout/stderr evidence, memory peaks, handle counts, and process I/O counters
- deeper signature coverage: deterministic rule pack plus embedded `YARA-X` rules for binaries and source-like targets
- structured output: JSON reports with optional Markdown and HTML exports
- built-in reports, runtime, compare/history, settings, and repro-bundle flows

---

## AppKind-Aware Runtime

Runtime evidence is collected as raw facts and then interpreted for the detected application kind.
The raw `timed_out` flag is retained, but it does not automatically mean instability.

- GUI applications with a visible responsive window can finish as `StillRunningExpected`.
- Console applications that exceed their budget finish as `TimedOutUnexpected`.
- Service-like applications use `NotApplicable` unless a service harness is available.
- Installers use cautious scenarios and keep long-running/file-write behavior under review.
- Unknown applications receive conservative review instead of an automatic malware or crash verdict.

Stability is calculated from `interpreted_outcome`, while raw timeout, exit, process, network,
window, and file evidence remain available in the report.

---

## Desktop Workflow

The desktop application centers around five views:

- `Home`: target selection, analysis profile, run controls, KPIs
- `Reports`: previous report loading, findings review, log access, export, report close
- `Runtime`: per-scenario timeline, stdout/stderr previews, timeout and exit evidence
- `Compare`: report diffing, run history, and network/process drift
- `Settings`: language, appearance, defaults, embedded-core diagnostics

Additional user-facing behavior:

- first-run welcome screen before the main workspace is initialized
- persisted settings in `%APPDATA%\\EXE_Analyzer\\settings.json`
- interface localization for English, Russian, Ukrainian, and German
- runtime report export to Markdown and HTML through the desktop UI
- a focused dark workbench theme for the desktop UI

---

## Analysis Profiles

The desktop UI exposes two release profiles. Sandbox selection is internal to the runtime harness and is not a user-facing control.

| Profile | User meaning | Verdict mode | Runs | Timeout |
|---|---|---|---|---|
| `STANDARD` | default local pass for everyday review | `BALANCED` | 4 | 5 s |
| `DEEP_REVIEW` | stricter extended pass for higher-risk files | `STRICT` | 16 | 10 s |

`DEEP_REVIEW` maps to the internal strict analysis mode and uses the strongest available local runtime isolation automatically.

---

## Quick Start

### End Users

1. Open `dist/EXE_Analyzer`
2. Run `exe_analyzer.exe`
3. Choose a Windows `.exe`
4. Pick `Standard` or `Deep Review`
5. Run analysis and review the report, runtime, and exports

Rust or Cargo are not required for end users.

### Developers

Build the desktop app:

```powershell
cargo build --release --bins
```

Run the desktop UI:

```powershell
cargo run --bin exe_analyzer
```

---

## Output

| Path | Contents |
|---|---|
| `logs/` | analysis reports and runtime artifacts |
| `dist/EXE_Analyzer/` | portable bundle generated in release packaging flow |
| `dist/EXE_Analyzer_Setup_<version>.exe` | installer generated in release packaging flow |
| `dist/EXE_Analyzer/SHA256SUMS.txt` | release hash manifest |
| `dist/EXE_Analyzer/SECURITY_PRECHECK.txt` | pre-release check log |

Desktop settings are stored at `%APPDATA%\\EXE_Analyzer\\settings.json`.

---

## Build And Packaging

CI note:
release artifacts should be produced by the GitHub Actions workflows under `.github/workflows/` rather than committed back into the repository.
The CI and release flows now enforce `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test` before packaging.

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

### Windows Developer Setup

Rust's `x86_64-pc-windows-msvc` target requires the native Microsoft linker and CRT libraries.
Install Visual Studio Build Tools with:

- Desktop development with C++
- MSVC x64/x86 build tools
- Windows 10 or Windows 11 SDK
- C++ CMake tools for Windows, recommended

Run Cargo from a Developer PowerShell, or ensure the normal MSVC and Windows SDK `LIB`,
`PATH`, and `INCLUDE` variables are initialized. `LNK1104: cannot open file 'msvcrt.lib'`
means the CRT workload is missing or the shell was not initialized by `VsDevCmd.bat`.
Repair the Build Tools installation if the MSVC directory contains only `lib\onecore`
and no normal `lib\x64\msvcrt.lib`.

Install the standard Rust developer components when needed:

```powershell
rustup component add rustfmt clippy
```

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
