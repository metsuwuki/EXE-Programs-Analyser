# Metsuki EXE Analyzer

Metsuki EXE Analyzer is a Windows-first analysis tool with a desktop GUI and an internal analysis engine.
It helps you inspect executable files, run runtime checks, and review structured reports.

GUI is the main user workflow. The packaged build is intended to be launched only through the GUI.

## Features

- Deep PE analysis: headers, sections, entropy, imports, entry point, overlay.
- Mitigation checks: ASLR, NX, CFG.
- Runtime edge-case scenarios (args/stdin/env).
- `STRICT` and `BALANCED` verdict modes.
- GUI workspace tabs: Overview, Findings, Runtime, Debugger.
- Debug diagnosis view: expected vs actual, failure point, probable root cause.
- Source static checks for `.cs`, `.java`, `.py`, `.go` (plus generic text checks).
- Report outputs: `full_*.log`, `issues_*.log`, `report_*.json`.
- Security-lab module catalog with profile/custom selection and compatibility markers.
- UI localization: Russian, English, German, Ukrainian.

## Quick Start (End Users)

Portable package path:

- `dist/EXE_Analyzer`

Run one of the following:

- `Start Analyzer GUI.cmd`
- `exe_tester_gui.exe`

Rust and Cargo are not required for end users.

## Development

```powershell
cargo build --bins
cargo run --bin exe_tester_gui
```

## GitHub Repository Contents

For a public source repository, keep these files in Git:

- `src/` (all Rust sources, including GUI and analyzer engine modules)
- `scripts/`, `installer/`, `build_*.cmd`, `release_artifacts.cmd`
- `Cargo.toml`, `Cargo.lock`, `README.md`, `SECURITY.md`, `SECURITY_LAB_MODULES.md`
- static assets (`icon.ico`, `logo.png`)

Do not commit generated artifacts:

- `target/`
- `dist/`
- runtime `logs/`

Internal developer CLI example (backend/testing):

```powershell
cargo run --bin exe_tester -- "C:\\path\\to\\app.exe" --strict --timeout 4 --runs 6 --out-dir logs
```

Security-lab catalog and profile examples:

```powershell
cargo run --bin exe_tester -- "C:\\path\\to\\app.exe" --list-lab-modules
cargo run --bin exe_tester -- "C:\\path\\to\\app.exe" --lab-profile aggressive --confirm-extended-tests
cargo run --bin exe_tester -- "C:\\path\\to\\app.exe" --modules pe_rules,asm_disasm,runtime_sandbox_trace,fuzz_native
```

Detailed module matrix:

- `SECURITY_LAB_MODULES.md`

## Internal Engine Exit Codes

- `0` = PASS
- `1` = WARN (`BALANCED` mode)
- `2` = FAIL
- `64` = argument/usage error

## Build Portable Package

```powershell
build_portable.cmd
```

The script builds release binaries and creates a ready-to-run package in `dist/EXE_Analyzer`.

## Build Setup Installer (.exe)

```powershell
build_setup.cmd
```

This script:

- builds (or reuses) `dist/EXE_Analyzer`
- compiles an installer using Inno Setup (`ISCC.exe`)

Output:

- `dist/Metsuki_EXE_Analyzer_Setup_<version>.exe`

Notes:

- Inno Setup 6 is required for setup generation.
- You can point a custom compiler path via `ISCC_EXE` environment variable.
- If portable build already exists, use `build_setup.cmd --skip-portable`.

## Release Artifacts (Recommended)

```powershell
release_artifacts.cmd
```

This pipeline runs:

- `build_portable.cmd` (release build + packaging)
- `scripts/pre_release_security_check.ps1` (SHA256 manifest + Defender precheck)
- `build_setup.cmd --skip-portable` (optional Setup.exe when Inno Setup is available)

Output files in `dist/EXE_Analyzer`:

- `SHA256SUMS.txt`
- `SECURITY_PRECHECK.txt`

## Modes

The analyzer uses exactly two verdict modes:

- `BALANCED`
- `STRICT`

No extra runtime mode switching is required for normal use.

## Security-Lab Compatibility Markers

The security-lab layer marks module status in telemetry/logs:

- `ON` active module
- `OFF` disabled by profile/custom selection
- `BLOCKED` incompatible with current target/build settings
- `ASK` requires explicit `--confirm-extended-tests`

## Security / EDR Notes

- The portable launcher uses a transparent `.cmd` start flow (no hidden VBS launcher).
- For enterprise endpoints, add your release folder to allowlist by hash/path/publisher policy.
- If a false positive occurs, submit the binary hash and sample to your AV vendor.
- See `SECURITY.md` for a short response checklist.

## Author

Metsuki
