# Metsuki EXE Analyzer

Metsuki EXE Analyzer is a Windows-first analysis tool with a desktop GUI and CLI.
It helps you inspect executable files, run runtime checks, and review structured reports.

## Features

- Deep PE analysis: headers, sections, entropy, imports, entry point, overlay.
- Mitigation checks: ASLR, NX, CFG.
- Runtime edge-case scenarios (args/stdin/env).
- `STRICT` and `BALANCED` verdict modes.
- GUI workspace tabs: Overview, Findings, Runtime, Debugger.
- Debug diagnosis view: expected vs actual, failure point, probable root cause.
- Source static checks for `.cs`, `.java`, `.py`, `.go` (plus generic text checks).
- Report outputs: `full_*.log`, `issues_*.log`, `report_*.json`.
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

CLI example:

```powershell
cargo run --bin exe_tester -- "C:\\path\\to\\app.exe" --strict --timeout 4 --runs 6 --out-dir logs
```

## CLI Exit Codes

- `0` = PASS
- `1` = WARN (`BALANCED` mode)
- `2` = FAIL
- `64` = argument/usage error

## Build Portable Package

```powershell
build_portable.cmd
```

The script builds release binaries and creates a ready-to-run package in `dist/EXE_Analyzer`.

## Release Artifacts (Recommended)

```powershell
release_artifacts.cmd
```

This pipeline runs:

- `build_portable.cmd` (release build + packaging)
- `scripts/pre_release_security_check.ps1` (SHA256 manifest + Defender precheck)

Output files in `dist/EXE_Analyzer`:

- `SHA256SUMS.txt`
- `SECURITY_PRECHECK.txt`

## Modes

The analyzer uses exactly two verdict modes:

- `BALANCED`
- `STRICT`

No extra runtime mode switching is required for normal use.

## Security / EDR Notes

- The portable launcher uses a transparent `.cmd` start flow (no hidden VBS launcher).
- For enterprise endpoints, add your release folder to allowlist by hash/path/publisher policy.
- If a false positive occurs, submit the binary hash and sample to your AV vendor.
- See `SECURITY.md` for a short response checklist.

## Author

Metsuki
