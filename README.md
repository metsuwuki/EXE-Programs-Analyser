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

Run one of the following files in this folder:

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

## Author

Metsuki
