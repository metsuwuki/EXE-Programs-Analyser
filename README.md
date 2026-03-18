# Metsuki EXE Analyzer

Metsuki EXE Analyzer is a Windows-focused executable analysis toolkit with a desktop WebView UI and a CLI engine.

## What is included

- `exe_tester_web_gui.exe`: desktop UI host (WebView-based).
- `.engine/analyzer_core.exe`: internal analysis engine used by the desktop app.
- `exe_tester` bin: CLI entrypoint for automation and local testing.

## Key capabilities

- PE checks: sections, entropy, imports, mitigations, overlay signals.
- Runtime scenarios and timing diagnostics.
- Structured findings with score and severity breakdown.
- Security-Lab profiles and custom module selection.
- Localization: English, Russian, Ukrainian, German.

## Analysis modes

- `MIN`: default safer profile.
- `PENTEST`: deeper checks; requires explicit confirmation.

## End-user quick start

1. Open the portable folder `dist/EXE_Analyzer`.
2. Run `exe_tester_web_gui.exe`.

Rust and Cargo are not required for end users.

## Development

Build all binaries:

```powershell
cargo build --release --bins
```

Run desktop UI:

```powershell
cargo run --bin exe_tester_web_gui
```

Run CLI engine:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --mode-min --timeout 4 --runs 6 --out-dir logs
```

PENTEST mode example:

```powershell
cargo run --bin exe_tester -- "C:\path\to\app.exe" --mode-pentest --confirm-extended-tests --timeout 4 --runs 8 --out-dir logs
```

## Packaging commands

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

## Output locations

- Portable bundle: `dist/EXE_Analyzer`
- Installer: `dist/Metsuki_EXE_Analyzer_Setup_<version>.exe`
- Security manifests: `dist/EXE_Analyzer/SHA256SUMS.txt`, `dist/EXE_Analyzer/SECURITY_PRECHECK.txt`

## Security-Lab docs

- Module matrix and profile behavior: `SECURITY_LAB_MODULES.md`
- Security and false-positive guidance: `SECURITY.md`

## Repository notes

- Keep source and scripts in Git (`src/`, `scripts/`, `installer/`, `webui/`, `assets/`).
- Do not commit generated outputs (`target/`, `dist/`, runtime logs).
