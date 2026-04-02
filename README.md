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

## Public Repository Scope

This directory is prepared for a public GitHub showcase repository.

It is intended to publish:

- product overview
- screenshots and release notes
- report format documentation
- security and integrity notes
- compiled release binaries, if desired

It is not intended to publish:

- application source code
- internal build logic
- runtime sandbox implementation details in source form
- debugger orchestration internals
- private assets, experiments, or development history

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

## Distribution Model

This public repository is a showcase and release surface.

Source code is not included in the public package represented by this folder. Public redistribution, copying, relicensing, and reuse are governed by the included `LICENSE` file.

If you publish releases:

- upload only the binaries or installer you want to distribute
- publish hashes together with every release
- do not upload the internal source tree unless you intentionally want to open it

---

## Documentation Map

- `REPORT_FORMAT.md`: report schema and compatibility notes
- `SECURITY.md`: release integrity and endpoint-security notes
- `REPOSITORY_NOTICE.md`: repository scope and usage restrictions
- `PUBLISH_CHECKLIST.md`: what to include in the public GitHub repo
- `LICENSE`: public repository rights and restrictions

---

## License

This public repository package is distributed under an `All Rights Reserved` license. See `LICENSE`.
