# Security-Lab Modules

This document explains what each analysis module is responsible for, how to select ready profiles, how to customize module sets, and how compatibility/confirmation rules work.

## Status Markers

- `ON`: module is enabled and active.
- `OFF`: module is currently disabled (not selected).
- `BLOCKED`: incompatible for current target/build settings.
- `ASK`: module requires explicit confirmation before running deep checks.

## Ready Profiles

- `standard`: safe default profile for regular scans.
- `aggressive`: deeper profile with heavier checks that can require confirmation.

## Module Catalog

| ID | Category | Standard | Aggressive | Target | Main Responsibilities |
|---|---|---|---|---|---|
| `pe_rules` | PE | ON | ON | EXE | PE integrity, sections, mitigations, import/overlay risk |
| `asm_disasm` | ASM | ON | ON | EXE | Opcode signatures, branch/call density, shellcode hints |
| `symbolic_pathing` | Symbolic | OFF | ASK | EXE + Source | Path complexity, branch pressure, high-risk condition hints |
| `taint_dataflow` | Dataflow | ON | ON | Source | Source-to-sink tracking, untrusted flow hotspots |
| `runtime_sandbox_trace` | Runtime | ON | ON | EXE | Runtime scenario telemetry, timeline evidence, env policy |
| `fuzz_native` | Fuzzing | ON | ON | EXE | Native mutation scenarios, crash/timeout surfacing |
| `fuzz_libafl` | Fuzzing | OFF | ASK/BLOCKED* | EXE | Coverage-guided campaign via libafl |
| `business_regression` | Regression | ON | ON | Source | Business/financial logic risk patterns |

`*` `fuzz_libafl` is `BLOCKED` unless built with libafl support and run with `--fuzz-engine libafl`.

## Compatibility Rules

- EXE-only modules are blocked for source targets.
- Source-only modules are blocked for executable targets.
- `fuzz_libafl` is blocked without `--fuzz-engine libafl`.
- Some aggressive modules are marked `ASK` until `--confirm-extended-tests` is provided.

## Selection Options

Primary path: configure Security-Lab directly in GUI (left inspector panel).

CLI commands below are for developer/internal workflows.

List all modules:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --list-lab-modules
```

Use ready profile:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --lab-profile standard
```

Use aggressive profile with confirmation:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --lab-profile aggressive --confirm-extended-tests
```

Use custom module set:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --modules pe_rules,asm_disasm,runtime_sandbox_trace,fuzz_native
```

## Recommendation Flow

1. Start with `standard` profile.
2. Review `BLOCKED` and `ASK` modules in report telemetry.
3. Enable `aggressive` and `--confirm-extended-tests` only when deep checks are required.
4. For CI stability, pin an explicit `--modules` set.
