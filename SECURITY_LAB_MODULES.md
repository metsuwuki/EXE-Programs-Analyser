# Security-Lab Modules

Security-Lab extends analysis with profile-driven modules and explicit compatibility checks.

## Status markers

- `ON`: module is selected and active.
- `OFF`: module is not selected.
- `BLOCKED`: module is incompatible with current target/build conditions.
- `ASK`: module needs explicit opt-in to run extended checks.

## Profiles

- `standard`: safer default profile.
- `aggressive`: deeper profile, can include `ASK` modules.

## Module catalog

| ID | Area | Standard | Aggressive | Target type | Purpose |
|---|---|---|---|---|---|
| `pe_rules` | PE | ON | ON | EXE | PE integrity, mitigations, imports, overlay risk |
| `asm_disasm` | ASM | ON | ON | EXE | Opcode and control-flow heuristics |
| `symbolic_pathing` | Symbolic | OFF | ASK | EXE + Source | Path complexity and risky branch detection |
| `taint_dataflow` | Dataflow | ON | ON | Source | Source-to-sink tracking |
| `runtime_sandbox_trace` | Runtime | ON | ON | EXE | Runtime scenarios and timeline evidence |
| `fuzz_native` | Fuzzing | ON | ON | EXE | Native mutation checks and timeout/crash surfacing |
| `fuzz_libafl` | Fuzzing | OFF | ASK/BLOCKED* | EXE | Coverage-guided fuzzing via libafl |
| `business_regression` | Regression | ON | ON | Source | Business-logic risk patterns |

`*` `fuzz_libafl` is blocked unless built with `libafl-engine` and executed with `--fuzz-engine libafl`.

## Compatibility rules

- EXE-only modules are blocked for source targets.
- Source-only modules are blocked for executable targets.
- Some aggressive checks require `--confirm-extended-tests`.
- Optional engines/features can force `BLOCKED` status.

## CLI usage examples

List available modules:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --list-lab-modules
```

Run standard profile:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --lab-profile standard
```

Run aggressive profile with explicit confirmation:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --lab-profile aggressive --confirm-extended-tests
```

Run custom module set:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --modules pe_rules,asm_disasm,runtime_sandbox_trace,fuzz_native
```

## Practical recommendation

1. Start with `standard` profile.
2. Review `ASK` and `BLOCKED` statuses in output telemetry.
3. Enable aggressive checks only when needed.
4. For CI repeatability, pin modules with `--modules`.
