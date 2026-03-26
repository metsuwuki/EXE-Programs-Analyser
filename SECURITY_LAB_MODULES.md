# Security-Lab Modules

<p align="center">
	Security-Lab extends analysis with profile-driven modules and explicit compatibility checks.
</p>

<p align="center">
	<img alt="Profiles" src="https://img.shields.io/badge/Profiles-standard%20%7C%20aggressive-0F766E">
	<img alt="Selection" src="https://img.shields.io/badge/Module%20State-ON%20%7C%20OFF%20%7C%20ASK%20%7C%20BLOCKED-334155">
	<img alt="CLI" src="https://img.shields.io/badge/CLI-exe__tester-2E8B57">
</p>

---

## 🧭 Status Markers

- `ON`: module is selected and active
- `OFF`: module is not selected
- `BLOCKED`: module is incompatible with the current target or build (e.g., missing optional engine)
- `ASK`: module requires explicit opt-in (`--confirm-extended-tests`)

---

## ⚙️ Profiles

- `standard`: safer default — PE, ASM, dataflow, runtime trace, native fuzzing, regression
- `aggressive`: deeper — adds `symbolic_pathing` (ASK) and `fuzz_libafl` (ASK/BLOCKED)

Both profiles are selected via `--lab-profile standard|aggressive` or automatically by `--mode-min` / `--mode-pentest`.

---

## 🧩 Module Catalog

| ID | Area | Standard | Aggressive | Target | Key capabilities |
|---|---|---|---|---|---|
| `pe_rules` | PE | ON | ON | EXE | Headers/sections integrity; mitigations scoring (ASLR/DEP/CFG); overlay + import risk heuristics |
| `asm_disasm` | ASM | ON | ON | EXE | Opcode signature scan; branch/call density sampling; packer/shellcode hints |
| `symbolic_pathing` | Symbolic | OFF | ASK | EXE + Source | Branch complexity estimation; path explosion hot spots; high-risk condition hints |
| `taint_dataflow` | Dataflow | ON | ON | Source | Source-to-sink mapping; unsafe API propagation; missing validation hotspots |
| `runtime_sandbox_trace` | Runtime | ON | ON | EXE | Scenario trace timeline; env policy capture; stderr/stdout evidence snippets |
| `fuzz_native` | Fuzzing | ON | ON | EXE | Seed mutation scenarios; unicode/ASCII boundary stress; crash and timeout surfacing |
| `fuzz_libafl` | Fuzzing | OFF | ASK/BLOCKED\* | EXE | Structured corpus mode; coverage-guided seed strategy; deeper stress profile |
| `business_regression` | Regression | ON | ON | Source | Money-value risk patterns; rounding precision checks; critical-path TODO/FIXME drift |

\* `fuzz_libafl` is `BLOCKED` unless the binary is built with the `libafl-engine` feature (`cargo build --features libafl-engine`) and `--fuzz-engine libafl` is passed at runtime.

---

## 🔒 Compatibility Rules

- EXE-only modules (`pe_rules`, `asm_disasm`, `runtime_sandbox_trace`, `fuzz_native`, `fuzz_libafl`) are `BLOCKED` for source targets
- Source-only modules (`taint_dataflow`, `business_regression`) are `BLOCKED` for executable targets
- `symbolic_pathing` supports both target types but requires `--confirm-extended-tests` in the `aggressive` profile
- Missing optional engines/features force `BLOCKED` status regardless of profile

---

## 💻 CLI Usage Examples

List module status for a given target:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --list-lab-modules
```

Run with the standard profile (default):

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --lab-profile standard
```

Run with the aggressive profile (extended tests auto-enabled via `--mode-pentest`):

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --mode-pentest --lab-profile aggressive
```

Run a custom module set:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --modules pe_rules,asm_disasm,runtime_sandbox_trace,fuzz_native
```

---

## ✅ Practical Recommendation

1. Start with `standard` profile for the first pass
2. Check `ASK` and `BLOCKED` statuses in the output telemetry
3. Enable `aggressive` checks via `--mode-pentest` only when deeper coverage is needed
4. For CI repeatability, pin the exact module set with `--modules`
