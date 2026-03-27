# Security-Lab Modules

Security-Lab is the module layer behind deeper EXE analysis presets.

For the MVP product surface, only EXE-oriented modules are documented as supported here. Older source-oriented experiments are intentionally out of scope for the main workflow.

## Status Markers

- `ON`: selected and active
- `OFF`: not selected
- `ASK`: requires explicit opt-in
- `BLOCKED`: unavailable for the current build or runtime context

## Profiles

- `standard`: safer first pass for routine EXE review
- `aggressive`: deeper pass with extra opt-in checks

These profiles can be selected through `--lab-profile standard|aggressive` and may also be implied by higher-level mode presets.

## Supported EXE Modules

| ID | Area | Standard | Aggressive | Key capabilities |
|---|---|---|---|---|
| `pe_rules` | PE | ON | ON | headers, sections, mitigations, imports, overlay heuristics |
| `asm_disasm` | ASM | ON | ON | opcode scans, packer hints, branch and call density sampling |
| `runtime_sandbox_trace` | Runtime | ON | ON | scenario timeline, stdout/stderr previews, policy capture |
| `fuzz_native` | Fuzzing | ON | ON | native stress inputs, unicode and argument boundary checks |
| `symbolic_pathing` | Experimental | OFF | ASK | deeper path exploration for harder EXE cases |
| `fuzz_libafl` | Experimental fuzzing | OFF | ASK/BLOCKED | optional coverage-guided stress mode when built with extra support |

## Compatibility Rules

- The supported MVP workflow is Windows `.exe` analysis.
- `symbolic_pathing` requires explicit confirmation for extended checks.
- `fuzz_libafl` remains optional and may be `BLOCKED` unless the binary is built with the required feature support.
- If an optional engine or feature is missing, the module is reported as `BLOCKED`.

## Practical Recommendation

1. Start with `standard` for the first pass.
2. Review findings, runtime evidence, and stability metrics.
3. Use the deeper pass only when you need broader coverage.
4. Pin exact module sets in CI if repeatability matters.

## CLI Examples

List module status for a target:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --list-lab-modules
```

Run the standard profile:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --lab-profile standard
```

Run a deeper profile:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --mode-pentest --lab-profile aggressive
```

Run an explicit EXE module set:

```powershell
cargo run --bin exe_tester -- "C:\path\target.exe" --modules pe_rules,asm_disasm,runtime_sandbox_trace,fuzz_native
```
