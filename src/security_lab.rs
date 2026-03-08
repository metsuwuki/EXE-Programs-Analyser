use super::*;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SecurityLabTelemetry {
    pub(crate) enabled: bool,
    pub(crate) profile: String,
    pub(crate) custom_selection: bool,
    pub(crate) confirmation_required: bool,
    pub(crate) recommended_next_step: String,
    pub(crate) selected_modules: Vec<LabModuleState>,
    pub(crate) coverage: LabCoverage,
    pub(crate) notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LabModuleState {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) category: String,
    pub(crate) capabilities: Vec<String>,
    pub(crate) status: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LabCoverage {
    pub(crate) disassembly_signals: usize,
    pub(crate) symbolic_signals: usize,
    pub(crate) taint_paths: usize,
    pub(crate) business_risks: usize,
    pub(crate) fuzz_cases: usize,
    pub(crate) runtime_traces: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModuleStatus {
    Enabled,
    Disabled,
    Incompatible,
    NeedsConfirmation,
}

impl ModuleStatus {
    fn as_str(self) -> &'static str {
        match self {
            ModuleStatus::Enabled => "enabled",
            ModuleStatus::Disabled => "disabled",
            ModuleStatus::Incompatible => "incompatible",
            ModuleStatus::NeedsConfirmation => "needs_confirmation",
        }
    }

    fn marker(self) -> &'static str {
        match self {
            ModuleStatus::Enabled => "ON",
            ModuleStatus::Disabled => "OFF",
            ModuleStatus::Incompatible => "BLOCKED",
            ModuleStatus::NeedsConfirmation => "ASK",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ModuleDef {
    id: &'static str,
    title: &'static str,
    category: &'static str,
    capabilities: &'static [&'static str],
    default_standard: bool,
    default_aggressive: bool,
    requires_confirmation: bool,
    requires_libafl: bool,
    supports_executable: bool,
    supports_source: bool,
    description: &'static str,
}

const MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: "pe_rules",
        title: "PE Structural Rules",
        category: "PE",
        capabilities: &[
            "headers/sections integrity",
            "mitigations scoring",
            "overlay + import risk heuristics",
        ],
        default_standard: true,
        default_aggressive: true,
        requires_confirmation: false,
        requires_libafl: false,
        supports_executable: true,
        supports_source: false,
        description: "Deep executable structure validation and hardening checks.",
    },
    ModuleDef {
        id: "asm_disasm",
        title: "ASM Signature + Pseudo Disassembly",
        category: "ASM",
        capabilities: &[
            "opcode signature scan",
            "branch/call density sampling",
            "packer shellcode hints",
        ],
        default_standard: true,
        default_aggressive: true,
        requires_confirmation: false,
        requires_libafl: false,
        supports_executable: true,
        supports_source: false,
        description: "Instruction-level heuristics for shellcode/packer-like behavior.",
    },
    ModuleDef {
        id: "symbolic_pathing",
        title: "Symbolic Path Explorer",
        category: "Symbolic",
        capabilities: &[
            "branch complexity estimation",
            "path explosion hot spots",
            "high-risk condition hints",
        ],
        default_standard: false,
        default_aggressive: true,
        requires_confirmation: true,
        requires_libafl: false,
        supports_executable: true,
        supports_source: true,
        description: "Approximate symbolic path pressure over source or binary signals.",
    },
    ModuleDef {
        id: "taint_dataflow",
        title: "Dataflow + Taint",
        category: "Dataflow",
        capabilities: &[
            "source-to-sink mapping",
            "unsafe API propagation",
            "missing validation hotspots",
        ],
        default_standard: true,
        default_aggressive: true,
        requires_confirmation: false,
        requires_libafl: false,
        supports_executable: false,
        supports_source: true,
        description: "Tracks suspicious flows from untrusted input to dangerous sinks.",
    },
    ModuleDef {
        id: "runtime_sandbox_trace",
        title: "Runtime Sandbox Tracing",
        category: "Runtime",
        capabilities: &[
            "scenario trace timeline",
            "env policy capture",
            "stderr/stdout evidence snippets",
        ],
        default_standard: true,
        default_aggressive: true,
        requires_confirmation: false,
        requires_libafl: false,
        supports_executable: true,
        supports_source: false,
        description: "Collects structured telemetry from sandbox-like runtime scenarios.",
    },
    ModuleDef {
        id: "fuzz_native",
        title: "Native Fuzz Campaign",
        category: "Fuzzing",
        capabilities: &[
            "seed mutation scenarios",
            "unicode/ascii boundary stress",
            "crash and timeout surfacing",
        ],
        default_standard: true,
        default_aggressive: true,
        requires_confirmation: false,
        requires_libafl: false,
        supports_executable: true,
        supports_source: false,
        description: "Fast in-process fuzzing scenarios integrated with runtime checks.",
    },
    ModuleDef {
        id: "fuzz_libafl",
        title: "LibAFL Campaign",
        category: "Fuzzing",
        capabilities: &[
            "structured corpus mode",
            "coverage-guided seed strategy",
            "deeper stress profile",
        ],
        default_standard: false,
        default_aggressive: true,
        requires_confirmation: true,
        requires_libafl: true,
        supports_executable: true,
        supports_source: false,
        description: "Extended campaign that requires libafl engine feature in build.",
    },
    ModuleDef {
        id: "business_regression",
        title: "Business Logic Regression",
        category: "Regression",
        capabilities: &[
            "money-value risk patterns",
            "rounding precision checks",
            "critical path TODO/FIXME drift",
        ],
        default_standard: true,
        default_aggressive: true,
        requires_confirmation: false,
        requires_libafl: false,
        supports_executable: false,
        supports_source: true,
        description: "Static risk checks for logic that can break financial/business correctness.",
    },
];

pub(crate) fn print_module_catalog() {
    println!("=== Security-Lab Module Catalog ===");
    println!("Format: id | category | standard/aggressive defaults | key capabilities");
    for m in MODULES {
        println!(
            "- {} | {} | std={} agg={} | {}",
            m.id,
            m.category,
            if m.default_standard { "on" } else { "off" },
            if m.default_aggressive { "on" } else { "off" },
            m.capabilities.join("; ")
        );
        println!("  {}", m.description);
    }
    println!(
        "Use: --lab-profile <standard|aggressive> --modules <id1,id2,...> --confirm-extended-tests"
    );
}

pub(crate) fn build_telemetry(
    config: &Config,
    target_kind: TargetKind,
    bytes: &[u8],
    runtime: &[RunResult],
    findings: &mut Vec<Finding>,
) -> SecurityLabTelemetry {
    if !config.security_lab_enabled {
        findings.push(finding(
            Severity::Warn,
            "SECURITY_LAB_DISABLED",
            "security-lab",
            4,
            "Security-lab pipeline disabled by --no-security-lab.",
        ));
        return SecurityLabTelemetry {
            enabled: false,
            profile: config.lab_profile.as_str().to_string(),
            custom_selection: !config.custom_modules.is_empty(),
            confirmation_required: false,
            recommended_next_step: "Enable security-lab pipeline for advanced analysis".to_string(),
            selected_modules: Vec::new(),
            coverage: LabCoverage {
                disassembly_signals: 0,
                symbolic_signals: 0,
                taint_paths: 0,
                business_risks: 0,
                fuzz_cases: 0,
                runtime_traces: runtime.len(),
            },
            notes: vec!["security-lab disabled".to_string()],
        };
    }

    let mut notes = Vec::new();
    let mut selected_states = Vec::new();

    let requested_ids = requested_module_ids(config);
    let custom_selection = !config.custom_modules.is_empty();

    for custom in &config.custom_modules {
        if MODULES.iter().all(|m| m.id != custom) {
            findings.push(finding(
                Severity::Warn,
                "LAB_UNKNOWN_MODULE",
                "security-lab",
                3,
                format!("Unknown module '{}' requested in --modules.", custom),
            ));
            notes.push(format!("unknown module id ignored: {}", custom));
        }
    }

    for module in MODULES {
        let requested = requested_ids.iter().any(|id| *id == module.id);
        let (status, reason) = evaluate_module_status(module, requested, config, target_kind);
        selected_states.push(LabModuleState {
            id: module.id.to_string(),
            title: module.title.to_string(),
            category: module.category.to_string(),
            capabilities: module.capabilities.iter().map(|c| (*c).to_string()).collect(),
            status: status.as_str().to_string(),
            reason,
        });
    }

    let confirmation_required = selected_states
        .iter()
        .any(|m| m.status == ModuleStatus::NeedsConfirmation.as_str());

    if confirmation_required {
        findings.push(finding(
            Severity::Warn,
            "LAB_EXTRA_CONFIRMATION_REQUIRED",
            "security-lab",
            5,
            "Aggressive checks are pending confirmation. Re-run with --confirm-extended-tests to enable all advanced modules.",
        ));
    }

    let disassembly_signals = if is_module_enabled(&selected_states, "asm_disasm") {
        detect_disassembly_signals(bytes)
    } else {
        0
    };
    if disassembly_signals > 0 {
        findings.push(finding(
            Severity::Warn,
            "LAB_ASM_SIGNAL",
            "asm",
            8,
            format!("ASM layer detected {} suspicious instruction signatures.", disassembly_signals),
        ));
    }

    let symbolic_signals = if is_module_enabled(&selected_states, "symbolic_pathing") {
        detect_symbolic_signals(target_kind, bytes)
    } else {
        0
    };
    if symbolic_signals > 14 {
        findings.push(finding(
            Severity::Warn,
            "LAB_SYMBOLIC_COMPLEXITY",
            "symbolic",
            7,
            format!("Symbolic path pressure is high (score={}).", symbolic_signals),
        ));
    }

    let taint_paths = if is_module_enabled(&selected_states, "taint_dataflow") {
        detect_taint_paths(target_kind, bytes)
    } else {
        0
    };
    if taint_paths > 0 {
        findings.push(finding(
            Severity::Warn,
            "LAB_TAINT_PATHS",
            "dataflow",
            10,
            format!("Dataflow/taint layer found {} source-to-sink suspicious paths.", taint_paths),
        ));
    }

    let business_risks = if is_module_enabled(&selected_states, "business_regression") {
        detect_business_risks(target_kind, bytes)
    } else {
        0
    };
    if business_risks > 0 {
        findings.push(finding(
            Severity::Warn,
            "LAB_BUSINESS_RISK",
            "regression",
            9,
            format!("Business logic regression scanner found {} risky code patterns.", business_risks),
        ));
    }

    let fuzz_cases = runtime
        .iter()
        .filter(|r| r.scenario.contains("fuzz") || r.trace.scenario_kind == "fuzz")
        .count();

    let runtime_traces = runtime.iter().filter(|r| !r.trace.events.is_empty()).count();

    let enabled_count = selected_states
        .iter()
        .filter(|m| m.status == ModuleStatus::Enabled.as_str())
        .count();

    if enabled_count == 0 {
        findings.push(finding(
            Severity::Warn,
            "LAB_NO_MODULES_ACTIVE",
            "security-lab",
            6,
            "No security-lab modules are active; check profile, module list, and compatibility.",
        ));
    } else {
        findings.push(finding(
            Severity::Pass,
            "LAB_MODULES_ACTIVE",
            "security-lab",
            0,
            format!("Security-lab active modules: {}", enabled_count),
        ));
    }

    let recommended_next_step = if confirmation_required {
        "Question: run extended deep checks? Use --confirm-extended-tests to unlock ASK modules."
            .to_string()
    } else {
        "Use --modules <id1,id2> to customize enabled modules for your target type.".to_string()
    };

    SecurityLabTelemetry {
        enabled: true,
        profile: config.lab_profile.as_str().to_string(),
        custom_selection,
        confirmation_required,
        recommended_next_step,
        selected_modules: selected_states,
        coverage: LabCoverage {
            disassembly_signals,
            symbolic_signals,
            taint_paths,
            business_risks,
            fuzz_cases,
            runtime_traces,
        },
        notes,
    }
}

pub(crate) fn print_module_info(telemetry: &SecurityLabTelemetry) {
    println!();
    println!("=== Security-Lab Modules ===");
    println!(
        "Profile={} | custom={} | confirmation_required={}",
        telemetry.profile, telemetry.custom_selection, telemetry.confirmation_required
    );
    for module in &telemetry.selected_modules {
        let marker = match module.status.as_str() {
            "enabled" => ModuleStatus::Enabled.marker(),
            "disabled" => ModuleStatus::Disabled.marker(),
            "incompatible" => ModuleStatus::Incompatible.marker(),
            "needs_confirmation" => ModuleStatus::NeedsConfirmation.marker(),
            _ => "OFF",
        };
        println!(
            "[{}] {} ({}) -> {} | caps: {}",
            marker,
            module.id,
            module.category,
            module.reason,
            module.capabilities.join("; ")
        );
    }
    println!("Security-Lab next step: {}", telemetry.recommended_next_step);
}

fn requested_module_ids(config: &Config) -> Vec<&'static str> {
    if !config.custom_modules.is_empty() {
        return MODULES
            .iter()
            .filter(|m| config.custom_modules.iter().any(|custom| custom == m.id))
            .map(|m| m.id)
            .collect();
    }

    MODULES
        .iter()
        .filter(|m| match config.lab_profile {
            SecurityLabProfile::Standard => m.default_standard,
            SecurityLabProfile::Aggressive => m.default_aggressive,
        })
        .map(|m| m.id)
        .collect()
}

fn evaluate_module_status(
    module: &ModuleDef,
    requested: bool,
    config: &Config,
    target_kind: TargetKind,
) -> (ModuleStatus, String) {
    if !requested {
        return (ModuleStatus::Disabled, "not selected by profile/custom list".to_string());
    }

    let supports_target = match target_kind {
        TargetKind::Executable => module.supports_executable,
        TargetKind::Source(_) => module.supports_source,
        TargetKind::Unknown => module.supports_source || module.supports_executable,
    };
    if !supports_target {
        return (
            ModuleStatus::Incompatible,
            format!("not compatible with target type {}", target_kind.as_str()),
        );
    }

    if module.requires_libafl && config.fuzz_engine != FuzzEngine::LibAfl {
        return (
            ModuleStatus::Incompatible,
            "requires --fuzz-engine libafl".to_string(),
        );
    }

    if module.requires_confirmation && !config.confirm_extended_tests {
        return (
            ModuleStatus::NeedsConfirmation,
            "requires explicit confirmation (--confirm-extended-tests)".to_string(),
        );
    }

    (ModuleStatus::Enabled, "active".to_string())
}

fn is_module_enabled(states: &[LabModuleState], id: &str) -> bool {
    states
        .iter()
        .any(|state| state.id == id && state.status == ModuleStatus::Enabled.as_str())
}

fn detect_disassembly_signals(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }

    let mut signals = 0;
    let sample = bytes.len().min(1_500_000);
    let view = &bytes[..sample];

    for win in view.windows(2) {
        if matches!(win, [0xCD, 0x80] | [0x0F, 0x05] | [0xFF, 0xE0] | [0xFF, 0xE4]) {
            signals += 1;
        }
    }

    let mut call_jmp_density = 0;
    for b in view {
        if matches!(*b, 0xE8 | 0xE9 | 0xEB | 0xC3 | 0xC2) {
            call_jmp_density += 1;
        }
    }

    if call_jmp_density > 5000 {
        signals += 1;
    }

    signals
}

fn detect_symbolic_signals(target_kind: TargetKind, bytes: &[u8]) -> usize {
    match target_kind {
        TargetKind::Executable => {
            let sample = bytes.len().min(1_500_000);
            let view = &bytes[..sample];
            let mut score = 0;
            for b in view {
                if (*b >= 0x70 && *b <= 0x7F) || matches!(*b, 0xE3 | 0x0F) {
                    score += 1;
                }
            }
            score / 1500
        }
        TargetKind::Source(_) | TargetKind::Unknown => {
            if !looks_mostly_text(bytes) {
                return 0;
            }
            let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
            let tokens = [" if ", " else", " match ", " switch", " try", " catch", " while", " for "];
            tokens.iter().map(|t| text.matches(t).count()).sum::<usize>()
        }
    }
}

fn detect_taint_paths(target_kind: TargetKind, bytes: &[u8]) -> usize {
    if target_kind == TargetKind::Executable || !looks_mostly_text(bytes) {
        return 0;
    }

    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let source_tokens = ["input", "request", "argv", "stdin", "query", "body", "params"];
    let sink_tokens = ["exec", "system", "sql", "write", "serialize", "eval", "process.start"];

    let mut paths = 0;
    for line in text.lines() {
        let has_source = source_tokens.iter().any(|t| line.contains(t));
        let has_sink = sink_tokens.iter().any(|t| line.contains(t));
        if has_source && has_sink {
            paths += 1;
        }
    }
    paths
}

fn detect_business_risks(target_kind: TargetKind, bytes: &[u8]) -> usize {
    if target_kind == TargetKind::Executable || !looks_mostly_text(bytes) {
        return 0;
    }

    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let risk_pairs = [
        ("balance", "float"),
        ("amount", "f64"),
        ("price", "double"),
        ("invoice", "round("),
        ("money", "todo"),
    ];

    risk_pairs
        .iter()
        .filter(|(left, right)| text.contains(left) && text.contains(right))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_config() -> Config {
        Config {
            exe_path: PathBuf::from("dummy.exe"),
            timeout_secs: 3,
            runs: 3,
            out_dir: PathBuf::from("logs"),
            mode: ScanMode::Strict,
            fuzz_engine: FuzzEngine::Native,
            security_lab_enabled: true,
            lab_profile: SecurityLabProfile::Standard,
            custom_modules: Vec::new(),
            confirm_extended_tests: false,
            list_lab_modules: false,
        }
    }

    #[test]
    fn aggressive_profile_marks_confirmation_modules() {
        let mut cfg = mk_config();
        cfg.lab_profile = SecurityLabProfile::Aggressive;

        let mut findings = Vec::new();
        let telemetry = build_telemetry(&cfg, TargetKind::Executable, b"MZ...", &[], &mut findings);

        let symbolic = telemetry
            .selected_modules
            .iter()
            .find(|m| m.id == "symbolic_pathing")
            .expect("symbolic_pathing module should exist");
        assert_eq!(symbolic.status, "needs_confirmation");
    }

    #[test]
    fn source_target_blocks_executable_only_modules() {
        let cfg = mk_config();

        let mut findings = Vec::new();
        let telemetry = build_telemetry(
            &cfg,
            TargetKind::Source(SourceLanguage::Python),
            b"print('ok')",
            &[],
            &mut findings,
        );

        let pe_rules = telemetry
            .selected_modules
            .iter()
            .find(|m| m.id == "pe_rules")
            .expect("pe_rules module should exist");
        assert_eq!(pe_rules.status, "incompatible");
    }

    #[test]
    fn custom_module_selection_enables_only_requested() {
        let mut cfg = mk_config();
        cfg.custom_modules = vec!["taint_dataflow".to_string()];

        let mut findings = Vec::new();
        let telemetry = build_telemetry(
            &cfg,
            TargetKind::Source(SourceLanguage::Go),
            b"input := os.Stdin; exec.Command(input)",
            &[],
            &mut findings,
        );

        let enabled_ids: Vec<&str> = telemetry
            .selected_modules
            .iter()
            .filter(|m| m.status == "enabled")
            .map(|m| m.id.as_str())
            .collect();

        assert_eq!(enabled_ids, vec!["taint_dataflow"]);
    }
}
