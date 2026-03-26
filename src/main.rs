use goblin::pe::PE;
use anyhow::Context;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod runtime_checks;
mod preflight;
mod security_lab;
mod cli;
mod teacher_audit;

// Re-export shared types from the library crate so sub-modules can access
// them via `use super::*;` without any #[path] hacks.
pub use exe_tester::shared::{AnalysisMode, ScanMode, Severity,
    Finding, Report, RunResult, RuntimeTrace, RuntimeTraceEvent,
    SandboxProfile, PowerProfile, SecurityLabProfile, ReportSummaryBlock,
    RuntimeSummary, SeveritySummary, ReportArtifacts, StaticAnalysisArtifacts,
    PeArtifacts, PeSectionArtifact, ImportArtifacts, MitigationArtifacts,
    StringsArtifacts, SourceArtifacts};
pub use exe_tester::core::{PowerProfileDefaults, power_profile_defaults, parse_power_profile};

#[derive(Debug, Clone)]
struct Config {
    exe_path: PathBuf,
    assignment_path: Option<PathBuf>,
    audit_dir: Option<PathBuf>,
    power_profile: PowerProfile,
    timeout_secs: u64,
    runs: u32,
    only_scenario: Option<String>,
    sandbox_profile: SandboxProfile,
    out_dir: PathBuf,
    analysis_mode: AnalysisMode,
    mode: ScanMode,
    fuzz_engine: FuzzEngine,
    security_lab_enabled: bool,
    lab_profile: SecurityLabProfile,
    custom_modules: Vec<String>,
    confirm_extended_tests: bool,
    list_lab_modules: bool,
    list_scenarios: bool,
    export_md: bool,
    export_html: bool,
}

struct ReportOutputs {
    full_log: PathBuf,
    issues_log: PathBuf,
    json_log: PathBuf,
    md_log: Option<PathBuf>,
    html_log: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FuzzEngine {
    Native,
    LibAfl,
}

impl FuzzEngine {
    fn as_str(self) -> &'static str {
        match self {
            FuzzEngine::Native => "native",
            FuzzEngine::LibAfl => "libafl",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceLanguage {
    CSharp,
    Java,
    Python,
    Go,
    JavaScript,
    TypeScript,
    Kotlin,
    Swift,
    Ruby,
    Php,
    Lua,
}

impl SourceLanguage {
    fn as_str(self) -> &'static str {
        match self {
            SourceLanguage::CSharp => "C#",
            SourceLanguage::Java => "Java",
            SourceLanguage::Python => "Python",
            SourceLanguage::Go => "Go",
            SourceLanguage::JavaScript => "JavaScript",
            SourceLanguage::TypeScript => "TypeScript",
            SourceLanguage::Kotlin => "Kotlin",
            SourceLanguage::Swift => "Swift",
            SourceLanguage::Ruby => "Ruby",
            SourceLanguage::Php => "PHP",
            SourceLanguage::Lua => "Lua",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Executable,
    Source(SourceLanguage),
    Unknown,
}

impl TargetKind {
    fn as_str(self) -> &'static str {
        match self {
            TargetKind::Executable => "Executable",
            TargetKind::Source(_) => "Source",
            TargetKind::Unknown => "Unknown",
        }
    }
}

fn main() {
    match cli::parse_args(env::args().collect()) {
        Ok(config) => run(config),
        Err(msg) => {
            eprintln!("{}", msg);
            eprintln!(
                "Usage: exe_tester <path_to_target> [--assignment <path.json>] [--audit-dir <folder>] [--power-profile <BASIC|AUDIT|PENTEST|EXTREME>] [--timeout <sec>] [--runs <count>] [--only-scenario <name>] [--sandbox-profile <none|limited|isolated>] [--out-dir <path>] [--export-format <json|md|html|both>] [--export-md] [--export-html] [--mode <min|pentest>] [--mode-min|--mode-pentest] [--strict|--balanced] [--fuzz-engine <native|libafl>] [--lab-profile <standard|aggressive>] [--modules <id1,id2,...>] [--confirm-extended-tests] [--list-lab-modules] [--list-scenarios] [--no-security-lab]"
            );
            std::process::exit(64);
        }
    }
}

fn run(config: Config) {
    let mut assignment_spec = None;
    if let Some(path) = &config.assignment_path {
        match teacher_audit::load_assignment(path) {
            Ok(spec) => {
                println!("[TEACHER/AUDIT] Assignment loaded: {}", path.display());
                println!(
                    "[TEACHER/AUDIT] id={} | title={} | targets={} | required_modules={}",
                    spec.id,
                    spec.title,
                    spec.targets.len(),
                    spec.policy.required_modules.len()
                );
                if let Err(err) = teacher_audit::validate_runtime_config(&spec, &config) {
                    eprintln!("[TEACHER/AUDIT] Assignment policy mismatch: {err}");
                    std::process::exit(65);
                }
                assignment_spec = Some(spec);
            }
            Err(err) => {
                eprintln!("[TEACHER/AUDIT] Invalid assignment: {err}");
                std::process::exit(65);
            }
        }
    }

    if let (Some(spec), Some(audit_dir)) = (assignment_spec.as_ref(), config.audit_dir.as_ref()) {
        println!("[TEACHER/AUDIT] Starting batch run in {}", audit_dir.display());
        match teacher_audit::run_batch_audit(&config, spec, audit_dir) {
            Ok(batch) => {
                println!("[TEACHER/AUDIT] Batch finished: total={} pass={} warn={} fail={}", batch.total, batch.pass, batch.warn, batch.fail);
                println!("[TEACHER/AUDIT] Summary JSON: {}", batch.summary_json);
                println!("[TEACHER/AUDIT] Summary CSV:  {}", batch.summary_csv);
                println!("[TEACHER/AUDIT] Rerun CMD:    {}", batch.rerun_script);
                if batch.fail > 0 {
                    std::process::exit(2);
                }
                if batch.warn > 0 {
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!("[TEACHER/AUDIT] Batch failed: {err}");
                std::process::exit(66);
            }
        }
    }

    let target_kind = detect_target_kind(&config.exe_path);

    if config.list_lab_modules {
        security_lab::print_module_catalog();
        return;
    }
    if config.list_scenarios {
        runtime_checks::print_scenario_catalog(&config);
        return;
    }

    let mut findings = Vec::new();
    let mut artifacts = ReportArtifacts {
        target_kind: target_kind.as_str().to_string(),
        file_size_bytes: 0,
        static_analysis: StaticAnalysisArtifacts::default(),
    };
    println!("=== Metsuki Analyzer (Rust) ===");
    println!("Target: {}", config.exe_path.display());
    println!("TargetType: {}", target_kind.as_str());
    println!(
        "AnalysisMode: {} | VerdictMode: {} | PowerProfile: {} | Timeout: {} sec | Runs: {} | Sandbox: {} | OutDir: {} | FuzzEngine: {}",
        config.analysis_mode.as_str(),
        config.mode.as_str(),
        config.power_profile.as_str(),
        config.timeout_secs,
        config.runs,
        config.sandbox_profile.as_str(),
        config.out_dir.display(),
        config.fuzz_engine.as_str()
    );
    println!(
        "SecurityLab: {} | Profile: {} | CustomModules: {} | ConfirmExtended: {}",
        if config.security_lab_enabled {
            "enabled"
        } else {
            "disabled"
        },
        config.lab_profile.as_str(),
        if config.custom_modules.is_empty() {
            "<profile defaults>".to_string()
        } else {
            config.custom_modules.join(",")
        },
        config.confirm_extended_tests
    );
    println!();
    println!("[PHASE 1/4] static analysis");

    let bytes = match preflight::preflight_and_load(&config.exe_path, target_kind, &mut findings) {
        Ok(data) => data,
        Err(_) => {
            let runtime = Vec::new();
            let telemetry =
                security_lab::build_telemetry(&config, target_kind, &[], &runtime, &mut findings);
            security_lab::print_module_info(&telemetry);
            let (score, final_status) = score_and_status(&config, &findings);
            emit_and_exit(&config, findings, runtime, telemetry, artifacts, score, final_status);
            return;
        }
    };
    artifacts.file_size_bytes = bytes.len();

    match target_kind {
        TargetKind::Executable => {
            artifacts.static_analysis.pe = run_pe_static_checks(&bytes, &config, &mut findings);
            artifacts.static_analysis.strings = Some(run_string_checks(&bytes, &mut findings));
        }
        TargetKind::Source(lang) => {
            artifacts.static_analysis.source = Some(run_source_static_checks(
                &config.exe_path,
                &bytes,
                Some(lang),
                &mut findings,
            ));
        }
        TargetKind::Unknown => {
            artifacts.static_analysis.source = Some(run_source_static_checks(
                &config.exe_path,
                &bytes,
                None,
                &mut findings,
            ));
        }
    }

    println!("[PHASE 2/4] runtime / behavior checks");
    let runtime = if target_kind == TargetKind::Executable {
        runtime_checks::run_runtime_checks(&config, &mut findings)
    } else {
        findings.push(finding(
            Severity::Pass,
            "RUNTIME_SKIPPED_SOURCE",
            "runtime",
            0,
            "Runtime stress scenarios are skipped for source files.",
        ));
        Vec::new()
    };

    println!("[PHASE 3/4] security-lab analysis");
    let telemetry =
        security_lab::build_telemetry(&config, target_kind, &bytes, &runtime, &mut findings);
    security_lab::print_module_info(&telemetry);

    println!("[PHASE 4/4] report generation");
    let (score, final_status) = score_and_status(&config, &findings);
    emit_and_exit(&config, findings, runtime, telemetry, artifacts, score, final_status);
}

fn finding(
    severity: Severity,
    code: &'static str,
    category: &'static str,
    points: u32,
    message: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        code,
        category,
        points,
        message: message.into(),
    }
}

fn detect_target_kind(path: &Path) -> TargetKind {
    let info = exe_tester::core::detect_target_type(path);
    match info.kind.as_str() {
        "executable" => TargetKind::Executable,
        "source" => {
            let lang = match info.language.as_deref().unwrap_or("") {
                "csharp" => SourceLanguage::CSharp,
                "java" => SourceLanguage::Java,
                "python" => SourceLanguage::Python,
                "go" => SourceLanguage::Go,
                "javascript" => SourceLanguage::JavaScript,
                "typescript" => SourceLanguage::TypeScript,
                "kotlin" => SourceLanguage::Kotlin,
                "swift" => SourceLanguage::Swift,
                "ruby" => SourceLanguage::Ruby,
                "php" => SourceLanguage::Php,
                "lua" => SourceLanguage::Lua,
                _ => return TargetKind::Unknown,
            };
            TargetKind::Source(lang)
        }
        _ => TargetKind::Unknown,
    }
}

fn run_pe_static_checks(
    bytes: &[u8],
    config: &Config,
    findings: &mut Vec<Finding>,
) -> Option<PeArtifacts> {
    if bytes.len() < 2 || &bytes[0..2] != b"MZ" {
        findings.push(finding(
            Severity::Fail,
            "MZ_SIGNATURE_MISSING",
            "pe",
            35,
            "DOS MZ signature missing.",
        ));
        return None;
    }

    let pe = match PE::parse(bytes) {
        Ok(pe) => pe,
        Err(e) => {
            findings.push(finding(
                Severity::Fail,
                "PE_PARSE_FAILED",
                "pe",
                45,
                format!("PE parse failed: {}", e),
            ));
            return None;
        }
    };

    findings.push(finding(
        Severity::Pass,
        "PE_PARSE_OK",
        "pe",
        0,
        "PE headers parsed successfully.",
    ));

    findings.push(finding(
        Severity::Pass,
        "ARCH",
        "pe",
        0,
        if pe.is_64 {
            "Architecture: x64"
        } else {
            "Architecture: x86"
        },
    ));

    if pe.is_lib {
        findings.push(finding(
            Severity::Warn,
            "PE_IS_DLL",
            "pe",
            5,
            "Target appears to be a DLL, not a standalone EXE.",
        ));
    }

    let section_count = pe.sections.len();
    if section_count < 3 {
        findings.push(finding(
            Severity::Warn,
            "FEW_SECTIONS",
            "pe",
            6,
            format!("Low section count: {}", section_count),
        ));
    }

    let mut rwx_sections = Vec::new();
    let mut section_artifacts = Vec::with_capacity(pe.sections.len());
    let mut high_entropy_sections = Vec::new();
    for sec in &pe.sections {
        let chars = sec.characteristics;
        let is_read = (chars & 0x4000_0000) != 0;
        let is_exec = (chars & 0x2000_0000) != 0;
        let is_write = (chars & 0x8000_0000) != 0;
        let start = sec.pointer_to_raw_data as usize;
        let size = sec.size_of_raw_data as usize;
        let entropy = if size > 0 {
            start
                .checked_add(size)
                .filter(|end| *end <= bytes.len())
                .map(|end| shannon_entropy(&bytes[start..end]))
                .unwrap_or(0.0)
        } else {
            0.0
        };

        if is_exec && is_write {
            rwx_sections.push(section_name(sec.name()));
        }
        let name = section_name(sec.name());
        if entropy >= 7.2 {
            high_entropy_sections.push((name.clone(), entropy));
        }
        section_artifacts.push(PeSectionArtifact {
            name,
            virtual_size: sec.virtual_size,
            raw_size: sec.size_of_raw_data,
            entropy,
            readable: is_read,
            writable: is_write,
            executable: is_exec,
        });
    }
    if !rwx_sections.is_empty() {
        findings.push(finding(
            Severity::Fail,
            "RWX_SECTIONS",
            "pe",
            30,
            format!("Executable+Writable sections found: {}", rwx_sections.join(", ")),
        ));
    }

    if !high_entropy_sections.is_empty() {
        let details = high_entropy_sections
            .iter()
            .map(|(name, ent)| format!("{}={:.2}", name, ent))
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(finding(
            Severity::Warn,
            "HIGH_ENTROPY_SECTIONS",
            "pe",
            12,
            format!("Potential packing/obfuscation: {}", details),
        ));
    }

    let mut entry_point_rva = None;
    if let Some(optional) = pe.header.optional_header {
        let entry_rva = optional.standard_fields.address_of_entry_point;
        entry_point_rva = Some(entry_rva);
        let mut entry_in_exec_section = false;
        for sec in &pe.sections {
            let start = sec.virtual_address as u64;
            let size = sec.virtual_size.max(sec.size_of_raw_data) as u64;
            let end = start.saturating_add(size);
            let is_exec = (sec.characteristics & 0x2000_0000) != 0;
            if entry_rva >= start && entry_rva < end && is_exec {
                entry_in_exec_section = true;
                break;
            }
        }
        if entry_in_exec_section {
            findings.push(finding(
                Severity::Pass,
                "ENTRYPOINT_EXEC_SECTION",
                "pe",
                0,
                format!("Entrypoint RVA 0x{entry_rva:08X} is inside executable section."),
            ));
        } else {
            findings.push(finding(
                Severity::Fail,
                "ENTRYPOINT_SUSPICIOUS",
                "pe",
                25,
                format!("Entrypoint RVA 0x{entry_rva:08X} is outside executable section bounds."),
            ));
        }
    }

    if pe.imports.is_empty() {
        findings.push(finding(
            Severity::Warn,
            "NO_IMPORTS",
            "imports",
            14,
            "No imports found; this can indicate static linking, packing, or malformed metadata.",
        ));
    }

    let suspicious_imports = [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
    ];

    let mut matched = Vec::new();
    for imp in &pe.imports {
        if suspicious_imports
            .iter()
            .any(|x| x.eq_ignore_ascii_case(&imp.name))
        {
            matched.push(imp.name.to_string());
        }
    }

    if matched.is_empty() {
        findings.push(finding(
            Severity::Pass,
            "IMPORTS_NO_HIGH_RISK_MATCH",
            "imports",
            0,
            "No high-risk API imports from the default suspicious list.",
        ));
    } else {
        matched.sort();
        matched.dedup();
        findings.push(finding(
            Severity::Warn,
            "SUSPICIOUS_IMPORTS",
            "imports",
            18,
            format!("High-risk imports found: {}", matched.join(", ")),
        ));
    }

    match pe_certificate_table_size(bytes) {
        Some(size) if size > 0 => findings.push(finding(
            Severity::Pass,
            "SIGNATURE_PRESENT",
            "signature",
            0,
            format!("Authenticode certificate table detected ({} bytes).", size),
        )),
        _ => {
            let sev = if config.mode == ScanMode::Strict {
                Severity::Fail
            } else {
                Severity::Warn
            };
            findings.push(finding(
                sev,
                "SIGNATURE_UNSIGNED",
                "signature",
                10,
                "Authenticode certificate table is missing; file appears unsigned.",
            ));
        }
    }

    let mut overlay_bytes = 0_u64;
    if let Some(last) = pe.sections.iter().max_by_key(|s| s.pointer_to_raw_data.saturating_add(s.size_of_raw_data)) {
        let end_of_sections = last.pointer_to_raw_data as usize + last.size_of_raw_data as usize;
        if bytes.len() > end_of_sections {
            let overlay = bytes.len() - end_of_sections;
            overlay_bytes = overlay as u64;
            if overlay > 4096 {
                let sev = if config.mode == ScanMode::Strict {
                    Severity::Fail
                } else {
                    Severity::Warn
                };
                findings.push(finding(
                    sev,
                    "LARGE_OVERLAY",
                    "pe",
                    20,
                    format!("Large overlay data after last section: {} bytes", overlay),
                ));
            }
        }
    }

    let timestamp = pe.header.coff_header.time_date_stamp;
    if timestamp == 0 {
        findings.push(finding(
            Severity::Warn,
            "ZERO_TIMESTAMP",
            "pe",
            8,
            "COFF timestamp is zero (possibly tampered/reproducible build/stripped).",
        ));
    }

    let chars = pe.header.optional_header.map(|h| h.windows_fields.dll_characteristics).unwrap_or(0);
    let nx_compat = (chars & 0x0100) != 0;
    let aslr = (chars & 0x0040) != 0;
    let cfg = (chars & 0x4000) != 0;

    if nx_compat {
        findings.push(finding(Severity::Pass, "NX_COMPAT", "mitigations", 0, "DEP/NX is enabled."));
    } else {
        findings.push(finding(Severity::Warn, "NX_MISSING", "mitigations", 10, "DEP/NX mitigation is not enabled."));
    }

    if aslr {
        findings.push(finding(Severity::Pass, "ASLR_ENABLED", "mitigations", 0, "ASLR is enabled."));
    } else {
        findings.push(finding(Severity::Warn, "ASLR_MISSING", "mitigations", 10, "ASLR mitigation is not enabled."));
    }

    if cfg {
        findings.push(finding(Severity::Pass, "CFG_ENABLED", "mitigations", 0, "Control Flow Guard appears enabled."));
    } else {
        findings.push(finding(Severity::Warn, "CFG_MISSING", "mitigations", 7, "Control Flow Guard is not enabled."));
    }

    Some(PeArtifacts {
        arch: if pe.is_64 {
            "x64".to_string()
        } else {
            "x86".to_string()
        },
        is_dll: pe.is_lib,
        section_count,
        entry_point_rva,
        sections: section_artifacts,
        imports: ImportArtifacts {
            total: pe.imports.len(),
            suspicious: matched,
        },
        mitigations: MitigationArtifacts {
            dep: nx_compat,
            aslr,
            cfg,
        },
        overlay_bytes,
        certificate_table_bytes: pe_certificate_table_size(bytes).unwrap_or(0),
        coff_timestamp: timestamp,
    })
}

fn section_name(raw: Result<&str, goblin::error::Error>) -> String {
    match raw {
        Ok(name) => name.to_string(),
        Err(_) => "<unknown>".to_string(),
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0_u64; 256];
    for b in data {
        counts[*b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn pe_certificate_table_size(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 0x40 {
        return None;
    }

    let pe_offset = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    if pe_offset.checked_add(0x18)? >= bytes.len() {
        return None;
    }

    let opt_offset = pe_offset + 4 + 20;
    if opt_offset.checked_add(2)? > bytes.len() {
        return None;
    }
    let magic = u16::from_le_bytes([bytes[opt_offset], bytes[opt_offset + 1]]);
    let data_dir_base = match magic {
        0x10B => opt_offset + 96,
        0x20B => opt_offset + 112,
        _ => return None,
    };

    let cert_entry = data_dir_base + (4 * 8);
    if cert_entry.checked_add(8)? > bytes.len() {
        return None;
    }

    let _file_offset = u32::from_le_bytes([
        bytes[cert_entry],
        bytes[cert_entry + 1],
        bytes[cert_entry + 2],
        bytes[cert_entry + 3],
    ]);
    let size = u32::from_le_bytes([
        bytes[cert_entry + 4],
        bytes[cert_entry + 5],
        bytes[cert_entry + 6],
        bytes[cert_entry + 7],
    ]);

    Some(size)
}

fn run_string_checks(bytes: &[u8], findings: &mut Vec<Finding>) -> StringsArtifacts {
    let strings = extract_ascii_strings(bytes, 6);

    let suspicious_tokens = [
        "powershell",
        "cmd.exe",
        "-enc",
        "http://",
        "https://",
        "reg add",
        "schtasks",
        "vssadmin",
        "bcdedit",
        "\"runas\"",
    ];

    let mut hits = Vec::new();
    for s in &strings {
        let lower = s.to_ascii_lowercase();
        if suspicious_tokens.iter().any(|t| lower.contains(t)) {
            let compact = s
                .chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
                .trim()
                .to_string();
            if !compact.is_empty() {
                hits.push(truncate_middle(&compact, 90));
            }
            if hits.len() >= 5 {
                break;
            }
        }
    }

    hits.sort();
    hits.dedup();

    if hits.is_empty() {
        findings.push(finding(
            Severity::Pass,
            "STRINGS_NO_SUSPICIOUS_HIT",
            "strings",
            0,
            "No suspicious command/network string patterns from default rules.",
        ));
    } else {
        findings.push(finding(
            Severity::Warn,
            "SUSPICIOUS_STRINGS",
            "strings",
            12,
            format!("Potentially dangerous strings: {}", hits.join(" | ")),
        ));
    }

    StringsArtifacts {
        total_strings_scanned: strings.len(),
        suspicious_hits: hits,
    }
}

fn run_source_static_checks(
    path: &Path,
    bytes: &[u8],
    language: Option<SourceLanguage>,
    findings: &mut Vec<Finding>,
) -> SourceArtifacts {
    let lang_name = language.map(|l| l.as_str()).unwrap_or("Generic source");
    let mostly_text = looks_mostly_text(bytes);

    findings.push(finding(
        Severity::Pass,
        "SOURCE_ANALYSIS_MODE",
        "source",
        0,
        format!("Running source analysis mode for {}", lang_name),
    ));

    if !mostly_text {
        findings.push(finding(
            Severity::Warn,
            "SOURCE_NOT_TEXT_LIKE",
            "source",
            8,
            "Input does not look like plain text source; results may be unreliable.",
        ));
    }

    let text = String::from_utf8_lossy(bytes).to_string();
    let line_count = text.lines().count().max(1);
    findings.push(finding(
        Severity::Pass,
        "SOURCE_SIZE_INFO",
        "source",
        0,
        format!(
            "{} file: {} lines, {} bytes ({})",
            lang_name,
            line_count,
            bytes.len(),
            path.display()
        ),
    ));

    if line_count < 3 {
        findings.push(finding(
            Severity::Warn,
            "SOURCE_TOO_SMALL",
            "source",
            3,
            "Source has very few lines; static checks are limited.",
        ));
    }

    if bytes.len() > 900_000 {
        findings.push(finding(
            Severity::Warn,
            "SOURCE_VERY_LARGE",
            "source",
            6,
            format!("Very large source file ({} bytes).", bytes.len()),
        ));
    }

    let mut suspicious_hits = collect_source_suspicious_hits(&text, language);
    suspicious_hits.sort();
    suspicious_hits.dedup();

    if suspicious_hits.is_empty() {
        findings.push(finding(
            Severity::Pass,
            "SOURCE_NO_SUSPICIOUS_PATTERN",
            "source",
            0,
            "No suspicious source patterns from current heuristic rules.",
        ));
    } else {
        let listed = suspicious_hits
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(finding(
            Severity::Warn,
            "SOURCE_SUSPICIOUS_PATTERN",
            "source",
            12,
            format!("Suspicious patterns detected: {}", listed),
        ));
    }

    let long_lines = text.lines().filter(|line| line.chars().count() > 180).count();
    if long_lines > 0 {
        findings.push(finding(
            Severity::Warn,
            "SOURCE_LONG_LINES",
            "source",
            3,
            format!("Found {} very long lines (>180 chars).", long_lines),
        ));
    }

    let unbalanced_delimiters = has_unbalanced_delimiters(&text);
    if unbalanced_delimiters {
        findings.push(finding(
            Severity::Warn,
            "SOURCE_UNBALANCED_DELIMITERS",
            "source",
            7,
            "Potentially unbalanced (), {}, [] delimiters.",
        ));
    } else {
        findings.push(finding(
            Severity::Pass,
            "SOURCE_DELIMITERS_OK",
            "source",
            0,
            "Basic delimiter balance check passed.",
        ));
    }

    let lower = text.to_ascii_lowercase();
    if lower.contains("todo") || lower.contains("fixme") {
        findings.push(finding(
            Severity::Warn,
            "SOURCE_TODO_FIXME",
            "source",
            2,
            "Source contains TODO/FIXME markers.",
        ));
    }

    SourceArtifacts {
        language: lang_name.to_string(),
        line_count,
        mostly_text,
        long_lines,
        unbalanced_delimiters,
        suspicious_hits,
    }
}

fn looks_mostly_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    let printable = bytes
        .iter()
        .filter(|b| matches!(**b, b'\n' | b'\r' | b'\t' | 0x20..=0x7E))
        .count();
    let ratio = printable as f64 / bytes.len() as f64;
    ratio >= 0.70
}

fn has_unbalanced_delimiters(text: &str) -> bool {
    let mut paren = 0_i32;
    let mut braces = 0_i32;
    let mut brackets = 0_i32;

    for ch in text.chars() {
        match ch {
            '(' => paren += 1,
            ')' => paren -= 1,
            '{' => braces += 1,
            '}' => braces -= 1,
            '[' => brackets += 1,
            ']' => brackets -= 1,
            _ => {}
        }

        if paren < 0 || braces < 0 || brackets < 0 {
            return true;
        }
    }

    paren != 0 || braces != 0 || brackets != 0
}

fn collect_source_suspicious_hits(text: &str, language: Option<SourceLanguage>) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut hits = Vec::new();

    let generic_tokens = [
        "eval(",
        "exec(",
        "system(",
        "shell",
        "download",
        "http://",
        "https://",
        "socket",
        "deserialize",
    ];
    push_matched_tokens(&mut hits, &lower, &generic_tokens);

    match language {
        Some(SourceLanguage::Python) => {
            let tokens = [
                "os.system(",
                "subprocess.",
                "pickle.loads(",
                "yaml.load(",
                "eval(",
                "exec(",
            ];
            push_matched_tokens(&mut hits, &lower, &tokens);
        }
        Some(SourceLanguage::Java) => {
            let tokens = [
                "runtime.getruntime().exec",
                "processbuilder(",
                "setaccessible(true)",
                "class.forname(",
            ];
            push_matched_tokens(&mut hits, &lower, &tokens);
        }
        Some(SourceLanguage::CSharp) => {
            let tokens = [
                "process.start(",
                "assembly.load(",
                "dllimport",
                "webclient(",
                "binaryformatter",
            ];
            push_matched_tokens(&mut hits, &lower, &tokens);
        }
        Some(SourceLanguage::Go) => {
            let tokens = ["exec.command(", "os/exec", "unsafe.", "syscall."];
            push_matched_tokens(&mut hits, &lower, &tokens);
        }
        Some(SourceLanguage::JavaScript) | Some(SourceLanguage::TypeScript) => {
            let tokens = ["child_process", "eval(", "function(", "fetch(", "xmlhttprequest"];
            push_matched_tokens(&mut hits, &lower, &tokens);
        }
        _ => {}
    }

    hits
}

fn push_matched_tokens(hits: &mut Vec<String>, lower: &str, tokens: &[&str]) {
    for token in tokens {
        if lower.contains(token) {
            hits.push((*token).to_string());
        }
    }
}

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();

    for b in data {
        if b.is_ascii_graphic() || *b == b' ' {
            current.push(*b);
        } else {
            if current.len() >= min_len {
                result.push(String::from_utf8_lossy(&current).to_string());
            }
            current.clear();
        }
    }

    if current.len() >= min_len {
        result.push(String::from_utf8_lossy(&current).to_string());
    }

    result
}

fn score_and_status(config: &Config, findings: &[Finding]) -> (u32, Severity) {
    let score: u32 = findings.iter().map(|f| f.points).sum();
    let has_fail = findings.iter().any(|f| f.severity == Severity::Fail);
    let has_warn = findings.iter().any(|f| f.severity == Severity::Warn);

    let final_status = match config.mode {
        ScanMode::Strict => {
            if has_fail || has_warn {
                Severity::Fail
            } else {
                Severity::Pass
            }
        }
        ScanMode::Balanced => {
            if has_fail || score >= 90 {
                Severity::Fail
            } else if has_warn || score >= 20 {
                Severity::Warn
            } else {
                Severity::Pass
            }
        }
    };

    (score, final_status)
}

fn summarize_findings(findings: &[Finding]) -> SeveritySummary {
    let pass = findings
        .iter()
        .filter(|f| f.severity == Severity::Pass)
        .count();
    let warn = findings
        .iter()
        .filter(|f| f.severity == Severity::Warn)
        .count();
    let fail = findings
        .iter()
        .filter(|f| f.severity == Severity::Fail)
        .count();

    SeveritySummary {
        pass,
        warn,
        fail,
        total: findings.len(),
    }
}

fn percentile_duration_ms(sorted_values: &[u128], percentile: usize) -> u128 {
    if sorted_values.is_empty() {
        return 0;
    }

    let idx = (((percentile as f64 / 100.0) * sorted_values.len() as f64).ceil() as usize)
        .saturating_sub(1)
        .min(sorted_values.len() - 1);
    sorted_values[idx]
}

fn summarize_runtime(runtime: &[RunResult]) -> RuntimeSummary {
    let mut durations = runtime.iter().map(|r| r.duration_ms).collect::<Vec<_>>();
    durations.sort_unstable();

    let timeout_count = runtime.iter().filter(|r| r.timed_out).count();
    let non_zero_exit_count = runtime
        .iter()
        .filter(|r| r.exit_code.unwrap_or(-1) != 0)
        .count();

    let mut unique_exit_codes = runtime
        .iter()
        .filter_map(|r| r.exit_code)
        .collect::<Vec<_>>();
    unique_exit_codes.sort_unstable();
    unique_exit_codes.dedup();

    let total_duration_ms = durations.iter().copied().sum();
    let flaky = timeout_count > 0
        || unique_exit_codes.len() > 1
        || (unique_exit_codes.first().copied().unwrap_or(0) != 0 && !runtime.is_empty());
    let flakiness_percent = if runtime.is_empty() {
        0
    } else {
        ((timeout_count + non_zero_exit_count) as u32 * 100 / runtime.len() as u32).min(100)
    };

    RuntimeSummary {
        runs: runtime.len(),
        timeout_count,
        non_zero_exit_count,
        unique_exit_codes,
        total_duration_ms,
        min_duration_ms: durations.first().copied().unwrap_or(0),
        max_duration_ms: durations.last().copied().unwrap_or(0),
        p50_duration_ms: percentile_duration_ms(&durations, 50),
        p95_duration_ms: percentile_duration_ms(&durations, 95),
        flaky,
        flakiness_percent,
        stability_percent: 100_u32.saturating_sub(flakiness_percent),
    }
}

fn build_report_summary(findings: &[Finding], runtime: &[RunResult]) -> ReportSummaryBlock {
    ReportSummaryBlock {
        severity: summarize_findings(findings),
        runtime: summarize_runtime(runtime),
    }
}

fn emit_and_exit(
    config: &Config,
    findings: Vec<Finding>,
    runtime: Vec<RunResult>,
    telemetry: security_lab::SecurityLabTelemetry,
    artifacts: ReportArtifacts,
    score: u32,
    final_status: Severity,
) {
    print_console_report(&findings, &runtime, &telemetry, score, final_status);
    let paths = write_report_files(
        config,
        &findings,
        &runtime,
        &telemetry,
        &artifacts,
        score,
        final_status,
    );

    if let Ok(outputs) = paths {
        println!();
        println!("[REPORT] Full:   {}", outputs.full_log.display());
        println!("[REPORT] Issues: {}", outputs.issues_log.display());
        println!("[REPORT] JSON:   {}", outputs.json_log.display());
        if let Some(path) = outputs.md_log {
            println!("[REPORT] MD:     {}", path.display());
        }
        if let Some(path) = outputs.html_log {
            println!("[REPORT] HTML:   {}", path.display());
        }
    }

    match final_status {
        Severity::Pass => std::process::exit(0),
        Severity::Warn => std::process::exit(1),
        Severity::Fail => std::process::exit(2),
    }
}

fn print_console_report(
    findings: &[Finding],
    runtime: &[RunResult],
    telemetry: &security_lab::SecurityLabTelemetry,
    score: u32,
    final_status: Severity,
) {
    let severity = summarize_findings(findings);
    let runtime_summary = summarize_runtime(runtime);

    println!("=== Findings ===");
    for f in findings {
        println!(
            "[{}] {} ({} | +{}) - {}",
            f.severity.as_str(),
            f.code,
            f.category,
            f.points,
            f.message
        );
    }

    if !runtime.is_empty() {
        println!();
        println!("=== Runtime Summary ===");
        for r in runtime {
            println!(
                "{} | exit={:?} | timeout={} | {} ms | stdout={}B | stderr={}B | reason={}",
                r.scenario,
                r.exit_code,
                r.timed_out,
                r.duration_ms,
                r.stdout_len,
                r.stderr_len,
                r.failure_reason
            );
        }
    }

    println!();
    println!("=== Security-Lab Coverage ===");
    println!(
        "profile={} enabled={} custom={} confirm_required={}",
        telemetry.profile,
        telemetry.enabled,
        telemetry.custom_selection,
        telemetry.confirmation_required
    );
    println!(
        "disasm={} symbolic={} taint={} business={} fuzz_cases={} runtime_traces={}",
        telemetry.coverage.disassembly_signals,
        telemetry.coverage.symbolic_signals,
        telemetry.coverage.taint_paths,
        telemetry.coverage.business_risks,
        telemetry.coverage.fuzz_cases,
        telemetry.coverage.runtime_traces
    );

    println!();
    println!("=== Totals ===");
    println!(
        "PASS: {}  WARN: {}  FAIL: {}",
        severity.pass, severity.warn, severity.fail
    );
    println!("RISK SCORE: {}", score);
    println!("FINAL: {}", final_status.as_str());
    if runtime_summary.runs > 0 {
        println!(
            "RUNTIME: runs={} p50={}ms p95={}ms flaky={} flakiness={}%",
            runtime_summary.runs,
            runtime_summary.p50_duration_ms,
            runtime_summary.p95_duration_ms,
            runtime_summary.flaky,
            runtime_summary.flakiness_percent
        );
    }
}

fn write_report_files(
    config: &Config,
    findings: &[Finding],
    runtime: &[RunResult],
    telemetry: &security_lab::SecurityLabTelemetry,
    artifacts: &ReportArtifacts,
    score: u32,
    final_status: Severity,
) -> anyhow::Result<ReportOutputs> {
    fs::create_dir_all(&config.out_dir).with_context(|| {
        format!(
            "Failed to create output dir '{}'",
            config.out_dir.display()
        )
    })?;

    let stamp = timestamp_string();
    let base = config
        .exe_path
        .file_stem()
        .and_then(|x| x.to_str())
        .unwrap_or("target");

    let full_log = config.out_dir.join(format!("full_{}_{}.log", base, stamp));
    let issues_log = config.out_dir.join(format!("issues_{}_{}.log", base, stamp));
    let json_log = config.out_dir.join(format!("report_{}_{}.json", base, stamp));
    let summary = build_report_summary(findings, runtime);

    let mut full = String::new();
    full.push_str("=== Metsuki Analyzer (Rust) ===\n");
    full.push_str("Schema: 2.0\n");
    full.push_str(&format!("Target: {}\n", config.exe_path.display()));
    full.push_str(&format!("AnalysisMode: {}\n", config.analysis_mode.as_str()));
    full.push_str(&format!("Mode: {}\n", config.mode.as_str()));
    full.push_str(&format!("PowerProfile: {}\n", config.power_profile.as_str()));
    full.push_str(&format!("SecurityLab profile: {}\n", telemetry.profile));
    full.push_str(&format!("Score: {}\n", score));
    full.push_str(&format!("Final: {}\n\n", final_status.as_str()));
    full.push_str(&format!(
        "Severity totals: pass={} warn={} fail={} total={}\n",
        summary.severity.pass,
        summary.severity.warn,
        summary.severity.fail,
        summary.severity.total
    ));
    if summary.runtime.runs > 0 {
        full.push_str(&format!(
            "Runtime summary: runs={} timeouts={} non_zero={} p50={}ms p95={}ms flaky={} flakiness={}% stability={}%\n\n",
            summary.runtime.runs,
            summary.runtime.timeout_count,
            summary.runtime.non_zero_exit_count,
            summary.runtime.p50_duration_ms,
            summary.runtime.p95_duration_ms,
            summary.runtime.flaky,
            summary.runtime.flakiness_percent,
            summary.runtime.stability_percent
        ));
    }
    full.push_str(&render_static_summary_text(artifacts));
    full.push_str("=== Findings ===\n");
    for f in findings {
        full.push_str(&format!(
            "[{}] {} ({} | +{}) - {}\n",
            f.severity.as_str(),
            f.code,
            f.category,
            f.points,
            f.message
        ));
    }
    full.push_str("\n=== Runtime ===\n");
    for r in runtime {
        full.push_str(&format!(
            "{} | exit={:?} | timeout={} | {} ms | stdout={}B | stderr={}B | reason={}\n",
            r.scenario,
            r.exit_code,
            r.timed_out,
            r.duration_ms,
            r.stdout_len,
            r.stderr_len,
            r.failure_reason
        ));
    }

    full.push_str("\n=== Security-Lab Modules ===\n");
    for module in &telemetry.selected_modules {
        full.push_str(&format!(
            "{} | {} | {} | {} | {}\n",
            module.id,
            module.category,
            module.status,
            module.reason,
            module.capabilities.join("; ")
        ));
    }
    full.push_str(&format!(
        "coverage: disasm={} symbolic={} taint={} business={} fuzz_cases={} runtime_traces={}\n",
        telemetry.coverage.disassembly_signals,
        telemetry.coverage.symbolic_signals,
        telemetry.coverage.taint_paths,
        telemetry.coverage.business_risks,
        telemetry.coverage.fuzz_cases,
        telemetry.coverage.runtime_traces
    ));
    full.push_str(&format!("next: {}\n", telemetry.recommended_next_step));

    let mut issues = String::new();
    issues.push_str("=== Metsuki Analyzer Issues ===\n");
    issues.push_str("Schema: 2.0\n");
    issues.push_str(&format!("Target: {}\n", config.exe_path.display()));
    issues.push_str(&format!("AnalysisMode: {}\n", config.analysis_mode.as_str()));
    issues.push_str(&format!("Mode: {}\n", config.mode.as_str()));
    issues.push_str(&format!("PowerProfile: {}\n", config.power_profile.as_str()));
    issues.push_str(&format!("Score: {} | Final: {}\n\n", score, final_status.as_str()));
    issues.push_str(&format!(
        "Severity totals: pass={} warn={} fail={} total={}\n",
        summary.severity.pass,
        summary.severity.warn,
        summary.severity.fail,
        summary.severity.total
    ));
    if summary.runtime.runs > 0 {
        issues.push_str(&format!(
            "Runtime summary: runs={} timeouts={} non_zero={} p50={}ms p95={}ms flaky={} flakiness={}% stability={}%\n\n",
            summary.runtime.runs,
            summary.runtime.timeout_count,
            summary.runtime.non_zero_exit_count,
            summary.runtime.p50_duration_ms,
            summary.runtime.p95_duration_ms,
            summary.runtime.flaky,
            summary.runtime.flakiness_percent,
            summary.runtime.stability_percent
        ));
    }
    issues.push_str(&render_static_summary_text(artifacts));
    for f in findings {
        if f.severity != Severity::Pass {
            issues.push_str(&format!(
                "[{}] {} ({} | +{}) - {}\n",
                f.severity.as_str(),
                f.code,
                f.category,
                f.points,
                f.message
            ));
        }
    }

    fs::write(&full_log, full).with_context(|| format!("Write full log failed: {}", full_log.display()))?;
    fs::write(&issues_log, issues)
        .with_context(|| format!("Write issues log failed: {}", issues_log.display()))?;

    let report = Report {
        schema_version: "2.2".to_string(),
        target: config.exe_path.display().to_string(),
        generated_unix: current_unix(),
        analysis_mode: config.analysis_mode,
        mode: config.mode,
        score,
        final_status,
        summary,
        artifacts: artifacts.clone(),
        findings: findings.to_vec(),
        runtime: runtime.to_vec(),
        telemetry: serde_json::to_value(telemetry).context("Serialize telemetry failed")?,
    };

    let json = serde_json::to_string_pretty(&report).context("Serialize JSON report failed")?;
    fs::write(&json_log, json)
        .with_context(|| format!("Write JSON report failed: {}", json_log.display()))?;

    let md_log = if config.export_md {
        let path = config.out_dir.join(format!("report_{}_{}.md", base, stamp));
        let body = render_report_markdown(&report);
        fs::write(&path, body)
            .with_context(|| format!("Write Markdown report failed: {}", path.display()))?;
        Some(path)
    } else {
        None
    };

    let html_log = if config.export_html {
        let path = config.out_dir.join(format!("report_{}_{}.html", base, stamp));
        let body = render_report_html(&report);
        fs::write(&path, body)
            .with_context(|| format!("Write HTML report failed: {}", path.display()))?;
        Some(path)
    } else {
        None
    };

    Ok(ReportOutputs {
        full_log,
        issues_log,
        json_log,
        md_log,
        html_log,
    })
}

fn render_report_markdown(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("# Metsuki Report\n\n");
    out.push_str(&format!("- Target: {}\n", report.target));
    out.push_str(&format!("- Schema: {}\n", report.schema_version));
    out.push_str(&format!("- Analysis mode: {}\n", report.analysis_mode.as_str()));
    out.push_str(&format!("- Verdict mode: {}\n", report.mode.as_str()));
    out.push_str(&format!("- Final status: {}\n", report.final_status.as_str()));
    out.push_str(&format!("- Score: {}\n\n", report.score));

    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "- Severity totals: PASS={} WARN={} FAIL={} TOTAL={}\n",
        report.summary.severity.pass,
        report.summary.severity.warn,
        report.summary.severity.fail,
        report.summary.severity.total
    ));
    out.push_str(&format!(
        "- Runtime: runs={} timeouts={} non-zero={} p50={}ms p95={}ms flaky={} flakiness={}% stability={}%\n\n",
        report.summary.runtime.runs,
        report.summary.runtime.timeout_count,
        report.summary.runtime.non_zero_exit_count,
        report.summary.runtime.p50_duration_ms,
        report.summary.runtime.p95_duration_ms,
        report.summary.runtime.flaky,
        report.summary.runtime.flakiness_percent,
        report.summary.runtime.stability_percent
    ));
    out.push_str(&render_static_summary_markdown(&report.artifacts));

    out.push_str("## Findings\n\n");
    out.push_str("| Severity | Code | Category | Points | Message |\n");
    out.push_str("|---|---|---|---:|---|\n");
    for f in &report.findings {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            f.severity.as_str(),
            f.code,
            f.category,
            f.points,
            f.message.replace('|', "\\|")
        ));
    }

    out.push_str("\n## Runtime\n\n");
    out.push_str("| Scenario | Exit | Timeout | Duration ms | stdout | stderr | Reason |\n");
    out.push_str("|---|---:|---|---:|---:|---:|---|\n");
    for r in &report.runtime {
        out.push_str(&format!(
            "| {} | {:?} | {} | {} | {} | {} | {} |\n",
            r.scenario,
            r.exit_code,
            r.timed_out,
            r.duration_ms,
            r.stdout_len,
            r.stderr_len,
            r.failure_reason.replace('|', "\\|")
        ));
    }

    out
}

fn render_report_html(report: &Report) -> String {
    fn esc(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    let findings_rows = report
        .findings
        .iter()
        .map(|f| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(f.severity.as_str()),
                esc(f.code),
                esc(f.category),
                f.points,
                esc(&f.message)
            )
        })
        .collect::<String>();

    let runtime_rows = report
        .runtime
        .iter()
        .map(|r| {
            format!(
                "<tr><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&r.scenario),
                r.exit_code,
                r.timed_out,
                r.duration_ms,
                r.stdout_len,
                r.stderr_len,
                esc(&r.failure_reason)
            )
        })
        .collect::<String>();

    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Metsuki Report</title><style>body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2937}}table{{border-collapse:collapse;width:100%;margin:12px 0}}th,td{{border:1px solid #d1d5db;padding:8px;text-align:left}}th{{background:#f3f4f6}}h1,h2{{margin:12px 0 8px}}</style></head><body><h1>Metsuki Report</h1><p><b>Target:</b> {}<br><b>Schema:</b> {}<br><b>Analysis mode:</b> {}<br><b>Verdict mode:</b> {}<br><b>Final status:</b> {}<br><b>Score:</b> {}</p><h2>Summary</h2><p><b>Severity totals:</b> PASS={} WARN={} FAIL={} TOTAL={}<br><b>Runtime:</b> runs={} timeouts={} non-zero={} p50={}ms p95={}ms flaky={} flakiness={}% stability={}%</p>{}<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Code</th><th>Category</th><th>Points</th><th>Message</th></tr></thead><tbody>{}</tbody></table><h2>Runtime</h2><table><thead><tr><th>Scenario</th><th>Exit</th><th>Timeout</th><th>Duration ms</th><th>stdout</th><th>stderr</th><th>Reason</th></tr></thead><tbody>{}</tbody></table></body></html>",
        esc(&report.target),
        esc(&report.schema_version),
        esc(report.analysis_mode.as_str()),
        esc(report.mode.as_str()),
        esc(report.final_status.as_str()),
        report.score,
        report.summary.severity.pass,
        report.summary.severity.warn,
        report.summary.severity.fail,
        report.summary.severity.total,
        report.summary.runtime.runs,
        report.summary.runtime.timeout_count,
        report.summary.runtime.non_zero_exit_count,
        report.summary.runtime.p50_duration_ms,
        report.summary.runtime.p95_duration_ms,
        report.summary.runtime.flaky,
        report.summary.runtime.flakiness_percent,
        report.summary.runtime.stability_percent,
        render_static_summary_html(&report.artifacts),
        findings_rows,
        runtime_rows,
    )
}

fn render_static_summary_text(artifacts: &ReportArtifacts) -> String {
    let mut out = String::new();
    out.push_str("Static artifacts:\n");
    out.push_str(&format!(
        "Target kind: {} | File size: {} bytes\n",
        artifacts.target_kind, artifacts.file_size_bytes
    ));

    if let Some(pe) = &artifacts.static_analysis.pe {
        out.push_str(&format!(
            "PE: arch={} dll={} sections={} overlay={} cert={} imports={} suspicious_imports={} mitigations=[DEP:{} ASLR:{} CFG:{}]\n",
            pe.arch,
            pe.is_dll,
            pe.section_count,
            pe.overlay_bytes,
            pe.certificate_table_bytes,
            pe.imports.total,
            pe.imports.suspicious.len(),
            pe.mitigations.dep,
            pe.mitigations.aslr,
            pe.mitigations.cfg
        ));
    }

    if let Some(source) = &artifacts.static_analysis.source {
        out.push_str(&format!(
            "Source: lang={} lines={} mostly_text={} long_lines={} unbalanced_delimiters={} suspicious_hits={}\n",
            source.language,
            source.line_count,
            source.mostly_text,
            source.long_lines,
            source.unbalanced_delimiters,
            source.suspicious_hits.len()
        ));
    }

    if let Some(strings) = &artifacts.static_analysis.strings {
        out.push_str(&format!(
            "Strings: scanned={} suspicious_hits={}\n",
            strings.total_strings_scanned,
            strings.suspicious_hits.len()
        ));
    }

    out.push('\n');
    out
}

fn render_static_summary_markdown(artifacts: &ReportArtifacts) -> String {
    let mut out = String::new();
    out.push_str("## Static Artifacts\n\n");
    out.push_str(&format!("- Target kind: {}\n", artifacts.target_kind));
    out.push_str(&format!("- File size: {} bytes\n", artifacts.file_size_bytes));

    if let Some(pe) = &artifacts.static_analysis.pe {
        out.push_str(&format!(
            "- PE: arch={} dll={} sections={} overlay={} cert_table={} imports={} suspicious_imports={}\n",
            pe.arch,
            pe.is_dll,
            pe.section_count,
            pe.overlay_bytes,
            pe.certificate_table_bytes,
            pe.imports.total,
            pe.imports.suspicious.len()
        ));
        out.push_str(&format!(
            "- Mitigations: DEP={} ASLR={} CFG={}\n",
            pe.mitigations.dep, pe.mitigations.aslr, pe.mitigations.cfg
        ));
        if !pe.imports.suspicious.is_empty() {
            out.push_str(&format!(
                "- Suspicious imports: {}\n",
                pe.imports.suspicious.join(", ")
            ));
        }
    }

    if let Some(source) = &artifacts.static_analysis.source {
        out.push_str(&format!(
            "- Source: lang={} lines={} mostly_text={} long_lines={} unbalanced_delimiters={}\n",
            source.language,
            source.line_count,
            source.mostly_text,
            source.long_lines,
            source.unbalanced_delimiters
        ));
        if !source.suspicious_hits.is_empty() {
            out.push_str(&format!(
                "- Source suspicious hits: {}\n",
                source.suspicious_hits.join(", ")
            ));
        }
    }

    if let Some(strings) = &artifacts.static_analysis.strings {
        out.push_str(&format!(
            "- Strings scanned: {} | suspicious hits: {}\n",
            strings.total_strings_scanned,
            strings.suspicious_hits.len()
        ));
    }

    out.push('\n');
    out
}

fn render_static_summary_html(artifacts: &ReportArtifacts) -> String {
    fn esc(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    let mut rows = vec![
        format!("<li><b>Target kind:</b> {}</li>", esc(&artifacts.target_kind)),
        format!("<li><b>File size:</b> {} bytes</li>", artifacts.file_size_bytes),
    ];

    if let Some(pe) = &artifacts.static_analysis.pe {
        rows.push(format!(
            "<li><b>PE:</b> arch={} dll={} sections={} overlay={} cert_table={} imports={} suspicious_imports={}</li>",
            esc(&pe.arch),
            pe.is_dll,
            pe.section_count,
            pe.overlay_bytes,
            pe.certificate_table_bytes,
            pe.imports.total,
            pe.imports.suspicious.len()
        ));
        rows.push(format!(
            "<li><b>Mitigations:</b> DEP={} ASLR={} CFG={}</li>",
            pe.mitigations.dep, pe.mitigations.aslr, pe.mitigations.cfg
        ));
        if !pe.imports.suspicious.is_empty() {
            rows.push(format!(
                "<li><b>Suspicious imports:</b> {}</li>",
                esc(&pe.imports.suspicious.join(", "))
            ));
        }
    }

    if let Some(source) = &artifacts.static_analysis.source {
        rows.push(format!(
            "<li><b>Source:</b> lang={} lines={} mostly_text={} long_lines={} unbalanced_delimiters={}</li>",
            esc(&source.language),
            source.line_count,
            source.mostly_text,
            source.long_lines,
            source.unbalanced_delimiters
        ));
    }

    if let Some(strings) = &artifacts.static_analysis.strings {
        rows.push(format!(
            "<li><b>Strings:</b> scanned={} suspicious_hits={}</li>",
            strings.total_strings_scanned,
            strings.suspicious_hits.len()
        ));
    }

    format!("<h2>Static Artifacts</h2><ul>{}</ul>", rows.join(""))
}

fn timestamp_string() -> String {
    current_unix().to_string()
}

fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn truncate_middle(text: &str, max_chars: usize) -> String {
    let chars = text.chars().collect::<Vec<_>>();
    if chars.len() <= max_chars {
        return text.to_string();
    }

    let head_len = max_chars / 2;
    let tail_len = max_chars.saturating_sub(head_len + 3);
    let head = chars[..head_len].iter().collect::<String>();
    let tail = chars[chars.len() - tail_len..].iter().collect::<String>();
    format!("{}...{}", head, tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_result(name: &str, exit_code: i32, timed_out: bool, duration_ms: u128) -> RunResult {
        RunResult {
            scenario: name.to_string(),
            exit_code: Some(exit_code),
            timed_out,
            duration_ms,
            stdout_len: 0,
            stderr_len: 0,
            failure_reason: String::new(),
            trace: RuntimeTrace {
                scenario_kind: "runtime".to_string(),
                sandbox_profile: "limited".to_string(),
                env_policy: "inherit".to_string(),
                working_dir: ".".to_string(),
                started_unix: 0,
                finished_unix: 0,
                events: Vec::new(),
                stdout_preview: String::new(),
                stderr_preview: String::new(),
            },
        }
    }

    #[test]
    fn runtime_summary_includes_percentiles_and_flaky_state() {
        let runtime = vec![
            run_result("a", 0, false, 10),
            run_result("b", 1, false, 20),
            run_result("c", 0, true, 50),
        ];

        let summary = summarize_runtime(&runtime);

        assert_eq!(summary.runs, 3);
        assert_eq!(summary.timeout_count, 1);
        assert_eq!(summary.non_zero_exit_count, 1);
        assert_eq!(summary.p50_duration_ms, 20);
        assert_eq!(summary.p95_duration_ms, 50);
        assert!(summary.flaky);
        assert_eq!(summary.flakiness_percent, 66);
        assert_eq!(summary.stability_percent, 34);
    }
}
