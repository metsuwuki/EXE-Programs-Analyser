use goblin::pe::PE;
use serde::Serialize;
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

#[derive(Debug, Clone)]
struct Config {
    exe_path: PathBuf,
    timeout_secs: u64,
    runs: u32,
    out_dir: PathBuf,
    mode: ScanMode,
    fuzz_engine: FuzzEngine,
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

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ScanMode {
    Strict,
    Balanced,
}

impl ScanMode {
    fn as_str(self) -> &'static str {
        match self {
            ScanMode::Strict => "STRICT",
            ScanMode::Balanced => "BALANCED",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Severity {
    Pass,
    Warn,
    Fail,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::Pass => "PASS",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Finding {
    severity: Severity,
    code: &'static str,
    category: &'static str,
    points: u32,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct RunResult {
    scenario: String,
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u128,
    stdout_len: usize,
    stderr_len: usize,
}

#[derive(Debug, Clone, Serialize)]
struct Report {
    target: String,
    generated_unix: u64,
    mode: ScanMode,
    score: u32,
    final_status: Severity,
    findings: Vec<Finding>,
    runtime: Vec<RunResult>,
}

fn main() {
    match parse_args(env::args().collect()) {
        Ok(config) => run(config),
        Err(msg) => {
            eprintln!("{}", msg);
            eprintln!(
                "Usage: exe_tester <path_to_target> [--timeout <sec>] [--runs <count>] [--out-dir <path>] [--strict|--balanced]"
            );
            std::process::exit(64);
        }
    }
}

fn run(config: Config) {
    let target_kind = detect_target_kind(&config.exe_path);
    let mut findings = Vec::new();
    println!("=== EXE Analyzer v2 (Rust) ===");
    println!("Target: {}", config.exe_path.display());
    println!("TargetType: {}", target_kind.as_str());
    println!(
        "Mode: {} | Timeout: {} sec | Runs: {} | OutDir: {} | FuzzEngine: {}",
        config.mode.as_str(),
        config.timeout_secs,
        config.runs,
        config.out_dir.display(),
        config.fuzz_engine.as_str()
    );
    println!();
    println!("[PHASE 1/3] static analysis");

    let bytes = match preflight::preflight_and_load(&config.exe_path, target_kind, &mut findings) {
        Ok(data) => data,
        Err(_) => {
            let (score, final_status) = score_and_status(&config, &findings);
            let runtime = Vec::new();
            emit_and_exit(&config, findings, runtime, score, final_status);
            return;
        }
    };

    match target_kind {
        TargetKind::Executable => {
            run_pe_static_checks(&bytes, &config, &mut findings);
            run_string_checks(&bytes, &mut findings);
        }
        TargetKind::Source(lang) => {
            run_source_static_checks(&config.exe_path, &bytes, Some(lang), &mut findings);
        }
        TargetKind::Unknown => {
            run_source_static_checks(&config.exe_path, &bytes, None, &mut findings);
        }
    }

    println!("[PHASE 2/3] runtime / behavior checks");
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

    println!("[PHASE 3/3] report generation");
    let (score, final_status) = score_and_status(&config, &findings);
    emit_and_exit(&config, findings, runtime, score, final_status);
}

fn parse_args(args: Vec<String>) -> Result<Config, String> {
    if args.len() < 2 {
        return Err("No target EXE path provided.".to_string());
    }

    let exe_path = PathBuf::from(&args[1]);
    let mut timeout_secs: u64 = 4;
    let mut runs: u32 = 6;
    let mut out_dir = PathBuf::from("logs");
    let mut mode = ScanMode::Strict;
    let mut fuzz_engine = FuzzEngine::Native;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--timeout" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --timeout".to_string());
                }
                timeout_secs = args[i]
                    .parse::<u64>()
                    .map_err(|_| "--timeout must be a positive integer".to_string())?;
                if timeout_secs == 0 {
                    return Err("--timeout must be >= 1".to_string());
                }
            }
            "--runs" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --runs".to_string());
                }
                runs = args[i]
                    .parse::<u32>()
                    .map_err(|_| "--runs must be a positive integer".to_string())?;
                if runs == 0 {
                    return Err("--runs must be >= 1".to_string());
                }
            }
            "--out-dir" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --out-dir".to_string());
                }
                out_dir = PathBuf::from(&args[i]);
            }
            "--strict" => {
                mode = ScanMode::Strict;
            }
            "--balanced" => {
                mode = ScanMode::Balanced;
            }
            "--fuzz-engine" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --fuzz-engine".to_string());
                }
                fuzz_engine = match args[i].to_ascii_lowercase().as_str() {
                    "native" => FuzzEngine::Native,
                    "libafl" => FuzzEngine::LibAfl,
                    _ => return Err("--fuzz-engine must be 'native' or 'libafl'".to_string()),
                };
            }
            other => return Err(format!("Unknown argument: {}", other)),
        }
        i += 1;
    }

    Ok(Config {
        exe_path,
        timeout_secs,
        runs,
        out_dir,
        mode,
        fuzz_engine,
    })
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
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .map(|x| x.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "exe" => TargetKind::Executable,
        "cs" => TargetKind::Source(SourceLanguage::CSharp),
        "java" => TargetKind::Source(SourceLanguage::Java),
        "py" => TargetKind::Source(SourceLanguage::Python),
        "go" => TargetKind::Source(SourceLanguage::Go),
        "js" => TargetKind::Source(SourceLanguage::JavaScript),
        "ts" => TargetKind::Source(SourceLanguage::TypeScript),
        "kt" => TargetKind::Source(SourceLanguage::Kotlin),
        "swift" => TargetKind::Source(SourceLanguage::Swift),
        "rb" => TargetKind::Source(SourceLanguage::Ruby),
        "php" => TargetKind::Source(SourceLanguage::Php),
        "lua" => TargetKind::Source(SourceLanguage::Lua),
        _ => TargetKind::Unknown,
    }
}

fn run_pe_static_checks(bytes: &[u8], config: &Config, findings: &mut Vec<Finding>) {
    if bytes.len() < 2 || &bytes[0..2] != b"MZ" {
        findings.push(finding(
            Severity::Fail,
            "MZ_SIGNATURE_MISSING",
            "pe",
            35,
            "DOS MZ signature missing.",
        ));
        return;
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
            return;
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
    for sec in &pe.sections {
        let chars = sec.characteristics;
        let is_exec = (chars & 0x2000_0000) != 0;
        let is_write = (chars & 0x8000_0000) != 0;
        if is_exec && is_write {
            rwx_sections.push(section_name(sec.name()));
        }
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

    let mut high_entropy_sections = Vec::new();
    for sec in &pe.sections {
        let start = sec.pointer_to_raw_data as usize;
        let size = sec.size_of_raw_data as usize;
        if size == 0 {
            continue;
        }

        if let Some(end) = start.checked_add(size) {
            if end <= bytes.len() {
                let ent = shannon_entropy(&bytes[start..end]);
                if ent >= 7.2 {
                    let name = section_name(sec.name());
                    high_entropy_sections.push((name, ent));
                }
            }
        }
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

    if let Some(optional) = pe.header.optional_header {
        let entry_rva = optional.standard_fields.address_of_entry_point;
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

    if let Some(last) = pe.sections.iter().max_by_key(|s| s.pointer_to_raw_data.saturating_add(s.size_of_raw_data)) {
        let end_of_sections = last.pointer_to_raw_data as usize + last.size_of_raw_data as usize;
        if bytes.len() > end_of_sections {
            let overlay = bytes.len() - end_of_sections;
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

fn run_string_checks(bytes: &[u8], findings: &mut Vec<Finding>) {
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
}

fn run_source_static_checks(
    path: &Path,
    bytes: &[u8],
    language: Option<SourceLanguage>,
    findings: &mut Vec<Finding>,
) {
    let lang_name = language.map(|l| l.as_str()).unwrap_or("Generic source");

    findings.push(finding(
        Severity::Pass,
        "SOURCE_ANALYSIS_MODE",
        "source",
        0,
        format!("Running source analysis mode for {}", lang_name),
    ));

    if !looks_mostly_text(bytes) {
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

    if has_unbalanced_delimiters(&text) {
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

fn emit_and_exit(
    config: &Config,
    findings: Vec<Finding>,
    runtime: Vec<RunResult>,
    score: u32,
    final_status: Severity,
) {
    print_console_report(&findings, &runtime, score, final_status);
    let paths = write_report_files(config, &findings, &runtime, score, final_status);

    if let Ok((full_log, issues_log, json_log)) = paths {
        println!();
        println!("[REPORT] Full:   {}", full_log.display());
        println!("[REPORT] Issues: {}", issues_log.display());
        println!("[REPORT] JSON:   {}", json_log.display());
    }

    match final_status {
        Severity::Pass => std::process::exit(0),
        Severity::Warn => std::process::exit(1),
        Severity::Fail => std::process::exit(2),
    }
}

fn print_console_report(findings: &[Finding], runtime: &[RunResult], score: u32, final_status: Severity) {
    let pass = findings.iter().filter(|f| f.severity == Severity::Pass).count();
    let warn = findings.iter().filter(|f| f.severity == Severity::Warn).count();
    let fail = findings.iter().filter(|f| f.severity == Severity::Fail).count();

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
                "{} | exit={:?} | timeout={} | {} ms | stdout={}B | stderr={}B",
                r.scenario, r.exit_code, r.timed_out, r.duration_ms, r.stdout_len, r.stderr_len
            );
        }
    }

    println!();
    println!("=== Totals ===");
    println!("PASS: {}  WARN: {}  FAIL: {}", pass, warn, fail);
    println!("RISK SCORE: {}", score);
    println!("FINAL: {}", final_status.as_str());
}

fn write_report_files(
    config: &Config,
    findings: &[Finding],
    runtime: &[RunResult],
    score: u32,
    final_status: Severity,
) -> anyhow::Result<(PathBuf, PathBuf, PathBuf)> {
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

    let mut full = String::new();
    full.push_str("=== EXE Analyzer v2 (Rust) ===\n");
    full.push_str(&format!("Target: {}\n", config.exe_path.display()));
    full.push_str(&format!("Mode: {}\n", config.mode.as_str()));
    full.push_str(&format!("Score: {}\n", score));
    full.push_str(&format!("Final: {}\n\n", final_status.as_str()));
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
            "{} | exit={:?} | timeout={} | {} ms | stdout={}B | stderr={}B\n",
            r.scenario, r.exit_code, r.timed_out, r.duration_ms, r.stdout_len, r.stderr_len
        ));
    }

    let mut issues = String::new();
    issues.push_str("=== EXE Analyzer v2 Issues ===\n");
    issues.push_str(&format!("Target: {}\n", config.exe_path.display()));
    issues.push_str(&format!("Mode: {}\n", config.mode.as_str()));
    issues.push_str(&format!("Score: {} | Final: {}\n\n", score, final_status.as_str()));
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
        target: config.exe_path.display().to_string(),
        generated_unix: current_unix(),
        mode: config.mode,
        score,
        final_status,
        findings: findings.to_vec(),
        runtime: runtime.to_vec(),
    };

    let json = serde_json::to_string_pretty(&report).context("Serialize JSON report failed")?;
    fs::write(&json_log, json)
        .with_context(|| format!("Write JSON report failed: {}", json_log.display()))?;

    Ok((full_log, issues_log, json_log))
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

