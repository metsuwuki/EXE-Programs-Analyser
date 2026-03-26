use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Sandbox isolation level for runtime scenarios.
/// Shared between CLI engine and GUI settings persistence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SandboxProfile {
    #[default]
    Limited,
    Isolated,
    None,
}

impl SandboxProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            SandboxProfile::None => "none",
            SandboxProfile::Limited => "limited",
            SandboxProfile::Isolated => "isolated",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnalysisMode {
    Min,
    Pentest,
}

impl Default for AnalysisMode {
    fn default() -> Self {
        Self::Min
    }
}

impl AnalysisMode {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            AnalysisMode::Min => "MIN",
            AnalysisMode::Pentest => "PENTEST",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanMode {
    Strict,
    Balanced,
}

impl ScanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanMode::Strict => "STRICT",
            ScanMode::Balanced => "BALANCED",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Pass,
    Warn,
    Fail,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Pass => "PASS",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub category: &'static str,
    pub points: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunResult {
    pub scenario: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u128,
    pub stdout_len: usize,
    pub stderr_len: usize,
    pub failure_reason: String,
    pub trace: RuntimeTrace,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeTrace {
    pub scenario_kind: String,
    pub sandbox_profile: String,
    pub env_policy: String,
    pub working_dir: String,
    pub started_unix: u64,
    pub finished_unix: u64,
    pub events: Vec<RuntimeTraceEvent>,
    pub stdout_preview: String,
    pub stderr_preview: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeTraceEvent {
    pub at_ms: u128,
    pub stage: String,
    pub detail: String,
}

/// Power profile presets that cascade defaults for mode, sandbox, runs, and timeout.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PowerProfile {
    #[default]
    Basic,
    Audit,
    Pentest,
    Extreme,
}

impl PowerProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            PowerProfile::Basic => "BASIC",
            PowerProfile::Audit => "AUDIT",
            PowerProfile::Pentest => "PENTEST",
            PowerProfile::Extreme => "EXTREME",
        }
    }

    /// Parse case-insensitively; unknown strings map to `Basic`.
    pub fn from_str_lossy(input: &str) -> Self {
        match input.trim().to_ascii_uppercase().as_str() {
            "AUDIT" => PowerProfile::Audit,
            "PENTEST" => PowerProfile::Pentest,
            "EXTREME" => PowerProfile::Extreme,
            _ => PowerProfile::Basic,
        }
    }
}

/// Security-lab scan intensity preset.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecurityLabProfile {
    #[default]
    Standard,
    Aggressive,
}

impl SecurityLabProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityLabProfile::Standard => "standard",
            SecurityLabProfile::Aggressive => "aggressive",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: String,
    pub target: String,
    pub generated_unix: u64,
    pub analysis_mode: AnalysisMode,
    pub mode: ScanMode,
    pub score: u32,
    pub final_status: Severity,
    pub summary: ReportSummaryBlock,
    pub artifacts: ReportArtifacts,
    pub findings: Vec<Finding>,
    pub runtime: Vec<RunResult>,
    pub telemetry: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSummaryBlock {
    pub severity: SeveritySummary,
    pub runtime: RuntimeSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeveritySummary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeSummary {
    pub runs: usize,
    pub timeout_count: usize,
    pub non_zero_exit_count: usize,
    pub unique_exit_codes: Vec<i32>,
    pub total_duration_ms: u128,
    pub min_duration_ms: u128,
    pub max_duration_ms: u128,
    pub p50_duration_ms: u128,
    pub p95_duration_ms: u128,
    pub flaky: bool,
    pub flakiness_percent: u32,
    pub stability_percent: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ReportArtifacts {
    pub target_kind: String,
    pub file_size_bytes: usize,
    pub static_analysis: StaticAnalysisArtifacts,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct StaticAnalysisArtifacts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe: Option<PeArtifacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceArtifacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings: Option<StringsArtifacts>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeArtifacts {
    pub arch: String,
    pub is_dll: bool,
    pub section_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point_rva: Option<u64>,
    pub sections: Vec<PeSectionArtifact>,
    pub imports: ImportArtifacts,
    pub mitigations: MitigationArtifacts,
    pub overlay_bytes: u64,
    pub certificate_table_bytes: u32,
    pub coff_timestamp: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeSectionArtifact {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub entropy: f64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportArtifacts {
    pub total: usize,
    pub suspicious: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MitigationArtifacts {
    pub dep: bool,
    pub aslr: bool,
    pub cfg: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringsArtifacts {
    pub total_strings_scanned: usize,
    pub suspicious_hits: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceArtifacts {
    pub language: String,
    pub line_count: usize,
    pub mostly_text: bool,
    pub long_lines: usize,
    pub unbalanced_delimiters: bool,
    pub suspicious_hits: Vec<String>,
}
