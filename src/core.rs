use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    #[serde(default)]
    pub language: String,
    #[serde(default = "default_theme_mode")]
    pub theme: String,
    #[serde(default = "default_accent")]
    pub accent: String,
    #[serde(default)]
    pub default_mode: AnalysisMode,
    #[serde(default = "default_power_profile")]
    pub power_profile: String,
    #[serde(default = "default_sandbox_profile")]
    pub sandbox_profile: String,
    #[serde(default)]
    pub out_dir: String,
    #[serde(default)]
    pub analyzer_path: Option<String>,
    #[serde(default)]
    pub vsdbg_path: Option<String>,
    #[serde(default)]
    pub linter_paths: Vec<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            language: "auto".to_string(),
            theme: default_theme_mode(),
            accent: default_accent(),
            default_mode: AnalysisMode::Min,
            power_profile: default_power_profile(),
            sandbox_profile: default_sandbox_profile(),
            out_dir: "logs".to_string(),
            analyzer_path: None,
            vsdbg_path: None,
            linter_paths: Vec::new(),
        }
    }
}

fn default_theme_mode() -> String {
    "AUTO".to_string()
}

fn default_accent() -> String {
    "AMETHYST".to_string()
}

fn default_power_profile() -> String {
    "BASIC".to_string()
}

fn default_sandbox_profile() -> String {
    "limited".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub path: String,
    pub modified_unix: u64,
    pub size_bytes: u64,
}

pub fn settings_path() -> PathBuf {
    if let Ok(appdata) = env::var("APPDATA") {
        return PathBuf::from(appdata)
            .join("Metsuki")
            .join("exe_analyzer")
            .join("settings.json");
    }

    if let Ok(home) = env::var("USERPROFILE") {
        return PathBuf::from(home)
            .join(".metsuki")
            .join("exe_analyzer")
            .join("settings.json");
    }

    PathBuf::from("settings.json")
}

pub fn load_settings() -> AppSettings {
    let path = settings_path();
    let text = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(_) => return AppSettings::default(),
    };

    serde_json::from_str(&text).unwrap_or_default()
}

pub fn save_settings(settings: &AppSettings) -> Result<(), String> {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Cannot create settings dir: {}", e))?;
    }

    let payload = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("Cannot serialize settings: {}", e))?;
    fs::write(path, payload).map_err(|e| format!("Cannot write settings: {}", e))
}

pub fn resolve_cli_path() -> Option<PathBuf> {
    let current = env::current_exe().ok()?;
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(parent) = current.parent() {
        candidates.push(parent.join(".engine").join("analyzer_core.exe"));
        candidates.push(parent.join("analyzer_core.exe"));
        candidates.push(parent.join("exe_tester.exe"));
        candidates.push(parent.join("..").join("exe_tester.exe"));
        candidates.push(parent.join("..").join("..").join("exe_tester.exe"));
    }

    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd.join(".engine").join("analyzer_core.exe"));
        candidates.push(cwd.join("analyzer_core.exe"));
        candidates.push(cwd.join("exe_tester.exe"));
        candidates.push(cwd.join("target").join("debug").join("exe_tester.exe"));
        candidates.push(cwd.join("target").join("release").join("exe_tester.exe"));
    }

    for ancestor in current.ancestors() {
        candidates.push(ancestor.join(".engine").join("analyzer_core.exe"));
        candidates.push(ancestor.join("analyzer_core.exe"));
        candidates.push(ancestor.join("target").join("debug").join("exe_tester.exe"));
        candidates.push(ancestor.join("target").join("release").join("exe_tester.exe"));
    }

    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

pub fn list_reports(out_dir: &Path) -> Vec<ReportSummary> {
    let mut reports = Vec::new();

    let entries = match fs::read_dir(out_dir) {
        Ok(v) => v,
        Err(_) => return reports,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let is_json = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("json"))
            == Some(true);
        if !is_json {
            continue;
        }

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !name.starts_with("report_") {
            continue;
        }

        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified_unix = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        reports.push(ReportSummary {
            path: path.display().to_string(),
            modified_unix,
            size_bytes: meta.len(),
        });
    }

    reports.sort_by(|a, b| b.modified_unix.cmp(&a.modified_unix));
    reports
}

pub fn read_report_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("Cannot read report: {}", e))?;
    serde_json::from_str(&text).map_err(|e| format!("Invalid report JSON: {}", e))
}

pub fn latest_report_for_target(out_dir: &Path, target: &Path) -> Option<PathBuf> {
    let stem = target.file_stem()?.to_string_lossy().to_string();
    let prefix = format!("report_{}", stem);

    let mut best: Option<(SystemTime, PathBuf)> = None;
    let entries = fs::read_dir(out_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name()?.to_string_lossy();
        if !name.ends_with(".json") || !name.starts_with(&prefix) {
            continue;
        }

        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        if let Some((prev_time, _)) = &best {
            if modified > *prev_time {
                best = Some((modified, path));
            }
        } else {
            best = Some((modified, path));
        }
    }

    best.map(|(_, p)| p)
}

pub fn list_logs_for_report(report_path: &Path) -> (Option<String>, Option<String>) {
    let file_name = match report_path.file_name().and_then(|n| n.to_str()) {
        Some(v) => v,
        None => return (None, None),
    };
    if !file_name.starts_with("report_") || !file_name.ends_with(".json") {
        return (None, None);
    }

    let suffix = &file_name["report_".len()..file_name.len() - ".json".len()];
    let parent = report_path.parent().unwrap_or_else(|| Path::new("."));

    let full = parent.join(format!("full_{}.log", suffix));
    let issues = parent.join(format!("issues_{}.log", suffix));

    let full_path = if full.exists() {
        Some(full.display().to_string())
    } else {
        None
    };
    let issues_path = if issues.exists() {
        Some(issues.display().to_string())
    } else {
        None
    };

    (full_path, issues_path)
}

pub fn open_path_in_explorer(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("explorer.exe");
        cmd.arg(path).stdout(Stdio::null()).stderr(Stdio::null());
        cmd.spawn().map_err(|e| format!("Cannot open path: {}", e))?;
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        let mut cmd = Command::new("xdg-open");
        cmd.arg(path).stdout(Stdio::null()).stderr(Stdio::null());
        cmd.spawn().map_err(|e| format!("Cannot open path: {}", e))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetTypeInfo {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

pub fn detect_target_type(path: &Path) -> TargetTypeInfo {
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .map(|x| x.to_ascii_lowercase())
        .unwrap_or_default();

    let language = match ext.as_str() {
        "cs" => Some("csharp".to_string()),
        "java" => Some("java".to_string()),
        "py" => Some("python".to_string()),
        "go" => Some("go".to_string()),
        "js" => Some("javascript".to_string()),
        "ts" => Some("typescript".to_string()),
        "kt" => Some("kotlin".to_string()),
        "swift" => Some("swift".to_string()),
        "rb" => Some("ruby".to_string()),
        "php" => Some("php".to_string()),
        "lua" => Some("lua".to_string()),
        _ => None,
    };

    if ext == "exe" {
        TargetTypeInfo {
            kind: "executable".to_string(),
            language: None,
        }
    } else if language.is_some() {
        TargetTypeInfo {
            kind: "source".to_string(),
            language,
        }
    } else {
        TargetTypeInfo {
            kind: "unknown".to_string(),
            language: None,
        }
    }
}