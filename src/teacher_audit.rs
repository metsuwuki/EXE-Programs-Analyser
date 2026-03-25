use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AssignmentSpec {
    pub(crate) id: String,
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) targets: Vec<String>,
    #[serde(default)]
    pub(crate) policy: AssignmentPolicy,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct AssignmentPolicy {
    #[serde(default)]
    pub(crate) required_modules: Vec<String>,
    pub(crate) max_timeout_secs: Option<u64>,
    pub(crate) mode: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AuditCaseResult {
    pub(crate) target: String,
    pub(crate) exit_code: i32,
    pub(crate) final_status: String,
    pub(crate) score: u32,
    pub(crate) report_json: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AuditBatchResult {
    pub(crate) assignment_id: String,
    pub(crate) assignment_title: String,
    pub(crate) total: usize,
    pub(crate) pass: usize,
    pub(crate) warn: usize,
    pub(crate) fail: usize,
    pub(crate) generated_unix: u64,
    pub(crate) summary_json: String,
    pub(crate) summary_csv: String,
    pub(crate) rerun_script: String,
    pub(crate) cases: Vec<AuditCaseResult>,
}

pub(crate) fn load_assignment(path: &Path) -> Result<AssignmentSpec> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read assignment file: {}", path.display()))?;
    let spec: AssignmentSpec = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse assignment JSON: {}", path.display()))?;
    validate_assignment(&spec)?;
    Ok(spec)
}

pub(crate) fn validate_runtime_config(spec: &AssignmentSpec, config: &Config) -> Result<()> {
    if let Some(limit) = spec.policy.max_timeout_secs {
        if config.timeout_secs > limit {
            return Err(anyhow!(
                "timeout {} exceeds assignment limit {}",
                config.timeout_secs,
                limit
            ));
        }
    }

    if let Some(expected_mode) = &spec.policy.mode {
        let expected = expected_mode.trim().to_ascii_uppercase();
        let actual = config.mode.as_str().to_ascii_uppercase();
        if expected != actual {
            return Err(anyhow!(
                "assignment requires mode '{}' but runtime mode is '{}'",
                expected,
                actual
            ));
        }
    }

    if !spec.policy.required_modules.is_empty() {
        let enabled = config
            .custom_modules
            .iter()
            .map(|m| m.to_ascii_lowercase())
            .collect::<Vec<_>>();

        for req in &spec.policy.required_modules {
            let req_l = req.to_ascii_lowercase();
            if !enabled.is_empty() && !enabled.iter().any(|m| m == &req_l) {
                return Err(anyhow!(
                    "required module '{}' is not in --modules selection",
                    req
                ));
            }
        }
    }

    Ok(())
}

pub(crate) fn run_batch_audit(config: &Config, spec: &AssignmentSpec, audit_dir: &Path) -> Result<AuditBatchResult> {
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    let stamp = current_unix();
    let base_out = config.out_dir.join(format!("audit_{}_{}", spec.id, stamp));
    fs::create_dir_all(&base_out)
        .with_context(|| format!("failed to create batch out dir: {}", base_out.display()))?;

    let mut cases = Vec::new();

    for (idx, rel) in spec.targets.iter().enumerate() {
        let target_path = resolve_target_path(audit_dir, rel);
        if !target_path.exists() {
            return Err(anyhow!("audit target does not exist: {}", target_path.display()));
        }

        let case_out = base_out.join(format!("case_{:03}", idx + 1));
        fs::create_dir_all(&case_out)
            .with_context(|| format!("failed to create case out dir: {}", case_out.display()))?;

        let mut cmd = Command::new(&exe);
        cmd.arg(&target_path)
            .arg("--out-dir")
            .arg(&case_out)
            .arg("--timeout")
            .arg(config.timeout_secs.to_string())
            .arg("--runs")
            .arg(config.runs.to_string())
            .arg("--sandbox-profile")
            .arg(config.sandbox_profile.as_str())
            .arg("--mode")
            .arg(config.analysis_mode.as_str().to_ascii_lowercase())
            .arg("--fuzz-engine")
            .arg(config.fuzz_engine.as_str())
            .arg("--lab-profile")
            .arg(config.lab_profile.as_str());

        if config.mode == ScanMode::Strict {
            cmd.arg("--strict");
        } else {
            cmd.arg("--balanced");
        }
        if !config.security_lab_enabled {
            cmd.arg("--no-security-lab");
        }
        if config.confirm_extended_tests {
            cmd.arg("--confirm-extended-tests");
        }
        if let Some(scenario) = &config.only_scenario {
            cmd.arg("--only-scenario").arg(scenario);
        }
        if !config.custom_modules.is_empty() {
            cmd.arg("--modules").arg(config.custom_modules.join(","));
        }

        let output = cmd.output().with_context(|| {
            format!(
                "failed to launch case analyzer for {}",
                target_path.display()
            )
        })?;

        let exit_code = output.status.code().unwrap_or(99);
        let report_json = find_single_report_json(&case_out).with_context(|| {
            format!(
                "report JSON was not generated for target {}",
                target_path.display()
            )
        })?;

        let parsed = parse_report_summary(&report_json)?;
        cases.push(AuditCaseResult {
            target: target_path.display().to_string(),
            exit_code,
            final_status: parsed.final_status,
            score: parsed.score,
            report_json: report_json.display().to_string(),
        });
    }

    let pass = cases.iter().filter(|c| c.final_status == "PASS").count();
    let warn = cases.iter().filter(|c| c.final_status == "WARN").count();
    let fail = cases.iter().filter(|c| c.final_status == "FAIL").count();

    let summary_json_path = base_out.join("audit_summary.json");
    let summary_csv_path = base_out.join("audit_summary.csv");
    let rerun_cmd_path = base_out.join("rerun_audit.cmd");

    let result = AuditBatchResult {
        assignment_id: spec.id.clone(),
        assignment_title: spec.title.clone(),
        total: cases.len(),
        pass,
        warn,
        fail,
        generated_unix: current_unix(),
        summary_json: summary_json_path.display().to_string(),
        summary_csv: summary_csv_path.display().to_string(),
        rerun_script: rerun_cmd_path.display().to_string(),
        cases,
    };

    write_summary_json(&summary_json_path, &result)?;
    write_summary_csv(&summary_csv_path, &result)?;
    write_rerun_script(&rerun_cmd_path, &exe, spec, audit_dir, config)?;

    Ok(result)
}

fn validate_assignment(spec: &AssignmentSpec) -> Result<()> {
    if spec.id.trim().is_empty() {
        return Err(anyhow!("assignment.id must be non-empty"));
    }
    if spec.title.trim().is_empty() {
        return Err(anyhow!("assignment.title must be non-empty"));
    }
    if spec.targets.is_empty() {
        return Err(anyhow!("assignment.targets must include at least one item"));
    }
    if let Some(v) = spec.policy.max_timeout_secs {
        if v == 0 {
            return Err(anyhow!("assignment.policy.max_timeout_secs must be >= 1"));
        }
    }
    if let Some(mode) = &spec.policy.mode {
        let m = mode.trim().to_ascii_uppercase();
        if m != "STRICT" && m != "BALANCED" {
            return Err(anyhow!("assignment.policy.mode must be STRICT or BALANCED"));
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ReportSummary {
    score: u32,
    final_status: String,
}

fn parse_report_summary(path: &Path) -> Result<ReportSummary> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read report json: {}", path.display()))?;
    let parsed: ReportSummary = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse report json: {}", path.display()))?;
    Ok(parsed)
}

fn find_single_report_json(case_out: &Path) -> Result<PathBuf> {
    let mut found = Vec::new();
    for ent in fs::read_dir(case_out)
        .with_context(|| format!("failed to list case output dir: {}", case_out.display()))?
    {
        let ent = ent?;
        let p = ent.path();
        if p.is_file() {
            let is_json = p
                .extension()
                .and_then(|x| x.to_str())
                .map(|x| x.eq_ignore_ascii_case("json"))
                .unwrap_or(false);
            let is_report = p
                .file_name()
                .and_then(|x| x.to_str())
                .map(|x| x.starts_with("report_"))
                .unwrap_or(false);
            if is_json && is_report {
                found.push(p);
            }
        }
    }

    if found.is_empty() {
        return Err(anyhow!("no report_*.json files found"));
    }

    found.sort();
    Ok(found[0].clone())
}

fn resolve_target_path(audit_dir: &Path, target: &str) -> PathBuf {
    let p = PathBuf::from(target);
    if p.is_absolute() {
        p
    } else {
        audit_dir.join(p)
    }
}

fn write_summary_json(path: &Path, result: &AuditBatchResult) -> Result<()> {
    let text = serde_json::to_string_pretty(result).context("failed to serialize audit summary json")?;
    fs::write(path, text).with_context(|| format!("failed to write summary json: {}", path.display()))?;
    Ok(())
}

fn write_summary_csv(path: &Path, result: &AuditBatchResult) -> Result<()> {
    let mut csv = String::new();
    csv.push_str("target,exit_code,final_status,score,report_json\n");
    for c in &result.cases {
        csv.push_str(&format!(
            "\"{}\",{},\"{}\",{},\"{}\"\n",
            c.target.replace('"', "''"),
            c.exit_code,
            c.final_status,
            c.score,
            c.report_json.replace('"', "''")
        ));
    }
    fs::write(path, csv).with_context(|| format!("failed to write summary csv: {}", path.display()))?;
    Ok(())
}

fn write_rerun_script(path: &Path, exe: &Path, spec: &AssignmentSpec, audit_dir: &Path, config: &Config) -> Result<()> {
    let mut script = String::new();
    script.push_str("@echo off\n");
    script.push_str("setlocal\n");
    script.push_str(&format!("set EXE=\"{}\"\n", exe.display()));
    script.push_str(&format!("set AUDIT_DIR=\"{}\"\n", audit_dir.display()));
    script.push_str("echo Re-running assignment batch...\n");

    for rel in &spec.targets {
        let full = resolve_target_path(audit_dir, rel);
        script.push_str("echo --------------------------------------------------\n");
        script.push_str(&format!("echo Target: {}\n", full.display()));
        script.push_str(&format!(
            "%EXE% \"{}\" --timeout {} --runs {} --sandbox-profile {} --mode {} --fuzz-engine {} --lab-profile {}{}{}{}\n",
            full.display(),
            config.timeout_secs,
            config.runs,
            config.sandbox_profile.as_str(),
            config.analysis_mode.as_str().to_ascii_lowercase(),
            config.fuzz_engine.as_str(),
            config.lab_profile.as_str(),
            if config.mode == ScanMode::Strict { " --strict" } else { " --balanced" },
            if config.confirm_extended_tests {
                " --confirm-extended-tests"
            } else {
                ""
            },
            if config.security_lab_enabled {
                ""
            } else {
                " --no-security-lab"
            }
        ));
    }

    script.push_str("echo Done.\n");
    script.push_str("endlocal\n");
    fs::write(path, script).with_context(|| format!("failed to write rerun script: {}", path.display()))?;
    Ok(())
}

fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
