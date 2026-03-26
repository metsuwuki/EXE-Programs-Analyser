use super::*;

pub(crate) fn parse_args(args: Vec<String>) -> Result<Config, String> {
    if args.len() < 2 {
        return Err("No target EXE path provided.".to_string());
    }

    let exe_path = PathBuf::from(&args[1]);
    let mut assignment_path: Option<PathBuf> = None;
    let mut audit_dir: Option<PathBuf> = None;
    let mut power_profile = PowerProfile::Basic;
    let mut timeout_secs: u64 = 4;
    let mut runs: u32 = 4;
    let mut only_scenario: Option<String> = None;
    let mut sandbox_profile = SandboxProfile::Limited;
    let mut out_dir = PathBuf::from("logs");
    let mut analysis_mode = AnalysisMode::Min;
    let mut mode = ScanMode::Balanced;
    let mut fuzz_engine = FuzzEngine::Native;
    let mut security_lab_enabled = true;
    let mut lab_profile = SecurityLabProfile::Standard;
    let mut custom_modules = Vec::new();
    let mut confirm_extended_tests = false;
    let mut list_lab_modules = false;
    let mut list_scenarios = false;
    let mut export_md = false;
    let mut export_html = false;
    let mut explicit_mode = false;
    let mut explicit_verdict = false;
    let mut explicit_runs = false;
    let mut explicit_timeout = false;
    let mut explicit_sandbox = false;

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
                explicit_timeout = true;
            }
            "--assignment" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --assignment".to_string());
                }
                assignment_path = Some(PathBuf::from(&args[i]));
            }
            "--audit-dir" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --audit-dir".to_string());
                }
                audit_dir = Some(PathBuf::from(&args[i]));
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
                explicit_runs = true;
            }
            "--only-scenario" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --only-scenario".to_string());
                }
                let name = args[i].trim();
                if name.is_empty() {
                    return Err("--only-scenario value cannot be empty".to_string());
                }
                only_scenario = Some(name.to_string());
            }
            "--out-dir" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --out-dir".to_string());
                }
                out_dir = PathBuf::from(&args[i]);
            }
            "--export-format" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --export-format".to_string());
                }
                match args[i].to_ascii_lowercase().as_str() {
                    "md" | "markdown" => {
                        export_md = true;
                    }
                    "html" => {
                        export_html = true;
                    }
                    "both" => {
                        export_md = true;
                        export_html = true;
                    }
                    "json" => {
                        export_md = false;
                        export_html = false;
                    }
                    _ => {
                        return Err("--export-format must be 'json', 'md', 'html', or 'both'".to_string());
                    }
                }
            }
            "--export-md" => {
                export_md = true;
            }
            "--export-html" => {
                export_html = true;
            }
            "--sandbox-profile" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --sandbox-profile".to_string());
                }
                sandbox_profile = match args[i].to_ascii_lowercase().as_str() {
                    "none" => SandboxProfile::None,
                    "limited" => SandboxProfile::Limited,
                    "isolated" => SandboxProfile::Isolated,
                    _ => return Err("--sandbox-profile must be 'none', 'limited', or 'isolated'".to_string()),
                };
                explicit_sandbox = true;
            }
            "--strict" => {
                mode = ScanMode::Strict;
                explicit_verdict = true;
            }
            "--balanced" => {
                mode = ScanMode::Balanced;
                explicit_verdict = true;
            }
            "--mode-min" => {
                analysis_mode = AnalysisMode::Min;
                mode = ScanMode::Balanced;
                lab_profile = SecurityLabProfile::Standard;
                explicit_mode = true;
            }
            "--mode-pentest" => {
                analysis_mode = AnalysisMode::Pentest;
                mode = ScanMode::Strict;
                lab_profile = SecurityLabProfile::Aggressive;
                confirm_extended_tests = true;
                explicit_mode = true;
            }
            "--mode" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --mode".to_string());
                }
                match args[i].to_ascii_lowercase().as_str() {
                    "min" => {
                        analysis_mode = AnalysisMode::Min;
                        mode = ScanMode::Balanced;
                        lab_profile = SecurityLabProfile::Standard;
                    }
                    "pentest" => {
                        analysis_mode = AnalysisMode::Pentest;
                        mode = ScanMode::Strict;
                        lab_profile = SecurityLabProfile::Aggressive;
                        confirm_extended_tests = true;
                    }
                    _ => return Err("--mode must be 'min' or 'pentest'".to_string()),
                }
                explicit_mode = true;
            }
            "--power-profile" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --power-profile".to_string());
                }
                power_profile = parse_power_profile(&args[i])?;
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
            "--lab-profile" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --lab-profile".to_string());
                }
                lab_profile = match args[i].to_ascii_lowercase().as_str() {
                    "standard" => SecurityLabProfile::Standard,
                    "aggressive" => SecurityLabProfile::Aggressive,
                    _ => return Err("--lab-profile must be 'standard' or 'aggressive'".to_string()),
                };
            }
            "--no-security-lab" => {
                security_lab_enabled = false;
            }
            "--confirm-extended-tests" => {
                confirm_extended_tests = true;
            }
            "--list-lab-modules" => {
                list_lab_modules = true;
            }
            "--list-scenarios" => {
                list_scenarios = true;
            }
            "--modules" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --modules".to_string());
                }
                custom_modules = args[i]
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                if custom_modules.is_empty() {
                    return Err("--modules requires at least one module id".to_string());
                }
            }
            other => return Err(format!("Unknown argument: {}", other)),
        }
        i += 1;
    }

    let defaults = power_profile_defaults(power_profile);
    if !explicit_mode {
        analysis_mode = defaults.analysis_mode;
        if defaults.analysis_mode == AnalysisMode::Pentest {
            confirm_extended_tests = true;
        }
    }
    if !explicit_verdict {
        mode = defaults.mode;
    }
    if !explicit_runs {
        runs = defaults.runs;
    }
    if !explicit_timeout {
        timeout_secs = defaults.timeout_secs;
    }
    if !explicit_sandbox {
        sandbox_profile = defaults.sandbox_profile;
    }

    if analysis_mode == AnalysisMode::Pentest && !confirm_extended_tests {
        return Err("PENTEST mode requires explicit --confirm-extended-tests opt-in".to_string());
    }

    Ok(Config {
        exe_path,
        assignment_path,
        audit_dir,
        power_profile,
        timeout_secs,
        runs,
        only_scenario,
        sandbox_profile,
        out_dir,
        analysis_mode,
        mode,
        fuzz_engine,
        security_lab_enabled,
        lab_profile,
        custom_modules,
        confirm_extended_tests,
        list_lab_modules,
        list_scenarios,
        export_md,
        export_html,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Vec<String> {
        vec!["exe_tester".to_string(), "target.exe".to_string()]
    }

    #[test]
    fn mode_pentest_implies_confirm_flag() {
        let mut args = base_args();
        args.push("--mode-pentest".to_string());
        let cfg = parse_args(args).expect("parse should succeed");
        assert_eq!(cfg.analysis_mode, AnalysisMode::Pentest);
        assert!(cfg.confirm_extended_tests);
    }

    #[test]
    fn mode_long_form_pentest_implies_confirm_flag() {
        let mut args = base_args();
        args.push("--mode".to_string());
        args.push("pentest".to_string());
        let cfg = parse_args(args).expect("parse should succeed");
        assert_eq!(cfg.analysis_mode, AnalysisMode::Pentest);
        assert!(cfg.confirm_extended_tests);
    }

    #[test]
    fn list_scenarios_flag_is_parsed() {
        let mut args = base_args();
        args.push("--list-scenarios".to_string());
        let cfg = parse_args(args).expect("parse should succeed");
        assert!(cfg.list_scenarios);
    }

    #[test]
    fn invalid_sandbox_profile_rejected() {
        let mut args = base_args();
        args.push("--sandbox-profile".to_string());
        args.push("bad".to_string());
        let err = parse_args(args).expect_err("parse should fail");
        assert!(err.contains("--sandbox-profile"));
    }

    #[test]
    fn power_profile_extreme_applies_defaults() {
        let mut args = base_args();
        args.push("--power-profile".to_string());
        args.push("EXTREME".to_string());
        let cfg = parse_args(args).expect("parse should succeed");
        assert_eq!(cfg.analysis_mode, AnalysisMode::Pentest);
        assert_eq!(cfg.mode, ScanMode::Strict);
        assert_eq!(cfg.runs, 12);
        assert_eq!(cfg.timeout_secs, 8);
        assert_eq!(cfg.sandbox_profile, SandboxProfile::Isolated);
    }

    #[test]
    fn export_format_both_enables_md_and_html() {
        let mut args = base_args();
        args.push("--export-format".to_string());
        args.push("both".to_string());
        let cfg = parse_args(args).expect("parse should succeed");
        assert!(cfg.export_md);
        assert!(cfg.export_html);
    }
}
