use super::*;

pub(crate) fn parse_args(args: Vec<String>) -> Result<Config, String> {
    if args.len() < 2 {
        return Err("No target EXE path provided.".to_string());
    }

    let exe_path = PathBuf::from(&args[1]);
    let mut assignment_path: Option<PathBuf> = None;
    let mut audit_dir: Option<PathBuf> = None;
    let mut timeout_secs: u64 = 4;
    let mut runs: u32 = 6;
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
            }
            "--strict" => {
                mode = ScanMode::Strict;
            }
            "--balanced" => {
                mode = ScanMode::Balanced;
            }
            "--mode-min" => {
                analysis_mode = AnalysisMode::Min;
                mode = ScanMode::Balanced;
                lab_profile = SecurityLabProfile::Standard;
            }
            "--mode-pentest" => {
                analysis_mode = AnalysisMode::Pentest;
                mode = ScanMode::Strict;
                lab_profile = SecurityLabProfile::Aggressive;
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
                    }
                    _ => return Err("--mode must be 'min' or 'pentest'".to_string()),
                }
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

    if analysis_mode == AnalysisMode::Pentest && !confirm_extended_tests {
        return Err("PENTEST mode requires explicit --confirm-extended-tests opt-in".to_string());
    }

    Ok(Config {
        exe_path,
        assignment_path,
        audit_dir,
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
    })
}
