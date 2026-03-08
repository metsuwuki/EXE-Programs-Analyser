use super::*;

#[derive(Debug, Clone)]
struct RuntimeScenario {
    name: String,
    args: Vec<String>,
    stdin_payload: String,
    clear_env: bool,
    timeout_secs: u64,
}

pub(crate) fn run_runtime_checks(config: &Config, findings: &mut Vec<Finding>) -> Vec<RunResult> {
    if config.fuzz_engine == FuzzEngine::LibAfl && !cfg!(feature = "libafl-engine") {
        findings.push(finding(
            Severity::Warn,
            "LIBAFL_FEATURE_DISABLED",
            "runtime",
            2,
            "--fuzz-engine libafl requested but binary was built without 'libafl-engine' feature; using fallback fuzz scenarios.",
        ));
    }

    let scenarios = build_runtime_scenarios(config);
    let mut results = Vec::with_capacity(scenarios.len());

    for scenario in scenarios {
        if let Some(result) = run_single_runtime_scenario(config, &scenario, findings) {
            println!(
                "[SCENARIO] done {} | exit={:?} timeout={} dur={}ms",
                result.scenario, result.exit_code, result.timed_out, result.duration_ms
            );
            results.push(result);
        }
    }

    results
}

fn build_runtime_scenarios(config: &Config) -> Vec<RuntimeScenario> {
    let mut scenarios = vec![
        RuntimeScenario {
            name: "no_args".to_string(),
            args: vec![],
            stdin_payload: "\n".to_string(),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(3),
        },
        RuntimeScenario {
            name: "empty_and_noise_stdin".to_string(),
            args: vec![],
            stdin_payload: "\n\n%%%INVALID%%%\n".to_string(),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(3),
        },
        RuntimeScenario {
            name: "long_arg".to_string(),
            args: vec!["A".repeat(4096)],
            stdin_payload: String::new(),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(3),
        },
        RuntimeScenario {
            name: "unicode_arg".to_string(),
            args: vec!["тест_输入_🔥".to_string()],
            stdin_payload: String::new(),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(3),
        },
        RuntimeScenario {
            name: "invalid_path_arg".to_string(),
            args: vec!["Z:\\definitely_missing_file_12345.tmp".to_string()],
            stdin_payload: String::new(),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(3),
        },
        RuntimeScenario {
            name: "very_long_unicode_arg".to_string(),
            args: vec!["Ю".repeat(2048)],
            stdin_payload: String::new(),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(4),
        },
        RuntimeScenario {
            name: "stdin_long_payload".to_string(),
            args: vec![],
            stdin_payload: "X".repeat(12000),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(3),
        },
        RuntimeScenario {
            name: "arg_shell_like".to_string(),
            args: vec!["&|<>^%".to_string()],
            stdin_payload: String::new(),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(3),
        },
        RuntimeScenario {
            name: "clean_env".to_string(),
            args: vec![],
            stdin_payload: "\n".to_string(),
            clear_env: true,
            timeout_secs: config.timeout_secs.min(3),
        },
        RuntimeScenario {
            name: "double_path_args".to_string(),
            args: vec![
                "C:\\this_path_should_not_exist_1.bin".to_string(),
                "C:\\this_path_should_not_exist_2.bin".to_string(),
            ],
            stdin_payload: String::new(),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(3),
        },
    ];

    scenarios.extend(build_fuzz_scenarios(config));

    if config.runs > scenarios.len() as u32 {
        for idx in (scenarios.len() as u32 + 1)..=config.runs {
            scenarios.push(RuntimeScenario {
                name: format!("extra_run_{}", idx),
                args: vec![],
                stdin_payload: "\n".to_string(),
                clear_env: false,
                timeout_secs: config.timeout_secs.min(3),
            });
        }
    }

    scenarios.truncate(config.runs as usize);
    scenarios
}

fn build_fuzz_scenarios(config: &Config) -> Vec<RuntimeScenario> {
    match config.fuzz_engine {
        FuzzEngine::Native => native_fuzz_scenarios(config),
        FuzzEngine::LibAfl => libafl_style_fuzz_scenarios(config),
    }
}

fn native_fuzz_scenarios(config: &Config) -> Vec<RuntimeScenario> {
    vec![
        RuntimeScenario {
            name: "fuzz_ascii_stdin".to_string(),
            args: vec![],
            stdin_payload: generate_fuzz_ascii(8192, 0xA51C_9331),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(3),
        },
        RuntimeScenario {
            name: "fuzz_unicode_stdin".to_string(),
            args: vec![],
            stdin_payload: generate_fuzz_unicode(2048, 0x0BAD_F00D),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(3),
        },
        RuntimeScenario {
            name: "fuzz_huge_stdin".to_string(),
            args: vec![],
            stdin_payload: "Ж".repeat(64_000),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(4),
        },
    ]
}

fn libafl_style_fuzz_scenarios(config: &Config) -> Vec<RuntimeScenario> {
    vec![
        RuntimeScenario {
            name: "libafl_seed_ascii".to_string(),
            args: vec![],
            stdin_payload: generate_fuzz_ascii(12_000, 0xD00D_BEEF),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(4),
        },
        RuntimeScenario {
            name: "libafl_seed_unicode".to_string(),
            args: vec![],
            stdin_payload: generate_fuzz_unicode(3_000, 0xBADC_0FFE),
            clear_env: false,
            timeout_secs: config.timeout_secs.min(4),
        },
    ]
}

fn run_single_runtime_scenario(
    config: &Config,
    scenario: &RuntimeScenario,
    findings: &mut Vec<Finding>,
) -> Option<RunResult> {
    println!("[SCENARIO] start {}", scenario.name);
    let start = Instant::now();
    let started_unix = current_unix();
    let mut trace_events = Vec::new();
    trace_events.push(RuntimeTraceEvent {
        at_ms: 0,
        stage: "scenario_start".to_string(),
        detail: format!(
            "args={} stdin_bytes={} clear_env={} timeout={}s",
            scenario.args.len(),
            scenario.stdin_payload.len(),
            scenario.clear_env,
            scenario.timeout_secs
        ),
    });

    let mut command = Command::new(&config.exe_path);
    command
        .args(&scenario.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if scenario.clear_env {
        command.env_clear();
        trace_events.push(RuntimeTraceEvent {
            at_ms: start.elapsed().as_millis(),
            stage: "sandbox_policy".to_string(),
            detail: "environment variables cleared".to_string(),
        });
    } else {
        trace_events.push(RuntimeTraceEvent {
            at_ms: start.elapsed().as_millis(),
            stage: "sandbox_policy".to_string(),
            detail: "environment inherited".to_string(),
        });
    }

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            findings.push(finding(
                Severity::Fail,
                "SPAWN_FAILED",
                "runtime",
                25,
                format!("Scenario '{}' failed to start: {}", scenario.name, e),
            ));
            return None;
        }
    };

    trace_events.push(RuntimeTraceEvent {
        at_ms: start.elapsed().as_millis(),
        stage: "process_spawned".to_string(),
        detail: format!("pid={}", child.id()),
    });

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(scenario.stdin_payload.as_bytes());
        trace_events.push(RuntimeTraceEvent {
            at_ms: start.elapsed().as_millis(),
            stage: "stdin_written".to_string(),
            detail: format!("bytes={}", scenario.stdin_payload.len()),
        });
    }

    let timeout = Duration::from_secs(scenario.timeout_secs.max(1));
    let timed_out = wait_with_timeout(&mut child, timeout, start, &scenario.name, findings)?;
    trace_events.push(RuntimeTraceEvent {
        at_ms: start.elapsed().as_millis(),
        stage: "wait_finished".to_string(),
        detail: if timed_out {
            "timed_out=true".to_string()
        } else {
            "timed_out=false".to_string()
        },
    });

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            findings.push(finding(
                Severity::Warn,
                "OUTPUT_CAPTURE_FAILED",
                "runtime",
                8,
                format!("Scenario '{}' output capture failed: {}", scenario.name, e),
            ));
            return None;
        }
    };

    trace_events.push(RuntimeTraceEvent {
        at_ms: start.elapsed().as_millis(),
        stage: "output_captured".to_string(),
        detail: format!("stdout={}B stderr={}B", output.stdout.len(), output.stderr.len()),
    });

    let duration_ms = start.elapsed().as_millis();
    let exit_code = output.status.code();
    let stdout_len = output.stdout.len();
    let stderr_len = output.stderr.len();
    let stdout_text = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_text = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();

    let failure_reason = push_runtime_findings(
        scenario,
        exit_code,
        timed_out,
        stderr_len,
        &stderr_text,
        findings,
    );

    trace_events.push(RuntimeTraceEvent {
        at_ms: duration_ms,
        stage: "scenario_finish".to_string(),
        detail: format!("exit={:?} reason={}", exit_code, failure_reason),
    });

    let finished_unix = current_unix();

    Some(RunResult {
        scenario: scenario.name.clone(),
        exit_code,
        timed_out,
        duration_ms,
        stdout_len,
        stderr_len,
        failure_reason,
        trace: RuntimeTrace {
            scenario_kind: scenario_kind(&scenario.name).to_string(),
            sandbox_profile: if scenario.clear_env {
                "isolated_env".to_string()
            } else {
                "baseline".to_string()
            },
            env_policy: if scenario.clear_env {
                "env_clear".to_string()
            } else {
                "inherit".to_string()
            },
            working_dir: std::env::current_dir()
                .ok()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
            started_unix,
            finished_unix,
            events: trace_events,
            stdout_preview: preview_text(&stdout_text, 320),
            stderr_preview: preview_text(&String::from_utf8_lossy(&output.stderr), 320),
        },
    })
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
    start: Instant,
    scenario_name: &str,
    findings: &mut Vec<Finding>,
) -> Option<bool> {
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    timed_out = true;
                    let _ = child.kill();
                    break;
                }
                thread::sleep(Duration::from_millis(40));
            }
            Err(e) => {
                findings.push(finding(
                    Severity::Fail,
                    "WAIT_FAILED",
                    "runtime",
                    20,
                    format!("Scenario '{}' wait failed: {}", scenario_name, e),
                ));
                return None;
            }
        }
    }
    Some(timed_out)
}

fn push_runtime_findings(
    scenario: &RuntimeScenario,
    exit_code: Option<i32>,
    timed_out: bool,
    stderr_len: usize,
    stderr_text: &str,
    findings: &mut Vec<Finding>,
) -> String {
    let mut reason = if timed_out {
        format!("timeout {}s exceeded", scenario.timeout_secs)
    } else if let Some(code) = exit_code {
        if is_windows_crash_exit(code) {
            format!("windows crash code {:#X}", code as u32)
        } else if code == 0 {
            "clean exit code 0".to_string()
        } else {
            format!("non-zero exit code {}", code)
        }
    } else {
        "process exited without normal code".to_string()
    };

    if timed_out {
        findings.push(finding(
            Severity::Fail,
            "RUNTIME_TIMEOUT",
            "runtime",
            25,
            format!(
                "Scenario '{}' exceeded timeout {} sec",
                scenario.name, scenario.timeout_secs
            ),
        ));
    } else if let Some(code) = exit_code {
        if is_windows_crash_exit(code) {
            findings.push(finding(
                Severity::Fail,
                "RUNTIME_CRASH_EXIT",
                "runtime",
                30,
                format!(
                    "Scenario '{}' crashed with NTSTATUS-like code {:#X}",
                    scenario.name, code as u32
                ),
            ));
        } else if code == 0 {
            findings.push(finding(
                Severity::Pass,
                "RUNTIME_EXIT_OK",
                "runtime",
                0,
                format!("Scenario '{}' exited with code 0", scenario.name),
            ));
        } else {
            findings.push(finding(
                Severity::Warn,
                "RUNTIME_NON_ZERO_EXIT",
                "runtime",
                8,
                format!("Scenario '{}' exited with code {}", scenario.name, code),
            ));
        }
    } else {
        findings.push(finding(
            Severity::Warn,
            "RUNTIME_NO_EXIT_CODE",
            "runtime",
            10,
            format!("Scenario '{}' exited without normal code", scenario.name),
        ));
    }

    if stderr_len > 0 {
        if reason == "clean exit code 0" {
            reason = format!("stderr output {} bytes", stderr_len);
        }
        findings.push(finding(
            Severity::Warn,
            "RUNTIME_STDERR_OUTPUT",
            "runtime",
            4,
            format!("Scenario '{}' produced {} bytes stderr", scenario.name, stderr_len),
        ));

        if stderr_text.contains("panic")
            || stderr_text.contains("traceback")
            || stderr_text.contains("segmentation fault")
            || stderr_text.contains("access violation")
            || stderr_text.contains("fatal")
        {
            reason = "crash signature found in stderr".to_string();
            findings.push(finding(
                Severity::Fail,
                "RUNTIME_CRASH_SIGNATURE",
                "runtime",
                28,
                format!(
                    "Scenario '{}' contains crash/panic signature in stderr",
                    scenario.name
                ),
            ));
        }
    }

    reason
}

fn scenario_kind(name: &str) -> &'static str {
    if name.contains("fuzz") {
        "fuzz"
    } else if name.contains("arg") || name.contains("stdin") {
        "input-stress"
    } else if name.contains("env") {
        "sandbox-env"
    } else {
        "baseline"
    }
}

fn preview_text(text: &str, max_chars: usize) -> String {
    let cleaned = text.replace('\n', "\\n").replace('\r', "");
    if cleaned.chars().count() <= max_chars {
        return cleaned;
    }
    cleaned.chars().take(max_chars).collect::<String>() + "..."
}

fn fuzz_next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn generate_fuzz_ascii(len: usize, initial_seed: u64) -> String {
    let mut seed = initial_seed.max(1);
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        let n = (fuzz_next(&mut seed) % 95) as u8;
        out.push((32 + n) as char);
    }
    out
}

fn generate_fuzz_unicode(len: usize, initial_seed: u64) -> String {
    const BANK: &[char] = &[
        'Ж', 'λ', '中', '火', 'ñ', 'ø', 'ß', 'Ω', '語', '🧪', '⚠', '𝛑', 'д', 'ا', 'א', 'क',
    ];
    let mut seed = initial_seed.max(1);
    let mut out = String::with_capacity(len * 2);
    for _ in 0..len {
        let idx = (fuzz_next(&mut seed) as usize) % BANK.len();
        out.push(BANK[idx]);
    }
    out
}

fn is_windows_crash_exit(code: i32) -> bool {
    let raw = code as u32;
    matches!(
        raw,
        0xC0000005
            | 0xC000001D
            | 0xC0000094
            | 0xC00000FD
            | 0xC0000135
            | 0xC0000139
            | 0xC0000409
            | 0x80000003
    )
}
