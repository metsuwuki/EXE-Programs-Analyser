use super::*;

pub(crate) fn scan_worker(
    target: PathBuf,
    out_dir: PathBuf,
    timeout: u64,
    runs: u32,
    strict_mode: bool,
    security_lab_enabled: bool,
    lab_profile: String,
    lab_custom_modules: Option<String>,
    lab_confirm_extended_tests: bool,
    cancel: Arc<AtomicBool>,
    tx: Sender<UiEvent>,
) {
    let _ = tx.send(UiEvent::Log("[worker] Resolving analysis engine path...".to_string()));
    let cli_path = match resolve_cli_path() {
        Some(p) => p,
        None => {
            let _ = tx.send(UiEvent::Log("[error] Cannot resolve internal analysis engine".to_string()));
            let _ = tx.send(UiEvent::Finished {
                exit_code: 2,
                report: None,
                report_path: None,
            });
            return;
        }
    };

    let _ = tx.send(UiEvent::Log(format!("[worker] CLI: {}", cli_path.display())));
    let _ = fs::create_dir_all(&out_dir);

    let mut command = Command::new(&cli_path);
    command
        .arg(&target)
        .arg("--timeout")
        .arg(timeout.to_string())
        .arg("--runs")
        .arg(runs.to_string())
        .arg("--out-dir")
        .arg(&out_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if strict_mode {
        command.arg("--strict");
    } else {
        command.arg("--balanced");
    }

    if !security_lab_enabled {
        command.arg("--no-security-lab");
    } else {
        command.arg("--lab-profile").arg(lab_profile);
        if let Some(modules) = lab_custom_modules {
            command.arg("--modules").arg(modules);
        }
        if lab_confirm_extended_tests {
            command.arg("--confirm-extended-tests");
        }
    }

    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
    }

    let _ = tx.send(UiEvent::Log("[worker] Starting analyzer subprocess...".to_string()));
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(UiEvent::Log(format!("[error] Failed to start analyzer: {}", e)));
            let _ = tx.send(UiEvent::Finished {
                exit_code: 2,
                report: None,
                report_path: None,
            });
            return;
        }
    };

    if let Some(stdout) = child.stdout.take() {
        let tx_out = tx.clone();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                let _ = tx_out.send(UiEvent::Log(format!("[cli] {}", line)));
            }
        });
    }

    if let Some(stderr) = child.stderr.take() {
        let tx_err = tx.clone();
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                let _ = tx_err.send(UiEvent::Log(format!("[cli:err] {}", line)));
            }
        });
    }

    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = tx.send(UiEvent::Log("[worker] Process killed by user".to_string()));
            let _ = tx.send(UiEvent::Finished {
                exit_code: 2,
                report: None,
                report_path: None,
            });
            return;
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                let exit_code = status.code().unwrap_or(2);
                let report_path = latest_report_json(&out_dir, &target);
                let report = report_path
                    .as_ref()
                    .and_then(|p| fs::read_to_string(p).ok())
                    .and_then(|text| serde_json::from_str::<ReportData>(&text).ok());

                if report.is_none() {
                    let _ = tx.send(UiEvent::Log("[warn] JSON report not found or parse failed".to_string()));
                }

                let _ = tx.send(UiEvent::Finished {
                    exit_code,
                    report,
                    report_path,
                });
                return;
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(120));
            }
            Err(e) => {
                let _ = tx.send(UiEvent::Log(format!("[error] Wait failed: {}", e)));
                let _ = tx.send(UiEvent::Finished {
                    exit_code: 2,
                    report: None,
                    report_path: None,
                });
                return;
            }
        }
    }
}

pub(crate) fn debug_worker_vsdbg(
    debugger_command: PathBuf,
    target: PathBuf,
    args: Vec<String>,
    timeout_secs: u64,
    cancel: Arc<AtomicBool>,
    control_rx: Receiver<DebugControl>,
    tx: Sender<UiEvent>,
) {
    if is_visual_studio_ide_executable(&debugger_command) {
        let _ = tx.send(UiEvent::DebugFinished {
            exit_code: None,
            timed_out: false,
            duration_ms: 0,
            stdout: String::new(),
            stderr: format!(
                "Unsupported debugger path '{}': Visual Studio IDE launch is disabled. Use vsdbg.exe.",
                debugger_command.display()
            ),
        });
        return;
    }

    let mut command = build_visual_debugger_command(&debugger_command, &target, &args);
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
    }

    let start = Instant::now();
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(UiEvent::DebugFinished {
                exit_code: None,
                timed_out: false,
                duration_ms: start.elapsed().as_millis(),
                stdout: String::new(),
                stderr: format!(
                    "Failed to start Visual Studio debugger at '{}': {}. Install Visual Studio debugger tools or set METSUKI_VSDBG_PATH.",
                    debugger_command.display(),
                    e,
                ),
            });
            return;
        }
    };

    let _ = tx.send(UiEvent::Log(format!(
        "[debug] Visual Studio debugger backend started ({})",
        debugger_command.display()
    )));

    let mut stream_threads = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        stream_threads.push(spawn_debug_stream(stdout, false, tx.clone()));
    }
    if let Some(stderr) = child.stderr.take() {
        stream_threads.push(spawn_debug_stream(stderr, true, tx.clone()));
    }

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut timed_out = false;
    let mut stop_requested = false;
    let mut exit_code: Option<i32> = None;

    loop {
        while let Ok(control) = control_rx.try_recv() {
            match control {
                DebugControl::Command(cmd) => {
                    let _ = tx.send(UiEvent::Log(format!(
                        "[debug] Interactive command '{}' ignored: handled by Visual Studio debugger UI",
                        cmd
                    )));
                }
                DebugControl::Stop => {
                    stop_requested = true;
                    let _ = child.kill();
                }
            }
        }

        if timed_out || stop_requested {
            break;
        }

        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            break;
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                break;
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    timed_out = true;
                    let _ = child.kill();
                    break;
                }
                thread::sleep(Duration::from_millis(35));
            }
            Err(e) => {
                let _ = tx.send(UiEvent::DebugFinished {
                    exit_code: None,
                    timed_out: false,
                    duration_ms: start.elapsed().as_millis(),
                    stdout: String::new(),
                    stderr: format!("Wait error: {}", e),
                });
                return;
            }
        }
    }

    if exit_code.is_none() {
        if let Ok(status) = child.wait() {
            exit_code = status.code();
        }
    }

    for handle in stream_threads {
        let _ = handle.join();
    }

    let _ = tx.send(UiEvent::DebugFinished {
        exit_code,
        timed_out,
        duration_ms: start.elapsed().as_millis(),
        stdout: String::new(),
        stderr: String::new(),
    });
}

pub(crate) fn install_vsdbg_worker(tx: Sender<UiEvent>) {
    #[cfg(not(windows))]
    {
        let _ = tx.send(UiEvent::VsdbgInstallFinished {
            success: false,
            path: None,
            details: "Automatic vsdbg install is currently supported only on Windows".to_string(),
        });
        return;
    }

    #[cfg(windows)]
    {
        let Some(user_profile) = env::var_os("USERPROFILE") else {
            let _ = tx.send(UiEvent::VsdbgInstallFinished {
                success: false,
                path: None,
                details: "USERPROFILE is not set; cannot resolve vsdbg install path".to_string(),
            });
            return;
        };

        let install_root = PathBuf::from(&user_profile).join("vsdbg");
        let script_path = PathBuf::from(&user_profile).join("getvsdbg.ps1");
        let install_root_ps = install_root.display().to_string().replace('\'', "''");
        let script_path_ps = script_path.display().to_string().replace('\'', "''");

        let _ = tx.send(UiEvent::Log(
            "[vsdbg] Downloading installer script from https://aka.ms/getvsdbgps1".to_string(),
        ));

        let download_command = format!(
            "Invoke-WebRequest https://aka.ms/getvsdbgps1 -OutFile '{}'",
            script_path_ps
        );

        let download_output = match run_powershell_command(&download_command) {
            Ok(output) => output,
            Err(e) => {
                let _ = tx.send(UiEvent::VsdbgInstallFinished {
                    success: false,
                    path: None,
                    details: e,
                });
                return;
            }
        };

        if !download_output.status.success() {
            let _ = tx.send(UiEvent::VsdbgInstallFinished {
                success: false,
                path: None,
                details: format!(
                    "getvsdbg.ps1 download failed. {}",
                    output_summary(&download_output)
                ),
            });
            return;
        }

        let _ = tx.send(UiEvent::Log(format!(
            "[vsdbg] Running installer: getvsdbg.ps1 -Version latest -RuntimeID win-x64 -InstallPath {}",
            install_root.display()
        )));

        let install_command = format!(
            "& '{}' -Version latest -RuntimeID win-x64 -InstallPath '{}'",
            script_path_ps,
            install_root_ps
        );

        let install_output = match run_powershell_command(&install_command) {
            Ok(output) => output,
            Err(e) => {
                let _ = tx.send(UiEvent::VsdbgInstallFinished {
                    success: false,
                    path: None,
                    details: e,
                });
                return;
            }
        };

        if !install_output.status.success() {
            let _ = tx.send(UiEvent::VsdbgInstallFinished {
                success: false,
                path: None,
                details: format!("vsdbg installation failed. {}", output_summary(&install_output)),
            });
            return;
        }

        let vsdbg_path = detect_vsdbg_command().or_else(|| {
            let candidate = install_root.join("vsdbg.exe");
            if vsdbg_probe_available(&candidate) {
                Some(candidate)
            } else {
                None
            }
        });

        let Some(vsdbg_path) = vsdbg_path else {
            let _ = tx.send(UiEvent::VsdbgInstallFinished {
                success: false,
                path: None,
                details: format!(
                    "vsdbg installation finished but vsdbg.exe was not discovered. Install root: '{}'. {}",
                    install_root.display(),
                    output_summary(&install_output)
                ),
            });
            return;
        };

        let mut verify = Command::new(&vsdbg_path);
        verify.arg("--help").stdout(Stdio::piped()).stderr(Stdio::piped());
        verify.creation_flags(0x08000000);
        let verify_details = match verify.output() {
            Ok(output) => {
                let summary = output_summary(&output);
                if summary.trim().is_empty() {
                    "vsdbg --help returned no output".to_string()
                } else {
                    summary
                }
            }
            Err(e) => format!("Installed, but verification failed: {}", e),
        };

        let _ = tx.send(UiEvent::VsdbgInstallFinished {
            success: true,
            path: Some(vsdbg_path),
            details: verify_details,
        });
    }
}

fn build_visual_debugger_command(debugger_command: &Path, target: &Path, args: &[String]) -> Command {
    let mut command = Command::new(debugger_command);
    command.arg("--").arg(target).args(args);

    command
}

#[cfg(windows)]
fn run_powershell_command(script: &str) -> Result<std::process::Output, String> {
    let mut command = Command::new("powershell");
    command
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.creation_flags(0x08000000);

    command
        .output()
        .map_err(|e| format!("Failed to run PowerShell command: {}", e))
}

fn output_summary(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let total_line_count = stdout.lines().count() + stderr.lines().count();
    let mut lines = stdout
        .lines()
        .chain(stderr.lines())
        .filter(|line| !line.trim().is_empty())
        .take(18)
        .map(|line| line.trim().to_string())
        .collect::<Vec<_>>();

    if lines.is_empty() {
        return String::new();
    }

    if total_line_count > 18 {
        lines.push("...".to_string());
    }
    lines.join("\n")
}

fn is_visual_studio_ide_executable(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.eq_ignore_ascii_case("devenv.exe") || name.eq_ignore_ascii_case("devenv"))
        .unwrap_or(false)
}

pub(crate) fn debug_worker_native(
    target: PathBuf,
    args: Vec<String>,
    timeout_secs: u64,
    cancel: Arc<AtomicBool>,
    tx: Sender<UiEvent>,
) {
    let mut command = Command::new(&target);
    command
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
    }

    let start = Instant::now();
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(UiEvent::DebugFinished {
                exit_code: None,
                timed_out: false,
                duration_ms: start.elapsed().as_millis(),
                stdout: String::new(),
                stderr: format!("Failed to start target in fallback debug mode: {}", e),
            });
            return;
        }
    };

    let _ = tx.send(UiEvent::Log(
        "[debug] Fallback debug mode started (without Visual Studio debugger integration)".to_string(),
    ));

    let mut stream_threads = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        stream_threads.push(spawn_debug_stream(stdout, false, tx.clone()));
    }
    if let Some(stderr) = child.stderr.take() {
        stream_threads.push(spawn_debug_stream(stderr, true, tx.clone()));
    }

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut timed_out = false;
    let mut exit_code: Option<i32> = None;

    loop {
        if cancel.load(Ordering::Relaxed) {
            timed_out = true;
            let _ = child.kill();
            break;
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                break;
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    timed_out = true;
                    let _ = child.kill();
                    break;
                }
                thread::sleep(Duration::from_millis(35));
            }
            Err(e) => {
                let _ = tx.send(UiEvent::DebugFinished {
                    exit_code: None,
                    timed_out: false,
                    duration_ms: start.elapsed().as_millis(),
                    stdout: String::new(),
                    stderr: format!("Wait error: {}", e),
                });
                return;
            }
        }
    }

    if exit_code.is_none() {
        if let Ok(status) = child.wait() {
            exit_code = status.code();
        }
    }

    for handle in stream_threads {
        let _ = handle.join();
    }

    let _ = tx.send(UiEvent::DebugFinished {
        exit_code,
        timed_out,
        duration_ms: start.elapsed().as_millis(),
        stdout: String::new(),
        stderr: String::new(),
    });
}

fn spawn_debug_stream<R>(stream: R, is_stderr: bool, tx: Sender<UiEvent>) -> thread::JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut buf = [0_u8; 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let text = String::from_utf8_lossy(&buf[..n]).to_string();
                    let _ = tx.send(UiEvent::DebugOutput { is_stderr, text });
                }
                Err(_) => break,
            }
        }
    })
}

fn resolve_cli_path() -> Option<PathBuf> {
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
        candidates.push(ancestor.join("debug").join("exe_tester.exe"));
        candidates.push(ancestor.join("release").join("exe_tester.exe"));
    }

    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

fn latest_report_json(out_dir: &Path, target: &Path) -> Option<PathBuf> {
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
