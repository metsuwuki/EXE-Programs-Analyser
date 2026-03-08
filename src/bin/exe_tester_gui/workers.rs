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

pub(crate) fn debug_worker_gdb(
    gdb_command: PathBuf,
    target: PathBuf,
    args: Vec<String>,
    timeout_secs: u64,
    cancel: Arc<AtomicBool>,
    control_rx: Receiver<DebugControl>,
    tx: Sender<UiEvent>,
) {
    let mut command = Command::new(&gdb_command);
    command
        .arg("--quiet")
        .arg("--nx")
        .arg("--args")
        .arg(&target)
        .args(&args)
        .stdin(Stdio::piped())
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
                stderr: format!(
                    "Failed to start gdb at '{}': {}. Install GDB (MSYS2: pacman -S mingw-w64-ucrt-x86_64-gdb) or set METSUKI_GDB_PATH.",
                    gdb_command.display(),
                    e,
                ),
            });
            return;
        }
    };

    let _ = tx.send(UiEvent::Log(format!(
        "[debug] GDB backend started ({})",
        gdb_command.display()
    )));

    let mut child_stdin = child.stdin.take();
    if let Some(stdin) = child_stdin.as_mut() {
        let _ = std::io::Write::write_all(stdin, b"set pagination off\n");
        let _ = std::io::Write::write_all(stdin, b"set confirm off\n");
        let _ = std::io::Write::write_all(stdin, b"run\n");
    }

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
        while let Ok(control) = control_rx.try_recv() {
            match control {
                DebugControl::Command(cmd) => {
                    if let Some(stdin) = child_stdin.as_mut() {
                        let mut line = cmd;
                        line.push('\n');
                        let _ = std::io::Write::write_all(stdin, line.as_bytes());
                    }
                }
                DebugControl::Stop => {
                    timed_out = true;
                    let _ = child.kill();
                }
            }
        }

        if timed_out {
            break;
        }

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

    drop(child_stdin);
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
        "[debug] Fallback debug mode started (no GDB step/backtrace)".to_string(),
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
