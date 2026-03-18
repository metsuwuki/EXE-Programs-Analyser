#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[path = "../core.rs"]
mod core;

use core::{AnalysisMode, AppSettings, ReportSummary};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::{Icon, WindowBuilder};
use wry::{WebView, WebViewBuilder};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[derive(Debug, Deserialize)]
struct IpcRequest {
    id: String,
    cmd: String,
    #[serde(default)]
    payload: Value,
}

#[derive(Debug, Serialize)]
struct IpcEnvelope {
    #[serde(rename = "type")]
    envelope_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<String>,
}

#[derive(Debug)]
enum UserEvent {
    Ipc(String),
    AnalysisLog(String),
    AnalysisFinished {
        exit_code: i32,
        report_path: Option<String>,
    },
}

#[derive(Debug)]
struct RunningAnalysis {
    cancel: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
struct AppState {
    settings: AppSettings,
    running: Option<RunningAnalysis>,
    last_reports: Vec<ReportSummary>,
}

#[derive(Debug, Deserialize)]
struct RunAnalysisPayload {
    target_path: String,
    mode: String,
    runs: u32,
    timeout_secs: u64,
    out_dir: String,
    #[serde(default)]
    confirm_pentest: bool,
}

#[derive(Debug, Deserialize)]
struct OpenPathPayload {
    path: String,
}

#[derive(Debug, Deserialize)]
struct ListReportsPayload {
    out_dir: String,
}

#[derive(Debug, Deserialize)]
struct OpenReportPayload {
    path: String,
}

#[derive(Debug, Deserialize)]
struct ReproBundlePayload {
    report_path: String,
    target_path: String,
    mode: String,
}

#[derive(Debug, Deserialize)]
struct RerunPayload {
    scenario: String,
    target_path: String,
    mode: String,
}

fn main() {
    if let Err(err) = run_app() {
        let msg = format!("Metsuki fatal error:\n{}", err);
        // Write crash log so the user can see it
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let _ = std::fs::write(dir.join("crash.log"), &msg);
            }
        }
        eprintln!("{}", msg);
    }
}

fn run_app() -> Result<(), String> {
    let mut state = AppState {
        settings: core::load_settings(),
        ..AppState::default()
    };

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let window_icon = load_window_icon();

    let window = WindowBuilder::new()
        .with_title("Metsuki Workbench")
        .with_inner_size(LogicalSize::new(1440.0, 900.0))
        .with_min_inner_size(LogicalSize::new(1024.0, 680.0))
        .with_window_icon(window_icon)
        .with_visible(false)
        .build(&event_loop)
        .map_err(|e| format!("window creation failed: {}", e))?;

    let logo_uri = resolve_logo_uri();
    let html = include_str!("../../webui/index.html").replace("..\\assets\\logo.png", &logo_uri);
    let proxy_for_ipc = proxy.clone();
    let webview_builder = WebViewBuilder::new()
        .with_html(html)
        .with_ipc_handler(move |request: wry::http::Request<String>| {
            let _ = proxy_for_ipc.send_event(UserEvent::Ipc(request.body().to_string()));
        });

    let webview = webview_builder
        .build(&window)
        .map_err(|e| format!("webview build failed: {}", e))?;

    window.set_visible(true);

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                window.set_visible(false);
                *control_flow = ControlFlow::Exit;
            }
            Event::UserEvent(UserEvent::Ipc(message)) => {
                handle_ipc(&webview, &mut state, &proxy, &message);
            }
            Event::UserEvent(UserEvent::AnalysisLog(line)) => {
                emit_event(&webview, "analysis-log", json!(line));
            }
            Event::UserEvent(UserEvent::AnalysisFinished {
                exit_code,
                report_path,
            }) => {
                state.running = None;
                let payload = json!({
                    "exitCode": exit_code,
                    "reportPath": report_path,
                });
                emit_event(&webview, "analysis-finished", payload);
            }
            _ => {}
        }
    });

    #[allow(unreachable_code)]
    Ok(())
}

fn load_window_icon() -> Option<Icon> {
    let bytes = include_bytes!("../../assets/icon.ico");
    let image = image::load_from_memory(bytes).ok()?.to_rgba8();
    let (width, height) = image.dimensions();
    Icon::from_rgba(image.into_raw(), width, height).ok()
}

fn resolve_logo_uri() -> String {
    let mut candidates: Vec<PathBuf> = Vec::new();
    let names = [
        "metsuki_logo.png",
        "metsuki-logo.png",
        "logo.png",
        "logo.webp",
        "logo.jpg",
        "logo.jpeg",
    ];

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in names {
                candidates.push(dir.join("assets").join(name));
                candidates.push(dir.join(name));
            }
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        for name in names {
            candidates.push(cwd.join("assets").join(name));
            candidates.push(cwd.join(name));
        }
    }

    for name in names {
        candidates.push(PathBuf::from("assets").join(name));
        candidates.push(PathBuf::from(name));
    }

    // Last-resort fallback: use bundled logo only when no neighbor asset exists.
    if let Ok(tmp_logo) = ensure_temp_logo_file() {
        candidates.push(tmp_logo);
    }

    for candidate in candidates {
        if let Ok(abs) = candidate.canonicalize() {
            return file_uri_from_path(&abs);
        }
    }

    String::new()
}

fn file_uri_from_path(path: &Path) -> String {
    let mut p = path.to_string_lossy().replace('\\', "/");
    if !p.starts_with('/') {
        p = format!("/{}", p);
    }

    let mut encoded = String::with_capacity(p.len() + 16);
    for b in p.as_bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(*b, b'-' | b'_' | b'.' | b'~' | b'/' | b':');
        if keep {
            encoded.push(*b as char);
        } else {
            encoded.push_str(&format!("%{:02X}", b));
        }
    }
    format!("file://{}", encoded)
}

fn ensure_temp_logo_file() -> Result<PathBuf, String> {
    let bytes = include_bytes!("../../assets/logo.png");
    let dir = std::env::temp_dir().join("metsuki_workbench_assets");
    fs::create_dir_all(&dir).map_err(|e| format!("temp assets dir create failed: {}", e))?;
    let path = dir.join("logo.png");
    fs::write(&path, bytes).map_err(|e| format!("temp logo write failed: {}", e))?;
    Ok(path)
}

fn handle_ipc(
    webview: &WebView,
    state: &mut AppState,
    proxy: &EventLoopProxy<UserEvent>,
    raw: &str,
) {
    let req: IpcRequest = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            let envelope = IpcEnvelope {
                envelope_type: "event".to_string(),
                id: None,
                ok: None,
                payload: None,
                error: Some(format!("invalid IPC payload: {}", e)),
                event: Some("host-error".to_string()),
            };
            send_to_webview(webview, &envelope);
            return;
        }
    };

    let response = match req.cmd.as_str() {
        "load_settings" => Ok(json!(state.settings)),
        "save_settings" => {
            let parsed: Result<AppSettings, _> = serde_json::from_value(req.payload.clone());
            match parsed {
                Ok(next) => {
                    state.settings = next;
                    match core::save_settings(&state.settings) {
                        Ok(()) => Ok(json!({"saved": true})),
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(format!("settings payload is invalid: {}", e)),
            }
        }
        "list_reports" => {
            let payload: Result<ListReportsPayload, _> = serde_json::from_value(req.payload.clone());
            match payload {
                Ok(v) => {
                    let out_dir = if v.out_dir.trim().is_empty() {
                        PathBuf::from("logs")
                    } else {
                        PathBuf::from(v.out_dir)
                    };
                    let rows = core::list_reports(&out_dir);
                    state.last_reports = rows.clone();
                    Ok(json!(rows))
                }
                Err(e) => Err(format!("list_reports payload invalid: {}", e)),
            }
        }
        "open_report" => {
            let payload: Result<OpenReportPayload, _> = serde_json::from_value(req.payload.clone());
            match payload {
                Ok(v) => core::read_report_json(Path::new(&v.path)),
                Err(e) => Err(format!("open_report payload invalid: {}", e)),
            }
        }
        "open_path" => {
            let payload: Result<OpenPathPayload, _> = serde_json::from_value(req.payload.clone());
            match payload {
                Ok(v) => {
                    if v.path.trim().is_empty() {
                        Err("path is empty".to_string())
                    } else {
                        core::open_path_in_explorer(Path::new(&v.path)).map(|_| json!({"opened": true}))
                    }
                }
                Err(e) => Err(format!("open_path payload invalid: {}", e)),
            }
        }
        "pick_target" => pick_target_file(),
        "tools_status" => Ok(tools_status(&state.settings)),
        "run_analysis" => {
            let payload: Result<RunAnalysisPayload, _> = serde_json::from_value(req.payload.clone());
            match payload {
                Ok(v) => start_analysis(state, proxy.clone(), v).map(|_| json!({"started": true})),
                Err(e) => Err(format!("run_analysis payload invalid: {}", e)),
            }
        }
        "stop_analysis" => {
            if let Some(run) = &state.running {
                run.cancel.store(true, Ordering::Relaxed);
                Ok(json!({"stopRequested": true}))
            } else {
                Ok(json!({"stopRequested": false, "reason": "no-running-analysis"}))
            }
        }
        "create_repro_bundle" => {
            let payload: Result<ReproBundlePayload, _> = serde_json::from_value(req.payload.clone());
            match payload {
                Ok(v) => create_repro_bundle(v),
                Err(e) => Err(format!("create_repro_bundle payload invalid: {}", e)),
            }
        }
        "rerun_scenario" => {
            let payload: Result<RerunPayload, _> = serde_json::from_value(req.payload.clone());
            match payload {
                Ok(v) => {
                    let mode = parse_mode(&v.mode);
                    let result = launch_scenario_rerun(proxy.clone(), v.target_path, mode, v.scenario);
                    result.map(|_| json!({"accepted": true}))
                }
                Err(e) => Err(format!("rerun_scenario payload invalid: {}", e)),
            }
        }
        _ => Err(format!("unknown command: {}", req.cmd)),
    };

    let envelope = match response {
        Ok(payload) => IpcEnvelope {
            envelope_type: "response".to_string(),
            id: Some(req.id),
            ok: Some(true),
            payload: Some(payload),
            error: None,
            event: None,
        },
        Err(error) => IpcEnvelope {
            envelope_type: "response".to_string(),
            id: Some(req.id),
            ok: Some(false),
            payload: None,
            error: Some(error),
            event: None,
        },
    };

    send_to_webview(webview, &envelope);
}

fn pick_target_file() -> Result<Value, String> {
    let dialog = rfd::FileDialog::new()
        .add_filter("Executable files", &["exe", "com", "bat", "cmd", "ps1", "scr"])
        .set_title("Choose target program");

    match dialog.pick_file() {
        Some(path) => Ok(json!({ "path": path.to_string_lossy().to_string() })),
        None => Ok(json!({ "path": null })),
    }
}

fn start_analysis(
    state: &mut AppState,
    proxy: EventLoopProxy<UserEvent>,
    payload: RunAnalysisPayload,
) -> Result<(), String> {
    if state.running.is_some() {
        return Err("analysis is already running".to_string());
    }

    let target = PathBuf::from(payload.target_path.trim().trim_matches('"'));
    if !target.exists() {
        return Err("target file does not exist".to_string());
    }

    let out_dir = if payload.out_dir.trim().is_empty() {
        PathBuf::from("logs")
    } else {
        PathBuf::from(payload.out_dir.trim())
    };
    fs::create_dir_all(&out_dir).map_err(|e| format!("cannot create out_dir: {}", e))?;

    let cli_path = core::resolve_cli_path().ok_or_else(|| {
        "cannot resolve analyzer core executable. Expected .engine/analyzer_core.exe or exe_tester.exe".to_string()
    })?;

    let mode = parse_mode(&payload.mode);
    if mode == AnalysisMode::Pentest && !payload.confirm_pentest {
        return Err("PENTEST mode requires explicit opt-in: enable 'confirm pentest extended tests'".to_string());
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_worker = Arc::clone(&cancel);
    let target_for_worker = target.clone();
    let out_dir_for_worker = out_dir.clone();

    thread::spawn(move || {
        let mut command = Command::new(cli_path);
        command
            .arg(&target_for_worker)
            .arg("--timeout")
            .arg(payload.timeout_secs.max(1).to_string())
            .arg("--runs")
            .arg(payload.runs.max(1).to_string())
            .arg("--out-dir")
            .arg(&out_dir_for_worker)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        match mode {
            AnalysisMode::Min => {
                command.arg("--mode-min");
            }
            AnalysisMode::Pentest => {
                command.arg("--mode-pentest");
                command.arg("--confirm-extended-tests");
            }
        }

        #[cfg(windows)]
        {
            command.creation_flags(0x08000000);
        }

        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = proxy.send_event(UserEvent::AnalysisLog(format!(
                    "[error] failed to start analyzer: {}",
                    e
                )));
                let _ = proxy.send_event(UserEvent::AnalysisFinished {
                    exit_code: 2,
                    report_path: None,
                });
                return;
            }
        };

        if let Some(stdout) = child.stdout.take() {
            let tx = proxy.clone();
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines().map_while(Result::ok) {
                    let _ = tx.send_event(UserEvent::AnalysisLog(format!("[cli] {}", line)));
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let tx = proxy.clone();
            thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines().map_while(Result::ok) {
                    let _ = tx.send_event(UserEvent::AnalysisLog(format!("[cli:err] {}", line)));
                }
            });
        }

        let exit_code = loop {
            if cancel_for_worker.load(Ordering::Relaxed) {
                let _ = child.kill();
                break 2;
            }

            match child.try_wait() {
                Ok(Some(status)) => break status.code().unwrap_or(2),
                Ok(None) => thread::sleep(std::time::Duration::from_millis(80)),
                Err(_) => break 2,
            }
        };

        let report_path = core::latest_report_for_target(&out_dir_for_worker, &target_for_worker)
            .map(|p| p.display().to_string());

        let _ = proxy.send_event(UserEvent::AnalysisFinished {
            exit_code,
            report_path,
        });
    });

    state.running = Some(RunningAnalysis {
        cancel,
    });

    Ok(())
}

fn launch_scenario_rerun(
    proxy: EventLoopProxy<UserEvent>,
    target_path: String,
    mode: AnalysisMode,
    scenario: String,
) -> Result<(), String> {
    let target = PathBuf::from(target_path.trim().trim_matches('"'));
    if !target.exists() {
        return Err("target file for rerun not found".to_string());
    }

    let cli_path = core::resolve_cli_path().ok_or_else(|| "cannot resolve analyzer core executable".to_string())?;

    thread::spawn(move || {
        let mut command = Command::new(cli_path);
        command
            .arg(&target)
            .arg("--timeout")
            .arg("4")
            .arg("--runs")
            .arg("1")
            .arg("--out-dir")
            .arg("logs");

        match mode {
            AnalysisMode::Min => {
                command.arg("--mode-min");
            }
            AnalysisMode::Pentest => {
                command.arg("--mode-pentest");
                command.arg("--confirm-extended-tests");
            }
        }

        #[cfg(windows)]
        {
            command.creation_flags(0x08000000);
        }

        let _ = proxy.send_event(UserEvent::AnalysisLog(format!(
            "[rerun] scenario='{}' mapped to single-run replay",
            scenario
        )));

        match command.output() {
            Ok(output) => {
                let out = String::from_utf8_lossy(&output.stdout);
                for line in out.lines().take(60) {
                    let _ = proxy.send_event(UserEvent::AnalysisLog(format!("[rerun] {}", line)));
                }
            }
            Err(e) => {
                let _ = proxy.send_event(UserEvent::AnalysisLog(format!(
                    "[rerun:error] {}",
                    e
                )));
            }
        }
    });

    Ok(())
}

fn create_repro_bundle(payload: ReproBundlePayload) -> Result<Value, String> {
    let report_path = PathBuf::from(payload.report_path.trim());
    if !report_path.exists() {
        return Err("report file was not found".to_string());
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let base_dir = report_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let bundle_dir = base_dir.join(format!("repro_bundle_{}", ts));
    fs::create_dir_all(&bundle_dir).map_err(|e| format!("cannot create bundle dir: {}", e))?;

    let report_copy = bundle_dir.join(
        report_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("report.json"),
    );
    fs::copy(&report_path, &report_copy).map_err(|e| format!("cannot copy report: {}", e))?;

    let rerun_cmd = bundle_dir.join("rerun.cmd");
    let lines = [
        "@echo off".to_string(),
        "setlocal".to_string(),
        "chcp 65001 >nul".to_string(),
        format!("REM target: {}", payload.target_path),
        format!("REM mode: {}", payload.mode),
        "echo Run this command in repository root:".to_string(),
        format!(
            "echo cargo run --bin exe_tester -- \"{}\" --mode-{} --confirm-extended-tests",
            payload.target_path,
            payload.mode.to_ascii_lowercase()
        ),
    ];
    fs::write(&rerun_cmd, lines.join("\r\n")).map_err(|e| format!("cannot write rerun.cmd: {}", e))?;

    Ok(json!({
        "path": bundle_dir.display().to_string(),
        "reportCopy": report_copy.display().to_string(),
    }))
}

fn tools_status(settings: &AppSettings) -> Value {
    let vsdbg_status = settings
        .vsdbg_path
        .as_ref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| {
            if Path::new(p).exists() {
                "ready"
            } else {
                "configured-missing"
            }
        })
        .unwrap_or("not-configured");

    let linters_status = if settings.linter_paths.is_empty() {
        "not-configured"
    } else if settings
        .linter_paths
        .iter()
        .all(|p| !p.trim().is_empty() && Path::new(p).exists())
    {
        "ready"
    } else {
        "partial"
    };

    json!({
        "vsdbg": vsdbg_status,
        "linters": linters_status,
    })
}

fn parse_mode(input: &str) -> AnalysisMode {
    match input.trim().to_ascii_uppercase().as_str() {
        "PENTEST" => AnalysisMode::Pentest,
        _ => AnalysisMode::Min,
    }
}

fn send_to_webview(webview: &WebView, envelope: &IpcEnvelope) {
    let payload = match serde_json::to_string(envelope) {
        Ok(v) => v,
        Err(_) => return,
    };
    let script = format!("window.__METSUKI_HOST_DISPATCH({});", payload);
    let _ = webview.evaluate_script(&script);
}

fn emit_event(webview: &WebView, event: &str, payload: Value) {
    let envelope = IpcEnvelope {
        envelope_type: "event".to_string(),
        id: None,
        ok: None,
        payload: Some(payload),
        error: None,
        event: Some(event.to_string()),
    };
    send_to_webview(webview, &envelope);
}
