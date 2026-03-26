#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use exe_tester::core;
use exe_tester::shared;
use core::{AppSettings, ReportSummary};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::AnalysisMode;
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
    #[serde(default)]
    verdict_mode: Option<String>,
    #[serde(default)]
    power_profile: Option<String>,
    #[serde(default)]
    sandbox_profile: Option<String>,
    runs: u32,
    timeout_secs: u64,
    out_dir: String,
    #[serde(default)]
    assignment_path: Option<String>,
    #[serde(default)]
    audit_dir: Option<String>,
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
struct DetectTargetTypePayload {
    path: String,
}

#[derive(Debug, Deserialize)]
struct ReportLogsPayload {
    report_path: String,
}

#[derive(Debug, Deserialize)]
struct ReproBundlePayload {
    report_path: String,
    target_path: String,
    mode: String,
}

#[derive(Debug, Deserialize)]
struct ExportReportPayload {
    report_path: String,
    format: String,
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
    let html = include_str!("../../webui/index.html")
        .replace("__INLINE_CSS__", include_str!("../../webui/styles.css"))
        .replace(
            "__INLINE_JS__",
            concat!(
                include_str!("../../webui/js/01_i18n.js"),
                "\n",
                include_str!("../../webui/js/02_core.js"),
                "\n",
                include_str!("../../webui/js/03_app.js")
            ),
        )
        .replace("..\\assets\\logo.png", &logo_uri);
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
    // Normalise path separators and ensure it is absolute-looking.
    let mut p = path.to_string_lossy().replace('\\', "/");
    if !p.starts_with('/') {
        p = format!("/{}", p);
    }

    // Percent-encode the path component.
    // Unreserved chars (RFC 3986 §2.3) + '/' and ':' (drive letter / separators)
    // are passed through verbatim; everything else — including '#', '?', '[', ']',
    // spaces, and non-ASCII UTF-8 bytes — is encoded as %XX.
    let mut encoded = String::with_capacity(p.len() + 32);
    for byte in p.as_bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(*byte, b'-' | b'_' | b'.' | b'~' | b'/' | b':' | b'@' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=');
        if keep {
            encoded.push(*byte as char);
        } else {
            encoded.push_str(&format!("%{:02X}", byte));
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
        "list_reports" => handle_list_reports(state, req.payload.clone()),
        "open_report" => handle_open_report(req.payload.clone()),
        "list_logs_for_report" => handle_list_logs_for_report(req.payload.clone()),
        "open_path" => handle_open_path(req.payload.clone()),
        "detect_target_type" => handle_detect_target_type(req.payload.clone()),
        "pick_target" => pick_target_file(),
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
        "export_report" => handle_export_report(req.payload.clone()),
        "rerun_scenario" => {
            let payload: Result<RerunPayload, _> = serde_json::from_value(req.payload.clone());
            match payload {
                Ok(v) => {
                    let mode = parse_mode(&v.mode);
                    let result = launch_scenario_rerun(
                        proxy.clone(),
                        v.target_path,
                        mode,
                        v.scenario,
                        state.settings.analyzer_path.clone(),
                    );
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

fn handle_list_reports(state: &mut AppState, payload_value: Value) -> Result<Value, String> {
    let payload: Result<ListReportsPayload, _> = serde_json::from_value(payload_value);
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

fn handle_open_report(payload_value: Value) -> Result<Value, String> {
    let payload: Result<OpenReportPayload, _> = serde_json::from_value(payload_value);
    match payload {
        Ok(v) => {
            let report_path = sanitize_local_path(&v.path)?;
            core::read_report_json(&report_path)
        }
        Err(e) => Err(format!("open_report payload invalid: {}", e)),
    }
}

fn handle_list_logs_for_report(payload_value: Value) -> Result<Value, String> {
    let payload: Result<ReportLogsPayload, _> = serde_json::from_value(payload_value);
    match payload {
        Ok(v) => {
            let report_path = sanitize_local_path(&v.report_path)?;
            if !report_path.exists() {
                Err("report file was not found".to_string())
            } else {
                let (full_log, issues_log) = core::list_logs_for_report(&report_path);
                Ok(json!({
                    "json_report": report_path.display().to_string(),
                    "full_log": full_log,
                    "issues_log": issues_log,
                }))
            }
        }
        Err(e) => Err(format!("list_logs_for_report payload invalid: {}", e)),
    }
}

fn handle_open_path(payload_value: Value) -> Result<Value, String> {
    let payload: Result<OpenPathPayload, _> = serde_json::from_value(payload_value);
    match payload {
        Ok(v) => {
            if v.path.trim().is_empty() {
                Err("path is empty".to_string())
            } else {
                if is_http_url(&v.path) {
                    core::open_path_in_explorer(v.path.trim()).map(|_| json!({"opened": true}))
                } else {
                    let local_path = sanitize_local_path(&v.path)?;
                    core::open_path_in_explorer(&local_path.display().to_string())
                        .map(|_| json!({"opened": true}))
                }
            }
        }
        Err(e) => Err(format!("open_path payload invalid: {}", e)),
    }
}

fn is_http_url(path: &str) -> bool {
    let v = path.trim().to_ascii_lowercase();
    v.starts_with("http://") || v.starts_with("https://")
}

fn sanitize_local_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("path is empty".to_string());
    }
    if trimmed.starts_with("\\\\") {
        return Err("UNC paths are not allowed in IPC operations".to_string());
    }

    let path = PathBuf::from(trimmed);
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("parent directory traversal is not allowed".to_string());
    }

    Ok(path)
}

fn handle_detect_target_type(payload_value: Value) -> Result<Value, String> {
    let payload: Result<DetectTargetTypePayload, _> = serde_json::from_value(payload_value);
    match payload {
        Ok(v) => {
            let path = PathBuf::from(v.path.trim());
            let info = core::detect_target_type(&path);
            Ok(json!({
                "kind": info.kind,
                "language": info.language,
            }))
        }
        Err(e) => Err(format!("detect_target_type payload invalid: {}", e)),
    }
}

fn pick_target_file() -> Result<Value, String> {
    let dialog = rfd::FileDialog::new()
        .add_filter("Executable files", &["exe"])
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

    let cli_path = core::resolve_cli_path_with_override(state.settings.analyzer_path.as_deref())
        .ok_or_else(|| {
            "cannot resolve analysis engine executable. Expected configured analyzer_path, .engine/analyzer_core.exe, or exe_tester.exe".to_string()
        })?;

    let run_plan = resolve_run_plan(&payload, &state.settings);
    if run_plan.mode == AnalysisMode::Pentest && !payload.confirm_pentest {
        return Err("PENTEST mode requires explicit opt-in: enable 'confirm pentest extended tests'".to_string());
    }

    let _ = proxy.send_event(UserEvent::AnalysisLog(format!(
        "[profile] power={} verdict={} sandbox={}",
        run_plan.profile, run_plan.verdict_mode, run_plan.sandbox_profile
    )));

    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_worker = Arc::clone(&cancel);
    let target_for_worker = target.clone();
    let out_dir_for_worker = out_dir.clone();
    let assignment_for_worker = payload.assignment_path.clone();
    let audit_dir_for_worker = payload.audit_dir.clone();

    thread::spawn(move || {
        let mut command = build_analysis_command(
            cli_path,
            &target_for_worker,
            &out_dir_for_worker,
            run_plan,
            assignment_for_worker.as_deref(),
            audit_dir_for_worker.as_deref(),
        );

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
    analyzer_path: Option<String>,
) -> Result<(), String> {
    let target = PathBuf::from(target_path.trim().trim_matches('"'));
    if !target.exists() {
        return Err("target file for rerun not found".to_string());
    }

    let cli_path = core::resolve_cli_path_with_override(analyzer_path.as_deref())
        .ok_or_else(|| "cannot resolve analysis engine executable".to_string())?;

    thread::spawn(move || {
        let mut command = build_rerun_command(cli_path, &target, mode, &scenario);

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
    let mode = payload.mode.to_ascii_uppercase();
    let mut rerun_line = format!(
        "echo cargo run --bin exe_tester -- \"{}\" --mode-{}",
        payload.target_path,
        payload.mode.to_ascii_lowercase()
    );
    if mode == "PENTEST" {
        rerun_line.push_str(" --confirm-extended-tests");
    }
    let lines = [
        "@echo off".to_string(),
        "setlocal".to_string(),
        "chcp 65001 >nul".to_string(),
        format!("REM target: {}", payload.target_path),
        format!("REM mode: {}", payload.mode),
        "echo Run this command in repository root:".to_string(),
        rerun_line,
    ];
    fs::write(&rerun_cmd, lines.join("\r\n")).map_err(|e| format!("cannot write rerun.cmd: {}", e))?;

    Ok(json!({
        "path": bundle_dir.display().to_string(),
        "reportCopy": report_copy.display().to_string(),
    }))
}

fn handle_export_report(payload_value: Value) -> Result<Value, String> {
    let payload: Result<ExportReportPayload, _> = serde_json::from_value(payload_value);
    let payload = payload.map_err(|e| format!("export_report payload invalid: {}", e))?;

    let report_path = sanitize_local_path(&payload.report_path)?;
    if !report_path.exists() {
        return Err("report file was not found".to_string());
    }

    let report_json = core::read_report_json(&report_path)?;
    let format = payload.format.trim().to_ascii_lowercase();
    let (extension, body) = match format.as_str() {
        "md" | "markdown" => ("md", render_report_markdown(&report_json)),
        "html" => ("html", render_report_html(&report_json)),
        _ => return Err("export format must be 'md' or 'html'".to_string()),
    };

    let output = report_path.with_extension(extension);
    fs::write(&output, body).map_err(|e| format!("cannot write export file: {}", e))?;

    Ok(json!({
        "path": output.display().to_string(),
    }))
}

fn render_report_markdown(report: &Value) -> String {
    let target = report.get("target").and_then(Value::as_str).unwrap_or("-");
    let schema = report
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let status = report
        .get("final_status")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN");
    let score = report.get("score").and_then(Value::as_u64).unwrap_or(0);
    let severity = report.get("summary").and_then(|v| v.get("severity"));
    let runtime_summary = report.get("summary").and_then(|v| v.get("runtime"));
    let artifacts = report.get("artifacts");
    let pe = artifacts.and_then(|v| v.get("static_analysis")).and_then(|v| v.get("pe"));
    let source = artifacts.and_then(|v| v.get("static_analysis")).and_then(|v| v.get("source"));
    let strings = artifacts.and_then(|v| v.get("static_analysis")).and_then(|v| v.get("strings"));

    let mut out = String::new();
    out.push_str("# Metsuki Report\n\n");
    out.push_str(&format!("- Target: {}\n", target));
    out.push_str(&format!("- Schema: {}\n", schema));
    out.push_str(&format!("- Final status: {}\n", status));
    out.push_str(&format!("- Score: {}\n\n", score));
    if let Some(severity) = severity {
        out.push_str("## Summary\n\n");
        out.push_str(&format!(
            "- Severity totals: PASS={} WARN={} FAIL={} TOTAL={}\n",
            severity.get("pass").and_then(Value::as_u64).unwrap_or(0),
            severity.get("warn").and_then(Value::as_u64).unwrap_or(0),
            severity.get("fail").and_then(Value::as_u64).unwrap_or(0),
            severity.get("total").and_then(Value::as_u64).unwrap_or(0),
        ));
        if let Some(runtime_summary) = runtime_summary {
            out.push_str(&format!(
                "- Runtime: runs={} timeouts={} non-zero={} p50={}ms p95={}ms flaky={} flakiness={}% stability={}%\n\n",
                runtime_summary.get("runs").and_then(Value::as_u64).unwrap_or(0),
                runtime_summary.get("timeout_count").and_then(Value::as_u64).unwrap_or(0),
                runtime_summary.get("non_zero_exit_count").and_then(Value::as_u64).unwrap_or(0),
                runtime_summary.get("p50_duration_ms").and_then(Value::as_u64).unwrap_or(0),
                runtime_summary.get("p95_duration_ms").and_then(Value::as_u64).unwrap_or(0),
                runtime_summary.get("flaky").and_then(Value::as_bool).unwrap_or(false),
                runtime_summary.get("flakiness_percent").and_then(Value::as_u64).unwrap_or(0),
                runtime_summary.get("stability_percent").and_then(Value::as_u64).unwrap_or(0),
            ));
        } else {
            out.push('\n');
        }
    }
    if let Some(artifacts) = artifacts {
        out.push_str("## Static Artifacts\n\n");
        out.push_str(&format!(
            "- Target kind: {}\n",
            artifacts.get("target_kind").and_then(Value::as_str).unwrap_or("-")
        ));
        out.push_str(&format!(
            "- File size: {} bytes\n",
            artifacts.get("file_size_bytes").and_then(Value::as_u64).unwrap_or(0)
        ));
        if let Some(pe) = pe {
            out.push_str(&format!(
                "- PE: arch={} sections={} overlay={} cert_table={} imports={}\n",
                pe.get("arch").and_then(Value::as_str).unwrap_or("-"),
                pe.get("section_count").and_then(Value::as_u64).unwrap_or(0),
                pe.get("overlay_bytes").and_then(Value::as_u64).unwrap_or(0),
                pe.get("certificate_table_bytes").and_then(Value::as_u64).unwrap_or(0),
                pe.get("imports").and_then(|v| v.get("total")).and_then(Value::as_u64).unwrap_or(0)
            ));
        }
        if let Some(source) = source {
            out.push_str(&format!(
                "- Source: lang={} lines={} long_lines={}\n",
                source.get("language").and_then(Value::as_str).unwrap_or("-"),
                source.get("line_count").and_then(Value::as_u64).unwrap_or(0),
                source.get("long_lines").and_then(Value::as_u64).unwrap_or(0)
            ));
        }
        if let Some(strings) = strings {
            out.push_str(&format!(
                "- Strings: scanned={} suspicious_hits={}\n\n",
                strings.get("total_strings_scanned").and_then(Value::as_u64).unwrap_or(0),
                strings
                    .get("suspicious_hits")
                    .and_then(Value::as_array)
                    .map(|v| v.len())
                    .unwrap_or(0)
            ));
        } else {
            out.push('\n');
        }
    }

    out.push_str("## Findings\n\n");
    out.push_str("| Severity | Code | Category | Points | Message |\n");
    out.push_str("|---|---|---|---:|---|\n");
    if let Some(findings) = report.get("findings").and_then(Value::as_array) {
        for f in findings {
            let sev = f.get("severity").and_then(Value::as_str).unwrap_or("-");
            let code = f.get("code").and_then(Value::as_str).unwrap_or("-");
            let cat = f.get("category").and_then(Value::as_str).unwrap_or("-");
            let points = f.get("points").and_then(Value::as_u64).unwrap_or(0);
            let msg = f.get("message").and_then(Value::as_str).unwrap_or("-").replace('|', "\\|");
            out.push_str(&format!("| {} | {} | {} | {} | {} |\n", sev, code, cat, points, msg));
        }
    }

    out.push_str("\n## Runtime\n\n");
    out.push_str("| Scenario | Exit | Timeout | Duration ms | stdout | stderr | Reason |\n");
    out.push_str("|---|---:|---|---:|---:|---:|---|\n");
    if let Some(runtime) = report.get("runtime").and_then(Value::as_array) {
        for r in runtime {
            let scenario = r.get("scenario").and_then(Value::as_str).unwrap_or("-");
            let exit = r.get("exit_code").map(|v| v.to_string()).unwrap_or_else(|| "null".to_string());
            let timeout = r.get("timed_out").map(|v| v.to_string()).unwrap_or_else(|| "false".to_string());
            let duration = r.get("duration_ms").and_then(Value::as_u64).unwrap_or(0);
            let stdout_len = r.get("stdout_len").and_then(Value::as_u64).unwrap_or(0);
            let stderr_len = r.get("stderr_len").and_then(Value::as_u64).unwrap_or(0);
            let reason = r.get("failure_reason").and_then(Value::as_str).unwrap_or("-").replace('|', "\\|");
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                scenario, exit, timeout, duration, stdout_len, stderr_len, reason
            ));
        }
    }

    out
}

fn render_report_html(report: &Value) -> String {
    fn esc(v: &str) -> String {
        v.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    let target = esc(report.get("target").and_then(Value::as_str).unwrap_or("-"));
    let schema = esc(report.get("schema_version").and_then(Value::as_str).unwrap_or("unknown"));
    let status = esc(report.get("final_status").and_then(Value::as_str).unwrap_or("UNKNOWN"));
    let score = report.get("score").and_then(Value::as_u64).unwrap_or(0);
    let summary = report.get("summary");
    let severity = summary.and_then(|v| v.get("severity"));
    let runtime_summary = summary.and_then(|v| v.get("runtime"));
    let artifacts = report.get("artifacts");
    let pe = artifacts.and_then(|v| v.get("static_analysis")).and_then(|v| v.get("pe"));
    let source = artifacts.and_then(|v| v.get("static_analysis")).and_then(|v| v.get("source"));
    let strings = artifacts.and_then(|v| v.get("static_analysis")).and_then(|v| v.get("strings"));

    let mut findings_rows = String::new();
    if let Some(findings) = report.get("findings").and_then(Value::as_array) {
        for f in findings {
            let sev = esc(f.get("severity").and_then(Value::as_str).unwrap_or("-"));
            let code = esc(f.get("code").and_then(Value::as_str).unwrap_or("-"));
            let cat = esc(f.get("category").and_then(Value::as_str).unwrap_or("-"));
            let pts = f.get("points").and_then(Value::as_u64).unwrap_or(0);
            let msg = esc(f.get("message").and_then(Value::as_str).unwrap_or("-"));
            findings_rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                sev, code, cat, pts, msg
            ));
        }
    }

    let mut runtime_rows = String::new();
    if let Some(runtime) = report.get("runtime").and_then(Value::as_array) {
        for r in runtime {
            let scenario = esc(r.get("scenario").and_then(Value::as_str).unwrap_or("-"));
            let exit = esc(&r.get("exit_code").map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()));
            let timeout = esc(&r.get("timed_out").map(|v| v.to_string()).unwrap_or_else(|| "false".to_string()));
            let duration = r.get("duration_ms").and_then(Value::as_u64).unwrap_or(0);
            let stdout_len = r.get("stdout_len").and_then(Value::as_u64).unwrap_or(0);
            let stderr_len = r.get("stderr_len").and_then(Value::as_u64).unwrap_or(0);
            let reason = esc(r.get("failure_reason").and_then(Value::as_str).unwrap_or("-"));
            runtime_rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                scenario, exit, timeout, duration, stdout_len, stderr_len, reason
            ));
        }
    }

    let summary_html = format!(
        "<p><b>Severity totals:</b> PASS={} WARN={} FAIL={} TOTAL={}<br><b>Runtime:</b> runs={} timeouts={} non-zero={} p50={}ms p95={}ms flaky={} flakiness={}% stability={}%</p>",
        severity.and_then(|v| v.get("pass")).and_then(Value::as_u64).unwrap_or(0),
        severity.and_then(|v| v.get("warn")).and_then(Value::as_u64).unwrap_or(0),
        severity.and_then(|v| v.get("fail")).and_then(Value::as_u64).unwrap_or(0),
        severity.and_then(|v| v.get("total")).and_then(Value::as_u64).unwrap_or(0),
        runtime_summary.and_then(|v| v.get("runs")).and_then(Value::as_u64).unwrap_or(0),
        runtime_summary.and_then(|v| v.get("timeout_count")).and_then(Value::as_u64).unwrap_or(0),
        runtime_summary.and_then(|v| v.get("non_zero_exit_count")).and_then(Value::as_u64).unwrap_or(0),
        runtime_summary.and_then(|v| v.get("p50_duration_ms")).and_then(Value::as_u64).unwrap_or(0),
        runtime_summary.and_then(|v| v.get("p95_duration_ms")).and_then(Value::as_u64).unwrap_or(0),
        esc(&runtime_summary.and_then(|v| v.get("flaky")).and_then(Value::as_bool).unwrap_or(false).to_string()),
        runtime_summary.and_then(|v| v.get("flakiness_percent")).and_then(Value::as_u64).unwrap_or(0),
        runtime_summary.and_then(|v| v.get("stability_percent")).and_then(Value::as_u64).unwrap_or(0),
    );
    let artifacts_html = format!(
        "<h2>Static Artifacts</h2><ul><li><b>Target kind:</b> {}</li><li><b>File size:</b> {} bytes</li>{}{}{}</ul>",
        esc(artifacts.and_then(|v| v.get("target_kind")).and_then(Value::as_str).unwrap_or("-")),
        artifacts.and_then(|v| v.get("file_size_bytes")).and_then(Value::as_u64).unwrap_or(0),
        if let Some(pe) = pe {
            format!(
                "<li><b>PE:</b> arch={} sections={} overlay={} cert_table={} imports={}</li>",
                esc(pe.get("arch").and_then(Value::as_str).unwrap_or("-")),
                pe.get("section_count").and_then(Value::as_u64).unwrap_or(0),
                pe.get("overlay_bytes").and_then(Value::as_u64).unwrap_or(0),
                pe.get("certificate_table_bytes").and_then(Value::as_u64).unwrap_or(0),
                pe.get("imports").and_then(|v| v.get("total")).and_then(Value::as_u64).unwrap_or(0)
            )
        } else {
            String::new()
        },
        if let Some(source) = source {
            format!(
                "<li><b>Source:</b> lang={} lines={} long_lines={}</li>",
                esc(source.get("language").and_then(Value::as_str).unwrap_or("-")),
                source.get("line_count").and_then(Value::as_u64).unwrap_or(0),
                source.get("long_lines").and_then(Value::as_u64).unwrap_or(0)
            )
        } else {
            String::new()
        },
        if let Some(strings) = strings {
            format!(
                "<li><b>Strings:</b> scanned={} suspicious_hits={}</li>",
                strings.get("total_strings_scanned").and_then(Value::as_u64).unwrap_or(0),
                strings
                    .get("suspicious_hits")
                    .and_then(Value::as_array)
                    .map(|v| v.len())
                    .unwrap_or(0)
            )
        } else {
            String::new()
        },
    );

    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Metsuki Report</title><style>body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2937}}table{{border-collapse:collapse;width:100%;margin:12px 0}}th,td{{border:1px solid #d1d5db;padding:8px;text-align:left}}th{{background:#f3f4f6}}h1,h2{{margin:12px 0 8px}}</style></head><body><h1>Metsuki Report</h1><p><b>Target:</b> {}<br><b>Schema:</b> {}<br><b>Final status:</b> {}<br><b>Score:</b> {}</p><h2>Summary</h2>{}{}<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Code</th><th>Category</th><th>Points</th><th>Message</th></tr></thead><tbody>{}</tbody></table><h2>Runtime</h2><table><thead><tr><th>Scenario</th><th>Exit</th><th>Timeout</th><th>Duration ms</th><th>stdout</th><th>stderr</th><th>Reason</th></tr></thead><tbody>{}</tbody></table></body></html>",
        target, schema, status, score, summary_html, artifacts_html, findings_rows, runtime_rows
    )
}

#[derive(Debug, Clone, Copy)]
struct RunPlan {
    profile: &'static str,
    mode: AnalysisMode,
    verdict_mode: &'static str,
    runs: u32,
    timeout_secs: u64,
    sandbox_profile: &'static str,
}

fn resolve_run_plan(payload: &RunAnalysisPayload, settings: &AppSettings) -> RunPlan {
    let power_profile = core::parse_power_profile(
        payload
            .power_profile
            .as_deref()
            .unwrap_or(&settings.power_profile),
    )
    .unwrap_or_default();
    let defaults = core::power_profile_defaults(power_profile);

    RunPlan {
        profile: power_profile.as_str(),
        mode: parse_mode_or_default(&payload.mode, defaults.analysis_mode),
        verdict_mode: normalize_verdict_mode(
            payload
                .verdict_mode
                .as_deref()
                .unwrap_or(defaults.mode.as_str()),
        ),
        runs: if payload.runs == 0 {
            defaults.runs
        } else {
            payload.runs
        },
        timeout_secs: if payload.timeout_secs == 0 {
            defaults.timeout_secs
        } else {
            payload.timeout_secs
        },
        sandbox_profile: normalize_sandbox_profile(
            payload
                .sandbox_profile
                .as_deref()
                .unwrap_or(defaults.sandbox_profile.as_str()),
        ),
    }
}

fn build_analysis_command(
    cli_path: PathBuf,
    target: &Path,
    out_dir: &Path,
    plan: RunPlan,
    assignment_path: Option<&str>,
    audit_dir: Option<&str>,
) -> Command {
    let mut command = Command::new(cli_path);
    command
        .arg(target)
        .arg("--power-profile")
        .arg(plan.profile)
        .arg("--timeout")
        .arg(plan.timeout_secs.max(1).to_string())
        .arg("--runs")
        .arg(plan.runs.max(1).to_string())
        .arg("--sandbox-profile")
        .arg(plan.sandbox_profile)
        .arg("--out-dir")
        .arg(out_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    append_mode_args(&mut command, plan.mode);
    append_verdict_args(&mut command, plan.verdict_mode);

    if let Some(p) = assignment_path {
        if !p.trim().is_empty() {
            command.arg("--assignment").arg(p.trim());
        }
    }
    if let Some(p) = audit_dir {
        if !p.trim().is_empty() {
            command.arg("--audit-dir").arg(p.trim());
        }
    }

    command
}

fn build_rerun_command(cli_path: PathBuf, target: &Path, mode: AnalysisMode, scenario: &str) -> Command {
    let sandbox = if mode == AnalysisMode::Pentest {
        "isolated"
    } else {
        "limited"
    };

    let mut command = Command::new(cli_path);
    command
        .arg(target)
        .arg("--timeout")
        .arg("4")
        .arg("--runs")
        .arg("1")
        .arg("--only-scenario")
        .arg(scenario)
        .arg("--sandbox-profile")
        .arg(sandbox)
        .arg("--out-dir")
        .arg("logs");

    append_mode_args(&mut command, mode);
    command
}

fn append_mode_args(command: &mut Command, mode: AnalysisMode) {
    match mode {
        AnalysisMode::Min => {
            command.arg("--mode-min");
        }
        AnalysisMode::Pentest => {
            command.arg("--mode-pentest");
            command.arg("--confirm-extended-tests");
        }
    }
}

fn append_verdict_args(command: &mut Command, verdict_mode: &str) {
    if verdict_mode == "STRICT" {
        command.arg("--strict");
    } else {
        command.arg("--balanced");
    }
}

fn parse_mode_or_default(input: &str, default_mode: AnalysisMode) -> AnalysisMode {
    let raw = input.trim();
    if raw.is_empty() {
        return default_mode;
    }
    parse_mode(raw)
}

fn normalize_verdict_mode(input: &str) -> &'static str {
    match input.trim().to_ascii_uppercase().as_str() {
        "STRICT" => "STRICT",
        _ => "BALANCED",
    }
}

fn normalize_sandbox_profile(input: &str) -> &'static str {
    match input.trim().to_ascii_lowercase().as_str() {
        "none" => "none",
        "isolated" => "isolated",
        _ => "limited",
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_analysis_command_places_target_before_flags() {
        let command = build_analysis_command(
            PathBuf::from("exe_tester.exe"),
            Path::new("sample.exe"),
            Path::new("logs"),
            RunPlan {
                profile: "BASIC",
                mode: AnalysisMode::Min,
                verdict_mode: "BALANCED",
                runs: 4,
                timeout_secs: 4,
                sandbox_profile: "limited",
            },
            None,
            None,
        );

        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert_eq!(args.first().map(String::as_str), Some("sample.exe"));
        assert_eq!(args.get(1).map(String::as_str), Some("--power-profile"));
    }
}
