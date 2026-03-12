#![cfg_attr(windows, windows_subsystem = "windows")]

#[path = "exe_tester_gui/workers.rs"]
mod workers;
#[path = "exe_tester_gui/diagnostics.rs"]
mod diagnostics;
#[path = "exe_tester_gui/theming.rs"]
mod theming;

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use image::ImageReader;
use notify::{EventKind, RecursiveMode, Watcher, recommended_watcher};
use rfd::FileDialog;
use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use sysinfo::System;

#[derive(Debug, Clone, Deserialize)]
struct ReportFinding {
    severity: String,
    code: String,
    category: String,
    points: u32,
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ReportRuntime {
    scenario: String,
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u128,
    stdout_len: usize,
    stderr_len: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct ReportData {
    target: String,
    mode: String,
    score: u32,
    final_status: String,
    findings: Vec<ReportFinding>,
    runtime: Vec<ReportRuntime>,
}

#[derive(Debug, Clone)]
struct RunHistoryEntry {
    timestamp_unix: u64,
    kind: String,
    target: String,
    exit: Option<i32>,
    timed_out: bool,
    duration_ms: u128,
    score: Option<u32>,
    status: String,
}

#[derive(Debug, Clone)]
struct PerfSample {
    at_ms: u128,
    cpu_percent: f32,
    ram_mb: u64,
}

#[derive(Debug, Clone)]
struct DebugReplaySession {
    timestamp_unix: u64,
    status: String,
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u128,
    stdout: String,
    stderr: String,
    source_path: String,
    active_line: Option<usize>,
    line_history: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DebugSessionFilter {
    All,
    Pass,
    Error,
}

impl DebugSessionFilter {
    fn label(self) -> &'static str {
        match self {
            DebugSessionFilter::All => "All",
            DebugSessionFilter::Pass => "Pass",
            DebugSessionFilter::Error => "Error",
        }
    }
}

trait AnalyzerPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn on_report_loaded(&self, report: &ReportData) -> Option<String>;
}

struct HighRiskFindingPlugin;

impl AnalyzerPlugin for HighRiskFindingPlugin {
    fn name(&self) -> &'static str {
        "high-risk-findings"
    }

    fn on_report_loaded(&self, report: &ReportData) -> Option<String> {
        let count = report
            .findings
            .iter()
            .filter(|f| f.severity == "FAIL" || f.code.contains("SUSPICIOUS") || f.code.contains("CRASH"))
            .count();
        if count > 0 {
            Some(format!("plugin:{} detected {} high-risk items", self.name(), count))
        } else {
            None
        }
    }
}

struct RuntimeTimeoutPlugin;

impl AnalyzerPlugin for RuntimeTimeoutPlugin {
    fn name(&self) -> &'static str {
        "runtime-timeout-detector"
    }

    fn on_report_loaded(&self, report: &ReportData) -> Option<String> {
        let timeout_count = report.runtime.iter().filter(|r| r.timed_out).count();
        if timeout_count > 0 {
            Some(format!(
                "plugin:{} found {} timed out runtime scenarios",
                self.name(),
                timeout_count
            ))
        } else {
            None
        }
    }
}

fn default_plugins() -> Vec<Box<dyn AnalyzerPlugin>> {
    vec![Box::new(HighRiskFindingPlugin), Box::new(RuntimeTimeoutPlugin)]
}

enum UiEvent {
    Log(String),
    Finished {
        exit_code: i32,
        report: Option<ReportData>,
        report_path: Option<PathBuf>,
    },
    DebugOutput {
        is_stderr: bool,
        text: String,
    },
    DebugFinished {
        exit_code: Option<i32>,
        timed_out: bool,
        duration_ms: u128,
        stdout: String,
        stderr: String,
    },
    WatchedFileChanged(String),
    VsdbgInstallFinished {
        success: bool,
        path: Option<PathBuf>,
        details: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanPreset {
    Fast,
    Deep,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceTab {
    Overview,
    Findings,
    Runtime,
    Debugger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuiLabProfile {
    Standard,
    Aggressive,
    Custom,
}

impl GuiLabProfile {
    fn as_cli_value(self) -> &'static str {
        match self {
            GuiLabProfile::Standard | GuiLabProfile::Custom => "standard",
            GuiLabProfile::Aggressive => "aggressive",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiLanguage {
    Ru,
    En,
    De,
    Uk,
}

impl UiLanguage {
    fn label(self) -> &'static str {
        match self {
            UiLanguage::Ru => "RU",
            UiLanguage::En => "EN",
            UiLanguage::De => "DE",
            UiLanguage::Uk => "UK",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DebugBackend {
    VsDbgCli,
}

impl DebugBackend {
    fn label(self) -> &'static str {
        "Visual Studio Debugger (vsdbg)"
    }
}

enum DebugControl {
    Command(String),
    Stop,
}

fn zed_bg_0() -> egui::Color32 {
    egui::Color32::from_rgb(12, 15, 20)
}

fn zed_bg_1() -> egui::Color32 {
    egui::Color32::from_rgb(18, 22, 29)
}

fn zed_bg_2() -> egui::Color32 {
    egui::Color32::from_rgb(24, 29, 38)
}

fn zed_bg_3() -> egui::Color32 {
    egui::Color32::from_rgb(32, 38, 49)
}

fn zed_fg_muted() -> egui::Color32 {
    egui::Color32::from_rgb(132, 142, 160)
}

fn zed_accent() -> egui::Color32 {
    egui::Color32::from_rgb(110, 150, 210)
}

fn severity_color(sev: &str) -> egui::Color32 {
    match sev {
        "PASS" => egui::Color32::from_rgb(73, 182, 117),
        "WARN" => egui::Color32::from_rgb(225, 172, 69),
        "FAIL" => egui::Color32::from_rgb(229, 84, 84),
        _ => egui::Color32::from_rgb(186, 193, 206),
    }
}

struct AnalyzerGuiApp {
    target_path: String,
    out_dir: String,
    timeout_secs: String,
    runs: String,
    strict_mode: bool,
    scan_preset: ScanPreset,
    lab_profile: GuiLabProfile,
    lab_confirm_extended_tests: bool,
    lab_custom_modules: String,
    active_tab: WorkspaceTab,
    ui_language: UiLanguage,

    is_running: bool,
    started_at: Option<Instant>,
    cancel_flag: Arc<AtomicBool>,

    logs: Vec<String>,
    run_history: Vec<RunHistoryEntry>,
    show_logs_window: bool,
    findings: Vec<ReportFinding>,
    runtime: Vec<ReportRuntime>,
    score: u32,
    final_status: String,
    mode_label: String,
    report_path: String,
    selected_finding: Option<usize>,
    logo_texture: Option<egui::TextureHandle>,
    splash_started_at: Instant,
    splash_duration: Duration,

    debugger_args: String,
    debugger_timeout_secs: String,
    debugger_expected_exit: String,
    debugger_expected_exception: bool,
    debugger_expected_stdout_contains: String,
    debugger_expected_stderr_contains: String,
    debugger_backend: DebugBackend,
    vsdbg_available: bool,
    vsdbg_command: Option<PathBuf>,
    vsdbg_install_is_running: bool,
    debugger_is_running: bool,
    debugger_cancel_flag: Arc<AtomicBool>,
    debugger_command_input: String,
    debugger_controls_tx: Option<Sender<DebugControl>>,
    debugger_last_exit: Option<i32>,
    debugger_last_timed_out: bool,
    debugger_last_duration_ms: u128,
    debugger_had_exception: bool,
    debugger_verdict_ok: bool,
    debugger_expected_view: String,
    debugger_got_view: String,
    debugger_failure_point: String,
    debugger_root_cause: String,
    debugger_stdout: String,
    debugger_stderr: String,
    debugger_source_path: String,
    debugger_source_lines: Vec<String>,
    debugger_active_line: Option<usize>,
    debugger_line_history: Vec<usize>,
    debugger_line_history_cursor: usize,
    debug_replay_sessions: Vec<DebugReplaySession>,
    debug_replay_filter: DebugSessionFilter,
    debug_replay_selected: Option<usize>,
    stdout_snapshots: Vec<String>,
    stdout_diff_left: usize,
    stdout_diff_right: usize,
    stdout_diff_text: String,

    perf_samples: Vec<PerfSample>,
    last_perf_sample_at: Instant,
    system: System,

    watcher_stop: Arc<AtomicBool>,
    plugins: Vec<Box<dyn AnalyzerPlugin>>,

    ui_tx: Option<Sender<UiEvent>>,
    rx: Option<Receiver<UiEvent>>,
}

impl Default for AnalyzerGuiApp {
    fn default() -> Self {
        let vsdbg_command = detect_vsdbg_command();
        Self {
            target_path: String::new(),
            out_dir: "logs".to_string(),
            timeout_secs: "10".to_string(),
            runs: "10".to_string(),
            strict_mode: true,
            scan_preset: ScanPreset::Deep,
            lab_profile: GuiLabProfile::Standard,
            lab_confirm_extended_tests: false,
            lab_custom_modules: String::new(),
            active_tab: WorkspaceTab::Overview,
            ui_language: UiLanguage::Ru,
            is_running: false,
            started_at: None,
            cancel_flag: Arc::new(AtomicBool::new(false)),
            logs: Vec::new(),
            run_history: Vec::new(),
            show_logs_window: false,
            findings: Vec::new(),
            runtime: Vec::new(),
            score: 0,
            final_status: "-".to_string(),
            mode_label: "STRICT".to_string(),
            report_path: String::new(),
            selected_finding: None,
            logo_texture: None,
            splash_started_at: Instant::now(),
            splash_duration: Duration::from_millis(2200),
            debugger_args: String::new(),
            debugger_timeout_secs: "30".to_string(),
            debugger_expected_exit: "0".to_string(),
            debugger_expected_exception: false,
            debugger_expected_stdout_contains: String::new(),
            debugger_expected_stderr_contains: String::new(),
            debugger_backend: DebugBackend::VsDbgCli,
            vsdbg_available: vsdbg_command.is_some(),
            vsdbg_command,
            vsdbg_install_is_running: false,
            debugger_is_running: false,
            debugger_cancel_flag: Arc::new(AtomicBool::new(false)),
            debugger_command_input: String::new(),
            debugger_controls_tx: None,
            debugger_last_exit: None,
            debugger_last_timed_out: false,
            debugger_last_duration_ms: 0,
            debugger_had_exception: false,
            debugger_verdict_ok: true,
            debugger_expected_view: String::new(),
            debugger_got_view: String::new(),
            debugger_failure_point: "-".to_string(),
            debugger_root_cause: "-".to_string(),
            debugger_stdout: String::new(),
            debugger_stderr: String::new(),
            debugger_source_path: String::new(),
            debugger_source_lines: Vec::new(),
            debugger_active_line: None,
            debugger_line_history: Vec::new(),
            debugger_line_history_cursor: 0,
            debug_replay_sessions: Vec::new(),
            debug_replay_filter: DebugSessionFilter::All,
            debug_replay_selected: None,
            stdout_snapshots: Vec::new(),
            stdout_diff_left: 0,
            stdout_diff_right: 0,
            stdout_diff_text: String::new(),
            perf_samples: Vec::new(),
            last_perf_sample_at: Instant::now(),
            system: System::new_all(),
            watcher_stop: Arc::new(AtomicBool::new(false)),
            plugins: default_plugins(),
            ui_tx: None,
            rx: None,
        }
    }
}

impl AnalyzerGuiApp {
    fn t<'a>(&self, ru: &'a str, en: &'a str, de: &'a str, uk: &'a str) -> &'a str {
        match self.ui_language {
            UiLanguage::Ru => ru,
            UiLanguage::En => en,
            UiLanguage::De => de,
            UiLanguage::Uk => uk,
        }
    }

    fn apply_preset(&mut self, preset: ScanPreset) {
        self.scan_preset = preset;
        match preset {
            ScanPreset::Fast => {
                self.timeout_secs = "2".to_string();
                self.runs = "3".to_string();
                self.strict_mode = false;
                self.append_log("[ui] Preset FAST applied (balanced, short run)");
            }
            ScanPreset::Deep => {
                self.timeout_secs = "5".to_string();
                self.runs = "10".to_string();
                self.strict_mode = true;
                self.append_log("[ui] Preset DEEP applied (strict, full run)");
            }
            ScanPreset::Custom => {
                self.append_log("[ui] Preset CUSTOM active");
            }
        }
    }

    fn append_log(&mut self, line: impl Into<String>) {
        self.logs.push(line.into());
        if self.logs.len() > 1500 {
            let overflow = self.logs.len() - 1500;
            self.logs.drain(0..overflow);
        }
    }

    fn current_unix() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn apply_theme_if_needed(&self, ctx: &egui::Context) {
        theming::apply_theme(ctx);
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if dropped.is_empty() {
            return;
        }

        if let Some(file) = dropped.iter().find_map(|f| f.path.clone()) {
            self.target_path = file.display().to_string();
            self.append_log(format!("[ui] Dropped file selected: {}", self.target_path));
            self.restart_file_watcher();
        }
    }

    fn push_scan_history(&mut self, exit_code: i32, duration_ms: u128) {
        let entry = RunHistoryEntry {
            timestamp_unix: Self::current_unix(),
            kind: "scan".to_string(),
            target: self.target_path.clone(),
            exit: Some(exit_code),
            timed_out: false,
            duration_ms,
            score: Some(self.score),
            status: self.final_status.clone(),
        };
        self.run_history.push(entry);
        if self.run_history.len() > 200 {
            let overflow = self.run_history.len() - 200;
            self.run_history.drain(0..overflow);
        }
    }

    fn push_debug_history(&mut self, exit_code: Option<i32>, timed_out: bool, duration_ms: u128) {
        let entry = RunHistoryEntry {
            timestamp_unix: Self::current_unix(),
            kind: "debug".to_string(),
            target: self.target_path.clone(),
            exit: exit_code,
            timed_out,
            duration_ms,
            score: None,
            status: if timed_out {
                "TIMEOUT".to_string()
            } else if exit_code == Some(0) {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
        };
        self.run_history.push(entry);
        if self.run_history.len() > 200 {
            let overflow = self.run_history.len() - 200;
            self.run_history.drain(0..overflow);
        }
    }

    fn sample_performance(&mut self) {
        if self.last_perf_sample_at.elapsed() < Duration::from_millis(500) {
            return;
        }
        self.last_perf_sample_at = Instant::now();

        self.system.refresh_all();
        let cpu = self.system.global_cpu_usage();
        let ram_mb = self.system.used_memory() / (1024 * 1024);
        let at_ms = self
            .started_at
            .map(|s| s.elapsed().as_millis())
            .unwrap_or_else(|| self.splash_started_at.elapsed().as_millis());

        self.perf_samples.push(PerfSample {
            at_ms,
            cpu_percent: cpu,
            ram_mb,
        });
        if self.perf_samples.len() > 300 {
            let overflow = self.perf_samples.len() - 300;
            self.perf_samples.drain(0..overflow);
        }
    }

    fn draw_perf_timeline(&self, ui: &mut egui::Ui) {
        let desired_size = egui::vec2(ui.available_width(), 130.0);
        let (rect, _) = ui.allocate_exact_size(desired_size, egui::Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 6.0, zed_bg_1());

        if self.perf_samples.is_empty() {
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "No performance samples",
                egui::FontId::proportional(13.0),
                zed_fg_muted(),
            );
            return;
        }

        let max_ram = self.perf_samples.iter().map(|s| s.ram_mb).max().unwrap_or(1) as f32;
        let max_cpu = 100.0_f32;
        let width = (rect.width() - 12.0).max(10.0);
        let left = rect.left() + 6.0;
        let bottom = rect.bottom() - 8.0;
        let top = rect.top() + 8.0;
        let count = self.perf_samples.len().max(2);

        for i in 1..self.perf_samples.len() {
            let prev = &self.perf_samples[i - 1];
            let curr = &self.perf_samples[i];

            let x0 = left + width * (i as f32 - 1.0) / (count as f32 - 1.0);
            let x1 = left + width * (i as f32) / (count as f32 - 1.0);

            let y0_cpu = bottom - ((prev.cpu_percent / max_cpu).clamp(0.0, 1.0) * (bottom - top));
            let y1_cpu = bottom - ((curr.cpu_percent / max_cpu).clamp(0.0, 1.0) * (bottom - top));
            painter.line_segment(
                [egui::pos2(x0, y0_cpu), egui::pos2(x1, y1_cpu)],
                egui::Stroke::new(1.4, egui::Color32::from_rgb(225, 172, 69)),
            );

            let y0_ram = bottom - (((prev.ram_mb as f32) / max_ram).clamp(0.0, 1.0) * (bottom - top));
            let y1_ram = bottom - (((curr.ram_mb as f32) / max_ram).clamp(0.0, 1.0) * (bottom - top));
            painter.line_segment(
                [egui::pos2(x0, y0_ram), egui::pos2(x1, y1_ram)],
                egui::Stroke::new(1.4, egui::Color32::from_rgb(103, 164, 255)),
            );
        }

        if let Some(last) = self.perf_samples.last() {
            painter.text(
                egui::pos2(rect.right() - 10.0, rect.top() + 6.0),
                egui::Align2::RIGHT_TOP,
                format!("t={}ms cpu={:.1}% ram={}MB", last.at_ms, last.cpu_percent, last.ram_mb),
                egui::FontId::monospace(10.0),
                zed_fg_muted(),
            );
        }
    }

    fn restart_file_watcher(&mut self) {
        self.watcher_stop.store(true, Ordering::Relaxed);
        self.watcher_stop = Arc::new(AtomicBool::new(false));

        let target = PathBuf::from(self.target_path.trim().trim_matches('"'));
        if !target.exists() {
            return;
        }

        let Some(tx) = self.ui_tx.clone() else {
            return;
        };
        let stop = Arc::clone(&self.watcher_stop);
        let watched_path = target.clone();
        thread::spawn(move || {
            let tx_inner = tx.clone();
            let mut watcher = match recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_) => {
                            let _ = tx_inner.send(UiEvent::WatchedFileChanged(format!(
                                "{}",
                                event
                                    .paths
                                    .first()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "<unknown>".to_string())
                            )));
                        }
                        _ => {}
                    }
                }
            }) {
                Ok(w) => w,
                Err(_) => return,
            };

            if watcher.watch(&watched_path, RecursiveMode::NonRecursive).is_err() {
                return;
            }

            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(250));
            }
        });
        self.append_log(format!("[watcher] Watching file changes: {}", target.display()));
    }

    fn rebuild_stdout_diff(&mut self) {
        if self.stdout_snapshots.is_empty() {
            self.stdout_diff_text.clear();
            return;
        }
        self.stdout_diff_left = self.stdout_diff_left.min(self.stdout_snapshots.len().saturating_sub(1));
        self.stdout_diff_right = self.stdout_diff_right.min(self.stdout_snapshots.len().saturating_sub(1));
        let left = &self.stdout_snapshots[self.stdout_diff_left];
        let right = &self.stdout_snapshots[self.stdout_diff_right];
        self.stdout_diff_text = diagnostics::unified_diff(left, right, "stdout_A", "stdout_B");
    }

    fn try_load_debug_source(&mut self, path: &Path) -> bool {
        let Ok(content) = fs::read_to_string(path) else {
            return false;
        };

        self.debugger_source_path = path.display().to_string();
        self.debugger_source_lines = content.lines().map(|line| line.to_string()).collect();
        self.debugger_active_line = None;
        self.debugger_line_history.clear();
        self.debugger_line_history_cursor = 0;
        true
    }

    fn ensure_debug_source_loaded(&mut self) {
        let target = PathBuf::from(self.target_path.trim().trim_matches('"'));
        if !target.exists() || target.is_dir() {
            return;
        }

        let current = PathBuf::from(&self.debugger_source_path);
        if current == target && !self.debugger_source_lines.is_empty() {
            return;
        }

        if self.try_load_debug_source(&target) {
            self.append_log(format!("[debug] Source loaded: {}", target.display()));
        }
    }

    fn set_debug_active_line(&mut self, line: usize) {
        if line == 0 {
            return;
        }

        self.debugger_active_line = Some(line);
        if self
            .debugger_line_history
            .last()
            .copied()
            .map(|last| last != line)
            .unwrap_or(true)
        {
            self.debugger_line_history.push(line);
            if self.debugger_line_history.len() > 200 {
                let overflow = self.debugger_line_history.len() - 200;
                self.debugger_line_history.drain(0..overflow);
            }
        }
        self.debugger_line_history_cursor = self.debugger_line_history.len().saturating_sub(1);
    }

    fn ingest_debug_output_for_location(&mut self, text: &str) {
        for line in text.lines() {
            let Some(loc) = diagnostics::parse_debug_source_location(line) else {
                continue;
            };

            let loc_path = PathBuf::from(loc.path.trim_matches('"'));
            if loc_path.exists() {
                let current = PathBuf::from(&self.debugger_source_path);
                if current != loc_path || self.debugger_source_lines.is_empty() {
                    let _ = self.try_load_debug_source(&loc_path);
                }
            }

            self.set_debug_active_line(loc.line);
        }
    }

    fn selected_debug_line(&self) -> Option<usize> {
        self.debugger_line_history
            .get(self.debugger_line_history_cursor)
            .copied()
            .or(self.debugger_active_line)
    }

    fn step_back_in_history(&mut self) {
        if self.debugger_line_history_cursor > 0 {
            self.debugger_line_history_cursor -= 1;
        }
    }

    fn send_debug_next(&mut self) {
        self.append_log("[debug] Step command is handled by external Visual Studio debugger");
    }

    fn send_debug_continue(&mut self) {
        self.append_log("[debug] Continue command is handled by external Visual Studio debugger");
    }

    fn send_debug_pause(&mut self) {
        self.append_log("[debug] Pause command is handled by external Visual Studio debugger");
    }

    fn add_debug_replay_session(&mut self) {
        let status = if self.debugger_last_timed_out {
            "TIMEOUT".to_string()
        } else if self.debugger_last_exit == Some(0) && !self.debugger_had_exception {
            "PASS".to_string()
        } else {
            "ERROR".to_string()
        };

        self.debug_replay_sessions.push(DebugReplaySession {
            timestamp_unix: Self::current_unix(),
            status,
            exit_code: self.debugger_last_exit,
            timed_out: self.debugger_last_timed_out,
            duration_ms: self.debugger_last_duration_ms,
            stdout: self.debugger_stdout.clone(),
            stderr: self.debugger_stderr.clone(),
            source_path: self.debugger_source_path.clone(),
            active_line: self.debugger_active_line,
            line_history: self.debugger_line_history.clone(),
        });

        if self.debug_replay_sessions.len() > 120 {
            let overflow = self.debug_replay_sessions.len() - 120;
            self.debug_replay_sessions.drain(0..overflow);
        }

        self.debug_replay_selected = Some(self.debug_replay_sessions.len().saturating_sub(1));
    }

    fn session_matches_filter(&self, session: &DebugReplaySession) -> bool {
        match self.debug_replay_filter {
            DebugSessionFilter::All => true,
            DebugSessionFilter::Pass => session.status == "PASS",
            DebugSessionFilter::Error => session.status != "PASS",
        }
    }

    fn load_replay_session(&mut self, idx: usize) {
        let Some(session) = self.debug_replay_sessions.get(idx).cloned() else {
            return;
        };

        self.debug_replay_selected = Some(idx);
        self.debugger_last_exit = session.exit_code;
        self.debugger_last_timed_out = session.timed_out;
        self.debugger_last_duration_ms = session.duration_ms;
        self.debugger_stdout = session.stdout;
        self.debugger_stderr = session.stderr;

        if !session.source_path.trim().is_empty() {
            let path = PathBuf::from(&session.source_path);
            if path.exists() {
                let _ = self.try_load_debug_source(&path);
            }
        }

        self.debugger_active_line = session.active_line;
        self.debugger_line_history = session.line_history;
        self.debugger_line_history_cursor = self.debugger_line_history.len().saturating_sub(1);
        self.debugger_had_exception = diagnostics::infer_debug_exception(
            self.debugger_last_exit,
            self.debugger_last_timed_out,
            &self.debugger_stderr,
        );
        self.append_log(format!("[debug] Replay loaded: #{}", idx));
    }

    fn run_plugins(&mut self, report: &ReportData) {
        let mut plugin_logs = Vec::new();
        for plugin in &self.plugins {
            if let Some(msg) = plugin.on_report_loaded(report) {
                plugin_logs.push(msg);
            }
        }
        for msg in plugin_logs {
            self.append_log(format!("[plugin] {}", msg));
        }
    }

    fn pick_file(&mut self) {
        if let Some(path) = FileDialog::new().add_filter("Executable", &["exe"]).pick_file() {
            self.target_path = path.display().to_string();
            self.append_log(format!("[ui] Selected file: {}", self.target_path));
            self.restart_file_watcher();
        }
    }

    fn pick_any_file(&mut self) {
        if let Some(path) = FileDialog::new().pick_file() {
            self.target_path = path.display().to_string();
            self.append_log(format!("[ui] Selected file: {}", self.target_path));
            self.restart_file_watcher();
        }
    }

    fn run_scan(&mut self) {
        if self.is_running || self.debugger_is_running {
            return;
        }

        if self.target_path.trim().is_empty() {
            self.append_log("[warn] Select EXE file first");
            return;
        }

        let target_input = self.target_path.trim().trim_matches('"').to_string();
        self.target_path = target_input.clone();
        let target = PathBuf::from(target_input);
        if !target.exists() {
            self.append_log("[error] Target file does not exist");
            return;
        }

        let timeout = self.timeout_secs.trim().parse::<u64>().unwrap_or(10).max(1);
        let runs = self.runs.trim().parse::<u32>().unwrap_or(10).max(1);
        let out_dir = self.resolve_out_dir();
        let strict_mode = self.strict_mode;
        let lab_enabled = true;
        let lab_profile = self.lab_profile.as_cli_value().to_string();
        let lab_confirm_extended_tests = self.lab_confirm_extended_tests;
        let lab_custom_modules = {
            let trimmed = self.lab_custom_modules.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        };

        self.findings.clear();
        self.runtime.clear();
        self.score = 0;
        self.final_status = "RUNNING".to_string();
        self.mode_label = if strict_mode { "STRICT".to_string() } else { "BALANCED".to_string() };
        self.report_path.clear();
        self.selected_finding = None;

        self.is_running = true;
        self.started_at = Some(Instant::now());
        self.cancel_flag = Arc::new(AtomicBool::new(false));

        let cancel = Arc::clone(&self.cancel_flag);
        let (tx, rx) = mpsc::channel::<UiEvent>();
        self.rx = Some(rx);
        self.ui_tx = Some(tx.clone());
        self.restart_file_watcher();

        self.append_log(format!(
            "[run] Start scan: target='{}' timeout={} runs={} mode={} out='{}' lab_profile={} custom_modules={} confirm_extended={} ",
            target.display(),
            timeout,
            runs,
            if strict_mode { "STRICT" } else { "BALANCED" },
            out_dir.display(),
            lab_profile,
            lab_custom_modules.as_deref().unwrap_or("<none>"),
            lab_confirm_extended_tests
        ));

        thread::spawn(move || {
                    workers::scan_worker(
                        target,
                        out_dir,
                        timeout,
                        runs,
                        strict_mode,
                        lab_enabled,
                        lab_profile,
                        lab_custom_modules,
                        lab_confirm_extended_tests,
                        cancel,
                        tx,
                    );
        });
    }

    fn severity_counts(&self) -> (usize, usize, usize) {
        let mut pass = 0;
        let mut warn = 0;
        let mut fail = 0;
        for f in &self.findings {
            match f.severity.as_str() {
                "PASS" => pass += 1,
                "WARN" => warn += 1,
                "FAIL" => fail += 1,
                _ => {}
            }
        }
        (pass, warn, fail)
    }

    fn top_finding_indices(&self, limit: usize) -> Vec<usize> {
        let mut ranked: Vec<(usize, u8, u32)> = self
            .findings
            .iter()
            .enumerate()
            .map(|(idx, finding)| (idx, severity_rank(&finding.severity), finding.points))
            .collect();

        ranked.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| b.2.cmp(&a.2)));
        ranked.into_iter().take(limit).map(|(idx, _, _)| idx).collect()
    }

    fn runtime_reason(&self, runtime: &ReportRuntime) -> String {
        let mut base = if runtime.timed_out {
            self.t(
                "превышен лимит времени",
                "execution timed out",
                "Zeitlimit ueberschritten",
                "перевищено лiмiт часу",
            )
            .to_string()
        } else if let Some(code) = runtime.exit_code {
            let raw = code as u32;
            if matches!(
                raw,
                0xC0000005
                    | 0xC000001D
                    | 0xC0000094
                    | 0xC00000FD
                    | 0xC0000135
                    | 0xC0000139
                    | 0xC0000409
                    | 0x80000003
            ) {
                format!("NTSTATUS crash code {:#X}", raw)
            } else if code == 0 {
                self.t("без критических сбоев", "no critical failure", "kein kritischer Fehler", "без критичних збоїв")
                    .to_string()
            } else {
                format!(
                    "{} {}",
                    self.t(
                        "ненулевой код выхода",
                        "non-zero exit code",
                        "Exit-Code ungleich null",
                        "ненульовий код виходу"
                    ),
                    code
                )
            }
        } else {
            self.t(
                "нет нормального кода завершения",
                "no normal exit code",
                "kein normaler Exit-Code",
                "немає нормального коду завершення",
            )
            .to_string()
        };

        if let Some(detail) = self.runtime_related_finding_message(&runtime.scenario) {
            base.push_str("; ");
            base.push_str(&detail);
        }

        base
    }

    fn runtime_related_finding_message(&self, scenario: &str) -> Option<String> {
        let needle_quoted = format!("'{}'", scenario);
        let mut best: Option<&ReportFinding> = None;

        for finding in &self.findings {
            if !finding.category.eq_ignore_ascii_case("runtime") {
                continue;
            }

            if !finding.message.contains(&needle_quoted) && !finding.message.contains(scenario) {
                continue;
            }

            let current_rank = severity_rank(&finding.severity);
            let replace = match best {
                Some(prev) => {
                    let prev_rank = severity_rank(&prev.severity);
                    current_rank < prev_rank || (current_rank == prev_rank && finding.points > prev.points)
                }
                None => true,
            };

            if replace {
                best = Some(finding);
            }
        }

        best.map(|finding| {
            format!(
                "{}: {}",
                finding.code,
                truncate_label(&finding.message, 110)
            )
        })
    }

    fn draw_runtime_chart(&self, ui: &mut egui::Ui) {
        let desired_size = egui::vec2(ui.available_width(), 140.0);
        let (rect, _) = ui.allocate_exact_size(desired_size, egui::Sense::hover());
        let painter = ui.painter_at(rect);

        painter.rect_filled(rect, 6.0, zed_bg_1());
        if self.runtime.is_empty() {
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "No runtime data",
                egui::FontId::proportional(14.0),
                zed_fg_muted(),
            );
            return;
        }

        let max_ms = self.runtime.iter().map(|r| r.duration_ms).max().unwrap_or(1) as f32;
        let left = rect.left() + 10.0;
        let right = rect.right() - 10.0;
        let bottom = rect.bottom() - 18.0;
        let top = rect.top() + 12.0;
        let width = right - left;
        let bar_w = (width / self.runtime.len() as f32).max(8.0) - 4.0;

        for (idx, r) in self.runtime.iter().enumerate() {
            let x = left + idx as f32 * (bar_w + 4.0);
            let h_ratio = (r.duration_ms as f32 / max_ms).clamp(0.05, 1.0);
            let h = (bottom - top) * h_ratio;
            let bar_rect = egui::Rect::from_min_size(
                egui::pos2(x, bottom - h),
                egui::vec2(bar_w, h),
            );

            let color = if r.timed_out {
                egui::Color32::from_rgb(229, 84, 84)
            } else if r.exit_code.unwrap_or(1) == 0 {
                egui::Color32::from_rgb(73, 182, 117)
            } else {
                egui::Color32::from_rgb(225, 172, 69)
            };
            painter.rect_filled(bar_rect, 3.0, color);

            if self.runtime.len() <= 12 {
                let label = truncate_label(&r.scenario, 10);
                painter.text(
                    egui::pos2(x + bar_w * 0.5, bottom + 2.0),
                    egui::Align2::CENTER_TOP,
                    label,
                    egui::FontId::monospace(10.0),
                    zed_fg_muted(),
                );
            }
        }
    }

    fn stop_scan(&mut self) {
        if !self.is_running {
            return;
        }
        self.cancel_flag.store(true, Ordering::Relaxed);
        self.append_log("[run] Stop requested");
    }

    fn open_logs_window(&mut self) {
        self.show_logs_window = true;
    }

    fn ensure_ui_event_sender(&mut self) -> Sender<UiEvent> {
        if let Some(tx) = &self.ui_tx {
            return tx.clone();
        }

        let (tx, rx) = mpsc::channel::<UiEvent>();
        self.rx = Some(rx);
        self.ui_tx = Some(tx.clone());
        tx
    }

    fn install_vsdbg(&mut self) {
        if self.vsdbg_install_is_running {
            return;
        }

        #[cfg(not(windows))]
        {
            self.append_log("[vsdbg] Automatic install is currently supported only on Windows");
            return;
        }

        #[cfg(windows)]
        {
            self.vsdbg_install_is_running = true;
            self.append_log(
                "[vsdbg] Prerequisite: install Visual Studio Code before using this setup.",
            );
            self.append_log(
                "[vsdbg] Prerequisite: install C# Dev Kit (ms-dotnettools.csdevkit) or C# (ms-dotnettools.csharp).",
            );
            self.append_log("[vsdbg] Installing Visual Studio Code debugger (vsdbg)...");
            let tx = self.ensure_ui_event_sender();
            thread::spawn(move || {
                workers::install_vsdbg_worker(tx);
            });
        }
    }

    fn resolve_out_dir(&self) -> PathBuf {
        let trimmed = self.out_dir.trim().trim_matches('"');
        if trimmed.is_empty() {
            PathBuf::from("logs")
        } else {
            PathBuf::from(trimmed)
        }
    }

    fn open_logs_folder_on_disk(&mut self) {
        let out_dir = self.resolve_out_dir();
        if let Err(e) = fs::create_dir_all(&out_dir) {
            self.append_log(format!("[logs] Failed to create directory '{}': {}", out_dir.display(), e));
            return;
        }

        #[cfg(windows)]
        {
            let mut command = Command::new("explorer.exe");
            command.arg(&out_dir);
            command.creation_flags(0x08000000);
            match command.spawn() {
                Ok(_) => self.append_log(format!("[logs] Opened folder: {}", out_dir.display())),
                Err(e) => self.append_log(format!("[logs] Failed to open folder '{}': {}", out_dir.display(), e)),
            }
        }

        #[cfg(not(windows))]
        {
            match Command::new("xdg-open").arg(&out_dir).spawn() {
                Ok(_) => self.append_log(format!("[logs] Opened folder: {}", out_dir.display())),
                Err(e) => self.append_log(format!("[logs] Failed to open folder '{}': {}", out_dir.display(), e)),
            }
        }
    }

    fn delete_all_log_files(&mut self) {
        let out_dir = self.resolve_out_dir();
        if !out_dir.exists() {
            self.append_log(format!("[logs] Directory not found: {}", out_dir.display()));
            return;
        }

        let mut removed = 0usize;
        let mut failed = 0usize;
        let mut stack = vec![out_dir.clone()];

        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(_) => {
                    failed += 1;
                    continue;
                }
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }

                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.to_ascii_lowercase())
                    .unwrap_or_default();
                if ext != "log" && ext != "json" {
                    continue;
                }

                match fs::remove_file(&path) {
                    Ok(_) => removed += 1,
                    Err(_) => failed += 1,
                }
            }
        }

        self.logs.clear();
        self.append_log(format!(
            "[logs] Cleanup complete: removed={} failed={} in '{}'",
            removed,
            failed,
            out_dir.display()
        ));
    }

    fn start_debugger_run(&mut self) {
        if self.is_running || self.debugger_is_running {
            return;
        }

        self.ensure_debug_source_loaded();

        let target_input = self.target_path.trim().trim_matches('"').to_string();
        if target_input.is_empty() {
            self.append_log("[debug] Select target file first");
            return;
        }

        let target = PathBuf::from(&target_input);
        if !target.exists() {
            self.append_log("[debug] Target path not found");
            return;
        }

        self.debugger_backend = DebugBackend::VsDbgCli;
        self.vsdbg_command = detect_vsdbg_command();
        self.vsdbg_available = self.vsdbg_command.is_some();
        let vsdbg_command = self.vsdbg_command.clone();
        if vsdbg_command.is_none() {
            self.append_log("[debug] vsdbg is not available. Running fallback debug mode.");
            self.append_log("[debug] Install hint: Visual Studio debugger tools (vsdbg).");
            self.append_log("[debug] Optional override: set METSUKI_VSDBG_PATH to vsdbg.exe path.");
        }

        let timeout = self
            .debugger_timeout_secs
            .trim()
            .parse::<u64>()
            .unwrap_or(5)
            .max(1);
        let args = split_debugger_args(&self.debugger_args);

        self.debugger_is_running = true;
        self.debugger_cancel_flag = Arc::new(AtomicBool::new(false));
        self.debugger_controls_tx = None;
        self.debugger_last_exit = None;
        self.debugger_last_timed_out = false;
        self.debugger_last_duration_ms = 0;
        self.debugger_had_exception = false;
        self.debugger_verdict_ok = true;
        self.debugger_expected_view.clear();
        self.debugger_got_view.clear();
        self.debugger_failure_point = "-".to_string();
        self.debugger_root_cause = "-".to_string();
        self.debugger_stdout.clear();
        self.debugger_stderr.clear();
        self.debugger_active_line = None;
        self.debugger_line_history.clear();
        self.debugger_line_history_cursor = 0;

        let cancel = Arc::clone(&self.debugger_cancel_flag);
        let (tx, rx) = mpsc::channel::<UiEvent>();
        self.rx = Some(rx);
        self.ui_tx = Some(tx.clone());
        self.restart_file_watcher();

        let backend_label = if vsdbg_command.is_some() {
            self.debugger_backend.label().to_string()
        } else {
            "Fallback (no vsdbg)".to_string()
        };
        self.append_log(format!(
            "[debug] Start: backend={} target='{}' args={} timeout={}s",
            backend_label,
            target.display(),
            args.len(),
            timeout
        ));

        if let Some(vsdbg_command) = vsdbg_command {
            let (control_tx, control_rx) = mpsc::channel::<DebugControl>();
            self.debugger_controls_tx = Some(control_tx);
            thread::spawn(move || {
                workers::debug_worker_vsdbg(vsdbg_command, target, args, timeout, cancel, control_rx, tx);
            });
        } else {
            self.debugger_controls_tx = None;
            thread::spawn(move || {
                workers::debug_worker_native(target, args, timeout, cancel, tx);
            });
        }
    }

    fn send_debugger_command(&mut self, command: String) {
        let trimmed = command.trim();
        if trimmed.is_empty() {
            return;
        }

        if let Some(tx) = &self.debugger_controls_tx {
            let _ = tx.send(DebugControl::Command(trimmed.to_string()));
            self.append_log(format!("[debug] >> {}", trimmed));
        } else {
            self.append_log("[debug] Interactive command channel is not active");
        }
    }

    fn stop_debugger_run(&mut self) {
        if !self.debugger_is_running {
            return;
        }
        self.debugger_cancel_flag.store(true, Ordering::Relaxed);
        if let Some(tx) = &self.debugger_controls_tx {
            let _ = tx.send(DebugControl::Stop);
        }
        self.append_log("[debug] Stop requested");
    }

    fn poll_events(&mut self) {
        let mut drained = Vec::new();
        if let Some(rx) = &self.rx {
            while let Ok(ev) = rx.try_recv() {
                drained.push(ev);
            }
        }

        for ev in drained {
            match ev {
                UiEvent::Log(line) => self.append_log(line),
                UiEvent::Finished {
                    exit_code,
                    report,
                    report_path,
                } => {
                    self.is_running = false;
                    let duration_ms = self
                        .started_at
                        .map(|s| s.elapsed().as_millis())
                        .unwrap_or(0);
                    self.started_at = None;
                    self.append_log(format!("[run] Finished with exit code {}", exit_code));

                    if let Some(data) = report {
                        self.score = data.score;
                        self.final_status = data.final_status;
                        self.mode_label = data.mode;
                        self.findings = data.findings;
                        self.runtime = data.runtime;
                        self.append_log(format!("[report] Loaded report for {}", data.target));
                        let report_data = ReportData {
                            target: data.target,
                            mode: self.mode_label.clone(),
                            score: self.score,
                            final_status: self.final_status.clone(),
                            findings: self.findings.clone(),
                            runtime: self.runtime.clone(),
                        };
                        self.run_plugins(&report_data);
                    } else {
                        self.final_status = if exit_code == 0 {
                            "PASS".to_string()
                        } else if exit_code == 1 {
                            "WARN".to_string()
                        } else {
                            "FAIL".to_string()
                        };
                    }

                    if let Some(path) = report_path {
                        self.report_path = path.display().to_string();
                        self.append_log(format!("[report] Internal artifact: {}", self.report_path));
                    }

                    self.push_scan_history(exit_code, duration_ms);
                }
                UiEvent::DebugOutput { is_stderr, text } => {
                    if is_stderr {
                        self.debugger_stderr.push_str(&text);
                    } else {
                        self.debugger_stdout.push_str(&text);
                    }
                    self.ingest_debug_output_for_location(&text);
                }
                UiEvent::DebugFinished {
                    exit_code,
                    timed_out,
                    duration_ms,
                    stdout,
                    stderr,
                } => {
                    self.debugger_is_running = false;
                    self.debugger_controls_tx = None;
                    self.debugger_last_timed_out = timed_out;
                    self.debugger_last_duration_ms = duration_ms;
                    if !stdout.is_empty() {
                        self.debugger_stdout = stdout;
                    }
                    if !stderr.is_empty() {
                        self.debugger_stderr = stderr;
                    }

                    self.debugger_last_exit = exit_code.or_else(|| {
                        diagnostics::infer_exit_code_from_output(&self.debugger_stdout, &self.debugger_stderr)
                    });

                    self.debugger_had_exception = diagnostics::infer_debug_exception(
                        self.debugger_last_exit,
                        self.debugger_last_timed_out,
                        &self.debugger_stderr,
                    );

                    let diagnosis = diagnostics::build_debug_diagnosis(
                        self.ui_language,
                        &self.debugger_expected_exit,
                        self.debugger_expected_exception,
                        &self.debugger_expected_stdout_contains,
                        &self.debugger_expected_stderr_contains,
                        self.debugger_last_exit,
                        self.debugger_last_timed_out,
                        self.debugger_had_exception,
                        &self.debugger_stdout,
                        &self.debugger_stderr,
                    );
                    self.debugger_verdict_ok = diagnosis.verdict_ok;
                    self.debugger_expected_view = diagnosis.expected;
                    self.debugger_got_view = diagnosis.got;
                    self.debugger_failure_point = diagnosis.failure_point;
                    self.debugger_root_cause = format!(
                        "{}; crash_analyzer={} ",
                        diagnosis.root_cause,
                        diagnostics::analyze_crash_signature(self.debugger_last_exit, &self.debugger_stderr, &self.debugger_stdout)
                    );

                    if !self.debugger_stdout.trim().is_empty() {
                        self.stdout_snapshots.push(self.debugger_stdout.clone());
                        if self.stdout_snapshots.len() > 30 {
                            let overflow = self.stdout_snapshots.len() - 30;
                            self.stdout_snapshots.drain(0..overflow);
                        }
                        self.stdout_diff_right = self.stdout_snapshots.len().saturating_sub(1);
                        self.stdout_diff_left = self.stdout_diff_right.saturating_sub(1);
                        self.rebuild_stdout_diff();
                    }

                    self.push_debug_history(self.debugger_last_exit, timed_out, duration_ms);
                    self.add_debug_replay_session();

                    self.append_log(format!(
                        "[debug] Finished: exit={:?} timeout={} duration={}ms",
                        self.debugger_last_exit,
                        self.debugger_last_timed_out,
                        self.debugger_last_duration_ms
                    ));
                }
                UiEvent::WatchedFileChanged(path) => {
                    self.append_log(format!("[watcher] File change detected: {}", path));
                }
                UiEvent::VsdbgInstallFinished {
                    success,
                    path,
                    details,
                } => {
                    self.vsdbg_install_is_running = false;
                    if success {
                        if let Some(path) = path {
                            self.vsdbg_command = Some(path.clone());
                            self.vsdbg_available = true;
                            env::set_var("METSUKI_VSDBG_PATH", &path);
                            self.append_log(format!("[vsdbg] Installed: {}", path.display()));
                        } else {
                            self.vsdbg_available = false;
                            self.append_log("[vsdbg] Installation completed, but path was not returned");
                        }
                    } else {
                        self.vsdbg_available = self
                            .vsdbg_command
                            .as_ref()
                            .map(|p| p.exists())
                            .unwrap_or(false);
                        self.append_log("[vsdbg] Installation failed");
                    }

                    if !details.trim().is_empty() {
                        for line in details.lines() {
                            self.append_log(format!("[vsdbg] {}", line));
                        }
                    }
                }
            }
        }
    }

    fn ensure_logo_texture(&mut self, ctx: &egui::Context) {
        if self.logo_texture.is_some() {
            return;
        }

        let Some(path) = resolve_asset_path("logo.png") else {
            return;
        };

        let Ok(reader) = ImageReader::open(path) else {
            return;
        };
        let Ok(image) = reader.decode() else {
            return;
        };
        let rgba = image.to_rgba8();
        let size = [rgba.width() as usize, rgba.height() as usize];
        let pixels = rgba.into_raw();
        let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
        let texture = ctx.load_texture("dev_logo", color_image, egui::TextureOptions::LINEAR);
        self.logo_texture = Some(texture);
    }
}

impl eframe::App for AnalyzerGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();
        self.handle_dropped_files(ctx);
        self.apply_theme_if_needed(ctx);
        self.ensure_logo_texture(ctx);

        let splash_elapsed = self.splash_started_at.elapsed();
        if splash_elapsed < self.splash_duration {
            ctx.request_repaint_after(Duration::from_millis(16));
            draw_splash(ctx, self.logo_texture.as_ref(), self.splash_duration, splash_elapsed);
            return;
        }

        if self.is_running || self.debugger_is_running {
            ctx.request_repaint_after(Duration::from_millis(80));
            self.sample_performance();
        }

        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::default()
                    .fill(zed_bg_1())
                    .stroke(egui::Stroke::new(1.0, zed_bg_3())),
            )
            .show(ctx, |ui| {
                ui.add_space(3.0);
                ui.horizontal(|ui| {
                    ui.set_min_height(34.0);
                    ui.spacing_mut().item_spacing.x = 10.0;

                    ui.horizontal(|ui| {
                        if let Some(texture) = &self.logo_texture {
                            ui.add(egui::Image::new(texture).fit_to_exact_size(egui::vec2(30.0, 30.0)));
                        }

                        ui.label(
                            egui::RichText::new("Metsuki Workbench")
                                .size(20.0)
                                .strong()
                                .color(egui::Color32::from_rgb(216, 223, 236)),
                        );
                    });

                    ui.add_space(12.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.spacing_mut().interact_size.y = 28.0;
                        ui.spacing_mut().button_padding = egui::vec2(10.0, 6.0);

                        egui::ComboBox::from_id_salt("ui_lang_select")
                            .width(64.0)
                            .selected_text(self.ui_language.label())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.ui_language, UiLanguage::Ru, "RU");
                                ui.selectable_value(&mut self.ui_language, UiLanguage::En, "EN");
                                ui.selectable_value(&mut self.ui_language, UiLanguage::De, "DE");
                                ui.selectable_value(&mut self.ui_language, UiLanguage::Uk, "UK");
                            });

                        let logs_label = format!(
                            "{} ({})",
                            self.t("Логи", "Logs", "Protokoll", "Логи"),
                            self.logs.len()
                        );
                        if ui.add_sized([108.0, 28.0], egui::Button::new(logs_label)).clicked() {
                            self.open_logs_window();
                        }

                        if ui
                            .add_sized(
                                [160.0, 28.0],
                                egui::Button::new(self.t(
                                    "Сервер поддержки",
                                    "Support Server",
                                    "Support-Server",
                                    "Сервер підтримки",
                                )),
                            )
                            .clicked()
                        {
                            ui.ctx().open_url(egui::OpenUrl {
                                url: "https://discord.gg/xuHMjdJN6".to_string(),
                                new_tab: true,
                            });
                        }

                        if self.debugger_is_running {
                            ui.spinner();
                        }

                        ui.add_space(10.0);
                        let target_slot_width = ui.available_width().max(140.0);
                        if !self.target_path.trim().is_empty() {
                            ui.add_sized(
                                [target_slot_width, 28.0],
                                egui::Label::new(
                                    egui::RichText::new(format!("target: {}", self.target_path.trim()))
                                        .monospace()
                                        .color(zed_fg_muted()),
                                )
                                .truncate(),
                            );
                        } else {
                            ui.add_sized(
                                [target_slot_width, 28.0],
                                egui::Label::new(
                                    egui::RichText::new(self.t(
                                        "Выберите файл для анализа",
                                        "Select a file to analyze",
                                        "Datei zur Analyse auswaehlen",
                                        "Оберiть файл для аналiзу",
                                    ))
                                    .color(zed_fg_muted()),
                                )
                                .truncate(),
                            );
                        }
                    });
                });
                if self.is_running || self.debugger_is_running {
                    let expected = self
                        .timeout_secs
                        .trim()
                        .parse::<u64>()
                        .unwrap_or(10)
                        .max(1) as f32
                        * self.runs.trim().parse::<u32>().unwrap_or(10).max(1) as f32;
                    let elapsed = self
                        .started_at
                        .map(|s| s.elapsed().as_secs_f32())
                        .unwrap_or(0.0);
                    let progress = if expected > 0.0 {
                        (elapsed / expected).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };
                    ui.add(
                        egui::ProgressBar::new(progress)
                            .desired_width(ui.available_width())
                            .text(format!("running {:.0}%", progress * 100.0)),
                    );
                }
                ui.add_space(4.0);
            });

        if self.show_logs_window {
            let mut open = self.show_logs_window;
            egui::Window::new(self.t(
                "Активность / Терминал",
                "Activity / Terminal",
                "Aktivitaet / Terminal",
                "Активність / Термінал",
            ))
                .open(&mut open)
                .resizable(true)
                .movable(false)
                .default_size(egui::vec2(860.0, 320.0))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong(self.t("Поток логов", "Log stream", "Protokoll-Stream", "Потiк логiв"));
                        if self.is_running || self.debugger_is_running {
                            ui.spinner();
                        }
                        if ui.button(self.t("Открыть папку", "Open folder", "Ordner oeffnen", "Вiдкрити папку")).clicked() {
                            self.open_logs_folder_on_disk();
                        }
                        if ui.button(self.t("Удалить файлы логов", "Delete log files", "Log-Dateien loeschen", "Видалити файли логiв")).clicked() {
                            self.delete_all_log_files();
                        }
                        if ui.button(self.t("Очистить", "Clear", "Leeren", "Очистити")).clicked() {
                            self.logs.clear();
                        }
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .id_salt("activity_log_window_scroll")
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in &self.logs {
                                let color = if line.contains("[error]") {
                                    egui::Color32::from_rgb(229, 84, 84)
                                } else if line.contains("[warn]") {
                                    egui::Color32::from_rgb(225, 172, 69)
                                } else if line.contains("[run]")
                                    || line.contains("[worker]")
                                    || line.contains("[debug]")
                                {
                                    zed_accent()
                                } else {
                                    egui::Color32::from_rgb(198, 206, 219)
                                };
                                ui.label(egui::RichText::new(line).monospace().color(color));
                            }
                        });
                });
            self.show_logs_window = open;
        }

        egui::SidePanel::left("left_controls")
            .resizable(true)
            .default_width(360.0)
            .frame(
                egui::Frame::default()
                    .fill(zed_bg_1())
                    .stroke(egui::Stroke::new(1.0, zed_bg_3())),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("left_controls_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(self.t("Инспектор", "Inspector", "Inspektor", "Iнспектор"))
                        .strong()
                        .size(18.0)
                        .color(egui::Color32::from_rgb(214, 222, 238)),
                );
                ui.add_space(6.0);

                ui.label(
                    egui::RichText::new(self.t("Целевой файл", "Target file", "Zieldatei", "Цiльовий файл"))
                        .color(zed_fg_muted()),
                );
                ui.add_sized(
                    [ui.available_width(), 30.0],
                    egui::TextEdit::singleline(&mut self.target_path)
                        .hint_text("C:\\path\\to\\file"),
                );
                ui.horizontal(|ui| {
                    if ui
                        .add_sized(
                            [120.0, 28.0],
                            egui::Button::new(self.t("EXE", "Browse EXE", "EXE waehlen", "EXE")),
                        )
                        .clicked()
                    {
                        self.pick_file();
                    }
                    if ui
                        .add_sized(
                            [120.0, 28.0],
                            egui::Button::new(self.t("Любой", "Browse Any", "Beliebig", "Будь-який")),
                        )
                        .clicked()
                    {
                        self.pick_any_file();
                    }
                });

                let target = PathBuf::from(self.target_path.trim().trim_matches('"'));
                if !self.target_path.trim().is_empty() {
                    if target.exists() {
                        ui.colored_label(
                            egui::Color32::from_rgb(73, 182, 117),
                            self.t("Путь OK", "Path OK", "Pfad OK", "Шлях OK"),
                        );
                    } else {
                        ui.colored_label(
                            egui::Color32::from_rgb(229, 84, 84),
                            self.t(
                                "Путь не найден",
                                "Path not found",
                                "Pfad nicht gefunden",
                                "Шлях не знайдено",
                            ),
                        );
                    }
                }

                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(self.t("Папка отчётов", "Out dir", "Ausgabeordner", "Папка звiтiв"))
                        .color(zed_fg_muted()),
                );
                ui.add_sized([ui.available_width(), 30.0], egui::TextEdit::singleline(&mut self.out_dir));
                ui.horizontal(|ui| {
                    if ui.button(self.t("Открыть папку логов", "Open logs folder", "Log-Ordner oeffnen", "Вiдкрити папку логiв")).clicked() {
                        self.open_logs_folder_on_disk();
                    }
                    if ui.button(self.t("Удалить все логи", "Delete all logs", "Alle Logs loeschen", "Видалити всi логи")).clicked() {
                        self.delete_all_log_files();
                    }
                });

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(self.t("Таймаут", "Timeout", "Zeitlimit", "Таймаут")).color(zed_fg_muted()));
                    let timeout_edit = ui.add_sized([92.0, 28.0], egui::TextEdit::singleline(&mut self.timeout_secs));
                    ui.label(egui::RichText::new(self.t("Прогоны", "Runs", "Durchlaeufe", "Прогони")).color(zed_fg_muted()));
                    let runs_edit = ui.add_sized([92.0, 28.0], egui::TextEdit::singleline(&mut self.runs));
                    if timeout_edit.changed() || runs_edit.changed() {
                        self.scan_preset = ScanPreset::Custom;
                    }
                });

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(self.t("Профиль", "Profile", "Profil", "Профiль")).color(zed_fg_muted()));
                    if ui
                        .selectable_label(self.scan_preset == ScanPreset::Fast, self.t("Быстрый", "Fast", "Schnell", "Швидкий"))
                        .clicked()
                    {
                        self.apply_preset(ScanPreset::Fast);
                    }
                    if ui
                        .selectable_label(self.scan_preset == ScanPreset::Deep, self.t("Глубокий", "Deep", "Tief", "Глибокий"))
                        .clicked()
                    {
                        self.apply_preset(ScanPreset::Deep);
                    }
                    if ui
                        .selectable_label(self.scan_preset == ScanPreset::Custom, self.t("Кастом", "Custom", "Benutzerdef.", "Кастом"))
                        .clicked()
                    {
                        self.scan_preset = ScanPreset::Custom;
                    }
                });

                let profile_hint = match self.scan_preset {
                    ScanPreset::Fast => self.t(
                        "Быстрый прогон (меньше сценариев, мягкий вердикт)",
                        "Quick sanity test (few scenarios, balanced verdict)",
                        "Schneller Test (wenige Szenarien, ausgewogenes Urteil)",
                        "Швидкий прогiн (менше сценарiїв, м'який вердикт)",
                    ),
                    ScanPreset::Deep => self.t(
                        "Глубокий strict-прогон (больше сценариев)",
                        "Deep strict test (more scenarios, higher coverage)",
                        "Tiefer Strict-Test (mehr Szenarien)",
                        "Глибокий strict-прогiн (бiльше сценарiїв)",
                    ),
                    ScanPreset::Custom => self.t("Ручные параметры", "Manual parameters", "Manuelle Parameter", "Ручнi параметри"),
                };
                ui.colored_label(zed_fg_muted(), profile_hint);

                ui.separator();
                let strict_label = self.t(
                    "STRICT (любое предупреждение = FAIL)",
                    "STRICT mode (any warning => FAIL)",
                    "STRICT (jede Warnung = FAIL)",
                    "STRICT (будь-яке попередження = FAIL)",
                );
                let strict_changed = ui
                    .checkbox(&mut self.strict_mode, strict_label)
                    .changed();
                if strict_changed && self.scan_preset != ScanPreset::Custom {
                    self.scan_preset = ScanPreset::Custom;
                }

                ui.separator();
                ui.strong(self.t(
                    "Security-Lab (всегда включен)",
                    "Security-Lab (always enabled)",
                    "Security-Lab (immer aktiv)",
                    "Security-Lab (завжди увiмкнено)",
                ));
                ui.colored_label(
                    zed_fg_muted(),
                    self.t(
                        "По умолчанию используется готовый профиль Standard для всех целей.",
                        "Default Standard profile is used for all targets.",
                        "Standardprofil wird standardmaessig fuer alle Ziele verwendet.",
                        "Типово для всiх цiлей використовується профiль Standard.",
                    ),
                );

                ui.collapsing(
                    self.t(
                        "Расширенные настройки Security-Lab",
                        "Advanced Security-Lab settings",
                        "Erweiterte Security-Lab Einstellungen",
                        "Розширенi налаштування Security-Lab",
                    ),
                    |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(self.t("Профиль", "Profile", "Profil", "Профiль")).color(zed_fg_muted()));
                            if ui
                                .selectable_label(self.lab_profile == GuiLabProfile::Standard, self.t("Стандарт", "Standard", "Standard", "Стандарт"))
                                .clicked()
                            {
                                self.lab_profile = GuiLabProfile::Standard;
                            }
                            if ui
                                .selectable_label(self.lab_profile == GuiLabProfile::Aggressive, self.t("Агрессивный", "Aggressive", "Aggressiv", "Агресивний"))
                                .clicked()
                            {
                                self.lab_profile = GuiLabProfile::Aggressive;
                            }
                            if ui
                                .selectable_label(self.lab_profile == GuiLabProfile::Custom, self.t("Кастом", "Custom", "Benutzerdef.", "Кастом"))
                                .clicked()
                            {
                                self.lab_profile = GuiLabProfile::Custom;
                            }
                        });

                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(self.t("Модули", "Modules", "Module", "Модулi")).color(zed_fg_muted()));
                            let modules_changed = ui
                                .add_sized(
                                    [ui.available_width(), 26.0],
                                    egui::TextEdit::singleline(&mut self.lab_custom_modules)
                                        .hint_text("pe_rules,asm_disasm,runtime_sandbox_trace"),
                                )
                                .changed();
                            if modules_changed && !self.lab_custom_modules.trim().is_empty() {
                                self.lab_profile = GuiLabProfile::Custom;
                            }
                        });

                        let confirm_extended_label = self
                            .t(
                                "Разрешить deep-check (confirm extended tests)",
                                "Allow deep-check (confirm extended tests)",
                                "Deep-Checks erlauben (confirm extended tests)",
                                "Дозволити deep-check (confirm extended tests)",
                            )
                            .to_string();
                        ui.checkbox(
                            &mut self.lab_confirm_extended_tests,
                            confirm_extended_label,
                        );
                    },
                );

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let run_btn = ui.add_enabled(
                        !self.is_running && !self.debugger_is_running,
                        egui::Button::new(self.t("Запустить скан", "Start Full Scan", "Vollscan starten", "Запустити скан")),
                    );
                    if run_btn.clicked() {
                        self.run_scan();
                    }
                    let stop_btn = ui.add_enabled(
                        self.is_running,
                        egui::Button::new(self.t("Стоп", "Stop", "Stopp", "Стоп")),
                    );
                    if stop_btn.clicked() {
                        self.stop_scan();
                    }
                });

                ui.separator();
                ui.collapsing(
                    self.t("История запусков", "Run history", "Verlauf", "Iсторiя запускiв"),
                    |ui| {
                        if self.run_history.is_empty() {
                            ui.colored_label(zed_fg_muted(), self.t("Пусто", "Empty", "Leer", "Порожньо"));
                        } else {
                            for item in self.run_history.iter().rev().take(12) {
                                ui.monospace(format!(
                                    "{} | {} | exit={:?} timeout={} dur={}ms score={:?} status={} | {}",
                                    item.timestamp_unix,
                                    item.kind,
                                    item.exit,
                                    item.timed_out,
                                    item.duration_ms,
                                    item.score,
                                    item.status,
                                    truncate_label(&item.target, 42)
                                ));
                            }
                        }
                    },
                );

                ui.separator();
                ui.strong(self.t("Покрытие сборки", "Coverage in this build", "Abdeckung dieses Builds", "Покриття збiрки"));
                ui.colored_label(
                    zed_fg_muted(),
                    self.t(
                        "• PE headers, sections, entropy, entrypoint, overlay, imports",
                        "• PE headers, sections, entropy, entrypoint, overlay, imports",
                        "• PE-Header, Sektionen, Entropie, Entrypoint, Overlay, Imports",
                        "• PE headers, sections, entropy, entrypoint, overlay, imports",
                    ),
                );
                ui.colored_label(
                    zed_fg_muted(),
                    self.t(
                        "• Статический анализ source: C#, Java, Python, Go (+ generic)",
                        "• Source static checks: C#, Java, Python, Go (+ generic)",
                        "• Statische Source-Checks: C#, Java, Python, Go (+ generisch)",
                        "• Статичнi source-перевiрки: C#, Java, Python, Go (+ generic)",
                    ),
                );
                ui.colored_label(zed_fg_muted(), self.t("• Защиты: ASLR / NX / CFG", "• Mitigations: ASLR / NX / CFG", "• Schutzmechanismen: ASLR / NX / CFG", "• Захисти: ASLR / NX / CFG"));
                ui.colored_label(zed_fg_muted(), self.t("• Строковые эвристики", "• String heuristics", "• String-Heuristiken", "• Рядковi евристики"));
                ui.colored_label(
                    zed_fg_muted(),
                    self.t(
                        "• Runtime edge-case сценарии (args/stdin/env)",
                        "• Runtime edge-case scenarios (args/stdin/env)",
                        "• Laufzeit-Edge-Case-Szenarien (args/stdin/env)",
                        "• Runtime edge-case сценарiї (args/stdin/env)",
                    ),
                );
                ui.colored_label(
                    zed_fg_muted(),
                    self.t(
                        "• Strict scoring и внутренние артефакты анализа",
                        "• Strict scoring and internal analysis artifacts",
                        "• Strict-Bewertung und interne Analyse-Artefakte",
                        "• Strict scoring та внутрiшнi артефакти аналiзу",
                    ),
                );

                ui.separator();
                ui.collapsing(
                    self.t(
                        "Security-Lab: модули и совместимость",
                        "Security-Lab: modules and compatibility",
                        "Security-Lab: Module und Kompatibilitaet",
                        "Security-Lab: модулi та сумiснiсть",
                    ),
                    |ui| {
                        let target_kind = detect_info_target_kind(self.target_path.trim());
                        ui.colored_label(
                            zed_fg_muted(),
                            format!(
                                "{}: {}",
                                self.t("Тип цели", "Target class", "Zielklasse", "Тип цiлi"),
                                target_kind.label(self.ui_language)
                            ),
                        );

                        for (id, status, capability) in security_lab_overview_rows(target_kind) {
                            ui.horizontal_wrapped(|ui| {
                                ui.colored_label(lab_status_color(status), format!("[{}]", status));
                                ui.monospace(id);
                                ui.colored_label(zed_fg_muted(), capability);
                            });
                        }

                        ui.add_space(4.0);
                        ui.colored_label(
                            zed_fg_muted(),
                            self.t(
                                "ASK = модуль требует подтверждение deep-check уровня",
                                "ASK = module needs confirmation for deep-check level",
                                "ASK = Modul braucht Bestaetigung fuer Deep-Checks",
                                "ASK = модуль потребує пiдтвердження deep-check рiвня",
                            ),
                        );
                        ui.colored_label(
                            zed_fg_muted(),
                            self.t(
                                "CLI настройка: --lab-profile, --modules, --confirm-extended-tests",
                                "CLI tuning: --lab-profile, --modules, --confirm-extended-tests",
                                "CLI Anpassung: --lab-profile, --modules, --confirm-extended-tests",
                                "CLI налаштування: --lab-profile, --modules, --confirm-extended-tests",
                            ),
                        );
                    },
                );
                    });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(zed_bg_0())
                    .inner_margin(egui::Margin::same(8)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("workspace_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                ui.add_space(4.0);
                let (pass_count, warn_count, fail_count) = self.severity_counts();
                let total_findings = (pass_count + warn_count + fail_count).max(1) as f32;

                ui.horizontal(|ui| {
                    let tab_overview = self.t("Обзор", "Overview", "Uebersicht", "Огляд");
                    let tab_findings = self.t("Нахождения", "Findings", "Befunde", "Знахiдки");
                    let tab_runtime = self.t("Рантайм", "Runtime", "Laufzeit", "Рантайм");
                    let tab_debugger = self.t("Дебаг", "Debugger", "Debugger", "Дебаг");
                    ui.selectable_value(
                        &mut self.active_tab,
                        WorkspaceTab::Overview,
                        tab_overview,
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        WorkspaceTab::Findings,
                        tab_findings,
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        WorkspaceTab::Runtime,
                        tab_runtime,
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        WorkspaceTab::Debugger,
                        tab_debugger,
                    );
                });
                ui.separator();

                match self.active_tab {
                    WorkspaceTab::Overview => {
                        ui.heading(self.t("Обзор", "Overview", "Uebersicht", "Огляд"));
                        ui.columns(4, |cols| {
                            cols[0].group(|ui| {
                                ui.label(egui::RichText::new("PASS").color(severity_color("PASS")));
                                ui.heading(pass_count.to_string());
                            });
                            cols[1].group(|ui| {
                                ui.label(egui::RichText::new("WARN").color(severity_color("WARN")));
                                ui.heading(warn_count.to_string());
                            });
                            cols[2].group(|ui| {
                                ui.label(egui::RichText::new("FAIL").color(severity_color("FAIL")));
                                ui.heading(fail_count.to_string());
                            });
                            cols[3].group(|ui| {
                                ui.label(
                                    egui::RichText::new(self.t("Риск-скор", "Risk score", "Risiko-Score", "Ризик-скор"))
                                        .color(zed_fg_muted()),
                                );
                                ui.heading(self.score.to_string());
                            });
                        });

                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.colored_label(severity_color("PASS"), "PASS");
                            ui.add(
                                egui::ProgressBar::new(pass_count as f32 / total_findings)
                                    .desired_width(120.0)
                                    .show_percentage(),
                            );
                            ui.colored_label(severity_color("WARN"), "WARN");
                            ui.add(
                                egui::ProgressBar::new(warn_count as f32 / total_findings)
                                    .desired_width(120.0)
                                    .show_percentage(),
                            );
                            ui.colored_label(severity_color("FAIL"), "FAIL");
                            ui.add(
                                egui::ProgressBar::new(fail_count as f32 / total_findings)
                                    .desired_width(120.0)
                                    .show_percentage(),
                            );
                        });

                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(self.t("График длительности", "Runtime duration chart", "Laufzeitdiagramm", "Графiк тривалостi"))
                                .color(zed_fg_muted()),
                        );
                        self.draw_runtime_chart(ui);

                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(self.t(
                                "Performance timeline (CPU/RAM)",
                                "Performance timeline (CPU/RAM)",
                                "Performance-Timeline (CPU/RAM)",
                                "Performance timeline (CPU/RAM)",
                            ))
                            .color(zed_fg_muted()),
                        );
                        self.draw_perf_timeline(ui);

                        ui.add_space(10.0);
                        ui.heading(self.t("Топ находок", "Top Findings", "Top-Befunde", "Топ знахiдок"));
                        ui.separator();
                        if self.findings.is_empty() {
                            ui.colored_label(
                                zed_fg_muted(),
                                self.t("Пока нет данных", "No findings loaded yet", "Noch keine Befunde", "Поки немає даних"),
                            );
                        } else {
                            let top_indices = self.top_finding_indices(24);
                            egui::ScrollArea::vertical()
                                .id_salt("overview_top_findings_scroll")
                                .max_height(220.0)
                                .show(ui, |ui| {
                                    for idx in top_indices {
                                        let finding = &self.findings[idx];
                                        ui.horizontal(|ui| {
                                            let selected = self.selected_finding == Some(idx);
                                            if ui
                                                .selectable_label(
                                                    selected,
                                                    egui::RichText::new(format!("[{}]", finding.severity))
                                                        .color(severity_color(&finding.severity)),
                                                )
                                                .clicked()
                                            {
                                                self.selected_finding = Some(idx);
                                                self.active_tab = WorkspaceTab::Findings;
                                            }
                                            ui.monospace(egui::RichText::new(&finding.code).color(zed_fg_muted()));
                                            ui.label(truncate_label(&finding.message, 116));
                                        });
                                    }
                                });
                        }
                    }
                    WorkspaceTab::Findings => {
                        ui.heading(self.t("Нахождения", "Findings", "Befunde", "Знахiдки"));
                        ui.separator();

                        let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 8.0;
                        egui::ScrollArea::horizontal()
                            .id_salt("findings_table_hscroll")
                            .show(ui, |ui| {
                                TableBuilder::new(ui)
                                    .id_salt("findings_table")
                                    .striped(true)
                                    .column(Column::exact(70.0))
                                    .column(Column::exact(170.0))
                                    .column(Column::exact(110.0))
                                    .column(Column::exact(60.0))
                                    .column(Column::remainder())
                                    .min_scrolled_height(220.0)
                                    .header(22.0, |mut header| {
                                        header.col(|ui| {
                                            ui.strong(self.t("Уровень", "Severity", "Schwere", "Рiвень"));
                                        });
                                        header.col(|ui| {
                                            ui.strong(self.t("Код", "Code", "Code", "Код"));
                                        });
                                        header.col(|ui| {
                                            ui.strong(self.t("Категория", "Category", "Kategorie", "Категорiя"));
                                        });
                                        header.col(|ui| {
                                            ui.strong(self.t("Баллы", "Pts", "Punkte", "Бали"));
                                        });
                                        header.col(|ui| {
                                            ui.strong(self.t("Сообщение", "Message", "Meldung", "Повiдомлення"));
                                        });
                                    })
                                    .body(|body| {
                                        body.rows(text_height, self.findings.len(), |mut row| {
                                            let index = row.index();
                                            let item = &self.findings[index];
                                            row.col(|ui| {
                                                let selected = self.selected_finding == Some(index);
                                                if ui
                                                    .selectable_label(
                                                        selected,
                                                        egui::RichText::new(&item.severity)
                                                            .color(severity_color(&item.severity)),
                                                    )
                                                    .clicked()
                                                {
                                                    self.selected_finding = Some(index);
                                                }
                                            });
                                            row.col(|ui| {
                                                ui.monospace(&item.code);
                                            });
                                            row.col(|ui| {
                                                ui.label(&item.category);
                                            });
                                            row.col(|ui| {
                                                ui.label(item.points.to_string());
                                            });
                                            row.col(|ui| {
                                                ui.label(&item.message);
                                            });
                                        });
                                    });
                            });

                        if let Some(idx) = self.selected_finding {
                            if let Some(item) = self.findings.get(idx) {
                                ui.add_space(8.0);
                                ui.group(|ui| {
                                    ui.strong(format!(
                                        "{}: {}",
                                        self.t("Выбранное", "Selected finding", "Ausgewaehlt", "Вибране"),
                                        item.code
                                    ));
                                    ui.label(format!(
                                        "{}: {} | {}: {} | {}: {}",
                                        self.t("Уровень", "Severity", "Schwere", "Рiвень"),
                                        item.severity,
                                        self.t("Категория", "Category", "Kategorie", "Категорiя"),
                                        item.category,
                                        self.t("Баллы", "Points", "Punkte", "Бали"),
                                        item.points
                                    ));
                                    ui.label(&item.message);
                                });
                            }
                        }
                    }
                    WorkspaceTab::Runtime => {
                        ui.heading(self.t("Runtime-сценарии", "Runtime Scenarios", "Laufzeit-Szenarien", "Runtime-сценарiї"));
                        ui.separator();
                        self.draw_runtime_chart(ui);
                        ui.add_space(10.0);

                        let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 8.0;
                        egui::ScrollArea::horizontal()
                            .id_salt("runtime_table_hscroll")
                            .show(ui, |ui| {
                                TableBuilder::new(ui)
                                    .id_salt("runtime_table")
                                    .striped(true)
                                    .column(Column::exact(220.0))
                                    .column(Column::exact(80.0))
                                    .column(Column::exact(70.0))
                                    .column(Column::exact(90.0))
                                    .column(Column::exact(90.0))
                                    .column(Column::exact(90.0))
                                    .column(Column::exact(110.0))
                                    .column(Column::remainder())
                                    .min_scrolled_height(210.0)
                                    .header(22.0, |mut header| {
                                        header.col(|ui| {
                                            ui.strong(self.t("Сценарий", "Scenario", "Szenario", "Сценарiй"));
                                        });
                                        header.col(|ui| {
                                            ui.strong(self.t("Выход", "Exit", "Exit", "Вихiд"));
                                        });
                                        header.col(|ui| {
                                            ui.strong(self.t("Таймаут", "Timeout", "Zeitlimit", "Таймаут"));
                                        });
                                        header.col(|ui| {
                                            ui.strong("ms");
                                        });
                                        header.col(|ui| {
                                            ui.strong("stdout");
                                        });
                                        header.col(|ui| {
                                            ui.strong("stderr");
                                        });
                                        header.col(|ui| {
                                            ui.strong(self.t("Статус", "State", "Status", "Стан"));
                                        });
                                        header.col(|ui| {
                                            ui.strong(self.t("Причина", "Reason", "Grund", "Причина"));
                                        });
                                    })
                                    .body(|body| {
                                        body.rows(text_height, self.runtime.len(), |mut row| {
                                            let r = &self.runtime[row.index()];
                                            row.col(|ui| {
                                                ui.label(&r.scenario);
                                            });
                                            row.col(|ui| {
                                                ui.label(format!("{:?}", r.exit_code));
                                            });
                                            row.col(|ui| {
                                                ui.label(if r.timed_out {
                                                    self.t("да", "yes", "ja", "так")
                                                } else {
                                                    self.t("нет", "no", "nein", "нi")
                                                });
                                            });
                                            row.col(|ui| {
                                                ui.label(r.duration_ms.to_string());
                                            });
                                            row.col(|ui| {
                                                ui.label(r.stdout_len.to_string());
                                            });
                                            row.col(|ui| {
                                                ui.label(r.stderr_len.to_string());
                                            });
                                            row.col(|ui| {
                                                let mut label = self.t("ок", "ok", "ok", "ок");
                                                if r.timed_out {
                                                    label = self.t("таймаут", "timeout", "Zeitlimit", "таймаут");
                                                } else if let Some(code) = r.exit_code {
                                                    if code != 0 {
                                                        label = self.t("ненулевой", "non-zero", "ungleich null", "ненульовий");
                                                    }
                                                } else {
                                                    label = self.t("аномально", "abnormal", "abnormal", "аномально");
                                                }
                                                ui.label(label);
                                            });
                                            row.col(|ui| {
                                                ui.label(self.runtime_reason(r));
                                            });
                                        });
                                    });
                            });
                    }
                    WorkspaceTab::Debugger => {
                        self.ensure_debug_source_loaded();

                        ui.heading(self.t("Дебагер", "Debugger", "Debugger", "Дебагер"));
                        ui.separator();

                        ui.horizontal(|ui| {
                            self.debugger_backend = DebugBackend::VsDbgCli;
                            ui.label(egui::RichText::new(self.t("Бэкенд", "Backend", "Backend", "Бекенд")).color(zed_fg_muted()));
                            let backend_label = if self.vsdbg_available {
                                self.t("vsdbg (готов)", "vsdbg (ready)", "vsdbg (bereit)", "vsdbg (готовий)")
                            } else {
                                self.t("vsdbg (нет, fallback)", "vsdbg (missing, fallback)", "vsdbg (fehlt, fallback)", "vsdbg (нема, fallback)")
                            };
                            let backend_color = if self.vsdbg_available {
                                egui::Color32::from_rgb(73, 182, 117)
                            } else {
                                egui::Color32::from_rgb(225, 172, 69)
                            };
                            ui.colored_label(backend_color, backend_label);
                            if ui.button(self.t("Проверить vsdbg", "Recheck vsdbg", "vsdbg pruefen", "Перевiрити vsdbg")).clicked() {
                                self.vsdbg_command = detect_vsdbg_command();
                                self.vsdbg_available = self.vsdbg_command.is_some();
                                if let Some(path) = &self.vsdbg_command {
                                    self.append_log(format!("[debug] vsdbg detected: {}", path.display()));
                                } else {
                                    self.append_log("[debug] vsdbg not found in PATH or known folders");
                                }
                            }
                            let install_button = ui.add_enabled(
                                !self.vsdbg_install_is_running,
                                egui::Button::new(self.t(
                                    "Установить vsdbg",
                                    "Install vsdbg",
                                    "vsdbg installieren",
                                    "Встановити vsdbg",
                                )),
                            );
                            let install_clicked = install_button.clicked();
                            install_button.on_hover_text(self.t(
                                "Перед установкой: нужен Visual Studio Code и расширение C# Dev Kit (или C#).",
                                "Before install: Visual Studio Code and C# Dev Kit extension (or C#) are required.",
                                "Vor der Installation: Visual Studio Code und C# Dev Kit (oder C#) sind erforderlich.",
                                "Перед встановленням: потрiбен Visual Studio Code i розширення C# Dev Kit (або C#).",
                            ));
                            if install_clicked {
                                self.install_vsdbg();
                            }
                            if self.vsdbg_install_is_running {
                                ui.spinner();
                            }
                            ui.separator();
                            ui.label(egui::RichText::new(self.t("Аргументы", "Args", "Argumente", "Аргументи")).color(zed_fg_muted()));
                            ui.add_sized([220.0, 26.0], egui::TextEdit::singleline(&mut self.debugger_args));
                            ui.label(egui::RichText::new(self.t("Таймаут, сек", "Timeout, sec", "Zeitlimit, sek", "Таймаут, сек")).color(zed_fg_muted()));
                            ui.add_sized([66.0, 26.0], egui::TextEdit::singleline(&mut self.debugger_timeout_secs));
                        });

                        let interactive_backend = false;

                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .add_enabled(!self.debugger_is_running && !self.is_running, egui::Button::new(self.t("Старт", "Start", "Start", "Старт")))
                                .clicked()
                            {
                                self.start_debugger_run();
                            }
                            if ui
                                .add_enabled(self.debugger_is_running && interactive_backend, egui::Button::new(self.t("Следующий шаг", "Next step", "Naechster Schritt", "Наступний крок")))
                                .clicked()
                            {
                                self.send_debug_next();
                            }
                            if ui.button(self.t("Предыдущий", "Previous", "Vorheriger", "Попереднiй")).clicked() {
                                self.step_back_in_history();
                            }
                            if ui
                                .add_enabled(self.debugger_is_running && interactive_backend, egui::Button::new(self.t("Авто вперед", "Auto forward", "Auto vorwaerts", "Авто вперед")))
                                .clicked()
                            {
                                self.send_debug_continue();
                            }
                            if ui
                                .add_enabled(self.debugger_is_running && interactive_backend, egui::Button::new(self.t("Пауза", "Pause", "Pause", "Пауза")))
                                .clicked()
                            {
                                self.send_debug_pause();
                            }
                            if ui
                                .add_enabled(self.debugger_is_running, egui::Button::new(self.t("Стоп", "Stop", "Stopp", "Стоп")))
                                .clicked()
                            {
                                self.stop_debugger_run();
                            }
                        });

                        ui.add_space(6.0);
                        ui.group(|ui| {
                            ui.strong(self.t(
                                "Проверка результата и причина сбоя",
                                "Result verification and failure reason",
                                "Ergebnispruefung und Fehlergrund",
                                "Перевiрка результату та причина збою",
                            ));

                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new(self.t("Ожид. exit", "Expected exit", "Erwarteter Exit", "Очiк. exit")).color(zed_fg_muted()));
                                ui.add_sized([66.0, 24.0], egui::TextEdit::singleline(&mut self.debugger_expected_exit));
                                let expected_exception_label = self
                                    .t(
                                        "Ожидать exception",
                                        "Expect exception",
                                        "Exception erwarten",
                                        "Очiкувати exception",
                                    )
                                    .to_string();
                                ui.checkbox(
                                    &mut self.debugger_expected_exception,
                                    expected_exception_label,
                                );
                                ui.label(egui::RichText::new("stdout~").color(zed_fg_muted()));
                                ui.add_sized(
                                    [170.0, 24.0],
                                    egui::TextEdit::singleline(&mut self.debugger_expected_stdout_contains),
                                );
                                ui.label(egui::RichText::new("stderr~").color(zed_fg_muted()));
                                ui.add_sized(
                                    [170.0, 24.0],
                                    egui::TextEdit::singleline(&mut self.debugger_expected_stderr_contains),
                                );
                            });

                            if interactive_backend {
                                let mut send_clicked = false;
                                let mut enter_pressed = false;

                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(self.t("Команда", "Command", "Befehl", "Команда")).color(zed_fg_muted()));
                                    let command_hint = self
                                        .t(
                                            "например: where / bt / next / continue",
                                            "e.g. where / bt / next / continue",
                                            "z.B. where / bt / next / continue",
                                            "наприклад: where / bt / next / continue",
                                        )
                                        .to_string();
                                    let resp = ui.add_sized(
                                        [360.0, 24.0],
                                        egui::TextEdit::singleline(&mut self.debugger_command_input)
                                            .hint_text(command_hint),
                                    );
                                    enter_pressed =
                                        resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                    send_clicked = ui
                                        .add_enabled(
                                            self.debugger_is_running,
                                            egui::Button::new(self.t("Отправить", "Send", "Senden", "Надiслати")),
                                        )
                                        .clicked();
                                });

                                if (send_clicked || enter_pressed) && self.debugger_is_running {
                                    let command = self.debugger_command_input.trim().to_string();
                                    if !command.is_empty() {
                                        self.send_debugger_command(command);
                                        self.debugger_command_input.clear();
                                    }
                                }
                            }

                            if self.vsdbg_available {
                                if let Some(path) = &self.vsdbg_command {
                                    ui.monospace(format!(
                                        "{}: {}",
                                        self.t("Путь vsdbg", "vsdbg path", "vsdbg-Pfad", "Шлях vsdbg"),
                                        path.display()
                                    ));
                                }
                                ui.colored_label(
                                    zed_fg_muted(),
                                    self.t(
                                        "vsdbg найден: запуск идет через Visual Studio Debugger CLI, без старта Visual Studio IDE",
                                        "vsdbg detected: launch goes through Visual Studio Debugger CLI without opening Visual Studio IDE",
                                        "vsdbg erkannt: Start erfolgt ueber Visual Studio Debugger CLI ohne Visual Studio IDE",
                                        "vsdbg знайдено: запуск йде через Visual Studio Debugger CLI без старту Visual Studio IDE",
                                    ),
                                );
                            } else {
                                ui.colored_label(
                                    egui::Color32::from_rgb(225, 172, 69),
                                    self.t(
                                        "vsdbg не найден: работает fallback-дебаг. Для backend Visual Studio Debugger установите vsdbg и нажмите 'Проверить vsdbg'.",
                                        "vsdbg not found: fallback debug is active. Install vsdbg and click 'Recheck vsdbg'.",
                                        "vsdbg nicht gefunden: Fallback-Debug ist aktiv. Installieren Sie vsdbg und klicken Sie 'vsdbg pruefen'.",
                                        "vsdbg не знайдено: активний fallback-дебаг. Встановiть vsdbg i натиснiть 'Перевiрити vsdbg'.",
                                    ),
                                );
                                ui.colored_label(
                                    zed_fg_muted(),
                                    self.t(
                                        "Требования: установленный Visual Studio Code и расширение C# Dev Kit (или C#).",
                                        "Requirements: installed Visual Studio Code and C# Dev Kit extension (or C#).",
                                        "Voraussetzungen: installiertes Visual Studio Code und C# Dev Kit (oder C#).",
                                        "Вимоги: встановлений Visual Studio Code i розширення C# Dev Kit (або C#).",
                                    ),
                                );
                            }

                            let verdict_color = if self.debugger_verdict_ok {
                                egui::Color32::from_rgb(73, 182, 117)
                            } else {
                                egui::Color32::from_rgb(229, 84, 84)
                            };
                            let verdict_label = if self.debugger_verdict_ok {
                                self.t("вердикт: OK", "verdict: OK", "Urteil: OK", "вердикт: OK")
                            } else {
                                self.t("вердикт: MISMATCH", "verdict: MISMATCH", "Urteil: ABWEICHUNG", "вердикт: MISMATCH")
                            };
                            ui.colored_label(verdict_color, verdict_label);

                            if !self.debugger_expected_view.trim().is_empty() {
                                ui.monospace(format!("expected => {}", self.debugger_expected_view));
                            }
                            if !self.debugger_got_view.trim().is_empty() {
                                ui.monospace(format!("got      => {}", self.debugger_got_view));
                            }
                            ui.label(format!(
                                "{}: {}",
                                self.t("Точка сбоя", "Failure point", "Fehlerstelle", "Точка збою"),
                                self.debugger_failure_point
                            ));
                            ui.label(format!(
                                "{}: {}",
                                self.t("Корень причины", "Root cause", "Hauptursache", "Корiнь причини"),
                                self.debugger_root_cause
                            ));
                        });

                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(self.t("Показывать прогоны", "Show runs", "Runs anzeigen", "Показувати прогони")).color(zed_fg_muted()));
                            egui::ComboBox::from_id_salt("debug_replay_filter")
                                .selected_text(self.debug_replay_filter.label())
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.debug_replay_filter, DebugSessionFilter::All, DebugSessionFilter::All.label());
                                    ui.selectable_value(&mut self.debug_replay_filter, DebugSessionFilter::Pass, DebugSessionFilter::Pass.label());
                                    ui.selectable_value(&mut self.debug_replay_filter, DebugSessionFilter::Error, DebugSessionFilter::Error.label());
                                });

                            let filtered_indices: Vec<usize> = self
                                .debug_replay_sessions
                                .iter()
                                .enumerate()
                                .filter_map(|(idx, session)| self.session_matches_filter(session).then_some(idx))
                                .collect();

                            let replay_text = self
                                .debug_replay_selected
                                .and_then(|idx| self.debug_replay_sessions.get(idx))
                                .map(|s| format!("#{} {} exit={:?}", self.debug_replay_selected.unwrap_or(0), s.status, s.exit_code))
                                .unwrap_or_else(|| "<none>".to_string());

                            egui::ComboBox::from_id_salt("debug_replay_selector")
                                .selected_text(replay_text)
                                .width(300.0)
                                .show_ui(ui, |ui| {
                                    for idx in filtered_indices.iter().rev().copied() {
                                        let Some(s) = self.debug_replay_sessions.get(idx) else { continue; };
                                        let label = format!(
                                            "#{} {} t={} exit={:?} {}ms",
                                            idx,
                                            s.status,
                                            s.timestamp_unix,
                                            s.exit_code,
                                            s.duration_ms
                                        );
                                        if ui.selectable_label(self.debug_replay_selected == Some(idx), label).clicked() {
                                            self.load_replay_session(idx);
                                        }
                                    }
                                });
                        });

                        ui.separator();
                        ui.group(|ui| {
                            ui.strong(self.t("Окно кода", "Code view", "Code-Fenster", "Вiкно коду"));
                            if self.debugger_source_path.trim().is_empty() {
                                ui.colored_label(zed_fg_muted(), self.t("Файл исходника не определен", "Source file is not resolved", "Quelldatei nicht gefunden", "Файл вихiдного коду не визначено"));
                            } else {
                                ui.monospace(format!("{}", self.debugger_source_path));
                            }

                            let selected_line = self.selected_debug_line();
                            if let Some(line) = selected_line {
                                ui.colored_label(zed_fg_muted(), format!("line: {}", line));
                            }

                            egui::ScrollArea::vertical()
                                .id_salt("debug_code_view")
                                .max_height(350.0)
                                .show(ui, |ui| {
                                    if self.debugger_source_lines.is_empty() {
                                        ui.colored_label(zed_fg_muted(), self.t("Нет кода для отображения", "No source loaded", "Kein Quellcode geladen", "Немає коду для вiдображення"));
                                    } else {
                                        for (idx, line) in self.debugger_source_lines.iter().enumerate() {
                                            let line_no = idx + 1;
                                            let is_active = selected_line == Some(line_no);
                                            let bg = if is_active {
                                                egui::Color32::from_rgb(40, 58, 82)
                                            } else {
                                                zed_bg_1()
                                            };
                                            egui::Frame::default()
                                                .fill(bg)
                                                .inner_margin(egui::Margin::same(2))
                                                .show(ui, |ui| {
                                                    ui.horizontal(|ui| {
                                                        let number_color = if is_active {
                                                            egui::Color32::from_rgb(166, 210, 255)
                                                        } else {
                                                            zed_fg_muted()
                                                        };
                                                        ui.monospace(egui::RichText::new(format!("{:>5}", line_no)).color(number_color));
                                                        ui.monospace(line);
                                                    });
                                                });
                                        }
                                    }
                                });
                        });

                        ui.add_space(6.0);
                        ui.columns(2, |cols| {
                            cols[0].group(|ui| {
                                ui.label(egui::RichText::new("stdout").color(zed_fg_muted()));
                                egui::ScrollArea::vertical()
                                    .id_salt("debug_stdout_scroll")
                                    .max_height(180.0)
                                    .show(ui, |ui| {
                                        if self.debugger_stdout.trim().is_empty() {
                                            ui.colored_label(zed_fg_muted(), "<empty>");
                                        } else {
                                            ui.monospace(&self.debugger_stdout);
                                        }
                                    });
                            });

                            cols[1].group(|ui| {
                                ui.label(egui::RichText::new("stderr").color(zed_fg_muted()));
                                egui::ScrollArea::vertical()
                                    .id_salt("debug_stderr_scroll")
                                    .max_height(180.0)
                                    .show(ui, |ui| {
                                        if self.debugger_stderr.trim().is_empty() {
                                            ui.colored_label(zed_fg_muted(), "<empty>");
                                        } else {
                                            ui.monospace(&self.debugger_stderr);
                                        }
                                    });
                            });
                        });
                    }
                }
                    });
            });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InfoTargetKind {
    Executable,
    Source,
    Unknown,
}

impl InfoTargetKind {
    fn label(self, lang: UiLanguage) -> &'static str {
        match lang {
            UiLanguage::Ru => match self {
                InfoTargetKind::Executable => "Executable (.exe)",
                InfoTargetKind::Source => "Source code",
                InfoTargetKind::Unknown => "Unknown",
            },
            UiLanguage::En => match self {
                InfoTargetKind::Executable => "Executable (.exe)",
                InfoTargetKind::Source => "Source code",
                InfoTargetKind::Unknown => "Unknown",
            },
            UiLanguage::De => match self {
                InfoTargetKind::Executable => "Executable (.exe)",
                InfoTargetKind::Source => "Quellcode",
                InfoTargetKind::Unknown => "Unbekannt",
            },
            UiLanguage::Uk => match self {
                InfoTargetKind::Executable => "Executable (.exe)",
                InfoTargetKind::Source => "Source code",
                InfoTargetKind::Unknown => "Unknown",
            },
        }
    }
}

fn detect_info_target_kind(target_path: &str) -> InfoTargetKind {
    let ext = PathBuf::from(target_path.trim().trim_matches('"'))
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "exe" => InfoTargetKind::Executable,
        "cs" | "java" | "py" | "go" | "js" | "ts" | "kt" | "swift" | "rb" | "php"
        | "lua" => InfoTargetKind::Source,
        _ => InfoTargetKind::Unknown,
    }
}

fn security_lab_overview_rows(target_kind: InfoTargetKind) -> Vec<(&'static str, &'static str, &'static str)> {
    let mut rows = Vec::new();
    match target_kind {
        InfoTargetKind::Executable => {
            rows.push(("pe_rules", "ON", "PE integrity, mitigations, imports/overlay"));
            rows.push(("asm_disasm", "ON", "opcode signatures and branch density"));
            rows.push(("symbolic_pathing", "ASK", "deep symbolic branch exploration"));
            rows.push(("taint_dataflow", "BLOCKED", "source-only taint propagation"));
            rows.push(("runtime_sandbox_trace", "ON", "runtime sandbox trace timeline"));
            rows.push(("fuzz_native", "ON", "native fuzz campaigns"));
            rows.push(("fuzz_libafl", "ASK", "coverage-guided libafl campaign"));
            rows.push(("business_regression", "BLOCKED", "source business-logic regression"));
        }
        InfoTargetKind::Source => {
            rows.push(("pe_rules", "BLOCKED", "PE checks require executable target"));
            rows.push(("asm_disasm", "BLOCKED", "ASM layer requires executable target"));
            rows.push(("symbolic_pathing", "ASK", "deep symbolic path pressure"));
            rows.push(("taint_dataflow", "ON", "source-to-sink taint and dataflow"));
            rows.push(("runtime_sandbox_trace", "BLOCKED", "runtime sandbox is exe-oriented"));
            rows.push(("fuzz_native", "BLOCKED", "native fuzz is exe-oriented"));
            rows.push(("fuzz_libafl", "BLOCKED", "libafl campaign is exe-oriented"));
            rows.push(("business_regression", "ON", "business logic regression checks"));
        }
        InfoTargetKind::Unknown => {
            rows.push(("pe_rules", "OFF", "select target file to resolve compatibility"));
            rows.push(("asm_disasm", "OFF", "select target file to resolve compatibility"));
            rows.push(("symbolic_pathing", "ASK", "deep checks available after target resolve"));
            rows.push(("taint_dataflow", "OFF", "select target file to resolve compatibility"));
            rows.push(("runtime_sandbox_trace", "OFF", "select target file to resolve compatibility"));
            rows.push(("fuzz_native", "OFF", "select target file to resolve compatibility"));
            rows.push(("fuzz_libafl", "ASK", "requires libafl build and confirmation"));
            rows.push(("business_regression", "OFF", "select target file to resolve compatibility"));
        }
    }
    rows
}

fn lab_status_color(status: &str) -> egui::Color32 {
    match status {
        "ON" => egui::Color32::from_rgb(73, 182, 117),
        "ASK" => egui::Color32::from_rgb(225, 172, 69),
        "BLOCKED" => egui::Color32::from_rgb(112, 120, 132),
        _ => zed_fg_muted(),
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "FAIL" => 0,
        "WARN" => 1,
        "PASS" => 2,
        _ => 3,
    }
}

fn truncate_label(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max {
        return text.to_string();
    }
    let keep = max.saturating_sub(1);
    chars.into_iter().take(keep).collect::<String>() + "…"
}

fn detect_vsdbg_command() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(path) = env::var_os("METSUKI_VSDBG_PATH") {
        candidates.push(PathBuf::from(path));
    }

    candidates.extend(vsdbg_local_candidates());
    candidates.extend(vsdbg_path_candidates());
    candidates.extend(vsdbg_where_candidates());
    candidates.extend(vsdbg_windows_candidates());

    let mut seen = HashSet::new();
    for candidate in candidates {
        let key = vsdbg_candidate_key(&candidate);
        if !seen.insert(key) {
            continue;
        }
        if vsdbg_probe_available(&candidate) {
            return Some(candidate);
        }
    }

    None
}

fn vsdbg_path_candidates() -> Vec<PathBuf> {
    if cfg!(windows) {
        vec![PathBuf::from("vsdbg.exe"), PathBuf::from("vsdbg")]
    } else {
        vec![PathBuf::from("vsdbg")]
    }
}

fn vsdbg_candidate_key(path: &Path) -> String {
    if cfg!(windows) {
        path.to_string_lossy().replace('/', "\\").to_ascii_lowercase()
    } else {
        path.to_string_lossy().to_string()
    }
}

fn vsdbg_local_candidates() -> Vec<PathBuf> {
    let vsdbg_name = if cfg!(windows) { "vsdbg.exe" } else { "vsdbg" };
    let mut candidates = Vec::new();

    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd.join(vsdbg_name));
        candidates.push(cwd.join(".tools").join("vsdbg").join(vsdbg_name));
        candidates.push(cwd.join("tools").join("vsdbg").join(vsdbg_name));
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join(vsdbg_name));
            candidates.push(exe_dir.join(".tools").join("vsdbg").join(vsdbg_name));
            candidates.push(exe_dir.join("tools").join("vsdbg").join(vsdbg_name));
            candidates.push(exe_dir.join("..").join(".tools").join("vsdbg").join(vsdbg_name));
            candidates.push(exe_dir.join("..").join("tools").join("vsdbg").join(vsdbg_name));
        }
    }

    candidates
}

fn vsdbg_probe_available(vsdbg_command: &Path) -> bool {
    let is_vsdbg_name = vsdbg_command
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_ascii_lowercase().contains("vsdbg"))
        .unwrap_or(false);
    if !is_vsdbg_name {
        return false;
    }

    let mut command = Command::new(vsdbg_command);
    command.arg("--help").stdout(Stdio::null()).stderr(Stdio::null());

    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
    }

    command.status().is_ok()
}

#[cfg(windows)]
fn vsdbg_where_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for query in ["vsdbg.exe", "vsdbg"] {
        let mut command = Command::new("where");
        command
            .arg(query)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(0x08000000);

        let Ok(output) = command.output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }

        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let trimmed = line.trim().trim_matches('"');
            if trimmed.is_empty() {
                continue;
            }
            candidates.push(PathBuf::from(trimmed));
        }
    }

    candidates
}

#[cfg(not(windows))]
fn vsdbg_where_candidates() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(windows)]
fn vsdbg_windows_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![
        PathBuf::from(r"C:\Program Files\vsdbg\vsdbg.exe"),
        PathBuf::from(r"C:\Program Files (x86)\vsdbg\vsdbg.exe"),
        PathBuf::from(r"C:\tools\vsdbg\vsdbg.exe"),
        PathBuf::from(r"C:\vsdbg\vsdbg.exe"),
    ];

    if let Some(user_profile) = env::var_os("USERPROFILE") {
        let base = PathBuf::from(user_profile);
        candidates.push(base.join("vsdbg").join("vsdbg.exe"));
        candidates.push(base.join(".vsdbg").join("vsdbg.exe"));
        candidates.push(base.join("scoop").join("apps").join("vsdbg").join("current").join("vsdbg.exe"));
        candidates.extend(vsdbg_vscode_extension_candidates(&base));
    }

    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        let base = PathBuf::from(local_app_data);
        candidates.push(base.join("vsdbg").join("vsdbg.exe"));
    }

    candidates.extend(vsdbg_visual_studio_candidates());
    candidates.extend(vsdbg_vswhere_candidates());

    candidates
}

#[cfg(windows)]
fn vsdbg_visual_studio_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for env_var in ["ProgramFiles", "ProgramFiles(x86)"] {
        let Some(base) = env::var_os(env_var) else {
            continue;
        };

        let visual_studio_root = PathBuf::from(base).join("Microsoft Visual Studio");
        let Ok(year_dirs) = fs::read_dir(&visual_studio_root) else {
            continue;
        };

        for year_dir in year_dirs.flatten() {
            let year_path = year_dir.path();
            if !year_path.is_dir() {
                continue;
            }

            for sku in ["Community", "Professional", "Enterprise", "BuildTools"] {
                let install_root = year_path.join(sku);
                candidates.push(
                    install_root
                        .join("Common7")
                        .join("IDE")
                        .join("Extensions")
                        .join("Microsoft")
                        .join("Debugger")
                        .join("vsdbg.exe"),
                );
                candidates.push(
                    install_root
                        .join("Common7")
                        .join("IDE")
                        .join("CommonExtensions")
                        .join("Microsoft")
                        .join("Debugger")
                        .join("vsdbg.exe"),
                );
            }
        }
    }

    candidates
}

#[cfg(windows)]
fn vsdbg_vswhere_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut vswhere_paths = Vec::new();

    if let Some(program_files_x86) = env::var_os("ProgramFiles(x86)") {
        vswhere_paths.push(
            PathBuf::from(program_files_x86)
                .join("Microsoft Visual Studio")
                .join("Installer")
                .join("vswhere.exe"),
        );
    }
    vswhere_paths.push(PathBuf::from(
        r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe",
    ));

    for vswhere in vswhere_paths {
        if !vswhere.exists() {
            continue;
        }

        let mut find_command = Command::new(&vswhere);
        find_command
            .arg("-products")
            .arg("*")
            .arg("-find")
            .arg(r"**\vsdbg.exe")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(0x08000000);
        if let Ok(output) = find_command.output() {
            if output.status.success() {
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    let trimmed = line.trim().trim_matches('"');
                    if trimmed.is_empty() {
                        continue;
                    }
                    candidates.push(PathBuf::from(trimmed));
                }
            }
        }

        let mut install_path_command = Command::new(&vswhere);
        install_path_command
            .arg("-products")
            .arg("*")
            .arg("-property")
            .arg("installationPath")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(0x08000000);
        let Ok(output) = install_path_command.output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }

        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let trimmed = line.trim().trim_matches('"');
            if trimmed.is_empty() {
                continue;
            }

            let install_path = PathBuf::from(trimmed);
            candidates.push(
                install_path
                    .join("Common7")
                    .join("IDE")
                    .join("Extensions")
                    .join("Microsoft")
                    .join("Debugger")
                    .join("vsdbg.exe"),
            );
            candidates.push(
                install_path
                    .join("Common7")
                    .join("IDE")
                    .join("CommonExtensions")
                    .join("Microsoft")
                    .join("Debugger")
                    .join("vsdbg.exe"),
            );
        }
    }

    candidates
}

#[cfg(windows)]
fn vsdbg_vscode_extension_candidates(user_profile: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let roots = [
        user_profile.join(".vscode").join("extensions"),
        user_profile.join(".vscode-insiders").join("extensions"),
    ];

    for root in roots {
        candidates.extend(vsdbg_collect_extension_candidates(&root));
    }

    candidates
}

#[cfg(windows)]
fn vsdbg_collect_extension_candidates(root: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return candidates;
    };

    for entry in entries.flatten() {
        let extension_dir = entry.path();
        if !extension_dir.is_dir() {
            continue;
        }

        let Some(name) = extension_dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        let is_dotnet_debug_extension = name.starts_with("ms-dotnettools.csharp")
            || name.starts_with("ms-dotnettools.csdevkit")
            || name.starts_with("ms-vscode.csharp");
        if !is_dotnet_debug_extension {
            continue;
        }

        let debugger_dir = extension_dir.join(".debugger");
        candidates.push(debugger_dir.join("vsdbg.exe"));
        candidates.push(debugger_dir.join("win-x64").join("vsdbg.exe"));
        candidates.push(debugger_dir.join("x86_64").join("vsdbg.exe"));
        candidates.extend(vsdbg_find_below(&debugger_dir, 3));
    }

    candidates
}

#[cfg(windows)]
fn vsdbg_find_below(root: &Path, depth_left: usize) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    if depth_left == 0 {
        return hits;
    }

    let Ok(entries) = fs::read_dir(root) else {
        return hits;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            hits.extend(vsdbg_find_below(&path, depth_left - 1));
            continue;
        }

        let is_vsdbg = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.eq_ignore_ascii_case("vsdbg.exe"))
            .unwrap_or(false);
        if is_vsdbg {
            hits.push(path);
        }
    }

    hits
}

#[cfg(not(windows))]
fn vsdbg_windows_candidates() -> Vec<PathBuf> {
    Vec::new()
}


fn split_debugger_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

fn main() -> eframe::Result<()> {
    let mut native_options = eframe::NativeOptions::default();
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1380.0, 860.0])
        .with_min_inner_size([980.0, 620.0])
        .with_title("EXE Analyzer");

    if let Some(icon_data) = load_icon_data() {
        viewport = viewport.with_icon(Arc::new(icon_data));
    }
    native_options.viewport = viewport;

    eframe::run_native(
        "EXE Analyzer",
        native_options,
        Box::new(|cc| {
            theming::apply_theme(&cc.egui_ctx);

            let mut style = (*cc.egui_ctx.style()).clone();
            style.spacing.item_spacing = egui::vec2(8.0, 8.0);
            style.spacing.button_padding = egui::vec2(10.0, 7.0);
            style.spacing.window_margin = egui::Margin::same(8);
            style.text_styles.insert(
                egui::TextStyle::Heading,
                egui::FontId::proportional(21.0),
            );
            style.text_styles.insert(
                egui::TextStyle::Body,
                egui::FontId::proportional(14.0),
            );
            style.text_styles.insert(
                egui::TextStyle::Monospace,
                egui::FontId::monospace(12.5),
            );
            style.text_styles.insert(
                egui::TextStyle::Button,
                egui::FontId::proportional(14.0),
            );
            cc.egui_ctx.set_style(style);
            Ok(Box::new(AnalyzerGuiApp::default()))
        }),
    )
}

fn resolve_asset_path(file_name: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd.join(file_name));
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join(file_name));
            candidates.push(exe_dir.join("..").join(file_name));
            candidates.push(exe_dir.join("..").join("..").join(file_name));
            candidates.push(exe_dir.join("..").join("..").join("..").join(file_name));
        }
    }

    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        candidates.push(PathBuf::from(manifest_dir).join(file_name));
    }

    candidates.into_iter().find(|path| path.exists())
}

fn load_icon_data() -> Option<egui::IconData> {
    let path = resolve_asset_path("icon.ico")?;
    let reader = ImageReader::open(path).ok()?;
    let image = reader.decode().ok()?.to_rgba8();
    let (width, height) = image.dimensions();
    Some(egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    })
}

fn draw_splash(
    ctx: &egui::Context,
    logo_texture: Option<&egui::TextureHandle>,
    splash_duration: Duration,
    splash_elapsed: Duration,
) {
    let progress = (splash_elapsed.as_secs_f32() / splash_duration.as_secs_f32()).clamp(0.0, 1.0);
    egui::CentralPanel::default()
        .frame(egui::Frame::default().fill(zed_bg_0()))
        .show(ctx, |ui| {
            let t = splash_elapsed.as_secs_f32();
            ui.vertical_centered(|ui| {
                ui.add_space((ui.available_height() * 0.22).max(16.0));
                if let Some(texture) = logo_texture {
                    ui.add(egui::Image::new(texture).fit_to_exact_size(egui::vec2(140.0, 140.0)));
                }
                ui.add_space(12.0);
                ui.heading("Metsuki Workbench");
                ui.colored_label(zed_fg_muted(), "Analyzer UI");
                ui.add_space(8.0);

                let typing_target = "METSUKI.src";
                let total_chars = typing_target.chars().count().max(1);
                let shown_chars = ((progress * total_chars as f32).ceil() as usize).min(total_chars);
                let typed = typing_target.chars().take(shown_chars).collect::<String>();
                let cursor_on = ((t * 3.4) as i32) % 2 == 0;
                let cursor = if cursor_on { "▋" } else { " " };

                ui.add_space(2.0);
                ui.monospace(
                    egui::RichText::new(format!("> {}{}", typed, cursor))
                        .size(20.0)
                        .color(zed_accent()),
                );

                ui.add_space(14.0);
                ui.add(
                    egui::ProgressBar::new(progress)
                        .desired_width(260.0)
                        .text(format!("Loading... {}%", (progress * 100.0) as u32)),
                );
            });
        });
}
