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
    NativeRun,
    PythonPdb,
}

impl DebugBackend {
    fn label(self) -> &'static str {
        match self {
            DebugBackend::NativeRun => "Native Run",
            DebugBackend::PythonPdb => "Python pdb",
        }
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
    debugger_stdin: String,
    debugger_timeout_secs: String,
    debugger_expected_exit: String,
    debugger_expected_exception: bool,
    debugger_expected_stdout_contains: String,
    debugger_expected_stderr_contains: String,
    debugger_backend: DebugBackend,
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
        Self {
            target_path: String::new(),
            out_dir: "logs".to_string(),
            timeout_secs: "10".to_string(),
            runs: "10".to_string(),
            strict_mode: true,
            scan_preset: ScanPreset::Deep,
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
            debugger_stdin: String::new(),
            debugger_timeout_secs: "5".to_string(),
            debugger_expected_exit: "0".to_string(),
            debugger_expected_exception: false,
            debugger_expected_stdout_contains: String::new(),
            debugger_expected_stderr_contains: String::new(),
            debugger_backend: DebugBackend::NativeRun,
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
        let out_dir = PathBuf::from(self.out_dir.trim());
        let strict_mode = self.strict_mode;

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
            "[run] Start scan: target='{}' timeout={} runs={} mode={} out='{}'",
            target.display(),
            timeout,
            runs,
            if strict_mode { "STRICT" } else { "BALANCED" },
            out_dir.display()
        ));

        thread::spawn(move || {
                    workers::scan_worker(target, out_dir, timeout, runs, strict_mode, cancel, tx);
        });
    }

    fn pick_report_json(&mut self) {
        if let Some(path) = FileDialog::new().add_filter("JSON", &["json"]).pick_file() {
            match fs::read_to_string(&path)
                .ok()
                .and_then(|txt| serde_json::from_str::<ReportData>(&txt).ok())
            {
                Some(data) => {
                    self.score = data.score;
                    self.final_status = data.final_status;
                    self.mode_label = data.mode;
                    self.findings = data.findings;
                    self.runtime = data.runtime;
                    self.report_path = path.display().to_string();
                    self.selected_finding = None;
                    let report_data = ReportData {
                        target: self.target_path.clone(),
                        mode: self.mode_label.clone(),
                        score: self.score,
                        final_status: self.final_status.clone(),
                        findings: self.findings.clone(),
                        runtime: self.runtime.clone(),
                    };
                    self.run_plugins(&report_data);
                    self.append_log(format!("[report] Loaded external JSON: {}", self.report_path));
                }
                None => self.append_log("[error] Invalid JSON report format"),
            }
        }
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

    fn start_debugger_run(&mut self) {
        if self.is_running || self.debugger_is_running {
            return;
        }

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

        let timeout = self
            .debugger_timeout_secs
            .trim()
            .parse::<u64>()
            .unwrap_or(5)
            .max(1);
        let args = split_debugger_args(&self.debugger_args);
        let stdin_payload = self.debugger_stdin.clone();

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

        let cancel = Arc::clone(&self.debugger_cancel_flag);
        let (tx, rx) = mpsc::channel::<UiEvent>();
        self.rx = Some(rx);
        self.ui_tx = Some(tx.clone());
        self.restart_file_watcher();

        self.append_log(format!(
            "[debug] Start: backend={} target='{}' args={} timeout={}s",
            self.debugger_backend.label(),
            target.display(),
            args.len(),
            timeout
        ));

        match self.debugger_backend {
            DebugBackend::NativeRun => {
                thread::spawn(move || {
                    workers::debug_worker_native(target, args, stdin_payload, timeout, cancel, tx);
                });
            }
            DebugBackend::PythonPdb => {
                let (control_tx, control_rx) = mpsc::channel::<DebugControl>();
                self.debugger_controls_tx = Some(control_tx);
                thread::spawn(move || {
                    workers::debug_worker_python_pdb(
                        target,
                        args,
                        stdin_payload,
                        timeout,
                        cancel,
                        control_rx,
                        tx,
                    );
                });
            }
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
                        self.append_log(format!("[report] JSON: {}", self.report_path));
                    }

                    self.push_scan_history(exit_code, duration_ms);
                }
                UiEvent::DebugOutput { is_stderr, text } => {
                    if is_stderr {
                        self.debugger_stderr.push_str(&text);
                    } else {
                        self.debugger_stdout.push_str(&text);
                    }
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
                    self.debugger_last_exit = exit_code;
                    self.debugger_last_timed_out = timed_out;
                    self.debugger_last_duration_ms = duration_ms;
                    if !stdout.is_empty() {
                        self.debugger_stdout = stdout;
                    }
                    if !stderr.is_empty() {
                        self.debugger_stderr = stderr;
                    }
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

                    self.push_debug_history(exit_code, timed_out, duration_ms);

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
                ui.add_space(4.0);
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

                    if !self.target_path.trim().is_empty() {
                        ui.separator();
                        ui.monospace(
                            egui::RichText::new(format!(
                                "target: {}",
                                truncate_label(self.target_path.trim(), 56)
                            ))
                            .color(zed_fg_muted()),
                        );
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let logs_label = format!(
                            "{} ({})",
                            self.t("Логи", "Logs", "Protokoll", "Логи"),
                            self.logs.len()
                        );
                        if ui.add_sized([96.0, 28.0], egui::Button::new(logs_label)).clicked() {
                            self.open_logs_window();
                        }

                        egui::ComboBox::from_id_salt("ui_lang_select")
                            .width(64.0)
                            .selected_text(self.ui_language.label())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.ui_language, UiLanguage::Ru, "RU");
                                ui.selectable_value(&mut self.ui_language, UiLanguage::En, "EN");
                                ui.selectable_value(&mut self.ui_language, UiLanguage::De, "DE");
                                ui.selectable_value(&mut self.ui_language, UiLanguage::Uk, "UK");
                            });

                        if self.debugger_is_running {
                            ui.spinner();
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

                if ui
                    .button(self.t("Загрузить JSON отчёт", "Load JSON Report", "JSON-Bericht laden", "Завантажити JSON звiт"))
                    .clicked()
                {
                    self.pick_report_json();
                }

                if !self.report_path.is_empty() {
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new(self.t("Последний JSON отчёт", "Last JSON report", "Letzter JSON-Bericht", "Останнiй JSON звiт"))
                            .color(zed_fg_muted()),
                    );
                    ui.monospace(egui::RichText::new(&self.report_path).color(zed_fg_muted()));
                }

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
                        "• Strict scoring и full/issues/json отчёты",
                        "• Strict scoring and full/issues/json logs",
                        "• Strict-Bewertung und full/issues/json-Logs",
                        "• Strict scoring та full/issues/json звiти",
                    ),
                );
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(zed_bg_0())
                    .inner_margin(egui::Margin::same(8)),
            )
            .show(ctx, |ui| {
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
                            for finding in self.findings.iter().take(8) {
                                ui.horizontal(|ui| {
                                    ui.colored_label(severity_color(&finding.severity), format!("[{}]", finding.severity));
                                    ui.monospace(egui::RichText::new(&finding.code).color(zed_fg_muted()));
                                    ui.label(&finding.message);
                                });
                            }
                        }
                    }
                    WorkspaceTab::Findings => {
                        ui.heading(self.t("Нахождения", "Findings", "Befunde", "Знахiдки"));
                        ui.separator();

                        let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 8.0;
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
                        TableBuilder::new(ui)
                            .id_salt("runtime_table")
                            .striped(true)
                            .column(Column::exact(220.0))
                            .column(Column::exact(80.0))
                            .column(Column::exact(70.0))
                            .column(Column::exact(90.0))
                            .column(Column::exact(90.0))
                            .column(Column::exact(90.0))
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
                                });
                            });
                    }
                    WorkspaceTab::Debugger => {
                        let lang = self.ui_language;
                        ui.heading(self.t("Дебагер (бета)", "Debugger (beta)", "Debugger (Beta)", "Дебагер (бета)"));
                        ui.colored_label(
                            zed_fg_muted(),
                            self.t(
                                "Режим диагностики: сравнение ожиданий и факта, где сломалось и что послужило виной.",
                                "Diagnostic mode: compares expected behavior with actual result and pinpoints probable root cause.",
                                "Diagnosemodus: vergleicht Erwartung mit Ergebnis und zeigt wahrscheinliche Ursache.",
                                "Режим дiагностики: порiвняння очiкування та факту, де зламалось i що стало причиною.",
                            ),
                        );
                        ui.separator();

                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(self.t("Бэкенд", "Backend", "Backend", "Бекенд")).color(zed_fg_muted()));
                            ui.selectable_value(
                                &mut self.debugger_backend,
                                DebugBackend::NativeRun,
                                DebugBackend::NativeRun.label(),
                            );
                            ui.selectable_value(
                                &mut self.debugger_backend,
                                DebugBackend::PythonPdb,
                                DebugBackend::PythonPdb.label(),
                            );
                        });

                        if self.debugger_backend == DebugBackend::PythonPdb {
                            ui.colored_label(
                                zed_fg_muted(),
                                self.t(
                                    "Подсказка: цель должна быть .py. Команды: break file.py:line, step, next, continue, where, list, quit.",
                                    "Tip: target should be a .py file. Commands: break file.py:line, step, next, continue, where, list, quit.",
                                    "Tipp: Ziel sollte eine .py-Datei sein. Befehle: break file.py:line, step, next, continue, where, list, quit.",
                                    "Пiдказка: цiль має бути .py. Команди: break file.py:line, step, next, continue, where, list, quit.",
                                ),
                            );
                        }

                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(self.t("Аргументы", "Args", "Argumente", "Аргументи")).color(zed_fg_muted()));
                            ui.add_sized(
                                [ui.available_width() - 130.0, 28.0],
                                egui::TextEdit::singleline(&mut self.debugger_args)
                                    .hint_text(lpick(lang, "--пример значение", "--example value", "--beispiel wert", "--приклад значення")),
                            );
                        });

                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(self.t("Таймаут", "Timeout", "Zeitlimit", "Таймаут")).color(zed_fg_muted()));
                            ui.add_sized(
                                [80.0, 28.0],
                                egui::TextEdit::singleline(&mut self.debugger_timeout_secs),
                            );
                            ui.label(egui::RichText::new(self.t("сек", "sec", "sek", "сек")).color(zed_fg_muted()));
                            let run_btn = ui.add_enabled(
                                !self.debugger_is_running && !self.is_running,
                                egui::Button::new(self.t("Запустить", "Run Debug", "Start", "Запустити")),
                            );
                            if run_btn.clicked() {
                                self.start_debugger_run();
                            }
                            let stop_btn = ui.add_enabled(
                                self.debugger_is_running,
                                egui::Button::new(self.t("Стоп", "Stop", "Stopp", "Стоп")),
                            );
                            if stop_btn.clicked() {
                                self.stop_debugger_run();
                            }
                        });

                        ui.label(egui::RichText::new(self.t("stdin данные", "stdin payload", "stdin-Daten", "stdin данi")).color(zed_fg_muted()));
                        ui.add_sized(
                            [ui.available_width(), 84.0],
                            egui::TextEdit::multiline(&mut self.debugger_stdin)
                                .hint_text(lpick(
                                    lang,
                                    "Опциональный stdin-текст для целевого процесса",
                                    "Optional stdin text for target process",
                                    "Optionaler stdin-Text fuer den Zielprozess",
                                    "Необов'язковий stdin-текст для цiльового процесу"
                                )),
                        );

                        ui.separator();
                        ui.strong(self.t("Ожидалось", "Expected", "Erwartet", "Очiкувалось"));
                        ui.horizontal(|ui| {
                            let expected_exception_label = self.t(
                                "Ожидается исключение",
                                "Exception expected",
                                "Exception erwartet",
                                "Очiкується виняток",
                            );
                            ui.label(egui::RichText::new(self.t("Выход", "Exit", "Exit", "Вихiд")).color(zed_fg_muted()));
                            ui.add_sized(
                                [60.0, 26.0],
                                egui::TextEdit::singleline(&mut self.debugger_expected_exit)
                                    .hint_text("0"),
                            );
                            ui.checkbox(&mut self.debugger_expected_exception, expected_exception_label);
                        });
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(
                                    self.t("stdout должен содержать", "stdout must contain", "stdout muss enthalten", "stdout має мiстити")
                                )
                                .color(zed_fg_muted()),
                            );
                            ui.add_sized(
                                [ui.available_width(), 26.0],
                                egui::TextEdit::singleline(&mut self.debugger_expected_stdout_contains)
                                    .hint_text(lpick(lang, "опциональная подстрока", "optional substring", "optionaler Teilstring", "необов'язковий пiдрядок")),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(
                                    self.t("stderr должен содержать", "stderr must contain", "stderr muss enthalten", "stderr має мiстити")
                                )
                                .color(zed_fg_muted()),
                            );
                            ui.add_sized(
                                [ui.available_width(), 26.0],
                                egui::TextEdit::singleline(&mut self.debugger_expected_stderr_contains)
                                    .hint_text(lpick(lang, "опциональная подстрока", "optional substring", "optionaler Teilstring", "необов'язковий пiдрядок")),
                            );
                        });

                        if self.debugger_backend == DebugBackend::PythonPdb {
                            ui.separator();
                            ui.label(
                                egui::RichText::new(
                                    self.t("Интерактивные команды", "Interactive commands", "Interaktive Befehle", "Iнтерактивнi команди")
                                )
                                .color(zed_fg_muted()),
                            );
                            ui.horizontal(|ui| {
                                ui.add_sized(
                                    [ui.available_width() - 120.0, 28.0],
                                    egui::TextEdit::singleline(&mut self.debugger_command_input)
                                        .hint_text(lpick(
                                            lang,
                                            "step / next / continue / break file.py:42",
                                            "step / next / continue / break file.py:42",
                                            "step / next / continue / break file.py:42",
                                            "step / next / continue / break file.py:42"
                                        )),
                                );
                                let send_btn = ui.add_enabled(
                                    self.debugger_is_running,
                                    egui::Button::new(self.t("Отправить", "Send", "Senden", "Надiслати")),
                                );
                                if send_btn.clicked() {
                                    let cmd = self.debugger_command_input.trim().to_string();
                                    self.send_debugger_command(cmd);
                                    self.debugger_command_input.clear();
                                }
                            });

                            ui.horizontal_wrapped(|ui| {
                                for cmd in ["where", "list", "step", "next", "continue", "quit"] {
                                    let btn = ui.add_enabled(
                                        self.debugger_is_running,
                                        egui::Button::new(cmd),
                                    );
                                    if btn.clicked() {
                                        self.send_debugger_command(cmd.to_string());
                                    }
                                }
                            });
                        }

                        ui.separator();
                        ui.group(|ui| {
                            ui.strong(self.t("Отправленные данные", "Sent data", "Gesendete Daten", "Надiсланi данi"));
                            ui.monospace(format!("target: {}", self.target_path.trim()));
                            ui.monospace(format!("backend: {}", self.debugger_backend.label()));
                            ui.monospace(format!("args: {}", self.debugger_args));
                            ui.monospace(format!("stdin bytes: {}", self.debugger_stdin.as_bytes().len()));
                            if !self.debugger_stdin.trim().is_empty() {
                                ui.monospace(format!(
                                    "stdin preview: {}",
                                    diagnostics::truncate_debug_text(&self.debugger_stdin, 120)
                                ));
                            }
                            ui.horizontal(|ui| {
                                ui.colored_label(zed_fg_muted(), format!("exit: {:?}", self.debugger_last_exit));
                                ui.colored_label(zed_fg_muted(), format!("timeout: {}", self.debugger_last_timed_out));
                                ui.colored_label(zed_fg_muted(), format!("duration: {} ms", self.debugger_last_duration_ms));
                                ui.colored_label(
                                    if self.debugger_had_exception {
                                        egui::Color32::from_rgb(229, 84, 84)
                                    } else {
                                        egui::Color32::from_rgb(73, 182, 117)
                                    },
                                    if self.debugger_had_exception {
                                        "exception: yes"
                                    } else {
                                        "exception: no"
                                    },
                                );
                            });
                        });

                        ui.add_space(6.0);
                        ui.group(|ui| {
                            ui.strong(self.t("Диагностика", "Diagnosis", "Diagnose", "Дiагностика"));
                            ui.colored_label(
                                if self.debugger_verdict_ok {
                                    egui::Color32::from_rgb(73, 182, 117)
                                } else {
                                    egui::Color32::from_rgb(229, 84, 84)
                                },
                                if self.debugger_verdict_ok {
                                    self.t("Соответствует ожиданиям", "Matches expected", "Entspricht der Erwartung", "Вiдповiдає очiкуванню")
                                } else {
                                    self.t("Найдено расхождение", "Mismatch detected", "Abweichung erkannt", "Виявлено розбiжнiсть")
                                },
                            );
                            ui.monospace(format!(
                                "{}: {}",
                                self.t("ожидалось", "expected", "erwartet", "очiкувалось"),
                                self.debugger_expected_view
                            ));
                            ui.monospace(format!(
                                "{}: {}",
                                self.t("получили", "got", "erhalten", "отримали"),
                                self.debugger_got_view
                            ));
                            ui.monospace(format!(
                                "{}: {}",
                                self.t("где сломалось", "where failed", "wo es fehlschlug", "де зламалось"),
                                self.debugger_failure_point
                            ));
                            ui.monospace(format!(
                                "{}: {}",
                                self.t("что послужило виной", "root cause", "Ursache", "що стало причиною"),
                                self.debugger_root_cause
                            ));
                        });

                        ui.add_space(6.0);
                        ui.columns(2, |cols| {
                            cols[0].group(|ui| {
                                ui.label(egui::RichText::new(self.t("stdout / окно выполнения", "stdout / execution view", "stdout / Ausfuehrung", "stdout / вiкно виконання")).color(zed_fg_muted()));
                                egui::ScrollArea::vertical()
                                    .id_salt("debug_stdout_scroll")
                                    .max_height(260.0)
                                    .show(ui, |ui| {
                                        if self.debugger_stdout.trim().is_empty() {
                                            ui.colored_label(zed_fg_muted(), self.t("<пусто>", "<empty>", "<leer>", "<порожньо>"));
                                        } else {
                                            ui.monospace(&self.debugger_stdout);
                                        }
                                    });
                            });

                            cols[1].group(|ui| {
                                ui.label(egui::RichText::new(self.t("stderr / диагностика", "stderr / diagnostics", "stderr / Diagnose", "stderr / дiагностика")).color(zed_fg_muted()));
                                egui::ScrollArea::vertical()
                                    .id_salt("debug_stderr_scroll")
                                    .max_height(260.0)
                                    .show(ui, |ui| {
                                        if self.debugger_stderr.trim().is_empty() {
                                            ui.colored_label(zed_fg_muted(), self.t("<пусто>", "<empty>", "<leer>", "<порожньо>"));
                                        } else {
                                            ui.monospace(&self.debugger_stderr);
                                        }
                                    });
                            });
                        });

                        ui.add_space(8.0);
                        ui.group(|ui| {
                            ui.strong(self.t("Diff stdout (git-like)", "Diff stdout (git-like)", "Diff stdout (git-aehnlich)", "Diff stdout (git-like)"));
                            if self.stdout_snapshots.len() < 2 {
                                ui.colored_label(zed_fg_muted(), self.t("Нужно минимум 2 прогона дебага", "Need at least 2 debug runs", "Mindestens 2 Debug-Runs", "Потрiбно щонайменше 2 прогони дебагу"));
                            } else {
                                ui.horizontal(|ui| {
                                    ui.label("A");
                                    egui::ComboBox::from_id_salt("stdout_diff_left")
                                        .selected_text(self.stdout_diff_left.to_string())
                                        .show_ui(ui, |ui| {
                                            for idx in 0..self.stdout_snapshots.len() {
                                                if ui
                                                    .selectable_value(&mut self.stdout_diff_left, idx, idx.to_string())
                                                    .clicked()
                                                {
                                                    self.rebuild_stdout_diff();
                                                }
                                            }
                                        });
                                    ui.label("B");
                                    egui::ComboBox::from_id_salt("stdout_diff_right")
                                        .selected_text(self.stdout_diff_right.to_string())
                                        .show_ui(ui, |ui| {
                                            for idx in 0..self.stdout_snapshots.len() {
                                                if ui
                                                    .selectable_value(&mut self.stdout_diff_right, idx, idx.to_string())
                                                    .clicked()
                                                {
                                                    self.rebuild_stdout_diff();
                                                }
                                            }
                                        });
                                });

                                egui::ScrollArea::vertical()
                                    .id_salt("stdout_diff_scroll")
                                    .max_height(180.0)
                                    .show(ui, |ui| {
                                        if self.stdout_diff_text.trim().is_empty() {
                                            ui.colored_label(zed_fg_muted(), "<empty diff>");
                                        } else {
                                            ui.monospace(&self.stdout_diff_text);
                                        }
                                    });
                            }
                        });
                    }
                }
            });
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

fn lpick<'a>(lang: UiLanguage, ru: &'a str, en: &'a str, de: &'a str, uk: &'a str) -> &'a str {
    match lang {
        UiLanguage::Ru => ru,
        UiLanguage::En => en,
        UiLanguage::De => de,
        UiLanguage::Uk => uk,
    }
}

fn main() -> eframe::Result<()> {
    let mut native_options = eframe::NativeOptions::default();
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1380.0, 860.0])
        .with_min_inner_size([1180.0, 740.0])
        .with_title("Metsuki EXE Analyzer");

    if let Some(icon_data) = load_icon_data() {
        viewport = viewport.with_icon(Arc::new(icon_data));
    }
    native_options.viewport = viewport;

    eframe::run_native(
        "Metsuki EXE Analyzer",
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
    let path = resolve_asset_path("exe_icon.ico")
        .or_else(|| resolve_asset_path("EXE_icon.ico"))?;
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
