#![cfg_attr(windows, windows_subsystem = "windows")]

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use image::ImageReader;
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
    egui::Color32::from_rgb(16, 19, 24)
}

fn zed_bg_1() -> egui::Color32 {
    egui::Color32::from_rgb(22, 26, 33)
}

fn zed_bg_2() -> egui::Color32 {
    egui::Color32::from_rgb(28, 33, 41)
}

fn zed_bg_3() -> egui::Color32 {
    egui::Color32::from_rgb(34, 40, 51)
}

fn zed_fg_muted() -> egui::Color32 {
    egui::Color32::from_rgb(148, 160, 184)
}

fn zed_accent() -> egui::Color32 {
    egui::Color32::from_rgb(103, 164, 255)
}

fn status_color(status: &str) -> egui::Color32 {
    match status {
        "PASS" => egui::Color32::from_rgb(73, 182, 117),
        "WARN" => egui::Color32::from_rgb(225, 172, 69),
        "FAIL" => egui::Color32::from_rgb(229, 84, 84),
        _ => zed_fg_muted(),
    }
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

    fn pick_file(&mut self) {
        if let Some(path) = FileDialog::new().add_filter("Executable", &["exe"]).pick_file() {
            self.target_path = path.display().to_string();
            self.append_log(format!("[ui] Selected file: {}", self.target_path));
        }
    }

    fn pick_any_file(&mut self) {
        if let Some(path) = FileDialog::new().pick_file() {
            self.target_path = path.display().to_string();
            self.append_log(format!("[ui] Selected file: {}", self.target_path));
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

        self.append_log(format!(
            "[run] Start scan: target='{}' timeout={} runs={} mode={} out='{}'",
            target.display(),
            timeout,
            runs,
            if strict_mode { "STRICT" } else { "BALANCED" },
            out_dir.display()
        ));

        thread::spawn(move || {
            scan_worker(target, out_dir, timeout, runs, strict_mode, cancel, tx);
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
                    debug_worker_native(target, args, stdin_payload, timeout, cancel, tx);
                });
            }
            DebugBackend::PythonPdb => {
                let (control_tx, control_rx) = mpsc::channel::<DebugControl>();
                self.debugger_controls_tx = Some(control_tx);
                thread::spawn(move || {
                    debug_worker_python_pdb(
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
                    self.started_at = None;
                    self.append_log(format!("[run] Finished with exit code {}", exit_code));

                    if let Some(data) = report {
                        self.score = data.score;
                        self.final_status = data.final_status;
                        self.mode_label = data.mode;
                        self.findings = data.findings;
                        self.runtime = data.runtime;
                        self.append_log(format!("[report] Loaded report for {}", data.target));
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
                    self.debugger_had_exception = infer_debug_exception(
                        self.debugger_last_exit,
                        self.debugger_last_timed_out,
                        &self.debugger_stderr,
                    );

                    let diagnosis = build_debug_diagnosis(
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
                    self.debugger_root_cause = diagnosis.root_cause;

                    self.append_log(format!(
                        "[debug] Finished: exit={:?} timeout={} duration={}ms",
                        self.debugger_last_exit,
                        self.debugger_last_timed_out,
                        self.debugger_last_duration_ms
                    ));
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
        self.ensure_logo_texture(ctx);

        let splash_elapsed = self.splash_started_at.elapsed();
        if splash_elapsed < self.splash_duration {
            ctx.request_repaint_after(Duration::from_millis(16));
            draw_splash(ctx, self.logo_texture.as_ref(), self.splash_duration, splash_elapsed);
            return;
        }

        if self.is_running || self.debugger_is_running {
            ctx.request_repaint_after(Duration::from_millis(80));
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
                        egui::ComboBox::from_id_salt("ui_lang_select")
                            .selected_text(self.ui_language.label())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.ui_language, UiLanguage::Ru, "RU");
                                ui.selectable_value(&mut self.ui_language, UiLanguage::En, "EN");
                                ui.selectable_value(&mut self.ui_language, UiLanguage::De, "DE");
                                ui.selectable_value(&mut self.ui_language, UiLanguage::Uk, "UK");
                            });

                        if ui
                            .button(format!(
                                "{} ({})",
                                self.t("Логи", "Logs", "Protokoll", "Логи"),
                                self.logs.len()
                            ))
                            .clicked()
                        {
                            self.open_logs_window();
                        }
                        if self.debugger_is_running {
                            ui.spinner();
                        }
                        ui.colored_label(status_color(&self.final_status), self.final_status.as_str());
                        ui.colored_label(zed_fg_muted(), format!("score {}", self.score));
                        ui.colored_label(zed_fg_muted(), format!("{}", self.mode_label));
                    });
                });
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
            .default_width(356.0)
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
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [180.0, 28.0],
                        egui::TextEdit::singleline(&mut self.target_path)
                            .hint_text("C:\\path\\to\\file"),
                    );
                    if ui.button(self.t("EXE", "Browse EXE", "EXE waehlen", "EXE")).clicked() {
                        self.pick_file();
                    }
                    if ui.button(self.t("Любой", "Browse Any", "Beliebig", "Будь-який")).clicked() {
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
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(self.t("Папка отчётов", "Out dir", "Ausgabeordner", "Папка звiтiв"))
                            .color(zed_fg_muted()),
                    );
                    ui.add_sized([250.0, 28.0], egui::TextEdit::singleline(&mut self.out_dir));
                });

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(self.t("Таймаут", "Timeout", "Zeitlimit", "Таймаут")).color(zed_fg_muted()));
                    let timeout_edit = ui.add_sized([80.0, 28.0], egui::TextEdit::singleline(&mut self.timeout_secs));
                    ui.label(egui::RichText::new(self.t("Прогоны", "Runs", "Durchlaeufe", "Прогони")).color(zed_fg_muted()));
                    let runs_edit = ui.add_sized([80.0, 28.0], egui::TextEdit::singleline(&mut self.runs));
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
                                    truncate_debug_text(&self.debugger_stdin, 120)
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

fn scan_worker(
    target: PathBuf,
    out_dir: PathBuf,
    timeout: u64,
    runs: u32,
    strict_mode: bool,
    cancel: Arc<AtomicBool>,
    tx: Sender<UiEvent>,
) {
    let _ = tx.send(UiEvent::Log("[worker] Resolving CLI path...".to_string()));
    let cli_path = match resolve_cli_path() {
        Some(p) => p,
        None => {
            let _ = tx.send(UiEvent::Log("[error] Cannot resolve exe_tester CLI path".to_string()));
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

fn debug_worker_native(
    target: PathBuf,
    args: Vec<String>,
    stdin_payload: String,
    timeout_secs: u64,
    cancel: Arc<AtomicBool>,
    tx: Sender<UiEvent>,
) {
    let mut command = Command::new(&target);
    command
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
                stderr: format!("Failed to start process: {}", e),
            });
            return;
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = std::io::Write::write_all(&mut stdin, stdin_payload.as_bytes());
    }

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut timed_out = false;
    loop {
        if cancel.load(Ordering::Relaxed) {
            timed_out = true;
            let _ = child.kill();
            break;
        }

        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    timed_out = true;
                    let _ = child.kill();
                    break;
                }
                thread::sleep(Duration::from_millis(30));
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

    let duration_ms = start.elapsed().as_millis();
    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            let _ = tx.send(UiEvent::DebugFinished {
                exit_code: None,
                timed_out,
                duration_ms,
                stdout: String::new(),
                stderr: format!("Output capture error: {}", e),
            });
            return;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let _ = tx.send(UiEvent::DebugFinished {
        exit_code: output.status.code(),
        timed_out,
        duration_ms,
        stdout,
        stderr,
    });
}

fn debug_worker_python_pdb(
    target: PathBuf,
    args: Vec<String>,
    stdin_payload: String,
    timeout_secs: u64,
    cancel: Arc<AtomicBool>,
    control_rx: Receiver<DebugControl>,
    tx: Sender<UiEvent>,
) {
    let mut command = Command::new("python");
    command
        .arg("-m")
        .arg("pdb")
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
                stderr: format!("Failed to start python pdb: {}", e),
            });
            return;
        }
    };

    let mut child_stdin = child.stdin.take();
    if !stdin_payload.trim().is_empty() {
        if let Some(stdin) = child_stdin.as_mut() {
            let _ = std::io::Write::write_all(stdin, stdin_payload.as_bytes());
            let _ = std::io::Write::write_all(stdin, b"\n");
        }
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

struct DebugDiagnosis {
    verdict_ok: bool,
    expected: String,
    got: String,
    failure_point: String,
    root_cause: String,
}

fn build_debug_diagnosis(
    lang: UiLanguage,
    expected_exit: &str,
    expected_exception: bool,
    expected_stdout_contains: &str,
    expected_stderr_contains: &str,
    got_exit: Option<i32>,
    got_timed_out: bool,
    got_exception: bool,
    got_stdout: &str,
    got_stderr: &str,
) -> DebugDiagnosis {
    let expected_exit_value = expected_exit.trim().parse::<i32>().ok();
    let mut mismatches = Vec::new();

    if let Some(exp) = expected_exit_value {
        if got_exit != Some(exp) {
            mismatches.push(format!(
                "{} {}, {:?}",
                lpick(
                    lang,
                    "код выхода ожидался",
                    "exit expected",
                    "erwarteter Exit",
                    "код виходу очiкувався"
                ),
                exp,
                got_exit
            ));
        }
    }

    if expected_exception != got_exception {
        mismatches.push(format!(
            "{} {}, {}",
            lpick(
                lang,
                "исключение ожидалось",
                "exception expected",
                "Exception erwartet",
                "виняток очiкувався"
            ),
            expected_exception, got_exception
        ));
    }

    let stdout_expect = expected_stdout_contains.trim();
    if !stdout_expect.is_empty() && !got_stdout.contains(stdout_expect) {
        mismatches.push(format!(
            "{} '{}'",
            lpick(
                lang,
                "stdout не содержит",
                "stdout does not contain",
                "stdout enthaelt nicht",
                "stdout не мiстить"
            ),
            stdout_expect
        ));
    }

    let stderr_expect = expected_stderr_contains.trim();
    if !stderr_expect.is_empty() && !got_stderr.contains(stderr_expect) {
        mismatches.push(format!(
            "{} '{}'",
            lpick(
                lang,
                "stderr не содержит",
                "stderr does not contain",
                "stderr enthaelt nicht",
                "stderr не мiстить"
            ),
            stderr_expect
        ));
    }

    if got_timed_out {
        mismatches.push(lpick(
            lang,
            "превышен таймаут выполнения",
            "execution timed out",
            "Zeitlimit ueberschritten",
            "перевищено таймаут виконання"
        ).to_string());
    }

    if mismatches.is_empty() && got_exit.is_none() {
        mismatches.push(lpick(
            lang,
            "процесс завершился без кода выхода",
            "process ended without exit code",
            "Prozess endete ohne Exit-Code",
            "процес завершився без коду виходу"
        ).to_string());
    }

    let verdict_ok = mismatches.is_empty();
    let expected = format!(
        "{}={}, {}={}, stdout~'{}', stderr~'{}'",
        lpick(lang, "код_выхода", "exit", "exit", "код_виходу"),
        if expected_exit.trim().is_empty() {
            "<any>".to_string()
        } else {
            expected_exit.trim().to_string()
        },
        lpick(lang, "исключение", "exception", "Exception", "виняток"),
        expected_exception,
        if stdout_expect.is_empty() {
            "<not set>"
        } else {
            stdout_expect
        },
        if stderr_expect.is_empty() {
            "<not set>"
        } else {
            stderr_expect
        }
    );

    let got = format!(
        "{}={:?}, {}={}, stdout={} {}, stderr={} {}",
        lpick(lang, "код_выхода", "exit", "exit", "код_виходу"),
        got_exit,
        lpick(lang, "исключение", "exception", "Exception", "виняток"),
        got_exception,
        got_stdout.chars().count(),
        lpick(lang, "символов", "chars", "Zeichen", "символiв"),
        got_stderr.chars().count(),
        lpick(lang, "символов", "chars", "Zeichen", "символiв")
    );

    let failure_point = if verdict_ok {
        lpick(
            lang,
            "не обнаружено (ожидания совпали)",
            "not detected (expectations matched)",
            "nicht erkannt (Erwartung erfuellt)",
            "не виявлено (очiкування спiвпали)"
        ).to_string()
    } else {
        detect_failure_point(lang, got_stderr, got_stdout)
    };

    let root_cause = if verdict_ok {
        lpick(lang, "расхождений нет", "no mismatch", "keine Abweichung", "розбiжностей немає").to_string()
    } else {
        mismatches.join("; ")
    };

    DebugDiagnosis {
        verdict_ok,
        expected,
        got,
        failure_point,
        root_cause,
    }
}

fn detect_failure_point(lang: UiLanguage, stderr: &str, stdout: &str) -> String {
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("File \"") {
            return trimmed.to_string();
        }
        if trimmed.contains("panicked at")
            || trimmed.starts_with("panic:")
            || trimmed.starts_with("Exception in thread")
            || trimmed.starts_with("Traceback")
            || trimmed.starts_with("at ")
        {
            return trimmed.to_string();
        }
    }

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Traceback") || trimmed.contains("Exception") {
            return trimmed.to_string();
        }
    }

    if let Some(line) = stderr.lines().find(|line| !line.trim().is_empty()) {
        return line.trim().to_string();
    }

    lpick(
        lang,
        "не удалось локализовать место ошибки по выводу",
        "unable to localize failure point from output",
        "Fehlerstelle konnte nicht aus der Ausgabe lokalisiert werden",
        "не вдалося локалiзувати мiсце помилки з виводу"
    )
    .to_string()
}

fn truncate_debug_text(text: &str, max_chars: usize) -> String {
    let chars = text.chars().count();
    if chars <= max_chars {
        return text.replace('\n', "\\n");
    }

    let mut truncated = text.chars().take(max_chars).collect::<String>();
    truncated = truncated.replace('\n', "\\n");
    format!("{}...", truncated)
}

fn infer_debug_exception(exit_code: Option<i32>, timed_out: bool, stderr: &str) -> bool {
    if timed_out {
        return true;
    }

    if let Some(code) = exit_code {
        if code != 0 {
            return true;
        }
    }

    let lower = stderr.to_ascii_lowercase();
    [
        "exception",
        "traceback",
        "panic",
        "fatal",
        "unhandled",
        "error:",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn resolve_cli_path() -> Option<PathBuf> {
    let current = env::current_exe().ok()?;
    let parent = current.parent()?;

    let direct = parent.join("exe_tester.exe");
    if direct.exists() {
        return Some(direct);
    }

    let fallback_debug = PathBuf::from("target").join("debug").join("exe_tester.exe");
    if fallback_debug.exists() {
        return Some(fallback_debug);
    }

    let fallback_release = PathBuf::from("target").join("release").join("exe_tester.exe");
    if fallback_release.exists() {
        return Some(fallback_release);
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
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = zed_bg_0();
            visuals.window_fill = zed_bg_1();
            visuals.faint_bg_color = zed_bg_1();
            visuals.extreme_bg_color = zed_bg_0();
            visuals.override_text_color = Some(egui::Color32::from_rgb(210, 218, 233));
            visuals.hyperlink_color = zed_accent();
            visuals.selection.bg_fill = egui::Color32::from_rgb(56, 92, 143);
            visuals.selection.stroke = egui::Stroke::new(1.0, zed_accent());
            visuals.widgets.noninteractive.bg_fill = zed_bg_1();
            visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, zed_fg_muted());
            visuals.widgets.inactive.bg_fill = zed_bg_2();
            visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(190, 200, 216));
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(38, 51, 68);
            visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.2, egui::Color32::from_rgb(218, 228, 242));
            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(48, 65, 88);
            visuals.widgets.active.fg_stroke = egui::Stroke::new(1.2, egui::Color32::from_rgb(224, 235, 247));
            visuals.widgets.open.bg_fill = egui::Color32::from_rgb(33, 44, 58);
            cc.egui_ctx.set_visuals(visuals);

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
    let cwd = env::current_dir().ok()?.join(file_name);
    if cwd.exists() {
        return Some(cwd);
    }

    let exe = env::current_exe().ok()?;
    let exe_dir = exe.parent()?.join(file_name);
    if exe_dir.exists() {
        return Some(exe_dir);
    }

    None
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
