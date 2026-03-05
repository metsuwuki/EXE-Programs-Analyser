use super::*;

pub(crate) fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = zed_bg_0();
    visuals.window_fill = zed_bg_1();
    visuals.faint_bg_color = zed_bg_1();
    visuals.extreme_bg_color = zed_bg_0();
    visuals.override_text_color = Some(egui::Color32::from_rgb(212, 220, 233));
    visuals.hyperlink_color = zed_accent();
    visuals.selection.bg_fill = egui::Color32::from_rgb(54, 78, 112);
    visuals.selection.stroke = egui::Stroke::new(1.0, zed_accent());
    visuals.widgets.noninteractive.bg_fill = zed_bg_1();
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, zed_fg_muted());
    visuals.widgets.inactive.bg_fill = zed_bg_2();
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(182, 194, 214));
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(30, 38, 50);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.2, egui::Color32::from_rgb(212, 223, 242));
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(36, 47, 62);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.2, egui::Color32::from_rgb(220, 232, 248));
    visuals.widgets.open.bg_fill = egui::Color32::from_rgb(26, 34, 45);
    visuals.override_text_color = visuals
        .override_text_color
        .or(Some(egui::Color32::from_rgb(220, 225, 235)));
    ctx.set_visuals(visuals);
}
