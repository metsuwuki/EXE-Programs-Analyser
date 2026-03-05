use super::*;

pub(crate) fn apply_theme(theme: UiTheme, ctx: &egui::Context) {
    let mut visuals = match theme {
        UiTheme::Current => {
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
            visuals.widgets.inactive.fg_stroke =
                egui::Stroke::new(1.0, egui::Color32::from_rgb(190, 200, 216));
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(38, 51, 68);
            visuals.widgets.hovered.fg_stroke =
                egui::Stroke::new(1.2, egui::Color32::from_rgb(218, 228, 242));
            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(48, 65, 88);
            visuals.widgets.active.fg_stroke =
                egui::Stroke::new(1.2, egui::Color32::from_rgb(224, 235, 247));
            visuals.widgets.open.bg_fill = egui::Color32::from_rgb(33, 44, 58);
            visuals
        }
        UiTheme::Dark => egui::Visuals::dark(),
        UiTheme::Dracula => {
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = egui::Color32::from_rgb(40, 42, 54);
            visuals.window_fill = egui::Color32::from_rgb(40, 42, 54);
            visuals.extreme_bg_color = egui::Color32::from_rgb(30, 31, 41);
            visuals.selection.bg_fill = egui::Color32::from_rgb(98, 114, 164);
            visuals.hyperlink_color = egui::Color32::from_rgb(139, 233, 253);
            visuals
        }
        UiTheme::Nord => {
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = egui::Color32::from_rgb(46, 52, 64);
            visuals.window_fill = egui::Color32::from_rgb(59, 66, 82);
            visuals.extreme_bg_color = egui::Color32::from_rgb(36, 41, 51);
            visuals.selection.bg_fill = egui::Color32::from_rgb(94, 129, 172);
            visuals.hyperlink_color = egui::Color32::from_rgb(136, 192, 208);
            visuals
        }
    };
    visuals.override_text_color = visuals
        .override_text_color
        .or(Some(egui::Color32::from_rgb(220, 225, 235)));
    ctx.set_visuals(visuals);
}
