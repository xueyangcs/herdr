use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Frame,
};

use super::widgets::{
    action_button_row_rects, centered_popup_rect, modal_stack_areas, panel_contrast_fg,
    render_action_button, render_modal_choice_list, render_panel_shell, ActionButtonSpec,
};
use crate::{
    app::{state::Palette, AppState},
    config::ToastDelivery,
};

/// Preset ports shown on the Server tab. Users can pick one with Left/Right
/// arrows; anyone needing something exotic edits `[server] ws_port` in
/// `config.toml` directly.
pub(crate) const SERVER_PORT_PRESETS: &[u16] = &[8080, 8081, 8443, 8888];

/// Selection encoding for the Server tab in Settings.
/// 0..PRESETS.len() = port preset index
/// PRESETS.len()    = toggle "on"
/// PRESETS.len()+1  = toggle "off"
pub(crate) const SERVER_TOGGLE_ON_IDX: usize = SERVER_PORT_PRESETS.len();
pub(crate) const SERVER_TOGGLE_OFF_IDX: usize = SERVER_PORT_PRESETS.len() + 1;

pub(super) fn render_settings_overlay(app: &AppState, frame: &mut Frame, area: Rect) {
    use crate::app::state::SettingsSection;

    let p = &app.palette;
    let Some(popup) = centered_popup_rect(area, 76, 22) else {
        return;
    };

    super::dim_background(frame, area);

    let Some(inner) = render_panel_shell(frame, popup, p.accent, p.panel_bg) else {
        return;
    };
    if inner.height < 4 || inner.width < 10 {
        return;
    }

    let stack = modal_stack_areas(inner, 3, 2, 0, 1);
    let header_rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas::<3>(stack.header);

    frame.render_widget(
        Paragraph::new(Line::from(vec![Span::styled(
            " settings",
            Style::default().fg(p.text).add_modifier(Modifier::BOLD),
        )])),
        header_rows[0],
    );

    let tabs = Tabs::new(SettingsSection::ALL.iter().map(|s| s.label()))
        .select(
            SettingsSection::ALL
                .iter()
                .position(|section| *section == app.settings.section)
                .unwrap_or(0),
        )
        .style(Style::default().fg(p.overlay1))
        .highlight_style(
            Style::default()
                .fg(panel_contrast_fg(p))
                .bg(p.accent)
                .add_modifier(Modifier::BOLD),
        )
        .divider(" ")
        .padding(" ", " ");
    frame.render_widget(tabs, header_rows[1]);

    let sep = "─".repeat(inner.width as usize);
    frame.render_widget(
        Paragraph::new(Span::styled(&sep, Style::default().fg(p.surface0))),
        header_rows[2],
    );

    let content_area = stack.content;

    match app.settings.section {
        SettingsSection::Theme => {
            render_settings_theme(app, frame, content_area);
        }
        SettingsSection::Sound => {
            render_settings_toggle(
                frame,
                content_area,
                p,
                "sound alerts",
                "play sounds when agents change state in background",
                app.sound_enabled(),
                app.settings.list.selected,
            );
        }
        SettingsSection::Toast => {
            render_modal_choice_list(
                frame,
                content_area,
                "notification popups",
                "choose where background popup notifications should appear",
                &[
                    ("off", ToastDelivery::Off),
                    ("inside herdr", ToastDelivery::Herdr),
                    ("via terminal", ToastDelivery::Terminal),
                    ("via system", ToastDelivery::System),
                ],
                app.toast_delivery(),
                app.settings.list.selected,
                p,
                2,
            );
        }
        SettingsSection::PaneLabels => {
            render_settings_toggle(
                frame,
                content_area,
                p,
                "agent border labels",
                "show detected agent names in split pane borders",
                app.agent_border_labels_enabled(),
                app.settings.list.selected,
            );
        }
        SettingsSection::Server => {
            render_settings_server(app, frame, content_area);
        }
    }

    if let Some(footer_area) = stack.footer {
        let footer_rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)])
            .areas::<2>(footer_area);
        let (apply_rect, close_rect) = settings_button_rects(inner);
        render_action_button(
            frame,
            apply_rect,
            Some("↵"),
            "apply",
            Style::default()
                .fg(panel_contrast_fg(p))
                .bg(p.accent)
                .add_modifier(Modifier::BOLD),
        );
        render_action_button(
            frame,
            close_rect,
            Some("esc"),
            "close",
            Style::default()
                .fg(p.text)
                .bg(p.surface0)
                .add_modifier(Modifier::BOLD),
        );

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" ↑↓", Style::default().fg(p.overlay0)),
                Span::styled(" select  ", Style::default().fg(p.overlay1)),
                Span::styled("tab", Style::default().fg(p.overlay0)),
                Span::styled(" section", Style::default().fg(p.overlay1)),
            ])),
            footer_rows[0],
        );
    }
}

pub(crate) fn settings_button_rects(inner: Rect) -> (Rect, Rect) {
    let rects = action_button_row_rects(
        inner,
        &[
            ActionButtonSpec {
                hint: Some("↵"),
                label: "apply",
            },
            ActionButtonSpec {
                hint: Some("esc"),
                label: "close",
            },
        ],
        2,
        inner.height.saturating_sub(1),
    );
    (rects[0], rects[1])
}

fn render_settings_theme(app: &AppState, frame: &mut Frame, area: Rect) {
    use crate::app::state::THEME_NAMES;

    let p = &app.palette;
    let items: Vec<ListItem> = THEME_NAMES
        .iter()
        .map(|name| {
            let is_current = name.to_lowercase().replace([' ', '_'], "-")
                == app.theme_name.to_lowercase().replace([' ', '_'], "-");
            let marker = if is_current { " ✓" } else { "" };
            ListItem::new(Line::from(vec![
                Span::styled(*name, Style::default().fg(p.subtext0)),
                Span::styled(marker, Style::default().fg(p.green)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .highlight_style(
            Style::default()
                .bg(p.surface0)
                .fg(p.text)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" ▸ ")
        .style(Style::default().fg(p.subtext0));

    let mut state = ListState::default().with_selected(Some(app.settings.list.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_settings_toggle(
    frame: &mut Frame,
    area: Rect,
    p: &Palette,
    title: &str,
    description: &str,
    current_value: bool,
    selected_idx: usize,
) {
    render_modal_choice_list(
        frame,
        area,
        title,
        description,
        &[("on", true), ("off", false)],
        current_value,
        selected_idx,
        p,
        1,
    );
}

/// Renders the Server tab: title, description, port preset row, password and
/// TLS fingerprint, the ready-to-paste connection command, and the on/off
/// toggle at the bottom. Selection encoding follows `SERVER_TOGGLE_*` /
/// `SERVER_PORT_PRESETS` constants above.
fn render_settings_server(app: &AppState, frame: &mut Frame, area: Rect) {
    let p = &app.palette;
    let running = crate::ws_transport::control::is_running();
    let current_port = app.server_config.ws_port;
    let pw = app.server_config.ws_password.as_deref().unwrap_or("");
    let tls = app.server_config.ws_tls;
    let scheme = if tls { "wss" } else { "ws" };
    let fingerprint = if tls {
        crate::ws_transport::tls::ensure_default_cert_and_read_fingerprint().ok()
    } else {
        None
    };
    let selected = app.settings.list.selected;

    // Layout:
    //   title (1)  description (1)  blank (1)
    //   port row (1)
    //   blank (1)
    //   details (variable)
    //   toggle row (1)
    let lines = [
        Constraint::Length(1), // title
        Constraint::Length(1), // description
        Constraint::Length(1), // blank
        Constraint::Length(1), // port row label
        Constraint::Length(1), // port choices
        Constraint::Length(1), // blank
        Constraint::Min(1),    // details (password, fp, command)
        Constraint::Length(1), // toggle
    ];
    let rows = Layout::vertical(lines).split(area);

    let title_style = Style::default().fg(p.text).add_modifier(Modifier::BOLD);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled("remote ws-server", title_style))),
        rows[0],
    );

    let desc = format!(
        "Expose this herdr session over {scheme}:// (TLS on by default). \
         Password and fingerprint are auto-generated."
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            desc,
            Style::default().fg(p.overlay1),
        )))
        .wrap(Wrap { trim: true }),
        rows[1],
    );

    // Port row label
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "port",
            Style::default().fg(p.overlay0),
        ))),
        rows[3],
    );

    // Port preset choices (horizontal)
    let mut port_spans: Vec<Span> = Vec::new();
    port_spans.push(Span::styled(" ", Style::default()));
    for (i, &port) in SERVER_PORT_PRESETS.iter().enumerate() {
        let is_current = port == current_port;
        let is_selected = selected == i;
        let label = if is_current {
            format!(" {port}* ")
        } else {
            format!(" {port} ")
        };
        let style = if is_selected {
            Style::default()
                .fg(panel_contrast_fg(p))
                .bg(p.accent)
                .add_modifier(Modifier::BOLD)
        } else if is_current {
            Style::default().fg(p.text).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(p.subtext0)
        };
        port_spans.push(Span::styled(label, style));
    }
    frame.render_widget(Paragraph::new(Line::from(port_spans)), rows[4]);

    // Details: password, fingerprint, ready-to-paste connect command
    let mut detail_lines: Vec<Line> = Vec::new();
    let label_style = Style::default().fg(p.overlay0);
    let value_style = Style::default().fg(p.text);
    if !pw.is_empty() {
        detail_lines.push(Line::from(vec![
            Span::styled("password:    ", label_style),
            Span::styled(pw.to_string(), value_style),
        ]));
    }
    if let Some(fp) = &fingerprint {
        detail_lines.push(Line::from(vec![
            Span::styled("fingerprint: ", label_style),
            Span::styled(fp.clone(), value_style),
        ]));
    }
    if running && !pw.is_empty() {
        detail_lines.push(Line::from(""));
        detail_lines.push(Line::from(Span::styled(
            "connect from elsewhere (replace <your-host>):",
            label_style,
        )));
        let mut cmd =
            format!("  herdr --remote {scheme}://<your-host>:{current_port} --ws-password {pw}");
        if let Some(fp) = &fingerprint {
            cmd.push_str(&format!(" --ws-fingerprint {fp}"));
        }
        detail_lines.push(Line::from(Span::styled(cmd, Style::default().fg(p.green))));
    } else if !running {
        detail_lines.push(Line::from(Span::styled(
            "toggle on below to start the gateway.",
            Style::default().fg(p.overlay0),
        )));
    }
    frame.render_widget(
        Paragraph::new(detail_lines).wrap(Wrap { trim: false }),
        rows[6],
    );

    // Toggle row at the bottom
    let toggle_selected = if selected == SERVER_TOGGLE_OFF_IDX {
        1
    } else {
        0
    };
    let toggle_spans = vec![
        Span::styled(" ", Style::default()),
        Span::styled(
            " on ",
            if toggle_selected == 0 && selected >= SERVER_TOGGLE_ON_IDX {
                Style::default()
                    .fg(panel_contrast_fg(p))
                    .bg(p.accent)
                    .add_modifier(Modifier::BOLD)
            } else if running {
                Style::default().fg(p.green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(p.subtext0)
            },
        ),
        Span::styled(" ", Style::default()),
        Span::styled(
            " off ",
            if toggle_selected == 1 && selected >= SERVER_TOGGLE_ON_IDX {
                Style::default()
                    .fg(panel_contrast_fg(p))
                    .bg(p.accent)
                    .add_modifier(Modifier::BOLD)
            } else if !running {
                Style::default().fg(p.text).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(p.subtext0)
            },
        ),
    ];
    frame.render_widget(Paragraph::new(Line::from(toggle_spans)), rows[7]);
}
