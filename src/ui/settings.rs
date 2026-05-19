use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Frame,
};

use super::widgets::{
    action_button_row_rects, centered_popup_rect, modal_choice_rows, modal_stack_areas,
    panel_contrast_fg, render_action_button, render_modal_choice_list, render_modal_description,
    render_panel_shell, ActionButtonSpec,
};
use crate::{
    app::{state::Palette, AppState},
    config::{ServerConfig, ToastDelivery},
};

/// Server tab: on/off toggle rows (same pattern as sound settings).
pub(crate) const SERVER_IDX_ON: usize = 0;
pub(crate) const SERVER_IDX_OFF: usize = 1;
/// Shown below the toggle when `ws_enabled` is true.
pub(crate) const SERVER_IDX_PORT: usize = 2;
/// Shown when the gateway is configured and a connect command is available.
pub(crate) const SERVER_IDX_COMMAND: usize = 3;

pub(crate) fn server_settings_item_count(config: &ServerConfig) -> usize {
    if !config.ws_enabled {
        return 2;
    }
    if server_connect_command(config).is_some() {
        4
    } else {
        3
    }
}

pub(crate) fn server_connect_command(config: &ServerConfig) -> Option<String> {
    if !config.ws_enabled {
        return None;
    }
    let password = config.ws_password.as_ref()?;
    let scheme = if config.ws_tls { "wss" } else { "ws" };
    let mut cmd = format!(
        "herdr --remote {scheme}://<your-host>:{} --password {password}",
        config.ws_port
    );
    if config.ws_tls {
        let fingerprint = config.ws_fingerprint.as_ref()?;
        cmd.push_str(&format!(" --fingerprint {fingerprint}"));
    }
    Some(cmd)
}

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

fn render_settings_server(app: &AppState, frame: &mut Frame, area: Rect) {
    let p = &app.palette;
    let config = &app.server_config;
    let enabled = config.ws_enabled;
    let selected = app.settings.list.selected;

    let [desc_area, _, list_area] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Min(2),
    ])
    .areas::<3>(area);

    render_modal_description(
        frame,
        desc_area,
        "expose this herdr session over wss:// for remote clients (TLS on by default)",
        Style::default().fg(p.overlay1),
    );

    enum ServerRow {
        Toggle { label: &'static str, value: bool },
        Port,
        Command(String),
    }

    let mut rows: Vec<ServerRow> = vec![
        ServerRow::Toggle {
            label: "on",
            value: true,
        },
        ServerRow::Toggle {
            label: "off",
            value: false,
        },
    ];
    if enabled {
        rows.push(ServerRow::Port);
        if let Some(cmd) = server_connect_command(config) {
            rows.push(ServerRow::Command(cmd));
        }
    }

    let choice_rows = modal_choice_rows(list_area, rows.len(), 1);
    for (idx, (row_kind, row_rect)) in rows.iter().zip(choice_rows.iter()).enumerate() {
        let (text, is_active) = match row_kind {
            ServerRow::Toggle { label, value } => {
                let marker = if *value == enabled { " ✓" } else { "" };
                (format!(" wss-server: {label}{marker}"), *value == enabled)
            }
            ServerRow::Port => (format!(" port  {}", config.ws_port), false),
            ServerRow::Command(cmd) => (format!(" {cmd}"), false),
        };
        let is_selected = idx == selected;
        let style = if is_selected {
            Style::default()
                .bg(p.surface0)
                .fg(if matches!(row_kind, ServerRow::Command(_)) {
                    p.green
                } else {
                    p.text
                })
                .add_modifier(Modifier::BOLD)
        } else if is_active {
            Style::default().fg(p.text).add_modifier(Modifier::BOLD)
        } else if matches!(row_kind, ServerRow::Command(_)) {
            Style::default().fg(p.green)
        } else {
            Style::default().fg(p.subtext0)
        };
        frame.render_widget(
            Paragraph::new(text).style(style).wrap(Wrap { trim: false }),
            *row_rect,
        );
    }
}
