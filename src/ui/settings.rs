use std::path::Path;

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
    config::{config_path, ServerConfig, ToastDelivery},
};

/// Server tab: on/off toggle rows (same pattern as sound settings).
pub(crate) const SERVER_IDX_ON: usize = 0;
pub(crate) const SERVER_IDX_OFF: usize = 1;
/// Shown below the toggle when the gateway is enabled.
pub(crate) const SERVER_IDX_PORT: usize = 2;

pub(crate) fn server_settings_item_count(config: &ServerConfig) -> usize {
    if config.enabled {
        3
    } else {
        2
    }
}

fn server_settings_description() -> String {
    let path = display_config_path();
    format!(
        "Password and TLS fingerprint are stored in [server] in:\n{path}\n\
         (wss-server uses TLS by default.)"
    )
}

fn display_config_path() -> String {
    let path = config_path();
    if let Ok(home) = std::env::var("HOME") {
        let home = Path::new(&home);
        if let Ok(suffix) = path.strip_prefix(home) {
            return format!("~/{}", suffix.display());
        }
    }
    path.display().to_string()
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
    let enabled = config.enabled;
    let selected = app.settings.list.selected;

    let [desc_area, _, list_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Min(2),
    ])
    .areas::<3>(area);

    render_modal_description(
        frame,
        desc_area,
        &server_settings_description(),
        Style::default().fg(p.overlay1),
    );

    enum ServerRow {
        Toggle { label: &'static str, value: bool },
        Port,
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
    }

    let choice_rows = modal_choice_rows(list_area, rows.len(), 1);
    for (idx, (row_kind, row_rect)) in rows.iter().zip(choice_rows.iter()).enumerate() {
        let (text, is_active) = match row_kind {
            ServerRow::Toggle { label, value } => {
                let marker = if *value == enabled { " ✓" } else { "" };
                (format!(" wss-server: {label}{marker}"), *value == enabled)
            }
            ServerRow::Port => (format!(" port  {}", config.port), false),
        };
        let is_selected = idx == selected;
        let style = if is_selected {
            Style::default()
                .bg(p.surface0)
                .fg(p.text)
                .add_modifier(Modifier::BOLD)
        } else if is_active {
            Style::default().fg(p.text).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(p.subtext0)
        };
        frame.render_widget(
            Paragraph::new(text).style(style).wrap(Wrap { trim: false }),
            *row_rect,
        );
    }
}
