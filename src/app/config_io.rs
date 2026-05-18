use super::App;

impl App {
    pub(super) fn update_config_file<F>(&mut self, error_context: &str, update: F) -> bool
    where
        F: FnOnce(&str) -> String,
    {
        #[cfg(test)]
        if std::env::var_os(crate::config::CONFIG_PATH_ENV_VAR).is_none() {
            return false;
        }

        let path = crate::config::config_path();
        if let Some(parent) = path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                crate::logging::config_write_failed(&path, error_context, &err.to_string());
                self.state.config_diagnostic =
                    Some(format!("failed to save {error_context}: {err}"));
                self.config_diagnostic_deadline =
                    Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
                return false;
            }
        }

        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let new_content = update(&content);
        if let Err(err) = std::fs::write(&path, new_content) {
            crate::logging::config_write_failed(&path, error_context, &err.to_string());
            self.state.config_diagnostic = Some(format!("failed to save {error_context}: {err}"));
            self.config_diagnostic_deadline =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
            return false;
        }

        true
    }

    pub(super) fn mark_onboarding_complete(&mut self) {
        self.update_config_file("onboarding setting", |content| {
            crate::config::upsert_top_level_bool(content, "onboarding", false)
        });
    }

    pub(super) fn save_theme(&mut self, name: &str) {
        if self.update_config_file("theme", |content| {
            crate::config::upsert_section_value(content, "theme", "name", &format!("\"{name}\""))
        }) {
            self.apply_config_from_disk(false);
        }
    }

    pub(super) fn save_sound(&mut self, enabled: bool) {
        if self.update_config_file("sound setting", |content| {
            crate::config::upsert_section_bool(content, "ui.sound", "enabled", enabled)
        }) {
            self.apply_config_from_disk(false);
        }
    }

    pub(super) fn save_toast_delivery(&mut self, delivery: crate::config::ToastDelivery) {
        let value = match delivery {
            crate::config::ToastDelivery::Off => "\"off\"",
            crate::config::ToastDelivery::Herdr => "\"herdr\"",
            crate::config::ToastDelivery::Terminal => "\"terminal\"",
            crate::config::ToastDelivery::System => "\"system\"",
        };
        if self.update_config_file("toast setting", |content| {
            let content =
                crate::config::upsert_section_value(content, "ui.toast", "delivery", value);
            crate::config::remove_section_key(&content, "ui.toast", "enabled")
        }) {
            self.apply_config_from_disk(false);
        }
    }

    /// Toggle the optional WebSocket gateway. Persists `[server] ws_enabled`
    /// in `config.toml` and starts/stops the `herdr ws-server` background
    /// subprocess so the user perceives the change as instant.
    ///
    /// On the first enable, if no password is configured a fresh random one
    /// is generated and persisted to `[server] ws_password`. We refuse to
    /// expose a herdr session on the network with no authentication.
    /// TLS is on by default (`[server] ws_tls = true`); the self-signed
    /// certificate is generated up front so the connection command we show
    /// in the Settings UI includes the correct fingerprint.
    pub(super) fn save_ws_server_enabled(&mut self, enabled: bool) {
        if enabled && self.state.server_config.ws_password.is_none() {
            match crate::ws_transport::control::generate_password() {
                Ok(pw) => {
                    if self.update_config_file("server.ws_password", |content| {
                        crate::config::upsert_section_value(
                            content,
                            "server",
                            "ws_password",
                            &format!("\"{pw}\""),
                        )
                    }) {
                        self.state.server_config.ws_password = Some(pw);
                    }
                }
                Err(err) => {
                    self.state.config_diagnostic =
                        Some(format!("could not generate ws-server password: {err}"));
                    self.config_diagnostic_deadline =
                        Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
                    return;
                }
            }
        }

        // Default to TLS on first enable. Pre-generate the self-signed cert
        // so the Settings UI can show its SHA-256 fingerprint immediately.
        if enabled && self.state.server_config.ws_tls {
            if let Err(err) = crate::ws_transport::tls::ensure_default_cert_and_read_fingerprint() {
                self.state.config_diagnostic = Some(format!(
                    "could not prepare ws-server TLS certificate: {err}"
                ));
                self.config_diagnostic_deadline =
                    Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
                return;
            }
        }

        let port = self.state.server_config.ws_port;
        let password = self.state.server_config.ws_password.clone();
        let tls = self.state.server_config.ws_tls;

        let process_outcome = if enabled {
            crate::ws_transport::control::start(port, password.as_deref(), tls)
                .map(|_| ())
                .or_else(|err| {
                    if err.kind() == std::io::ErrorKind::AlreadyExists {
                        Ok(())
                    } else {
                        Err(err)
                    }
                })
        } else {
            crate::ws_transport::control::stop().map(|_| ())
        };

        if let Err(err) = process_outcome {
            self.state.config_diagnostic = Some(format!(
                "ws-server {}: {err}",
                if enabled { "start" } else { "stop" }
            ));
            self.config_diagnostic_deadline =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
            return;
        }

        if self.update_config_file("server.ws_enabled", |content| {
            crate::config::upsert_section_bool(content, "server", "ws_enabled", enabled)
        }) {
            self.apply_config_from_disk(false);
        }
    }

    /// Persist a new `[server] ws_port` and, if the gateway is already
    /// running, restart it on the new port so the change is immediate.
    pub(super) fn save_ws_server_port(&mut self, port: u16) {
        if self.state.server_config.ws_port == port && !crate::ws_transport::control::is_running() {
            // Nothing to do: same value, nothing running to restart.
            self.state.server_config.ws_port = port;
        } else {
            self.state.server_config.ws_port = port;
        }
        if self.update_config_file("server.ws_port", |content| {
            crate::config::upsert_section_value(content, "server", "ws_port", &port.to_string())
        }) {
            self.apply_config_from_disk(false);
        }
        if crate::ws_transport::control::is_running() {
            let _ = crate::ws_transport::control::stop();
            let password = self.state.server_config.ws_password.clone();
            let tls = self.state.server_config.ws_tls;
            if let Err(err) = crate::ws_transport::control::start(port, password.as_deref(), tls) {
                self.state.config_diagnostic =
                    Some(format!("ws-server restart on port {port}: {err}"));
                self.config_diagnostic_deadline =
                    Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
            }
        }
    }

    pub(super) fn save_agent_border_labels(&mut self, enabled: bool) {
        if self.update_config_file("agent border labels", |content| {
            crate::config::upsert_section_bool(
                content,
                "ui",
                "show_agent_labels_on_pane_borders",
                enabled,
            )
        }) {
            self.apply_config_from_disk(false);
        }
    }

    pub(super) fn save_agent_panel_scope(&mut self, scope: crate::app::state::AgentPanelScope) {
        let value = match scope {
            crate::app::state::AgentPanelScope::CurrentWorkspace => {
                crate::config::AgentPanelScopeConfig::Current.as_str()
            }
            crate::app::state::AgentPanelScope::AllWorkspaces => {
                crate::config::AgentPanelScopeConfig::All.as_str()
            }
        };
        if self.update_config_file("agent panel scope", |content| {
            crate::config::upsert_section_value(
                content,
                "ui",
                "agent_panel_scope",
                &format!("\"{value}\""),
            )
        }) {
            self.apply_config_from_disk(false);
        }
    }
}
