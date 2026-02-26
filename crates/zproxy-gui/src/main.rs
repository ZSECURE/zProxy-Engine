// On Windows, use the "windows" subsystem so no console window appears.
#![cfg_attr(windows, windows_subsystem = "windows")]

/// zProxy GUI – egui/eframe-based frontend.

#[cfg(feature = "gui")]
mod gui {
    use eframe::egui;
    use zproxy_core::{
        checker::ProxyCheckResult,
        config::{AuthMethod, ProxyChain, ProxyConfig, ProxyProtocol, ProxyServer, Rule, RuleAction, Settings},
        stats::ConnectionInfo,
    };

    // -----------------------------------------------------------------------
    // Tab enum
    // -----------------------------------------------------------------------

    #[derive(Debug, PartialEq, Clone, Copy)]
    enum Tab {
        Dashboard,
        Proxies,
        Rules,
        Logs,
        Stats,
        Checker,
    }

    impl Tab {
        fn label(&self) -> &'static str {
            match self {
                Tab::Dashboard => "Dashboard",
                Tab::Proxies => "Proxies",
                Tab::Rules => "Rules",
                Tab::Logs => "Logs",
                Tab::Stats => "Stats",
                Tab::Checker => "Checker",
            }
        }
    }

    // -----------------------------------------------------------------------
    // Edit state for proxy servers
    // -----------------------------------------------------------------------

    #[derive(Default, Clone)]
    struct EditProxy {
        original_id: String, // ID when editing started (empty for new proxies)
        id: String,
        protocol: String,
        host: String,
        port: String,
        username: String,
        password: String,
        domain: String,
        auth_type: String,
        timeout_secs: String,
        enabled: bool,
    }

    impl EditProxy {
        fn from_server(s: &ProxyServer) -> Self {
            let (auth_type, username, password, domain) = match &s.auth {
                AuthMethod::None => ("none".into(), String::new(), String::new(), String::new()),
                AuthMethod::UserPass { username, password } => ("userpass".into(), username.clone(), password.clone(), String::new()),
                AuthMethod::Basic { username, password } => ("basic".into(), username.clone(), password.clone(), String::new()),
                AuthMethod::Ntlm { username, password, domain } => ("ntlm".into(), username.clone(), password.clone(), domain.clone()),
            };
            EditProxy {
                original_id: s.id.clone(),
                id: s.id.clone(),
                protocol: s.protocol.as_str().to_string(),
                host: s.host.clone(),
                port: s.port.to_string(),
                username,
                password,
                domain,
                auth_type,
                timeout_secs: s.timeout_secs.to_string(),
                enabled: s.enabled,
            }
        }

        fn to_server(&self) -> Option<ProxyServer> {
            let port: u16 = self.port.parse().ok()?;
            let timeout_secs: u64 = self.timeout_secs.parse().unwrap_or(30);
            let protocol = ProxyProtocol::from_str(&self.protocol).ok()?;
            let auth = match self.auth_type.as_str() {
                "userpass" => AuthMethod::UserPass { username: self.username.clone(), password: self.password.clone() },
                "basic" => AuthMethod::Basic { username: self.username.clone(), password: self.password.clone() },
                "ntlm" => AuthMethod::Ntlm { username: self.username.clone(), password: self.password.clone(), domain: self.domain.clone() },
                _ => AuthMethod::None,
            };
            Some(ProxyServer { id: self.id.clone(), protocol, host: self.host.clone(), port, auth, enabled: self.enabled, timeout_secs })
        }
    }

    // -----------------------------------------------------------------------
    // Edit state for rules
    // -----------------------------------------------------------------------

    #[derive(Default, Clone)]
    struct EditRule {
        original_id: String, // ID when editing started (empty for new rules)
        id: String,
        name: String,
        host_pattern: String,
        process_pattern: String,
        port: String,
        action: String,
        priority: String,
    }

    impl EditRule {
        fn from_rule(r: &Rule) -> Self {
            EditRule {
                original_id: r.id.clone(),
                id: r.id.clone(),
                name: r.name.clone(),
                host_pattern: r.host_pattern.clone().unwrap_or_default(),
                process_pattern: r.process_pattern.clone().unwrap_or_default(),
                port: r.port.map(|p| p.to_string()).unwrap_or_default(),
                action: r.action.as_str(),
                priority: r.priority.to_string(),
            }
        }

        fn to_rule(&self) -> Option<Rule> {
            let priority: i32 = self.priority.parse().unwrap_or(0);
            let action = RuleAction::from_str(&self.action).ok()?;
            Some(Rule {
                id: self.id.clone(),
                name: self.name.clone(),
                host_pattern: if self.host_pattern.is_empty() { None } else { Some(self.host_pattern.clone()) },
                process_pattern: if self.process_pattern.is_empty() { None } else { Some(self.process_pattern.clone()) },
                port: self.port.parse().ok(),
                action,
                priority,
            })
        }
    }

    // -----------------------------------------------------------------------
    // App state
    // -----------------------------------------------------------------------

    pub struct ZProxyApp {
        config: ProxyConfig,
        config_path: String,
        active_tab: Tab,

        // Logs
        log_lines: Vec<String>,
        log_filter: String,

        // Stats snapshot
        stats_snapshot: Vec<ConnectionInfo>,

        // Checker
        checker_results: Vec<ProxyCheckResult>,
        checking: bool,

        // Proxy edit state
        editing_proxy: Option<EditProxy>,
        new_proxy: bool,

        // Rule edit state
        editing_rule: Option<EditRule>,
        new_rule: bool,

        // Runtime for async tasks
        rt: tokio::runtime::Runtime,
    }

    impl ZProxyApp {
        pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to create Tokio runtime");

            ZProxyApp {
                config: ProxyConfig::default(),
                config_path: "zproxy.xml".into(),
                active_tab: Tab::Dashboard,
                log_lines: Vec::new(),
                log_filter: String::new(),
                stats_snapshot: Vec::new(),
                checker_results: Vec::new(),
                checking: false,
                editing_proxy: None,
                new_proxy: false,
                editing_rule: None,
                new_rule: false,
                rt,
            }
        }

        fn load_config(&mut self) {
            match ProxyConfig::load_from_file(&self.config_path) {
                Ok(cfg) => {
                    self.config = cfg;
                    self.log_lines.push(format!("Loaded config: {}", self.config_path));
                }
                Err(e) => {
                    self.log_lines.push(format!("Error loading config: {}", e));
                }
            }
        }

        fn save_config(&mut self) {
            match self.config.save_to_file(&self.config_path) {
                Ok(_) => self.log_lines.push(format!("Saved config: {}", self.config_path)),
                Err(e) => self.log_lines.push(format!("Error saving config: {}", e)),
            }
        }

        fn run_checks(&mut self) {
            let servers = self.config.servers.clone();
            let results = self.rt.block_on(async {
                zproxy_core::checker::check_all(&servers).await
            });
            self.checker_results = results;
        }
    }

    impl eframe::App for ZProxyApp {
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            // Handle Windows system tray events on every frame.
            #[cfg(windows)]
            self.handle_tray_events(ctx);

            // ---- Top menu bar ----
            egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        if ui.button("Load Config…").clicked() {
                            self.load_config();
                            ui.close_menu();
                        }
                        if ui.button("Save Config").clicked() {
                            self.save_config();
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Quit").clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.menu_button("Help", |ui| {
                        if ui.button("About zProxy").clicked() {
                            self.log_lines.push(format!("zProxy Engine v{} – Lightweight proxy client", env!("CARGO_PKG_VERSION")));
                            ui.close_menu();
                        }
                    });
                });
            });

            // ---- Tab bar ----
            egui::TopBottomPanel::top("tab_bar").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    for tab in [Tab::Dashboard, Tab::Proxies, Tab::Rules, Tab::Logs, Tab::Stats, Tab::Checker] {
                        let selected = self.active_tab == tab;
                        if ui.selectable_label(selected, tab.label()).clicked() {
                            self.active_tab = tab;
                        }
                    }
                });
            });

            // ---- Main content ----
            egui::CentralPanel::default().show(ctx, |ui| {
                match self.active_tab {
                    Tab::Dashboard => self.show_dashboard(ui),
                    Tab::Proxies => self.show_proxies(ui),
                    Tab::Rules => self.show_rules(ui),
                    Tab::Logs => self.show_logs(ui),
                    Tab::Stats => self.show_stats(ui),
                    Tab::Checker => self.show_checker(ui),
                }
            });
        }
    }

    // -----------------------------------------------------------------------
    // Tab implementations
    // -----------------------------------------------------------------------

    impl ZProxyApp {
        fn show_dashboard(&mut self, ui: &mut egui::Ui) {
            ui.heading("Dashboard");
            ui.separator();

            egui::Grid::new("dashboard_grid")
                .num_columns(2)
                .spacing([40.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Listen address:");
                    ui.label(format!("{}:{}", self.config.settings.listen_host, self.config.settings.listen_port));
                    ui.end_row();

                    ui.label("Active connections:");
                    ui.label(self.stats_snapshot.len().to_string());
                    ui.end_row();

                    ui.label("Configured proxies:");
                    ui.label(self.config.servers.len().to_string());
                    ui.end_row();

                    ui.label("Configured rules:");
                    ui.label(self.config.rules.len().to_string());
                    ui.end_row();

                    ui.label("DNS via proxy:");
                    ui.label(self.config.settings.dns_via_proxy.to_string());
                    ui.end_row();

                    ui.label("Default action:");
                    ui.label(self.config.settings.default_action.as_str());
                    ui.end_row();
                });

            ui.separator();
            ui.heading("Settings");
            egui::Grid::new("settings_grid").num_columns(2).show(ui, |ui| {
                ui.label("Listen host:");
                ui.text_edit_singleline(&mut self.config.settings.listen_host);
                ui.end_row();

                ui.label("Listen port:");
                let mut port_str = self.config.settings.listen_port.to_string();
                if ui.text_edit_singleline(&mut port_str).changed() {
                    if let Ok(p) = port_str.parse() {
                        self.config.settings.listen_port = p;
                    }
                }
                ui.end_row();

                ui.label("Log path:");
                ui.text_edit_singleline(&mut self.config.settings.log_path);
                ui.end_row();

                ui.label("Log level:");
                egui::ComboBox::from_id_salt("log_level")
                    .selected_text(&self.config.settings.log_level)
                    .show_ui(ui, |ui| {
                        for lvl in ["error", "warn", "info", "debug", "trace"] {
                            ui.selectable_value(&mut self.config.settings.log_level, lvl.into(), lvl);
                        }
                    });
                ui.end_row();
            });

            // Windows-specific: service management controls
            #[cfg(windows)]
            self.show_windows_service_panel(ui);
        }

        fn show_proxies(&mut self, ui: &mut egui::Ui) {
            ui.heading("Proxy Servers");
            if ui.button("+ Add Proxy").clicked() {
                self.editing_proxy = Some(EditProxy {
                    id: format!("proxy{}", self.config.servers.len() + 1),
                    protocol: "socks5".into(),
                    port: "1080".into(),
                    auth_type: "none".into(),
                    timeout_secs: "30".into(),
                    enabled: true,
                    ..Default::default()
                });
                self.new_proxy = true;
            }
            ui.separator();

            let mut to_delete: Option<usize> = None;
            let mut to_edit: Option<usize> = None;

            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, server) in self.config.servers.iter().enumerate() {
                    ui.horizontal(|ui| {
                        let status = if server.enabled { "✓" } else { "✗" };
                        ui.label(format!("{} [{}] {}  {}:{}", status, server.protocol, server.id, server.host, server.port));
                        if ui.small_button("Edit").clicked() {
                            to_edit = Some(i);
                        }
                        if ui.small_button("Delete").clicked() {
                            to_delete = Some(i);
                        }
                    });
                }
            });

            if let Some(i) = to_delete {
                self.config.servers.remove(i);
            }
            if let Some(i) = to_edit {
                self.editing_proxy = Some(EditProxy::from_server(&self.config.servers[i]));
                self.new_proxy = false;
            }

            // Edit dialog
            if let Some(ref mut ep) = self.editing_proxy.clone() {
                let mut open = true;
                egui::Window::new(if self.new_proxy { "Add Proxy" } else { "Edit Proxy" })
                    .open(&mut open)
                    .show(ui.ctx(), |ui| {
                        egui::Grid::new("proxy_edit_grid").num_columns(2).show(ui, |ui| {
                            ui.label("ID:"); ui.text_edit_singleline(&mut ep.id); ui.end_row();
                            ui.label("Protocol:");
                            egui::ComboBox::from_id_salt("edit_proto")
                                .selected_text(&ep.protocol)
                                .show_ui(ui, |ui| {
                                    for p in ["socks5", "socks4", "socks4a", "http", "https"] {
                                        ui.selectable_value(&mut ep.protocol, p.into(), p);
                                    }
                                });
                            ui.end_row();
                            ui.label("Host:"); ui.text_edit_singleline(&mut ep.host); ui.end_row();
                            ui.label("Port:"); ui.text_edit_singleline(&mut ep.port); ui.end_row();
                            ui.label("Auth:");
                            egui::ComboBox::from_id_salt("edit_auth")
                                .selected_text(&ep.auth_type)
                                .show_ui(ui, |ui| {
                                    for a in ["none", "userpass", "basic", "ntlm"] {
                                        ui.selectable_value(&mut ep.auth_type, a.into(), a);
                                    }
                                });
                            ui.end_row();
                            if ep.auth_type != "none" {
                                ui.label("Username:"); ui.text_edit_singleline(&mut ep.username); ui.end_row();
                                ui.label("Password:"); ui.text_edit_singleline(&mut ep.password); ui.end_row();
                                if ep.auth_type == "ntlm" {
                                    ui.label("Domain:"); ui.text_edit_singleline(&mut ep.domain); ui.end_row();
                                }
                            }
                            ui.label("Timeout (s):"); ui.text_edit_singleline(&mut ep.timeout_secs); ui.end_row();
                            ui.label("Enabled:"); ui.checkbox(&mut ep.enabled, ""); ui.end_row();
                        });
                        ui.horizontal(|ui| {
                            if ui.button("Save").clicked() {
                                if let Some(server) = ep.to_server() {
                                    if self.new_proxy {
                                        self.config.servers.push(server);
                                    } else if let Some(pos) = self.config.servers.iter().position(|s| s.id == ep.original_id) {
                                        self.config.servers[pos] = server;
                                    }
                                }
                                self.editing_proxy = None;
                            }
                            if ui.button("Cancel").clicked() {
                                self.editing_proxy = None;
                            }
                        });
                    });
                if !open {
                    self.editing_proxy = None;
                } else {
                    self.editing_proxy = Some(ep.clone());
                }
            }
        }

        fn show_rules(&mut self, ui: &mut egui::Ui) {
            ui.heading("Proxification Rules");
            if ui.button("+ Add Rule").clicked() {
                self.editing_rule = Some(EditRule {
                    id: format!("rule{}", self.config.rules.len() + 1),
                    action: "direct".into(),
                    priority: "0".into(),
                    ..Default::default()
                });
                self.new_rule = true;
            }
            ui.separator();

            let mut to_delete: Option<usize> = None;
            let mut to_edit: Option<usize> = None;

            egui::ScrollArea::vertical().show(ui, |ui| {
                let mut sorted_rules: Vec<(usize, &Rule)> = self.config.rules.iter().enumerate().collect();
                sorted_rules.sort_by(|a, b| b.1.priority.cmp(&a.1.priority));

                for (i, rule) in sorted_rules {
                    ui.horizontal(|ui| {
                        ui.label(format!("[{}] {} – {} → {}", rule.priority, rule.name,
                            rule.host_pattern.as_deref().unwrap_or("*"),
                            rule.action.as_str()));
                        if ui.small_button("Edit").clicked() { to_edit = Some(i); }
                        if ui.small_button("Delete").clicked() { to_delete = Some(i); }
                    });
                }
            });

            if let Some(i) = to_delete { self.config.rules.remove(i); }
            if let Some(i) = to_edit {
                self.editing_rule = Some(EditRule::from_rule(&self.config.rules[i]));
                self.new_rule = false;
            }

            if let Some(ref mut er) = self.editing_rule.clone() {
                let mut open = true;
                egui::Window::new(if self.new_rule { "Add Rule" } else { "Edit Rule" })
                    .open(&mut open)
                    .show(ui.ctx(), |ui| {
                        egui::Grid::new("rule_edit_grid").num_columns(2).show(ui, |ui| {
                            ui.label("ID:"); ui.text_edit_singleline(&mut er.id); ui.end_row();
                            ui.label("Name:"); ui.text_edit_singleline(&mut er.name); ui.end_row();
                            ui.label("Host pattern:"); ui.text_edit_singleline(&mut er.host_pattern); ui.end_row();
                            ui.label("Process pattern:"); ui.text_edit_singleline(&mut er.process_pattern); ui.end_row();
                            ui.label("Port:"); ui.text_edit_singleline(&mut er.port); ui.end_row();
                            ui.label("Action:"); ui.text_edit_singleline(&mut er.action); ui.end_row();
                            ui.label("Priority:"); ui.text_edit_singleline(&mut er.priority); ui.end_row();
                        });
                        ui.horizontal(|ui| {
                            if ui.button("Save").clicked() {
                                if let Some(rule) = er.to_rule() {
                                    if self.new_rule {
                                        self.config.rules.push(rule);
                                    } else if let Some(pos) = self.config.rules.iter().position(|r| r.id == er.original_id) {
                                        self.config.rules[pos] = rule;
                                    }
                                }
                                self.editing_rule = None;
                            }
                            if ui.button("Cancel").clicked() { self.editing_rule = None; }
                        });
                    });
                if !open { self.editing_rule = None; } else { self.editing_rule = Some(er.clone()); }
            }
        }

        fn show_logs(&mut self, ui: &mut egui::Ui) {
            ui.heading("Logs");
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.log_filter);
                if ui.button("Clear").clicked() {
                    self.log_lines.clear();
                }
            });
            ui.separator();

            let filter = self.log_filter.to_lowercase();
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.log_lines {
                        if filter.is_empty() || line.to_lowercase().contains(&filter) {
                            ui.label(line.as_str());
                        }
                    }
                });
        }

        fn show_stats(&mut self, ui: &mut egui::Ui) {
            ui.heading("Active Connections");
            if ui.button("Refresh").clicked() {
                // In a real app, stats would be pushed from the engine thread.
            }
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("stats_grid")
                    .num_columns(5)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("ID"); ui.strong("Source"); ui.strong("Target");
                        ui.strong("Proxy"); ui.strong("Bytes In/Out");
                        ui.end_row();

                        for conn in &self.stats_snapshot {
                            ui.label(&conn.id[..8.min(conn.id.len())]);
                            ui.label(&conn.source);
                            ui.label(&conn.target);
                            ui.label(&conn.proxy);
                            ui.label(format!("{}/{}", conn.bytes_in, conn.bytes_out));
                            ui.end_row();
                        }
                    });
            });
        }

        fn show_checker(&mut self, ui: &mut egui::Ui) {
            ui.heading("Proxy Checker");
            if ui.button("Check All Proxies").clicked() {
                self.run_checks();
            }
            ui.separator();

            if self.checker_results.is_empty() {
                ui.label("No results yet. Press 'Check All Proxies'.");
                return;
            }

            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("checker_grid")
                    .num_columns(4)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Server ID"); ui.strong("Status"); ui.strong("Latency"); ui.strong("Error");
                        ui.end_row();

                        for r in &self.checker_results {
                            ui.label(&r.server_id);
                            if r.reachable {
                                ui.colored_label(egui::Color32::GREEN, "OK");
                            } else {
                                ui.colored_label(egui::Color32::RED, "FAIL");
                            }
                            ui.label(r.latency_ms.map(|l| format!("{}ms", l)).unwrap_or_else(|| "-".into()));
                            ui.label(r.error.as_deref().unwrap_or("-"));
                            ui.end_row();
                        }
                    });
            });
        }

        // -----------------------------------------------------------------------
        // Windows-specific: system tray event handler
        // -----------------------------------------------------------------------

        #[cfg(windows)]
        fn handle_tray_events(&mut self, ctx: &egui::Context) {
            use tray_icon::menu::MenuEvent;
            while let Ok(event) = MenuEvent::receiver().try_recv() {
                match event.id.0.as_str() {
                    "zproxy_quit" => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                    "zproxy_show" => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                    _ => {}
                }
            }
        }

        // -----------------------------------------------------------------------
        // Windows-specific: service management panel (shown inside Dashboard)
        // -----------------------------------------------------------------------

        #[cfg(windows)]
        fn show_windows_service_panel(&mut self, ui: &mut egui::Ui) {
            ui.separator();
            ui.heading("Windows Service");
            ui.label("Manage zProxy as a Windows service (requires Administrator).");
            ui.horizontal(|ui| {
                if ui.button("Install Service").clicked() {
                    if let Ok(exe) = std::env::current_exe() {
                        let path = exe.display().to_string();
                        match std::process::Command::new("sc")
                            .args(["create", "zproxy", &format!("binPath={}", path), "start=auto"])
                            .output()
                        {
                            Ok(out) if out.status.success() => {
                                self.log_lines.push("Service installed successfully (zproxy).".into());
                            }
                            Ok(out) => {
                                let msg = String::from_utf8_lossy(&out.stderr);
                                self.log_lines.push(format!("Service install failed: {}", msg.trim()));
                            }
                            Err(e) => {
                                self.log_lines.push(format!("Failed to run sc.exe: {}", e));
                            }
                        }
                    }
                }
                if ui.button("Start Service").clicked() {
                    match std::process::Command::new("sc")
                        .args(["start", "zproxy"])
                        .output()
                    {
                        Ok(out) if out.status.success() => {
                            self.log_lines.push("Service started successfully.".into());
                        }
                        Ok(out) => {
                            let msg = String::from_utf8_lossy(&out.stderr);
                            self.log_lines.push(format!("Service start failed: {}", msg.trim()));
                        }
                        Err(e) => {
                            self.log_lines.push(format!("Failed to run sc.exe: {}", e));
                        }
                    }
                }
                if ui.button("Stop Service").clicked() {
                    match std::process::Command::new("sc")
                        .args(["stop", "zproxy"])
                        .output()
                    {
                        Ok(out) if out.status.success() => {
                            self.log_lines.push("Service stopped successfully.".into());
                        }
                        Ok(out) => {
                            let msg = String::from_utf8_lossy(&out.stderr);
                            self.log_lines.push(format!("Service stop failed: {}", msg.trim()));
                        }
                        Err(e) => {
                            self.log_lines.push(format!("Failed to run sc.exe: {}", e));
                        }
                    }
                }
            });
        }
    }

    // -----------------------------------------------------------------------
    // Windows: system tray icon setup
    // -----------------------------------------------------------------------

    #[cfg(windows)]
    fn create_tray_icon() -> tray_icon::TrayIcon {
        use tray_icon::menu::{Menu, MenuItem};
        use tray_icon::{Icon, TrayIconBuilder};

        let show_item = MenuItem::with_id("zproxy_show", "Show Window", true, None);
        let quit_item = MenuItem::with_id("zproxy_quit", "Quit", true, None);
        let menu = Menu::new();
        menu.append_items(&[&show_item, &quit_item]).unwrap();

        // Simple 16×16 blue icon (RGBA)
        let mut rgba = vec![0u8; 16 * 16 * 4];
        for chunk in rgba.chunks_mut(4) {
            chunk[0] = 30;   // R
            chunk[1] = 100;  // G
            chunk[2] = 200;  // B
            chunk[3] = 255;  // A
        }
        let icon = Icon::from_rgba(rgba, 16, 16).expect("failed to build tray icon");

        TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("zProxy Engine")
            .with_icon(icon)
            .build()
            .expect("failed to create tray icon")
    }

    pub fn run() -> eframe::Result<()> {
        // Create the system tray icon before the event loop starts.
        // The binding must remain alive for the entire duration of the app.
        #[cfg(windows)]
        let _tray_icon = create_tray_icon();

        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("zProxy Engine")
                .with_inner_size([900.0, 600.0]),
            ..Default::default()
        };
        eframe::run_native(
            "zProxy Engine",
            options,
            Box::new(|cc| Ok(Box::new(ZProxyApp::new(cc)))),
        )
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[cfg(feature = "gui")]
fn main() -> eframe::Result<()> {
    gui::run()
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("zProxy GUI was compiled without the 'gui' feature. Rebuild with --features gui.");
    std::process::exit(1);
}
