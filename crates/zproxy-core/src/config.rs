use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    Socks4,
    Socks4a,
    Socks5,
    Http,
    Https,
}

impl ProxyProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyProtocol::Socks4 => "socks4",
            ProxyProtocol::Socks4a => "socks4a",
            ProxyProtocol::Socks5 => "socks5",
            ProxyProtocol::Http => "http",
            ProxyProtocol::Https => "https",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "socks4" => Ok(ProxyProtocol::Socks4),
            "socks4a" => Ok(ProxyProtocol::Socks4a),
            "socks5" => Ok(ProxyProtocol::Socks5),
            "http" => Ok(ProxyProtocol::Http),
            "https" => Ok(ProxyProtocol::Https),
            other => Err(anyhow!("Unknown protocol: {}", other)),
        }
    }
}

impl std::fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthMethod {
    None,
    UserPass { username: String, password: String },
    Basic { username: String, password: String },
    Ntlm { username: String, password: String, domain: String },
}

impl AuthMethod {
    pub fn type_str(&self) -> &'static str {
        match self {
            AuthMethod::None => "none",
            AuthMethod::UserPass { .. } => "userpass",
            AuthMethod::Basic { .. } => "basic",
            AuthMethod::Ntlm { .. } => "ntlm",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleAction {
    Proxy(String),
    Direct,
    Block,
}

impl RuleAction {
    pub fn as_str(&self) -> String {
        match self {
            RuleAction::Proxy(id) => format!("proxy:{}", id),
            RuleAction::Direct => "direct".to_string(),
            RuleAction::Block => "block".to_string(),
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        if s == "direct" {
            Ok(RuleAction::Direct)
        } else if s == "block" {
            Ok(RuleAction::Block)
        } else if let Some(id) = s.strip_prefix("proxy:") {
            Ok(RuleAction::Proxy(id.to_string()))
        } else {
            Err(anyhow!("Unknown rule action: {}", s))
        }
    }
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyServer {
    pub id: String,
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    pub auth: AuthMethod,
    pub enabled: bool,
    pub timeout_secs: u64,
}

impl ProxyServer {
    pub fn new(id: impl Into<String>, protocol: ProxyProtocol, host: impl Into<String>, port: u16) -> Self {
        ProxyServer {
            id: id.into(),
            protocol,
            host: host.into(),
            port,
            auth: AuthMethod::None,
            enabled: true,
            timeout_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyChain {
    pub id: String,
    pub name: String,
    /// Ordered list of server IDs
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub host_pattern: Option<String>,
    pub process_pattern: Option<String>,
    pub port: Option<u16>,
    pub action: RuleAction,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub log_path: String,
    pub log_level: String,
    pub listen_host: String,
    pub listen_port: u16,
    pub dns_via_proxy: bool,
    pub handle_all_traffic: bool,
    pub default_action: RuleAction,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            log_path: "zproxy.log".to_string(),
            log_level: "info".to_string(),
            listen_host: "127.0.0.1".to_string(),
            listen_port: 1080,
            dns_via_proxy: false,
            handle_all_traffic: false,
            default_action: RuleAction::Direct,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub servers: Vec<ProxyServer>,
    pub chains: Vec<ProxyChain>,
    pub rules: Vec<Rule>,
    pub settings: Settings,
}

// ---------------------------------------------------------------------------
// ProxyConfig implementation
// ---------------------------------------------------------------------------

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            servers: Vec::new(),
            chains: Vec::new(),
            rules: Vec::new(),
            settings: Settings::default(),
        }
    }
}

impl ProxyConfig {

    pub fn find_server(&self, id: &str) -> Option<&ProxyServer> {
        self.servers.iter().find(|s| s.id == id)
    }

    pub fn find_chain(&self, id: &str) -> Option<&ProxyChain> {
        self.chains.iter().find(|c| c.id == id)
    }

    /// Load configuration from an XML file.
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read config file '{}': {}", path, e))?;
        Self::from_xml(&content)
    }

    /// Save configuration to an XML file.
    pub fn save_to_file(&self, path: &str) -> Result<()> {
        let xml = self.to_xml()?;
        let mut file = std::fs::File::create(path)
            .map_err(|e| anyhow!("Failed to create config file '{}': {}", path, e))?;
        file.write_all(xml.as_bytes())
            .map_err(|e| anyhow!("Failed to write config file: {}", e))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // XML serialization
    // -----------------------------------------------------------------------

    pub fn to_xml(&self) -> Result<String> {
        let mut out = String::new();
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str("<zproxy>\n");

        // Settings
        out.push_str("  <settings>\n");
        out.push_str(&format!("    <log_path>{}</log_path>\n", xml_escape(&self.settings.log_path)));
        out.push_str(&format!("    <log_level>{}</log_level>\n", xml_escape(&self.settings.log_level)));
        out.push_str(&format!("    <listen_host>{}</listen_host>\n", xml_escape(&self.settings.listen_host)));
        out.push_str(&format!("    <listen_port>{}</listen_port>\n", self.settings.listen_port));
        out.push_str(&format!("    <dns_via_proxy>{}</dns_via_proxy>\n", self.settings.dns_via_proxy));
        out.push_str(&format!("    <handle_all_traffic>{}</handle_all_traffic>\n", self.settings.handle_all_traffic));
        out.push_str(&format!("    <default_action>{}</default_action>\n", xml_escape(&self.settings.default_action.as_str())));
        out.push_str("  </settings>\n");

        // Servers
        out.push_str("  <servers>\n");
        for s in &self.servers {
            out.push_str(&format!(
                "    <server id=\"{}\" protocol=\"{}\" host=\"{}\" port=\"{}\" enabled=\"{}\" timeout_secs=\"{}\">\n",
                xml_escape(&s.id),
                s.protocol.as_str(),
                xml_escape(&s.host),
                s.port,
                s.enabled,
                s.timeout_secs
            ));
            match &s.auth {
                AuthMethod::None => out.push_str("      <auth type=\"none\"/>\n"),
                AuthMethod::UserPass { username, password } => {
                    out.push_str(&format!(
                        "      <auth type=\"userpass\" username=\"{}\" password=\"{}\"/>\n",
                        xml_escape(username), xml_escape(password)
                    ));
                }
                AuthMethod::Basic { username, password } => {
                    out.push_str(&format!(
                        "      <auth type=\"basic\" username=\"{}\" password=\"{}\"/>\n",
                        xml_escape(username), xml_escape(password)
                    ));
                }
                AuthMethod::Ntlm { username, password, domain } => {
                    out.push_str(&format!(
                        "      <auth type=\"ntlm\" username=\"{}\" password=\"{}\" domain=\"{}\"/>\n",
                        xml_escape(username), xml_escape(password), xml_escape(domain)
                    ));
                }
            }
            out.push_str("    </server>\n");
        }
        out.push_str("  </servers>\n");

        // Chains
        out.push_str("  <chains>\n");
        for c in &self.chains {
            out.push_str(&format!("    <chain id=\"{}\" name=\"{}\">\n", xml_escape(&c.id), xml_escape(&c.name)));
            for sid in &c.servers {
                out.push_str(&format!("      <server_ref id=\"{}\"/>\n", xml_escape(sid)));
            }
            out.push_str("    </chain>\n");
        }
        out.push_str("  </chains>\n");

        // Rules
        out.push_str("  <rules>\n");
        for r in &self.rules {
            out.push_str(&format!(
                "    <rule id=\"{}\" name=\"{}\" action=\"{}\" priority=\"{}\"",
                xml_escape(&r.id),
                xml_escape(&r.name),
                xml_escape(&r.action.as_str()),
                r.priority
            ));
            if let Some(hp) = &r.host_pattern {
                out.push_str(&format!(" host_pattern=\"{}\"", xml_escape(hp)));
            }
            if let Some(pp) = &r.process_pattern {
                out.push_str(&format!(" process_pattern=\"{}\"", xml_escape(pp)));
            }
            if let Some(port) = r.port {
                out.push_str(&format!(" port=\"{}\"", port));
            }
            out.push_str("/>\n");
        }
        out.push_str("  </rules>\n");

        out.push_str("</zproxy>\n");
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // XML deserialization (manual quick-xml reader)
    // -----------------------------------------------------------------------

    pub fn from_xml(xml: &str) -> Result<Self> {
        use quick_xml::Reader;
        use quick_xml::events::Event;

        let mut config = ProxyConfig::default();
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut current_section = String::new();
        let mut current_server: Option<ProxyServer> = None;
        let mut current_chain: Option<ProxyChain> = None;
        let mut current_text_tag = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = std::str::from_utf8(e.name().as_ref())?.to_string();
                    match name.as_str() {
                        "settings" | "servers" | "chains" | "rules" => {
                            current_section = name.clone();
                        }
                        "server" if current_section == "servers" => {
                            let mut srv = ProxyServer::new("", ProxyProtocol::Socks5, "", 1080);
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(attr.key.as_ref())?.to_string();
                                let val = attr.unescape_value()?.to_string();
                                match key.as_str() {
                                    "id" => srv.id = val,
                                    "protocol" => srv.protocol = ProxyProtocol::from_str(&val)?,
                                    "host" => srv.host = val,
                                    "port" => srv.port = val.parse()?,
                                    "enabled" => srv.enabled = val == "true",
                                    "timeout_secs" => srv.timeout_secs = val.parse()?,
                                    _ => {}
                                }
                            }
                            current_server = Some(srv);
                        }
                        "chain" if current_section == "chains" => {
                            let mut chain = ProxyChain {
                                id: String::new(),
                                name: String::new(),
                                servers: Vec::new(),
                            };
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(attr.key.as_ref())?.to_string();
                                let val = attr.unescape_value()?.to_string();
                                match key.as_str() {
                                    "id" => chain.id = val,
                                    "name" => chain.name = val,
                                    _ => {}
                                }
                            }
                            current_chain = Some(chain);
                        }
                        tag if current_section == "settings" => {
                            current_text_tag = tag.to_string();
                        }
                        _ => {}
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let name = std::str::from_utf8(e.name().as_ref())?.to_string();
                    match name.as_str() {
                        "auth" => {
                            if let Some(ref mut srv) = current_server {
                                let mut auth_type = String::new();
                                let mut username = String::new();
                                let mut password = String::new();
                                let mut domain = String::new();
                                for attr in e.attributes().flatten() {
                                    let key = std::str::from_utf8(attr.key.as_ref())?.to_string();
                                    let val = attr.unescape_value()?.to_string();
                                    match key.as_str() {
                                        "type" => auth_type = val,
                                        "username" => username = val,
                                        "password" => password = val,
                                        "domain" => domain = val,
                                        _ => {}
                                    }
                                }
                                srv.auth = match auth_type.as_str() {
                                    "userpass" => AuthMethod::UserPass { username, password },
                                    "basic" => AuthMethod::Basic { username, password },
                                    "ntlm" => AuthMethod::Ntlm { username, password, domain },
                                    _ => AuthMethod::None,
                                };
                            }
                        }
                        "server_ref" => {
                            if let Some(ref mut chain) = current_chain {
                                for attr in e.attributes().flatten() {
                                    let key = std::str::from_utf8(attr.key.as_ref())?.to_string();
                                    let val = attr.unescape_value()?.to_string();
                                    if key == "id" {
                                        chain.servers.push(val);
                                    }
                                }
                            }
                        }
                        "rule" if current_section == "rules" => {
                            let mut rule = Rule {
                                id: String::new(),
                                name: String::new(),
                                host_pattern: None,
                                process_pattern: None,
                                port: None,
                                action: RuleAction::Direct,
                                priority: 0,
                            };
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(attr.key.as_ref())?.to_string();
                                let val = attr.unescape_value()?.to_string();
                                match key.as_str() {
                                    "id" => rule.id = val,
                                    "name" => rule.name = val,
                                    "action" => rule.action = RuleAction::from_str(&val)?,
                                    "priority" => rule.priority = val.parse()?,
                                    "host_pattern" => rule.host_pattern = Some(val),
                                    "process_pattern" => rule.process_pattern = Some(val),
                                    "port" => rule.port = Some(val.parse()?),
                                    _ => {}
                                }
                            }
                            config.rules.push(rule);
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if current_section == "settings" && !current_text_tag.is_empty() {
                        let text = e.unescape()?.to_string();
                        match current_text_tag.as_str() {
                            "log_path" => config.settings.log_path = text,
                            "log_level" => config.settings.log_level = text,
                            "listen_host" => config.settings.listen_host = text,
                            "listen_port" => config.settings.listen_port = text.parse()?,
                            "dns_via_proxy" => config.settings.dns_via_proxy = text == "true",
                            "handle_all_traffic" => config.settings.handle_all_traffic = text == "true",
                            "default_action" => config.settings.default_action = RuleAction::from_str(&text)?,
                            _ => {}
                        }
                        current_text_tag.clear();
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = std::str::from_utf8(e.name().as_ref())?.to_string();
                    match name.as_str() {
                        "server" if current_section == "servers" => {
                            if let Some(srv) = current_server.take() {
                                config.servers.push(srv);
                            }
                        }
                        "chain" if current_section == "chains" => {
                            if let Some(chain) = current_chain.take() {
                                config.chains.push(chain);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow!("XML parse error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(config)
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_xml() {
        let mut cfg = ProxyConfig::default();
        cfg.servers.push(ProxyServer {
            id: "s1".to_string(),
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port: 1080,
            auth: AuthMethod::UserPass {
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            enabled: true,
            timeout_secs: 30,
        });
        cfg.chains.push(ProxyChain {
            id: "c1".to_string(),
            name: "Chain 1".to_string(),
            servers: vec!["s1".to_string()],
        });
        cfg.rules.push(Rule {
            id: "r1".to_string(),
            name: "Block ads".to_string(),
            host_pattern: Some("*.ads.com".to_string()),
            process_pattern: None,
            port: None,
            action: RuleAction::Block,
            priority: 10,
        });

        let xml = cfg.to_xml().unwrap();
        let cfg2 = ProxyConfig::from_xml(&xml).unwrap();

        assert_eq!(cfg2.servers.len(), 1);
        assert_eq!(cfg2.servers[0].id, "s1");
        assert_eq!(cfg2.servers[0].protocol, ProxyProtocol::Socks5);
        assert_eq!(cfg2.chains.len(), 1);
        assert_eq!(cfg2.chains[0].servers, vec!["s1"]);
        assert_eq!(cfg2.rules.len(), 1);
        assert_eq!(cfg2.rules[0].action, RuleAction::Block);
    }

    #[test]
    fn test_find_server() {
        let mut cfg = ProxyConfig::default();
        cfg.servers.push(ProxyServer::new("proxy1", ProxyProtocol::Http, "proxy.example.com", 8080));
        assert!(cfg.find_server("proxy1").is_some());
        assert!(cfg.find_server("nonexistent").is_none());
    }

    #[test]
    fn test_rule_action_roundtrip() {
        let a = RuleAction::Proxy("chain1".to_string());
        let s = a.as_str();
        let b = RuleAction::from_str(&s).unwrap();
        assert_eq!(a, b);
    }
}
