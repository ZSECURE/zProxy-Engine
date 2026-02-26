/// zProxy Engine – main entry point.
///
/// Acts as a local SOCKS5 proxy server that applies proxification rules and
/// forwards connections through configured upstream proxies.

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use zproxy_core::{
    checker,
    config::{ProxyConfig, RuleAction},
    proxy::{chain, connect_through_proxy},
    rules::find_matching_rule,
    stats::{ConnectionInfo, GlobalStats},
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "zproxy", about = "zProxy Engine – lightweight proxy client")]
struct Cli {
    /// Path to the XML configuration file
    #[arg(short, long, default_value = "zproxy.xml")]
    config: String,

    /// Override listen port
    #[arg(short, long)]
    port: Option<u16>,

    /// Run as Windows service
    #[arg(long)]
    service: bool,

    /// Check all configured proxies and exit
    #[arg(long)]
    check: bool,

    /// Enable verbose (debug) logging
    #[arg(short, long)]
    verbose: bool,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise tracing
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .init();

    let mut config = if std::path::Path::new(&cli.config).exists() {
        ProxyConfig::load_from_file(&cli.config).unwrap_or_else(|e| {
            warn!("Failed to load config '{}': {}. Using defaults.", cli.config, e);
            ProxyConfig::default()
        })
    } else {
        info!("Config file '{}' not found, using defaults.", cli.config);
        ProxyConfig::default()
    };

    if let Some(port) = cli.port {
        config.settings.listen_port = port;
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    if cli.check {
        rt.block_on(run_check(&config));
        return Ok(());
    }

    #[cfg(windows)]
    if cli.service {
        return run_as_service(config);
    }

    rt.block_on(run_proxy_server(config))
}

// ---------------------------------------------------------------------------
// Proxy checker
// ---------------------------------------------------------------------------

async fn run_check(config: &ProxyConfig) {
    if config.servers.is_empty() {
        println!("No proxy servers configured.");
        return;
    }
    println!("Checking {} proxy server(s)...", config.servers.len());
    let results = checker::check_all(&config.servers).await;
    for r in &results {
        if r.reachable {
            println!(
                "  [OK]  {} – {}ms",
                r.server_id,
                r.latency_ms.unwrap_or(0)
            );
        } else {
            println!(
                "  [ERR] {} – {}",
                r.server_id,
                r.error.as_deref().unwrap_or("unknown error")
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy server
// ---------------------------------------------------------------------------

async fn run_proxy_server(config: ProxyConfig) -> Result<()> {
    let listen_addr = format!(
        "{}:{}",
        config.settings.listen_host, config.settings.listen_port
    );
    let listener = TcpListener::bind(&listen_addr).await?;
    info!("zProxy listening on {}", listen_addr);

    let config = Arc::new(config);
    let stats = GlobalStats::new();

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let cfg = Arc::clone(&config);
                let st = Arc::clone(&stats);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, peer, cfg, st).await {
                        error!("Connection error from {}: {}", peer, e);
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Arc<ProxyConfig>,
    stats: Arc<GlobalStats>,
) -> Result<()> {
    // Peek at the first byte to decide the protocol
    let mut peek = [0u8; 1];
    stream.peek(&mut peek).await?;

    let (target_host, target_port) = match peek[0] {
        // SOCKS5: version byte = 5
        5 => parse_socks5_request(&mut stream).await?,
        // SOCKS4: version byte = 4
        4 => parse_socks4_request(&mut stream).await?,
        // HTTP: 'C' = CONNECT, 'G' = GET, 'P' = POST/PUT, etc.
        b'C' | b'G' | b'P' | b'H' | b'D' | b'O' | b'T' => {
            parse_http_connect_request(&mut stream).await?
        }
        b => return Err(anyhow::anyhow!("Unknown proxy protocol byte: 0x{:02X}", b)),
    };

    info!("Connection from {} -> {}:{}", peer, target_host, target_port);

    // --- Rule matching ---
    let process_name = get_process_name_for_peer(&peer);
    let rule = find_matching_rule(
        &config.rules,
        &target_host,
        process_name.as_deref(),
        Some(target_port),
    );

    let action = rule
        .map(|r| r.action.clone())
        .unwrap_or_else(|| config.settings.default_action.clone());

    let conn_id = generate_connection_id();
    let conn_info = ConnectionInfo {
        id: conn_id.clone(),
        source: peer.to_string(),
        target: format!("{}:{}", target_host, target_port),
        proxy: "direct".into(),
        started_at: chrono::Utc::now(),
        bytes_in: 0,
        bytes_out: 0,
    };
    stats.add_connection(conn_info);

    let result = match &action {
        RuleAction::Block => {
            info!("Blocking {}:{}", target_host, target_port);
            Err(anyhow::anyhow!("Blocked by rule"))
        }
        RuleAction::Direct => {
            let addr = format!("{}:{}", target_host, target_port);
            match TcpStream::connect(&addr).await {
                Ok(upstream) => {
                    send_socks5_success(&mut stream).await?;
                    pipe_streams(stream, upstream, &stats, &conn_id).await
                }
                Err(e) => Err(anyhow::anyhow!("Direct connect failed: {}", e)),
            }
        }
        RuleAction::Proxy(chain_id) => {
            match resolve_and_connect(&config, chain_id, &target_host, target_port).await {
                Ok(upstream) => {
                    send_socks5_success(&mut stream).await?;
                    pipe_streams(stream, upstream, &stats, &conn_id).await
                }
                Err(e) => Err(e),
            }
        }
    };

    stats.remove_connection(&conn_id);

    result
}

/// Resolve a chain or single server ID and connect.
async fn resolve_and_connect(
    config: &ProxyConfig,
    chain_or_server_id: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    // Try chain first
    if let Some(chain) = config.find_chain(chain_or_server_id) {
        let servers: Vec<_> = chain
            .servers
            .iter()
            .filter_map(|id| config.find_server(id))
            .collect();
        if servers.is_empty() {
            return Err(anyhow::anyhow!("Chain '{}' has no valid servers", chain_or_server_id));
        }
        return chain::connect_chain(&servers, target_host, target_port).await;
    }

    // Try as a direct server ID
    if let Some(server) = config.find_server(chain_or_server_id) {
        return connect_through_proxy(server, target_host, target_port).await;
    }

    Err(anyhow::anyhow!("Unknown proxy/chain ID: '{}'", chain_or_server_id))
}

// ---------------------------------------------------------------------------
// SOCKS5 server-side protocol parsing
// ---------------------------------------------------------------------------

async fn parse_socks5_request(stream: &mut TcpStream) -> Result<(String, u16)> {
    // Greeting: VER NMETHODS METHODS...
    let mut ver_nmeth = [0u8; 2];
    stream.read_exact(&mut ver_nmeth).await?;
    if ver_nmeth[0] != 5 {
        return Err(anyhow::anyhow!("SOCKS5: bad version {}", ver_nmeth[0]));
    }
    let nmethods = ver_nmeth[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // We always respond with no-auth (0x00)
    stream.write_all(&[5u8, 0x00]).await?;

    // Request: VER CMD RSV ATYP ...
    let mut req_head = [0u8; 4];
    stream.read_exact(&mut req_head).await?;
    if req_head[0] != 5 {
        return Err(anyhow::anyhow!("SOCKS5 request: bad version {}", req_head[0]));
    }
    if req_head[1] != 0x01 {
        // We only support CONNECT
        send_socks5_error(stream, 0x07).await?;
        return Err(anyhow::anyhow!("SOCKS5: unsupported command 0x{:02X}", req_head[1]));
    }

    let (host, port) = parse_socks5_addr(stream, req_head[3]).await?;
    Ok((host, port))
}

async fn parse_socks5_addr(stream: &mut TcpStream, atyp: u8) -> Result<(String, u16)> {
    let host = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        t => return Err(anyhow::anyhow!("SOCKS5: unknown address type 0x{:02X}", t)),
    };

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);
    Ok((host, port))
}

async fn send_socks5_success(stream: &mut TcpStream) -> Result<()> {
    // VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn send_socks5_error(stream: &mut TcpStream, rep: u8) -> Result<()> {
    stream
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SOCKS4 server-side protocol parsing
// ---------------------------------------------------------------------------

async fn parse_socks4_request(stream: &mut TcpStream) -> Result<(String, u16)> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await?;

    if header[0] != 4 {
        return Err(anyhow::anyhow!("SOCKS4: bad version {}", header[0]));
    }
    if header[1] != 1 {
        // Only CONNECT supported
        return Err(anyhow::anyhow!("SOCKS4: unsupported command {}", header[1]));
    }

    let port = u16::from_be_bytes([header[2], header[3]]);
    let ip = [header[4], header[5], header[6], header[7]];

    // Read user ID (NUL-terminated)
    read_nul_string(stream).await?;

    // SOCKS4A: IP in form 0.0.0.x where x != 0
    let host = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        // SOCKS4A – read domain
        read_nul_string(stream).await?
    } else {
        std::net::Ipv4Addr::from(ip).to_string()
    };

    // Send granted response
    stream.write_all(&[0x00, 0x5A, 0, 0, 0, 0, 0, 0]).await?;
    Ok((host, port))
}

async fn read_nul_string(stream: &mut TcpStream) -> Result<String> {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).await?;
        if buf[0] == 0 {
            break;
        }
        bytes.push(buf[0]);
    }
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

// ---------------------------------------------------------------------------
// HTTP CONNECT server-side parsing
// ---------------------------------------------------------------------------

async fn parse_http_connect_request(stream: &mut TcpStream) -> Result<(String, u16)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(anyhow::anyhow!("HTTP CONNECT request too large"));
        }
    }

    let req = String::from_utf8_lossy(&buf);
    let first_line = req.lines().next().ok_or_else(|| anyhow::anyhow!("Empty HTTP request"))?;

    // Expect: CONNECT host:port HTTP/1.x
    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method != "CONNECT" {
        // For non-CONNECT methods return a 405
        stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await?;
        return Err(anyhow::anyhow!("HTTP: only CONNECT is supported (got {})", method));
    }

    let (host, port) = parse_host_port(target)?;

    // Send 200 Connection Established
    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    Ok((host, port))
}

fn parse_host_port(target: &str) -> Result<(String, u16)> {
    if let Some(pos) = target.rfind(':') {
        let host = target[..pos].to_string();
        let port: u16 = target[pos + 1..].parse()?;
        Ok((host, port))
    } else {
        Err(anyhow::anyhow!("No port in CONNECT target: {}", target))
    }
}

// ---------------------------------------------------------------------------
// Bidirectional pipe
// ---------------------------------------------------------------------------

async fn pipe_streams(
    client: TcpStream,
    upstream: TcpStream,
    stats: &Arc<GlobalStats>,
    conn_id: &str,
) -> Result<()> {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    let id1 = conn_id.to_string();
    let id2 = conn_id.to_string();
    let stats1 = Arc::clone(stats);
    let stats2 = Arc::clone(stats);

    let client_to_upstream = async move {
        let n = tokio::io::copy(&mut cr, &mut uw).await.unwrap_or(0);
        stats1.update_bytes(&id1, 0, n);
        let _ = uw.shutdown().await;
    };

    let upstream_to_client = async move {
        let n = tokio::io::copy(&mut ur, &mut cw).await.unwrap_or(0);
        stats2.update_bytes(&id2, n, 0);
        let _ = cw.shutdown().await;
    };

    tokio::join!(client_to_upstream, upstream_to_client);
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn get_process_name_for_peer(_peer: &SocketAddr) -> Option<String> {
    // Process lookup by TCP socket is platform-specific.
    // On Linux/Windows this would use /proc/net/tcp or sysinfo.
    // Return None for now; real implementation would use sysinfo crate.
    None
}

/// Generate a unique connection ID using timestamp and a hash.
fn generate_connection_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = ts.as_secs();
    let nanos = ts.subsec_nanos();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:08x}{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}", secs, nanos, seq & 0xFFFF, seq & 0xFFF, seq & 0xFFFF, seq * 1_000_003)
}

// ---------------------------------------------------------------------------
// Windows service (stub, real impl requires windows-service crate)
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn run_as_service(config: ProxyConfig) -> Result<()> {
    use std::sync::OnceLock;
    use windows_service::{
        define_windows_service,
        service_dispatcher,
        service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
        service_control_handler::{self, ServiceControlHandlerResult},
    };

    // Store config in a global so that service_main (fixed signature) can access it.
    static SERVICE_CONFIG: OnceLock<ProxyConfig> = OnceLock::new();
    let _ = SERVICE_CONFIG.set(config);

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<std::ffi::OsString>) {
        // status handler
        let status_handle = service_control_handler::register("zproxy", move |ctrl| {
            match ctrl {
                ServiceControl::Stop => ServiceControlHandlerResult::NoError,
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        }).expect("Failed to register service control handler");

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        }).expect("Failed to set service status");

        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let svc_config = SERVICE_CONFIG.get().cloned().unwrap_or_default();
        let _ = rt.block_on(run_proxy_server(svc_config));
    }

    service_dispatcher::start("zproxy", ffi_service_main)?;
    Ok(())
}
