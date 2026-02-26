/// Proxy reachability checker.

use crate::config::{ProxyProtocol, ProxyServer};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ProxyCheckResult {
    pub server_id: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Single proxy check
// ---------------------------------------------------------------------------

/// Check a single proxy server and measure latency.
pub async fn check_proxy(server: ProxyServer) -> ProxyCheckResult {
    let connect_timeout = Duration::from_secs(server.timeout_secs.min(10));
    let start = Instant::now();

    let addr = format!("{}:{}", server.host, server.port);
    let stream_result = timeout(connect_timeout, TcpStream::connect(&addr)).await;

    match stream_result {
        Err(_) => ProxyCheckResult {
            server_id: server.id.clone(),
            reachable: false,
            latency_ms: None,
            error: Some("Connection timed out".into()),
        },
        Ok(Err(e)) => ProxyCheckResult {
            server_id: server.id.clone(),
            reachable: false,
            latency_ms: None,
            error: Some(e.to_string()),
        },
        Ok(Ok(mut stream)) => {
            // For SOCKS5 do a protocol-level greeting to verify the proxy
            // is actually responsive.
            let probe_result = match server.protocol {
                ProxyProtocol::Socks5 => {
                    probe_socks5(&mut stream, connect_timeout).await
                }
                ProxyProtocol::Socks4 | ProxyProtocol::Socks4a => {
                    // TCP connectivity is sufficient for SOCKS4
                    Ok(())
                }
                ProxyProtocol::Http | ProxyProtocol::Https => {
                    probe_http(&mut stream, &server.host, server.port, connect_timeout).await
                }
            };

            let latency_ms = start.elapsed().as_millis() as u64;

            match probe_result {
                Ok(_) => ProxyCheckResult {
                    server_id: server.id.clone(),
                    reachable: true,
                    latency_ms: Some(latency_ms),
                    error: None,
                },
                Err(e) => ProxyCheckResult {
                    server_id: server.id.clone(),
                    reachable: false,
                    latency_ms: Some(latency_ms),
                    error: Some(e.to_string()),
                },
            }
        }
    }
}

/// Send a SOCKS5 greeting and verify the response format.
async fn probe_socks5(stream: &mut TcpStream, dur: Duration) -> anyhow::Result<()> {
    let greeting = [0x05u8, 0x01, 0x00]; // VER=5, NMETHODS=1, METHOD=no-auth
    timeout(dur, stream.write_all(&greeting)).await??;

    let mut resp = [0u8; 2];
    timeout(dur, stream.read_exact(&mut resp)).await??;

    if resp[0] != 5 {
        return Err(anyhow::anyhow!("SOCKS5 probe: unexpected version {}", resp[0]));
    }
    Ok(())
}

/// Send a minimal HTTP OPTIONS request and verify an HTTP response starts.
async fn probe_http(stream: &mut TcpStream, host: &str, port: u16, dur: Duration) -> anyhow::Result<()> {
    let req = format!("OPTIONS / HTTP/1.0\r\nHost: {}:{}\r\n\r\n", host, port);
    timeout(dur, stream.write_all(req.as_bytes())).await??;

    let mut buf = [0u8; 8];
    timeout(dur, stream.read_exact(&mut buf)).await??;

    if &buf[0..5] == b"HTTP/" {
        Ok(())
    } else {
        Err(anyhow::anyhow!("HTTP probe: unexpected response {:?}", &buf[..]))
    }
}

// ---------------------------------------------------------------------------
// Bulk checker
// ---------------------------------------------------------------------------

/// Check all proxy servers concurrently.
pub async fn check_all(servers: &[ProxyServer]) -> Vec<ProxyCheckResult> {
    let handles: Vec<_> = servers
        .iter()
        .map(|s| tokio::spawn(check_proxy(s.clone())))
        .collect();
    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        results.push(h.await.unwrap_or_else(|e| ProxyCheckResult {
            server_id: "unknown".into(),
            reachable: false,
            latency_ms: None,
            error: Some(e.to_string()),
        }));
    }
    results
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMethod, ProxyProtocol, ProxyServer};

    #[tokio::test]
    async fn test_check_unreachable_proxy() {
        let server = ProxyServer {
            id: "test".into(),
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".into(),
            port: 19999, // nothing listening here
            auth: AuthMethod::None,
            enabled: true,
            timeout_secs: 2,
        };
        let result = check_proxy(server).await;
        assert!(!result.reachable);
        assert!(result.error.is_some());
    }
}
