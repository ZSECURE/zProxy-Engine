/// HTTP CONNECT proxy implementation.
///
/// Supports:
///   - Plain CONNECT (no auth)
///   - Proxy-Authorization: Basic
///   - Proxy-Authorization: NTLM (3-way handshake via 407 challenge)

use crate::auth::{ntlm, ProxyAuth};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Send an HTTP CONNECT request and negotiate authentication if required.
pub async fn connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    auth: Option<ProxyAuth>,
) -> Result<()> {
    let target = format!("{}:{}", host, port);
    let auth_header = auth.as_ref().map(|a| a.to_header_value());

    let (status, headers, _body) = send_connect(stream, &target, auth_header.as_deref()).await?;

    match status {
        200 => return Ok(()),
        407 => {
            // Proxy authentication required
            let proxy_auth = auth.ok_or_else(|| anyhow!("HTTP proxy requires authentication but none supplied"))?;
            match proxy_auth {
                ProxyAuth::Basic { .. } => {
                    return Err(anyhow!("HTTP proxy rejected Basic credentials (407)"));
                }
                ProxyAuth::Ntlm { username, password, domain } => {
                    handle_ntlm_auth(stream, &target, &username, &password, &domain, &headers).await?;
                    return Ok(());
                }
            }
        }
        code => {
            return Err(anyhow!("HTTP CONNECT failed with status {}", code));
        }
    }
}

/// Send one CONNECT request; return (status_code, raw_header_lines, body_bytes).
async fn send_connect(
    stream: &mut TcpStream,
    target: &str,
    auth_header: Option<&str>,
) -> Result<(u16, Vec<String>, Vec<u8>)> {
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(hdr) = auth_header {
        req.push_str(&format!("Proxy-Authorization: {}\r\n", hdr));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    read_http_response(stream).await
}

/// Read HTTP response headers up to `\r\n\r\n`.
async fn read_http_response(stream: &mut TcpStream) -> Result<(u16, Vec<String>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1];
    loop {
        stream.read_exact(&mut tmp).await?;
        buf.push(tmp[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(anyhow!("HTTP response header too large"));
        }
    }

    let header_str = String::from_utf8_lossy(&buf).to_string();
    let mut lines: Vec<String> = header_str
        .split("\r\n")
        .map(|s| s.to_string())
        .collect();

    let status_line = lines.first().ok_or_else(|| anyhow!("Empty HTTP response"))?.clone();
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Malformed HTTP status line: {}", status_line));
    }
    let status: u16 = parts[1].parse().map_err(|_| anyhow!("Non-numeric status code: {}", parts[1]))?;

    lines.remove(0);
    Ok((status, lines, Vec::new()))
}

/// Perform the NTLM 3-step exchange on an already-connected stream.
async fn handle_ntlm_auth(
    stream: &mut TcpStream,
    target: &str,
    username: &str,
    password: &str,
    domain: &str,
    challenge_headers: &[String],
) -> Result<()> {
    // Find the NTLM challenge in `Proxy-Authenticate: NTLM <b64>` header
    let challenge_b64 = challenge_headers
        .iter()
        .find_map(|h| {
            let lower = h.to_lowercase();
            if lower.starts_with("proxy-authenticate: ntlm ") {
                Some(h["Proxy-Authenticate: NTLM ".len()..].trim().to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("No NTLM challenge found in 407 headers"))?;

    let challenge_data = STANDARD
        .decode(challenge_b64.as_bytes())
        .map_err(|e| anyhow!("Failed to decode NTLM challenge: {}", e))?;

    let auth_hdr = ntlm::create_authenticate_header(&challenge_data, username, password, domain)?;

    let (status, _, _) = send_connect(stream, target, Some(&auth_hdr)).await?;
    if status != 200 {
        return Err(anyhow!("HTTP CONNECT with NTLM auth failed with status {}", status));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_http_module_compiles() {
        // Compilation test only; network tests require a live proxy.
    }
}
