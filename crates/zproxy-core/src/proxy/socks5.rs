/// SOCKS5 protocol implementation (RFC 1928 + RFC 1929).

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Version
pub const VERSION: u8 = 5;

// Auth methods
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_USER_PASS: u8 = 0x02;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

// Address types
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

// Commands
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP: u8 = 0x03;

// Reply codes
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NET_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Establish a SOCKS5 CONNECT through `stream`.
///
/// `auth` is an optional `(username, password)` pair for sub-negotiation.
pub async fn connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
) -> Result<()> {
    // ---- Greeting ----
    let methods: Vec<u8> = if auth.is_some() {
        vec![METHOD_NO_AUTH, METHOD_USER_PASS]
    } else {
        vec![METHOD_NO_AUTH]
    };

    let mut greeting = vec![VERSION, methods.len() as u8];
    greeting.extend_from_slice(&methods);
    stream.write_all(&greeting).await?;

    let mut server_choice = [0u8; 2];
    stream.read_exact(&mut server_choice).await?;

    if server_choice[0] != VERSION {
        return Err(anyhow!("SOCKS5: unexpected version byte {}", server_choice[0]));
    }

    match server_choice[1] {
        METHOD_NO_AUTH => {} // nothing to do
        METHOD_USER_PASS => {
            let (username, password) = auth
                .ok_or_else(|| anyhow!("SOCKS5: server requires authentication but none provided"))?;
            // RFC 1929 sub-negotiation
            let ulen = username.len() as u8;
            let plen = password.len() as u8;
            let mut auth_req = vec![0x01u8, ulen];
            auth_req.extend_from_slice(username.as_bytes());
            auth_req.push(plen);
            auth_req.extend_from_slice(password.as_bytes());
            stream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                return Err(anyhow!("SOCKS5: authentication failed (status {})", auth_resp[1]));
            }
        }
        METHOD_NO_ACCEPTABLE => {
            return Err(anyhow!("SOCKS5: no acceptable authentication methods"));
        }
        m => {
            return Err(anyhow!("SOCKS5: unknown auth method 0x{:02X}", m));
        }
    }

    // ---- CONNECT request ----
    // Always use DOMAIN address type (avoids client-side DNS resolution)
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(anyhow!("SOCKS5: hostname too long ({} bytes)", host_bytes.len()));
    }

    let mut request = vec![
        VERSION,
        CMD_CONNECT,
        0x00, // RSV
        ATYP_DOMAIN,
        host_bytes.len() as u8,
    ];
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    // ---- Read reply ----
    // VER + REP + RSV + ATYP = 4 bytes
    let mut reply_head = [0u8; 4];
    stream.read_exact(&mut reply_head).await?;

    if reply_head[0] != VERSION {
        return Err(anyhow!("SOCKS5: unexpected version in reply {}", reply_head[0]));
    }
    if reply_head[1] != REP_SUCCESS {
        return Err(anyhow!("SOCKS5: connect failed with code 0x{:02X} ({})", reply_head[1], rep_description(reply_head[1])));
    }

    // Consume the BND address/port
    match reply_head[3] {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6]; // 4 ip + 2 port
            stream.read_exact(&mut buf).await?;
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18]; // 16 ip + 2 port
            stream.read_exact(&mut buf).await?;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        t => {
            return Err(anyhow!("SOCKS5: unknown address type in reply 0x{:02X}", t));
        }
    }

    Ok(())
}

fn rep_description(code: u8) -> &'static str {
    match code {
        REP_SUCCESS => "success",
        REP_GENERAL_FAILURE => "general failure",
        REP_NOT_ALLOWED => "connection not allowed",
        REP_NET_UNREACHABLE => "network unreachable",
        REP_HOST_UNREACHABLE => "host unreachable",
        REP_CONN_REFUSED => "connection refused",
        REP_TTL_EXPIRED => "TTL expired",
        REP_CMD_NOT_SUPPORTED => "command not supported",
        REP_ATYP_NOT_SUPPORTED => "address type not supported",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(VERSION, 5);
        assert_eq!(METHOD_NO_AUTH, 0x00);
        assert_eq!(METHOD_USER_PASS, 0x02);
        assert_eq!(ATYP_DOMAIN, 0x03);
        assert_eq!(REP_SUCCESS, 0x00);
    }
}
