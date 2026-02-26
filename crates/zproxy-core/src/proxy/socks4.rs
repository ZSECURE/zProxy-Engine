/// SOCKS4 / SOCKS4A protocol implementation.
///
/// SOCKS4:  Works with IPv4 addresses only.
/// SOCKS4A: Passes hostnames to the proxy server (IP set to 0.0.0.x ≠ 0).

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Protocol constants
pub const VERSION: u8 = 4;
pub const CMD_CONNECT: u8 = 1;
pub const CMD_BIND: u8 = 2;

// Reply codes
pub const REPLY_GRANTED: u8 = 0x5A;
pub const REPLY_REJECTED: u8 = 0x5B;
pub const REPLY_NO_IDENTD: u8 = 0x5C;
pub const REPLY_IDENTD_MISMATCH: u8 = 0x5D;

/// Establish a SOCKS4/SOCKS4A CONNECT through `stream`.
///
/// - IPv4 addresses  → SOCKS4 (standard)
/// - Hostnames       → SOCKS4A (IP = 0.0.0.1, hostname appended after userid)
pub async fn connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    user: Option<&str>,
) -> Result<()> {
    let user_bytes = user.unwrap_or("").as_bytes();

    // Determine whether the host is a dotted IPv4 address.
    let ipv4: Option<[u8; 4]> = host.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets());

    let mut request: Vec<u8> = Vec::new();
    request.push(VERSION);
    request.push(CMD_CONNECT);
    request.extend_from_slice(&port.to_be_bytes());

    if let Some(ip) = ipv4 {
        // SOCKS4: real IPv4
        request.extend_from_slice(&ip);
        request.extend_from_slice(user_bytes);
        request.push(0x00); // NUL-terminate userid
    } else {
        // SOCKS4A: dummy IP 0.0.0.1, append host after userid
        request.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        request.extend_from_slice(user_bytes);
        request.push(0x00); // NUL-terminate userid
        request.extend_from_slice(host.as_bytes());
        request.push(0x00); // NUL-terminate hostname
    }

    stream.write_all(&request).await?;

    // Read 8-byte response: [VN, CD, DSTPORT(2), DSTIP(4)]
    let mut response = [0u8; 8];
    stream.read_exact(&mut response).await?;

    match response[1] {
        REPLY_GRANTED => Ok(()),
        REPLY_REJECTED => Err(anyhow!("SOCKS4: request rejected or failed")),
        REPLY_NO_IDENTD => Err(anyhow!("SOCKS4: connection refused (no identd)")),
        REPLY_IDENTD_MISMATCH => Err(anyhow!("SOCKS4: identd mismatch")),
        code => Err(anyhow!("SOCKS4: unknown reply code 0x{:02X}", code)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(VERSION, 4);
        assert_eq!(CMD_CONNECT, 1);
        assert_eq!(REPLY_GRANTED, 0x5A);
    }
}
