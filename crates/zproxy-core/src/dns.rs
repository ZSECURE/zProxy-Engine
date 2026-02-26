/// DNS resolution via a SOCKS5 proxy.
///
/// SOCKS5 can perform remote hostname resolution: by sending a CONNECT request
/// with the domain address type the server resolves the name and the reply
/// contains the resolved IP address in BND.ADDR.

use crate::config::ProxyServer;
use anyhow::{anyhow, Result};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Resolve `hostname` using the SOCKS5 proxy's built-in DNS.
///
/// This works by sending a SOCKS5 CONNECT for port 0 (or 80); the proxy
/// resolves the hostname and returns the IP in the reply's BND.ADDR field.
pub async fn resolve_via_socks5(
    proxy: &ProxyServer,
    hostname: &str,
) -> Result<IpAddr> {
    let connect_timeout = Duration::from_secs(proxy.timeout_secs.min(15));
    let addr = format!("{}:{}", proxy.host, proxy.port);
    let mut stream = timeout(connect_timeout, TcpStream::connect(&addr)).await??;

    // Greeting – no-auth only for simplicity
    let greeting = [0x05u8, 0x01, 0x00];
    timeout(connect_timeout, stream.write_all(&greeting)).await??;

    let mut method = [0u8; 2];
    timeout(connect_timeout, stream.read_exact(&mut method)).await??;
    if method[0] != 5 || method[1] == 0xFF {
        return Err(anyhow!("SOCKS5 DNS: server rejected no-auth method"));
    }

    // CONNECT request with DOMAINNAME type, port 80
    let host_bytes = hostname.as_bytes();
    if host_bytes.len() > 255 {
        return Err(anyhow!("Hostname too long"));
    }
    let mut req = vec![0x05u8, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&80u16.to_be_bytes());
    timeout(connect_timeout, stream.write_all(&req)).await??;

    // Read reply header
    let mut rep_head = [0u8; 4];
    timeout(connect_timeout, stream.read_exact(&mut rep_head)).await??;

    if rep_head[0] != 5 {
        return Err(anyhow!("SOCKS5 DNS: unexpected version {}", rep_head[0]));
    }
    if rep_head[1] != 0x00 {
        return Err(anyhow!("SOCKS5 DNS: CONNECT failed with code 0x{:02X}", rep_head[1]));
    }

    // Parse BND.ADDR based on address type
    match rep_head[3] {
        0x01 => {
            // IPv4
            let mut ip = [0u8; 4];
            timeout(connect_timeout, stream.read_exact(&mut ip)).await??;
            let mut _port = [0u8; 2];
            timeout(connect_timeout, stream.read_exact(&mut _port)).await??;
            Ok(IpAddr::V4(std::net::Ipv4Addr::from(ip)))
        }
        0x04 => {
            // IPv6
            let mut ip = [0u8; 16];
            timeout(connect_timeout, stream.read_exact(&mut ip)).await??;
            let mut _port = [0u8; 2];
            timeout(connect_timeout, stream.read_exact(&mut _port)).await??;
            Ok(IpAddr::V6(std::net::Ipv6Addr::from(ip)))
        }
        0x03 => {
            // Domain name returned (uncommon)
            let mut len = [0u8; 1];
            timeout(connect_timeout, stream.read_exact(&mut len)).await??;
            let mut domain_buf = vec![0u8; len[0] as usize + 2];
            timeout(connect_timeout, stream.read_exact(&mut domain_buf)).await??;
            Err(anyhow!("SOCKS5 DNS: server returned domain instead of IP"))
        }
        t => Err(anyhow!("SOCKS5 DNS: unknown address type 0x{:02X}", t)),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_dns_module_compiles() {
        // Network tests require a live SOCKS5 proxy; this just verifies compilation.
    }
}
