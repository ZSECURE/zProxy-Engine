pub mod chain;
pub mod http;
pub mod socks4;
pub mod socks5;

use crate::config::{AuthMethod, ProxyProtocol, ProxyServer};
use anyhow::Result;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Connect to `target_host:target_port` through the given proxy server.
pub async fn connect_through_proxy(
    proxy: &ProxyServer,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let connect_timeout = Duration::from_secs(proxy.timeout_secs);
    let addr = format!("{}:{}", proxy.host, proxy.port);

    let mut stream = timeout(connect_timeout, TcpStream::connect(&addr)).await??;

    match proxy.protocol {
        ProxyProtocol::Socks4 => {
            let user = match &proxy.auth {
                AuthMethod::UserPass { username, .. } => Some(username.as_str()),
                _ => None,
            };
            socks4::connect(&mut stream, target_host, target_port, user).await?;
        }
        ProxyProtocol::Socks4a => {
            let user = match &proxy.auth {
                AuthMethod::UserPass { username, .. } => Some(username.as_str()),
                _ => None,
            };
            socks4::connect(&mut stream, target_host, target_port, user).await?;
        }
        ProxyProtocol::Socks5 => {
            let auth_pair = match &proxy.auth {
                AuthMethod::UserPass { username, password }
                | AuthMethod::Basic { username, password } => {
                    Some((username.as_str(), password.as_str()))
                }
                _ => None,
            };
            socks5::connect(&mut stream, target_host, target_port, auth_pair).await?;
        }
        ProxyProtocol::Http | ProxyProtocol::Https => {
            let auth = match &proxy.auth {
                AuthMethod::Basic { username, password } => {
                    Some(crate::auth::ProxyAuth::Basic {
                        username: username.clone(),
                        password: password.clone(),
                    })
                }
                AuthMethod::Ntlm { username, password, domain } => {
                    Some(crate::auth::ProxyAuth::Ntlm {
                        username: username.clone(),
                        password: password.clone(),
                        domain: domain.clone(),
                    })
                }
                _ => None,
            };
            http::connect(&mut stream, target_host, target_port, auth).await?;
        }
    }

    Ok(stream)
}
