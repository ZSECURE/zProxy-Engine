/// Proxy chaining: tunnel through an ordered list of proxy servers.

use crate::config::ProxyServer;
use crate::proxy::{connect_through_proxy, http, socks4, socks5};
use anyhow::{anyhow, Result};
use tokio::net::TcpStream;

/// Connect to `target_host:target_port` through an ordered chain of proxies.
///
/// The first proxy is connected to directly; each subsequent proxy is reached
/// by tunnelling through the previous one.
pub async fn connect_chain(
    proxies: &[&ProxyServer],
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    if proxies.is_empty() {
        return Err(anyhow!("Proxy chain is empty"));
    }

    // Connect through the first proxy toward the second (or the target if
    // there is only one proxy in the chain).
    let (first_proxy, rest) = proxies.split_first().unwrap();

    if rest.is_empty() {
        // Single proxy – straightforward
        return connect_through_proxy(first_proxy, target_host, target_port).await;
    }

    // We need to reach the second proxy through the first, then the third
    // through the tunnel to the second, and so on.  Build the tunnel
    // incrementally.
    let second_proxy = rest[0];
    let mut stream = connect_through_proxy(first_proxy, &second_proxy.host, second_proxy.port).await?;

    // Now chain through the remaining proxies
    for (i, proxy) in rest.iter().enumerate() {
        let (next_host, next_port) = if i + 1 < rest.len() {
            (rest[i + 1].host.as_str(), rest[i + 1].port)
        } else {
            (target_host, target_port)
        };

        tunnel_through(&mut stream, proxy, next_host, next_port).await?;
    }

    Ok(stream)
}

/// Tunnel a connection from an existing `stream` (already authenticated at the
/// previous proxy) through `proxy` to reach `next_host:next_port`.
async fn tunnel_through(
    stream: &mut TcpStream,
    proxy: &ProxyServer,
    next_host: &str,
    next_port: u16,
) -> Result<()> {
    use crate::config::{AuthMethod, ProxyProtocol};

    match proxy.protocol {
        ProxyProtocol::Socks4 | ProxyProtocol::Socks4a => {
            let user = match &proxy.auth {
                AuthMethod::UserPass { username, .. } => Some(username.as_str()),
                _ => None,
            };
            socks4::connect(stream, next_host, next_port, user).await
        }
        ProxyProtocol::Socks5 => {
            let auth_pair = match &proxy.auth {
                AuthMethod::UserPass { username, password }
                | AuthMethod::Basic { username, password } => {
                    Some((username.as_str(), password.as_str()))
                }
                _ => None,
            };
            socks5::connect(stream, next_host, next_port, auth_pair).await
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
            http::connect(stream, next_host, next_port, auth).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_chain() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async { connect_chain(&[], "example.com", 80).await });
        assert!(result.is_err());
    }
}
