# zProxy-Engine

A lightweight, feature-rich proxy client written in Rust for Windows (and cross-platform compilation). Tunnels TCP connections through SOCKS4, SOCKS4A, SOCKS5, HTTP, and HTTPS proxies with flexible rule-based routing, proxy chaining, NTLM authentication, and a GUI.

## Features

- **Proxy Protocols**: SOCKS4, SOCKS4A, SOCKS5, HTTP CONNECT, HTTPS CONNECT
- **Authentication**: SOCKS5 username/password (RFC 1929), HTTP Basic, NTLM (Type 1/2/3 handshake)
- **Proxy Chaining**: Route traffic through a sequence of proxy servers using diverse protocols
- **Proxy Redundancy**: Multiple chains and fallback proxies configurable via XML
- **Proxification Rules**: Wildcard (`*`, `?`) matching on hostname and process name, priority-ordered
- **DNS via Proxy**: Resolve DNS names through a SOCKS5 proxy server
- **Proxy Checker**: Concurrent reachability and latency checks for all configured proxies
- **Connection Statistics**: Real-time bandwidth usage, active connections, per-host stats
- **Structured Logging**: JSON-lines log files with traffic dump support (TRACE level)
- **IPv6 Support**: SOCKS5 address type 0x04 (IPv6), bracketed `[::1]:port` HTTP CONNECT targets, IPv6 listener binding
- **GUI**: egui/eframe tabbed interface — Dashboard, Proxies, Rules, Logs, Stats, Checker
- **Windows Service**: Run as a Windows background service (Windows only, via `windows-service`)
- **XML Configuration**: Human-readable `zproxy.xml` with proxy servers, chains, rules, and settings
- **Build Tool**: Helper binary (`zproxy-build`) for easy cross-compilation targeting Windows

> **Note**: The current implementation tunnels TCP connections. UDP proxying is not yet implemented.

## Workspace Structure

```
zProxy-Engine/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── zproxy-core/              # Core library
│   │   └── src/
│   │       ├── config.rs         # XML configuration (ProxyServer, Chain, Rule, Settings)
│   │       ├── proxy/
│   │       │   ├── socks4.rs     # SOCKS4 / SOCKS4A protocol
│   │       │   ├── socks5.rs     # SOCKS5 protocol (user/pass auth)
│   │       │   ├── http.rs       # HTTP/HTTPS CONNECT (Basic + NTLM auth)
│   │       │   └── chain.rs      # Proxy chain traversal
│   │       ├── auth/
│   │       │   ├── basic.rs      # HTTP Basic encode/decode
│   │       │   └── ntlm.rs       # NTLM Type 1/2/3 message builder (NTLMv1)
│   │       ├── rules.rs          # Wildcard rule matching, priority lookup
│   │       ├── logger.rs         # JSON-lines structured logging + traffic dump
│   │       ├── checker.rs        # Concurrent proxy connectivity checker
│   │       ├── stats.rs          # Connection stats (Arc<Mutex<…>>)
│   │       └── dns.rs            # DNS resolution via SOCKS5
│   ├── zproxy-engine/            # CLI proxy daemon (zproxy binary)
│   │   └── src/main.rs
│   ├── zproxy-gui/               # GUI application (zproxy-gui binary)
│   │   └── src/main.rs
│   └── zproxy-build/             # Cross-compilation helper (zproxy-build binary)
│       └── src/main.rs
└── .github/workflows/ci.yml      # CI: Linux build+test + Windows cross-compile
```

## Quick Start

### Build (Linux / macOS)

```bash
# Build everything except GUI
cargo build --workspace --exclude zproxy-gui --release

# Build GUI (requires display libs on Linux: libxkbcommon-dev libwayland-dev)
cargo build -p zproxy-gui --release
```

### Build for Windows (cross-compilation)

```bash
# Install Windows target and MinGW toolchain
rustup target add x86_64-pc-windows-gnu
sudo apt-get install gcc-mingw-w64-x86-64   # Debian/Ubuntu

# Build engine for Windows
cargo build -p zproxy-engine --target x86_64-pc-windows-gnu --release

# Or use the build helper
cargo run -p zproxy-build -- --target x86_64-pc-windows-gnu --release
```

### Run the proxy engine

```bash
# Start with default config (listens on 127.0.0.1:1080)
./target/release/zproxy

# Use a custom config file
./target/release/zproxy --config /path/to/zproxy.xml

# Check all configured proxies
./target/release/zproxy --check --config zproxy.xml

# Override listen port
./target/release/zproxy --port 1081

# Run as Windows service
zproxy.exe --service
```

### Sample XML Configuration

```xml
<?xml version="1.0" encoding="UTF-8"?>
<zproxy>
  <settings>
    <listen_host>127.0.0.1</listen_host>
    <listen_port>1080</listen_port>
    <log_path>zproxy.log</log_path>
    <log_level>info</log_level>
    <dns_via_proxy>true</dns_via_proxy>
    <handle_all_traffic>false</handle_all_traffic>
    <default_action>direct</default_action>
  </settings>

  <servers>
    <server id="proxy1" protocol="socks5" host="192.168.1.100" port="1080"
            enabled="true" timeout_secs="30">
      <auth type="userpass" username="user" password="pass"/>
    </server>
    <server id="http1" protocol="http" host="10.0.0.1" port="8080"
            enabled="true" timeout_secs="30">
      <auth type="ntlm" username="DOMAIN\user" password="pass" domain="CORP"/>
    </server>
  </servers>

  <chains>
    <chain id="chain1" name="Main Chain">
      <server_ref id="proxy1"/>
    </chain>
  </chains>

  <rules>
    <rule id="rule1" name="All *.example.com via proxy"
          host_pattern="*.example.com" action="proxy:chain1" priority="10"/>
    <rule id="rule2" name="Block ads"
          host_pattern="*ads*.doubleclick.net" action="block" priority="5"/>
  </rules>
</zproxy>
```

## Security Notes

- NTLM authentication uses NTLMv1 for broad compatibility with legacy HTTP proxies. NTLMv1 is cryptographically weak; use it only when required by the target proxy.
- Credentials are stored in plaintext in `zproxy.xml`. Protect the config file with appropriate filesystem permissions.
- The local proxy listener binds to `127.0.0.1` by default; do not expose it to untrusted networks.

## License

MIT
