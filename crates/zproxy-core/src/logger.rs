/// Structured logging for connection events.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::Mutex;
use tracing::{error, info};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ConnectionLog {
    pub timestamp: DateTime<Utc>,
    pub connection_id: String,
    pub source_addr: String,
    pub target_host: String,
    pub target_port: u16,
    pub proxy_id: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ms: u64,
    pub status: String,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

pub struct Logger {
    log_path: String,
    writer: Mutex<Option<BufWriter<File>>>,
    level: tracing::Level,
}

impl Logger {
    pub fn new(log_path: &str, level: &str) -> Result<Self> {
        let tracing_level = match level.to_lowercase().as_str() {
            "error" => tracing::Level::ERROR,
            "warn" => tracing::Level::WARN,
            "debug" => tracing::Level::DEBUG,
            "trace" => tracing::Level::TRACE,
            _ => tracing::Level::INFO,
        };

        let writer = if !log_path.is_empty() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)?;
            Some(BufWriter::new(file))
        } else {
            None
        };

        Ok(Logger {
            log_path: log_path.to_string(),
            writer: Mutex::new(writer),
            level: tracing_level,
        })
    }

    /// Write a connection event as a JSON line to the log file.
    pub fn log_connection(&self, log: &ConnectionLog) {
        let line = match serde_json::to_string(log) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to serialize ConnectionLog: {}", e);
                return;
            }
        };
        self.write_line(&line);
        info!(
            connection_id = %log.connection_id,
            target = format!("{}:{}", log.target_host, log.target_port),
            status = %log.status,
            bytes_sent = log.bytes_sent,
            bytes_received = log.bytes_received,
            duration_ms = log.duration_ms,
            "connection closed"
        );
    }

    /// Log a hex dump of traffic data.
    pub fn log_traffic_dump(&self, connection_id: &str, direction: &str, data: &[u8]) {
        if self.level < tracing::Level::TRACE {
            return;
        }
        let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        let entry = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "TRACE",
            "type": "traffic_dump",
            "connection_id": connection_id,
            "direction": direction,
            "hex": hex,
            "len": data.len(),
        });
        self.write_line(&entry.to_string());
    }

    pub fn log_error(&self, msg: &str) {
        let entry = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "ERROR",
            "message": msg,
        });
        self.write_line(&entry.to_string());
        error!("{}", msg);
    }

    pub fn log_info(&self, msg: &str) {
        let entry = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "INFO",
            "message": msg,
        });
        self.write_line(&entry.to_string());
        info!("{}", msg);
    }

    fn write_line(&self, line: &str) {
        if let Ok(mut guard) = self.writer.lock() {
            if let Some(ref mut w) = *guard {
                let _ = writeln!(w, "{}", line);
                let _ = w.flush();
            }
        }
    }

    pub fn log_path(&self) -> &str {
        &self.log_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_logger_no_file() {
        let logger = Logger::new("", "info").unwrap();
        // Should not panic
        logger.log_info("test message");
        logger.log_error("test error");
    }

    #[test]
    fn test_logger_to_file() {
        let path = "/tmp/zproxy_test_logger.log";
        let _ = std::fs::remove_file(path);

        let logger = Logger::new(path, "info").unwrap();
        logger.log_info("hello from test");
        logger.log_connection(&ConnectionLog {
            timestamp: Utc::now(),
            connection_id: "test-conn".into(),
            source_addr: "127.0.0.1:12345".into(),
            target_host: "example.com".into(),
            target_port: 80,
            proxy_id: None,
            bytes_sent: 100,
            bytes_received: 200,
            duration_ms: 50,
            status: "success".into(),
            error: None,
        });
        drop(logger);

        let mut content = String::new();
        std::fs::File::open(path).unwrap().read_to_string(&mut content).unwrap();
        assert!(content.contains("hello from test"));
        assert!(content.contains("example.com"));

        let _ = std::fs::remove_file(path);
    }
}
