/// Connection statistics tracker.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: String,
    pub source: String,
    pub target: String,
    pub proxy: String,
    pub started_at: DateTime<Utc>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

// ---------------------------------------------------------------------------
// GlobalStats
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct GlobalStats {
    active: Mutex<HashMap<String, ConnectionInfo>>,
    total_connections: Mutex<u64>,
    total_bytes_in: Mutex<u64>,
    total_bytes_out: Mutex<u64>,
}

impl GlobalStats {
    pub fn new() -> Arc<Self> {
        Arc::new(GlobalStats {
            active: Mutex::new(HashMap::new()),
            total_connections: Mutex::new(0),
            total_bytes_in: Mutex::new(0),
            total_bytes_out: Mutex::new(0),
        })
    }

    /// Register a new active connection.
    pub fn add_connection(&self, info: ConnectionInfo) {
        if let Ok(mut map) = self.active.lock() {
            map.insert(info.id.clone(), info);
        }
        if let Ok(mut n) = self.total_connections.lock() {
            *n += 1;
        }
    }

    /// Remove a connection when it closes; returns the final [`ConnectionInfo`].
    pub fn remove_connection(&self, id: &str) -> Option<ConnectionInfo> {
        self.active.lock().ok()?.remove(id)
    }

    /// Update byte counters for an active connection.
    pub fn update_bytes(&self, id: &str, bytes_in: u64, bytes_out: u64) {
        if let Ok(mut map) = self.active.lock() {
            if let Some(info) = map.get_mut(id) {
                info.bytes_in += bytes_in;
                info.bytes_out += bytes_out;
            }
        }
        if let Ok(mut n) = self.total_bytes_in.lock() {
            *n += bytes_in;
        }
        if let Ok(mut n) = self.total_bytes_out.lock() {
            *n += bytes_out;
        }
    }

    /// Number of currently active connections.
    pub fn active_count(&self) -> usize {
        self.active.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Snapshot of all currently active connections.
    pub fn snapshot(&self) -> Vec<ConnectionInfo> {
        self.active
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn total_connections(&self) -> u64 {
        *self.total_connections.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn total_bytes_in(&self) -> u64 {
        *self.total_bytes_in.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn total_bytes_out(&self) -> u64 {
        *self.total_bytes_out.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(id: &str) -> ConnectionInfo {
        ConnectionInfo {
            id: id.into(),
            source: "127.0.0.1:12345".into(),
            target: "example.com:80".into(),
            proxy: "proxy1".into(),
            started_at: Utc::now(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    #[test]
    fn test_add_remove() {
        let stats = GlobalStats::new();
        stats.add_connection(make_info("c1"));
        assert_eq!(stats.active_count(), 1);
        let removed = stats.remove_connection("c1");
        assert!(removed.is_some());
        assert_eq!(stats.active_count(), 0);
    }

    #[test]
    fn test_update_bytes() {
        let stats = GlobalStats::new();
        stats.add_connection(make_info("c2"));
        stats.update_bytes("c2", 100, 200);
        let snap = stats.snapshot();
        assert_eq!(snap[0].bytes_in, 100);
        assert_eq!(snap[0].bytes_out, 200);
        assert_eq!(stats.total_bytes_in(), 100);
        assert_eq!(stats.total_bytes_out(), 200);
    }

    #[test]
    fn test_total_connections() {
        let stats = GlobalStats::new();
        stats.add_connection(make_info("c3"));
        stats.add_connection(make_info("c4"));
        assert_eq!(stats.total_connections(), 2);
        stats.remove_connection("c3");
        assert_eq!(stats.active_count(), 1);
        assert_eq!(stats.total_connections(), 2); // total never decreases
    }
}
