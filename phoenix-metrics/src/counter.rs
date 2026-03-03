//! Atomic counters for tracking HTTP/2 stress test metrics

use std::sync::atomic::{AtomicU64, Ordering};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Atomic counters for tracking various metrics during stress testing
#[derive(Debug)]
pub struct AtomicCounters {
    requests_sent: AtomicU64,
    requests_success: AtomicU64,
    requests_error: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    connections_active: AtomicU64,
}

/// Snapshot of counter values at a specific point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterSnapshot {
    pub timestamp: DateTime<Utc>,
    pub requests_sent: u64,
    pub requests_success: u64,
    pub requests_error: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connections_active: u64,
}

impl AtomicCounters {
    /// Create a new set of atomic counters, all initialized to zero
    pub fn new() -> Self {
        Self {
            requests_sent: AtomicU64::new(0),
            requests_success: AtomicU64::new(0),
            requests_error: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            connections_active: AtomicU64::new(0),
        }
    }

    /// Increment the number of requests sent
    pub fn increment_requests_sent(&self) {
        self.requests_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the number of successful requests
    pub fn increment_requests_success(&self) {
        self.requests_success.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the number of failed requests
    pub fn increment_requests_error(&self) {
        self.requests_error.fetch_add(1, Ordering::Relaxed);
    }

    /// Add bytes to the total bytes sent
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add bytes to the total bytes received
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment the number of active connections
    pub fn increment_connections_active(&self) {
        self.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the number of active connections
    pub fn decrement_connections_active(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get the current number of requests sent
    pub fn get_requests_sent(&self) -> u64 {
        self.requests_sent.load(Ordering::Relaxed)
    }

    /// Get the current number of successful requests
    pub fn get_requests_success(&self) -> u64 {
        self.requests_success.load(Ordering::Relaxed)
    }

    /// Get the current number of failed requests
    pub fn get_requests_error(&self) -> u64 {
        self.requests_error.load(Ordering::Relaxed)
    }

    /// Get the total bytes sent
    pub fn get_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get the total bytes received
    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get the current number of active connections
    pub fn get_connections_active(&self) -> u64 {
        self.connections_active.load(Ordering::Relaxed)
    }

    /// Reset all counters to zero
    pub fn reset(&self) {
        self.requests_sent.store(0, Ordering::Relaxed);
        self.requests_success.store(0, Ordering::Relaxed);
        self.requests_error.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.connections_active.store(0, Ordering::Relaxed);
    }

    /// Create a snapshot of the current counter values
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            timestamp: Utc::now(),
            requests_sent: self.get_requests_sent(),
            requests_success: self.get_requests_success(),
            requests_error: self.get_requests_error(),
            bytes_sent: self.get_bytes_sent(),
            bytes_received: self.get_bytes_received(),
            connections_active: self.get_connections_active(),
        }
    }
}

impl Default for AtomicCounters {
    fn default() -> Self {
        Self::new()
    }
}