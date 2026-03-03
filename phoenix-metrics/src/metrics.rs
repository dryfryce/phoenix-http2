//! Combined metrics for HTTP/2 stress testing

use std::sync::Arc;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::counter::{AtomicCounters, CounterSnapshot};
use crate::histogram::{LatencyHistogram, HistogramSnapshot};

/// Combined metrics for tracking an HTTP/2 stress test attack
#[derive(Debug, Clone)]
pub struct AttackMetrics {
    counters: Arc<AtomicCounters>,
    latency: Arc<LatencyHistogram>,
    start_time: Instant,
    attack_name: String,
}

/// Complete snapshot of all metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: DateTime<Utc>,
    pub attack_name: String,
    pub elapsed_seconds: f64,
    pub requests_per_second: f64,
    pub counters: CounterSnapshot,
    pub latency: HistogramSnapshot,
}

impl AttackMetrics {
    /// Create new attack metrics with the given name
    pub fn new(attack_name: &str) -> Self {
        Self {
            counters: Arc::new(AtomicCounters::new()),
            latency: Arc::new(LatencyHistogram::new()),
            start_time: Instant::now(),
            attack_name: attack_name.to_string(),
        }
    }

    /// Record a request with its latency, success status, and bytes transferred
    pub async fn record_request(&self, latency_us: u64, success: bool, bytes: u64) {
        // Record in counters
        self.counters.increment_requests_sent();
        
        if success {
            self.counters.increment_requests_success();
        } else {
            self.counters.increment_requests_error();
        }
        
        // Record bytes (assuming bytes sent ≈ bytes received for simplicity)
        self.counters.add_bytes_sent(bytes);
        self.counters.add_bytes_received(bytes);
        
        // Record latency if successful
        if success {
            self.latency.record(latency_us).await;
        }
    }

    /// Create a complete snapshot of all metrics
    pub async fn snapshot(&self) -> MetricsSnapshot {
        let counters_snapshot = self.counters.snapshot();
        let latency_snapshot = self.latency.snapshot().await;
        let elapsed = self.elapsed_secs();
        let rps = self.requests_per_second();

        MetricsSnapshot {
            timestamp: Utc::now(),
            attack_name: self.attack_name.clone(),
            elapsed_seconds: elapsed,
            requests_per_second: rps,
            counters: counters_snapshot,
            latency: latency_snapshot,
        }
    }

    /// Get the elapsed time in seconds since the attack started
    pub fn elapsed_secs(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Calculate the current requests per second
    pub fn requests_per_second(&self) -> f64 {
        let elapsed = self.elapsed_secs();
        if elapsed > 0.0 {
            self.counters.get_requests_sent() as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Get a reference to the counters
    pub fn counters(&self) -> &Arc<AtomicCounters> {
        &self.counters
    }

    /// Get a reference to the latency histogram
    pub fn latency(&self) -> &Arc<LatencyHistogram> {
        &self.latency
    }

    /// Get the attack name
    pub fn attack_name(&self) -> &str {
        &self.attack_name
    }

    /// Get the start time
    pub fn start_time(&self) -> Instant {
        self.start_time
    }
}

impl Default for AttackMetrics {
    fn default() -> Self {
        Self::new("unnamed-attack")
    }
}