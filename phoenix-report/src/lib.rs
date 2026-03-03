//! Report generation for Phoenix HTTP/2 stress testing framework

pub mod json;
pub mod summary;

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Metrics snapshot for an attack run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Phoenix version
    pub phoenix_version: String,
    /// Attack type
    pub attack: String,
    /// Target URL
    pub target: String,
    /// When the attack started
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Duration in seconds
    pub duration_secs: f64,
    /// Summary statistics
    pub summary: SummaryStats,
    /// Latency statistics in microseconds
    pub latency_us: LatencyStats,
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryStats {
    /// Total requests sent
    pub total_requests: u64,
    /// Successful responses
    pub successful: u64,
    /// Error responses
    pub errors: u64,
    /// Requests per second
    pub requests_per_second: f64,
    /// Error rate percentage
    pub error_rate_pct: f64,
}

/// Latency statistics in microseconds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    /// 50th percentile (median)
    pub p50: u64,
    /// 95th percentile
    pub p95: u64,
    /// 99th percentile
    pub p99: u64,
    /// 99.9th percentile
    pub p999: u64,
    /// Minimum latency
    pub min: u64,
    /// Maximum latency
    pub max: u64,
    /// Mean latency
    pub mean: u64,
}

impl Default for MetricsSnapshot {
    fn default() -> Self {
        Self {
            phoenix_version: env!("CARGO_PKG_VERSION").to_string(),
            attack: String::new(),
            target: String::new(),
            started_at: chrono::Utc::now(),
            duration_secs: 0.0,
            summary: SummaryStats::default(),
            latency_us: LatencyStats::default(),
        }
    }
}

impl Default for SummaryStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful: 0,
            errors: 0,
            requests_per_second: 0.0,
            error_rate_pct: 0.0,
        }
    }
}

impl Default for LatencyStats {
    fn default() -> Self {
        Self {
            p50: 0,
            p95: 0,
            p99: 0,
            p999: 0,
            min: 0,
            max: 0,
            mean: 0,
        }
    }
}

impl MetricsSnapshot {
    /// Create a new metrics snapshot
    pub fn new(attack: String, target: String, duration: Duration) -> Self {
        Self {
            attack,
            target,
            duration_secs: duration.as_secs_f64(),
            ..Default::default()
        }
    }

    /// Update summary statistics
    pub fn update_summary(&mut self, total: u64, successful: u64, errors: u64) {
        self.summary.total_requests = total;
        self.summary.successful = successful;
        self.summary.errors = errors;
        
        if total > 0 {
            self.summary.requests_per_second = total as f64 / self.duration_secs;
            self.summary.error_rate_pct = (errors as f64 / total as f64) * 100.0;
        }
    }

    /// Update latency statistics
    pub fn update_latency(&mut self, latencies: &[u64]) {
        if latencies.is_empty() {
            return;
        }

        let mut sorted = latencies.to_vec();
        sorted.sort_unstable();

        self.latency_us.min = *sorted.first().unwrap();
        self.latency_us.max = *sorted.last().unwrap();
        
        let sum: u64 = sorted.iter().sum();
        self.latency_us.mean = sum / sorted.len() as u64;
        
        self.latency_us.p50 = percentile(&sorted, 0.5);
        self.latency_us.p95 = percentile(&sorted, 0.95);
        self.latency_us.p99 = percentile(&sorted, 0.99);
        self.latency_us.p999 = percentile(&sorted, 0.999);
    }
}

/// Calculate percentile from sorted data
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    
    let idx = (sorted.len() as f64 * p).ceil() as usize - 1;
    sorted[idx.min(sorted.len() - 1)]
}