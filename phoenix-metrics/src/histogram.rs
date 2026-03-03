//! Latency histogram for tracking request latencies in microseconds

use hdrhistogram::Histogram;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Latency histogram for tracking request latencies in microseconds
#[derive(Debug)]
pub struct LatencyHistogram {
    histogram: Mutex<Histogram<u64>>,
}

/// Snapshot of histogram statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramSnapshot {
    pub p50: u64,
    pub p75: u64,
    pub p90: u64,
    pub p95: u64,
    pub p99: u64,
    pub p999: u64,
    pub p9999: u64,
    pub min: u64,
    pub max: u64,
    pub mean: u64,
    pub count: u64,
    pub stddev: f64,
}

impl LatencyHistogram {
    /// Create a new latency histogram
    ///
    /// The histogram is configured with:
    /// - 3 significant figures
    /// - Minimum value: 1 microsecond
    /// - Maximum value: 60_000_000 microseconds (60 seconds)
    pub fn new() -> Self {
        let histogram = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
            .expect("Failed to create histogram");
        
        Self {
            histogram: Mutex::new(histogram),
        }
    }

    /// Record a latency value in microseconds
    pub async fn record(&self, latency_us: u64) {
        let mut histogram = self.histogram.lock().await;
        histogram.record(latency_us).expect("Failed to record latency");
    }

    /// Create a snapshot of the current histogram statistics
    pub async fn snapshot(&self) -> HistogramSnapshot {
        let histogram = self.histogram.lock().await;
        
        HistogramSnapshot {
            p50: histogram.value_at_quantile(0.50),
            p75: histogram.value_at_quantile(0.75),
            p90: histogram.value_at_quantile(0.90),
            p95: histogram.value_at_quantile(0.95),
            p99: histogram.value_at_quantile(0.99),
            p999: histogram.value_at_quantile(0.999),
            p9999: histogram.value_at_quantile(0.9999),
            min: histogram.min(),
            max: histogram.max(),
            mean: histogram.mean() as u64,
            count: histogram.len(),
            stddev: histogram.stdev(),
        }
    }
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for HistogramSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Latency Percentiles (μs):")?;
        writeln!(f, "  p50:    {:>10} μs", self.p50)?;
        writeln!(f, "  p75:    {:>10} μs", self.p75)?;
        writeln!(f, "  p90:    {:>10} μs", self.p90)?;
        writeln!(f, "  p95:    {:>10} μs", self.p95)?;
        writeln!(f, "  p99:    {:>10} μs", self.p99)?;
        writeln!(f, "  p99.9:  {:>10} μs", self.p999)?;
        writeln!(f, "  p99.99: {:>10} μs", self.p9999)?;
        writeln!(f, "  min:    {:>10} μs", self.min)?;
        writeln!(f, "  max:    {:>10} μs", self.max)?;
        writeln!(f, "  mean:   {:>10} μs", self.mean)?;
        writeln!(f, "  stddev: {:>10.2} μs", self.stddev)?;
        writeln!(f, "  count:  {:>10}", self.count)?;
        Ok(())
    }
}