//! Phoenix Metrics - Metrics collection and terminal UI for Phoenix HTTP/2 stress testing framework
//!
//! This crate provides atomic counters, latency histograms, metrics aggregation,
//! and a live terminal dashboard for monitoring HTTP/2 stress tests.

pub mod counter;
pub mod histogram;
pub mod metrics;
pub mod dashboard;

// Re-exports for convenience
pub use counter::{AtomicCounters, CounterSnapshot};
pub use histogram::{LatencyHistogram, HistogramSnapshot};
pub use metrics::{AttackMetrics, MetricsSnapshot};
pub use dashboard::PhoenixDashboard;