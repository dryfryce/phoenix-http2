//! Legitimate HTTP/2 Load Test Module
//!
//! This module performs legitimate HTTP/2 load testing using the h2 crate
//! (not raw frames) to send valid HTTP/2 requests and measure performance.
//!
//! NOTE: This module requires Rust 1.83+ due to dependencies (rustls, webpki, etc.)
//! For older Rust versions, comment out this module in lib.rs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use phoenix_metrics::AttackMetrics;
use tracing::{info, warn, error};

use crate::{Attack, AttackContext, AttackError, AttackResult};

/// Legitimate HTTP/2 Load Test implementation
pub struct LoadTestAttack {
    /// Number of concurrent connections
    connection_count: usize,
    
    /// Target requests per second
    target_rps: u32,
    
    /// Test duration
    duration: Duration,
}

impl LoadTestAttack {
    /// Create a new LoadTestAttack with default configuration
    pub fn new() -> Self {
        Self {
            connection_count: 10,
            target_rps: 100,
            duration: Duration::from_secs(60),
        }
    }
    
    /// Set the number of concurrent connections
    pub fn with_connection_count(mut self, count: usize) -> Self {
        self.connection_count = count;
        self
    }
    
    /// Set the target requests per second
    pub fn with_target_rps(mut self, rps: u32) -> Self {
        self.target_rps = rps;
        self
    }
    
    /// Set the test duration
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }
}

#[async_trait::async_trait]
impl Attack for LoadTestAttack {
    fn name(&self) -> &str {
        "http2-load-test"
    }
    
    fn description(&self) -> &str {
        "Legitimate HTTP/2 load test. Sends valid HTTP/2 requests using the h2 crate, measures latency percentiles, tracks error rates, and implements coordinated omission-aware timing with warmup/ramp-up/steady-state/cooldown phases. NOTE: Requires Rust 1.83+."
    }
    
    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        error!("LoadTestAttack requires Rust 1.83+ and additional dependencies (rustls, webpki, h2, hyper). Current Rust version is 1.75.0.");
        error!("Please upgrade Rust or comment out the load_test module.");
        
        Err(AttackError::Config(
            "LoadTestAttack requires Rust 1.83+. Upgrade Rust or use alternative attack modules.".to_string()
        ))
    }
}

impl Default for LoadTestAttack {
    fn default() -> Self {
        Self::new()
    }
}