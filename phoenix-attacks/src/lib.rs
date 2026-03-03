//! Phoenix Attacks - Attack modules for HTTP/2 stress testing framework
//!
//! This crate provides implementations of various HTTP/2 attack vectors,
//! including CVE-specific exploits and legitimate load testing.
//!
//! Each attack sends raw HTTP/2 frames directly over TLS connections,
//! bypassing high-level HTTP crates for precise control.

pub mod continuation_flood;
pub mod hpack_bomb;
pub mod load_test;
pub mod ping_flood;
pub mod rapid_reset;
pub mod settings_flood;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use phoenix_metrics::{AttackMetrics, MetricsSnapshot};
use thiserror::Error;

/// Re-export all attack modules
pub use continuation_flood::ContinuationFloodAttack;
pub use hpack_bomb::HpackBombAttack;
pub use load_test::LoadTestAttack;
pub use ping_flood::PingFloodAttack;
pub use rapid_reset::RapidResetAttack;
pub use settings_flood::SettingsFloodAttack;

/// Error type for attack execution failures
#[derive(Error, Debug)]
pub enum AttackError {
    #[error("Connection error: {0}")]
    Connection(#[from] phoenix_core::PhoenixError),
    
    #[error("Frame construction error: {0}")]
    FrameConstruction(String),
    
    #[error("Rate limiting error: {0}")]
    RateLimit(String),
    
    #[error("Timeout: attack duration exceeded")]
    Timeout,
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Context provided to an attack during execution
pub struct AttackContext {
    /// Target URL (e.g., "https://example.com:443")
    pub target: String,
    
    /// Number of concurrent connections to establish
    pub connections: usize,
    
    /// Duration to run the attack
    pub duration: Duration,
    
    /// Optional requests per second limit
    pub rps: Option<u32>,
    
    /// Metrics collector for tracking attack progress
    pub metrics: Arc<AttackMetrics>,
    
    /// Additional attack-specific parameters
    pub extra: HashMap<String, String>,
}

/// Result of an attack execution
pub struct AttackResult {
    /// Whether the attack completed successfully (not whether it was effective)
    pub success: bool,
    
    /// Total number of requests/frames sent
    pub total_requests: u64,
    
    /// Number of errors encountered
    pub errors: u64,
    
    /// Actual duration the attack ran
    pub duration: Duration,
    
    /// Final metrics snapshot
    pub snapshot: MetricsSnapshot,
}

/// Trait defining an attack module
#[async_trait]
pub trait Attack: Send + Sync {
    /// Get the name of the attack
    fn name(&self) -> &str;
    
    /// Get a description of the attack
    fn description(&self) -> &str;
    
    /// Execute the attack with the given context
    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError>;
}

/// Helper function to parse target URL into hostname and port
pub(crate) fn parse_target(target: &str) -> Result<(String, u16), AttackError> {
    // Simple URL parsing without url crate
    let target = target.trim();
    
    // Remove scheme if present
    let without_scheme = if target.starts_with("https://") {
        &target[8..]
    } else if target.starts_with("http://") {
        &target[7..]
    } else {
        target
    };
    
    // Split host and port
    let parts: Vec<&str> = without_scheme.split('/').next().unwrap_or("").split(':').collect();
    
    if parts.is_empty() || parts[0].is_empty() {
        return Err(AttackError::Config("Target must have a host".to_string()));
    }
    
    let host = parts[0].to_string();
    let port = if parts.len() > 1 {
        parts[1].parse().map_err(|e| AttackError::Config(format!("Invalid port: {}", e)))?
    } else {
        // Default ports based on scheme
        if target.starts_with("https://") {
            443
        } else if target.starts_with("http://") {
            80
        } else {
            443 // Default to HTTPS
        }
    };
    
    Ok((host, port))
}

/// Helper function to create a rate limiter
pub(crate) fn create_rate_limiter(rps: Option<u32>) -> Option<governor::RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::QuantaClock>> {
    rps.map(|rps| {
        let quota = governor::Quota::per_second(std::num::NonZeroU32::new(rps).unwrap_or(std::num::NonZeroU32::new(1).unwrap()));
        governor::RateLimiter::direct(quota)
    })
}