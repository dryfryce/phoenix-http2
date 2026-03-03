//! Configuration types for Phoenix HTTP/2 stress testing
//!
//! This module defines the configuration structures for target servers
//! and attack parameters.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::PhoenixError;
use crate::Result;

/// Configuration for a target server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    /// Target URL (must be HTTPS)
    pub url: String,
    
    /// Number of concurrent connections to maintain
    #[serde(default = "default_connections")]
    pub connections: usize,
    
    /// Connection timeout in seconds
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    
    /// Whether to verify TLS certificates
    #[serde(default = "default_tls_verify")]
    pub tls_verify: bool,
    
    /// Custom headers to send with requests
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    
    /// Maximum retries for failed connections
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    
    /// Backoff multiplier for retries
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,
}

/// Default number of connections
fn default_connections() -> usize {
    10
}

/// Default timeout in seconds
fn default_timeout_secs() -> u64 {
    30
}

/// Default TLS verification
fn default_tls_verify() -> bool {
    true
}

/// Default maximum retries
fn default_max_retries() -> u32 {
    3
}

/// Default backoff multiplier
fn default_backoff_multiplier() -> f64 {
    1.5
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            url: "https://example.com".to_string(),
            connections: default_connections(),
            timeout_secs: default_timeout_secs(),
            tls_verify: default_tls_verify(),
            headers: Vec::new(),
            max_retries: default_max_retries(),
            backoff_multiplier: default_backoff_multiplier(),
        }
    }
}

impl TargetConfig {
    /// Create a new target configuration
    ///
    /// # Arguments
    /// * `url` - Target URL
    ///
    /// # Returns
    /// A new `TargetConfig` with default values
    pub fn new(url: String) -> Self {
        Self {
            url,
            ..Default::default()
        }
    }
    
    /// Validate the configuration
    ///
    /// # Returns
    /// `Ok(())` if valid, error otherwise
    pub fn validate(&self) -> Result<()> {
        let url = Url::parse(&self.url).map_err(|e| PhoenixError::config(
            format!("Invalid URL: {}", e)
        ))?;
        
        if url.scheme() != "https" {
            return Err(PhoenixError::config(
                "Target URL must use HTTPS scheme"
            ));
        }
        
        if self.connections == 0 {
            return Err(PhoenixError::config(
                "Number of connections must be greater than 0"
            ));
        }
        
        if self.timeout_secs == 0 {
            return Err(PhoenixError::config(
                "Timeout must be greater than 0"
            ));
        }
        
        Ok(())
    }
    
    /// Get the connection timeout as `Duration`
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
    
    /// Get the host from the URL
    pub fn host(&self) -> Result<Option<String>> {
        let url = Url::parse(&self.url).map_err(|e| PhoenixError::config(
            format!("Invalid URL: {}", e)
        ))?;
        Ok(url.host_str().map(|s| s.to_string()))
    }
    
    /// Get the port from the URL
    pub fn port(&self) -> Result<u16> {
        let url = Url::parse(&self.url).map_err(|e| PhoenixError::config(
            format!("Invalid URL: {}", e)
        ))?;
        Ok(url.port().unwrap_or(443))
    }
}

/// Configuration for an attack run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    /// Requests per second target
    #[serde(default = "default_rps")]
    pub rps: u32,
    
    /// Duration of the attack in seconds
    #[serde(default = "default_duration_secs")]
    pub duration_secs: u64,
    
    /// Number of concurrent connections to use
    #[serde(default = "default_attack_connections")]
    pub connections: usize,
    
    /// Path to save the attack report
    #[serde(default = "default_report_path")]
    pub report_path: PathBuf,
    
    /// Whether to enable detailed logging
    #[serde(default = "default_verbose")]
    pub verbose: bool,
    
    /// Maximum number of requests to send (0 for unlimited)
    #[serde(default)]
    pub max_requests: u64,
    
    /// Random delay between requests in milliseconds
    #[serde(default = "default_random_delay_ms")]
    pub random_delay_ms: u64,
    
    /// Attack pattern (linear, burst, random)
    #[serde(default = "default_attack_pattern")]
    pub pattern: AttackPattern,
    
    /// Specific paths to target (empty for default)
    #[serde(default)]
    pub paths: Vec<String>,
    
    /// HTTP methods to use (empty for GET only)
    #[serde(default)]
    pub methods: Vec<String>,
}

/// Default requests per second
fn default_rps() -> u32 {
    100
}

/// Default duration in seconds
fn default_duration_secs() -> u64 {
    60
}

/// Default number of connections for attacks
fn default_attack_connections() -> usize {
    50
}

/// Default report path
fn default_report_path() -> PathBuf {
    PathBuf::from("phoenix_report.json")
}

/// Default verbose setting
fn default_verbose() -> bool {
    false
}

/// Default random delay in milliseconds
fn default_random_delay_ms() -> u64 {
    0
}

/// Default attack pattern
fn default_attack_pattern() -> AttackPattern {
    AttackPattern::Linear
}

/// Attack pattern type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackPattern {
    /// Linear constant rate
    Linear,
    /// Burst pattern (periods of high activity)
    Burst {
        /// Burst duration in seconds
        burst_duration: u64,
        /// Quiet duration between bursts in seconds
        quiet_duration: u64,
        /// Requests per second during bursts
        burst_rps: u32,
    },
    /// Random rate within bounds
    Random {
        /// Minimum RPS
        min_rps: u32,
        /// Maximum RPS
        max_rps: u32,
        /// Change interval in seconds
        change_interval: u64,
    },
    /// Incremental ramp-up
    RampUp {
        /// Starting RPS
        start_rps: u32,
        /// Ending RPS
        end_rps: u32,
        /// Ramp duration in seconds
        ramp_duration: u64,
    },
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            rps: default_rps(),
            duration_secs: default_duration_secs(),
            connections: default_attack_connections(),
            report_path: default_report_path(),
            verbose: default_verbose(),
            max_requests: 0,
            random_delay_ms: default_random_delay_ms(),
            pattern: default_attack_pattern(),
            paths: Vec::new(),
            methods: Vec::new(),
        }
    }
}

impl AttackConfig {
    /// Create a new attack configuration
    ///
    /// # Arguments
    /// * `rps` - Requests per second
    /// * `duration_secs` - Duration in seconds
    ///
    /// # Returns
    /// A new `AttackConfig` with default values
    pub fn new(rps: u32, duration_secs: u64) -> Self {
        Self {
            rps,
            duration_secs,
            ..Default::default()
        }
    }
    
    /// Validate the configuration
    ///
    /// # Returns
    /// `Ok(())` if valid, error otherwise
    pub fn validate(&self) -> Result<()> {
        if self.rps == 0 {
            return Err(PhoenixError::config(
                "Requests per second must be greater than 0"
            ));
        }
        
        if self.duration_secs == 0 {
            return Err(PhoenixError::config(
                "Duration must be greater than 0"
            ));
        }
        
        if self.connections == 0 {
            return Err(PhoenixError::config(
                "Number of connections must be greater than 0"
            ));
        }
        
        // Validate attack pattern
        match &self.pattern {
            AttackPattern::Burst { burst_duration, quiet_duration, burst_rps } => {
                if *burst_duration == 0 {
                    return Err(PhoenixError::config(
                        "Burst duration must be greater than 0"
                    ));
                }
                if *quiet_duration == 0 {
                    return Err(PhoenixError::config(
                        "Quiet duration must be greater than 0"
                    ));
                }
                if *burst_rps == 0 {
                    return Err(PhoenixError::config(
                        "Burst RPS must be greater than 0"
                    ));
                }
            }
            AttackPattern::Random { min_rps, max_rps, change_interval } => {
                if min_rps >= max_rps {
                    return Err(PhoenixError::config(
                        "Minimum RPS must be less than maximum RPS"
                    ));
                }
                if *change_interval == 0 {
                    return Err(PhoenixError::config(
                        "Change interval must be greater than 0"
                    ));
                }
            }
            AttackPattern::RampUp { start_rps, end_rps, ramp_duration } => {
                if start_rps >= end_rps {
                    return Err(PhoenixError::config(
                        "Start RPS must be less than end RPS for ramp-up"
                    ));
                }
                if *ramp_duration == 0 {
                    return Err(PhoenixError::config(
                        "Ramp duration must be greater than 0"
                    ));
                }
            }
            _ => {}
        }
        
        Ok(())
    }
    
    /// Get the attack duration as `Duration`
    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.duration_secs)
    }
    
    /// Calculate total number of requests (if max_requests is set)
    pub fn total_requests(&self) -> Option<u64> {
        if self.max_requests > 0 {
            Some(self.max_requests)
        } else {
            None
        }
    }
    
    /// Get the random delay as `Duration`
    pub fn random_delay(&self) -> Duration {
        Duration::from_millis(self.random_delay_ms)
    }
    
    /// Check if this is a sustained attack (no max requests limit)
    pub fn is_sustained(&self) -> bool {
        self.max_requests == 0
    }
}