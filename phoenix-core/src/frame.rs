//! HTTP/2 frame construction and parsing
//!
//! This module provides low-level HTTP/2 frame construction functions
//! that bypass the standard `h2` crate for attack simulation purposes.

use bytes::{BufMut, Bytes, BytesMut};
use crate::error::PhoenixError;

/// HTTP/2 frame type constants
pub const DATA: u8 = 0x0;
pub const HEADERS: u8 = 0x1;
pub const PRIORITY: u8 = 0x2;
pub const RST_STREAM: u8 = 0x3;
pub const SETTINGS: u8 = 0x4;
pub const PUSH_PROMISE: u8 = 0x5;
pub const PING: u8 = 0x6;
pub const GOAWAY: u8 = 0x7;
pub const WINDOW_UPDATE: u8 = 0x8;
pub const CONTINUATION: u8 = 0x9;

/// HTTP/2 flag constants
pub const FLAG_END_STREAM: u8 = 0x1;
pub const FLAG_END_HEADERS: u8 = 0x4;
pub const FLAG_PADDED: u8 = 0x8;
pub const FLAG_PRIORITY: u8 = 0x20;
pub const FLAG_ACK: u8 = 0x1;

/// Build an HTTP/2 frame header
///
/// # Arguments
/// * `length` - Frame payload length (max 2^24-1)
/// * `frame_type` - Frame type (DATA, HEADERS, etc.)
/// * `flags` - Frame flags
/// * `stream_id` - Stream identifier (0 for connection-level frames)
///
/// # Returns
/// Bytes containing the 9-byte frame header
pub fn build_frame_header(length: u32, frame_type: u8, flags: u8, stream_id: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(9);
    
    // 3-byte length (24-bit big-endian)
    buf.put_u8(((length & 0x00FF_FFFF) >> 16) as u8);
    buf.put_u8(((length & 0x00FF_FFFF) >> 8) as u8);
    buf.put_u8((length & 0x00FF_FFFF) as u8);
    
    // 1-byte type
    buf.put_u8(frame_type);
    
    // 1-byte flags
    buf.put_u8(flags);
    
    // 4-byte stream ID (31-bit big-endian, most significant bit reserved)
    buf.put_u32(stream_id & 0x7FFF_FFFF);
    
    buf.freeze()
}

/// Build a SETTINGS frame with default client settings
///
/// # Returns
/// Bytes containing a complete SETTINGS frame
pub fn build_settings_frame() -> Bytes {
    // Default client settings:
    // - SETTINGS_HEADER_TABLE_SIZE = 4096
    // - SETTINGS_ENABLE_PUSH = 0 (disable server push)
    // - SETTINGS_MAX_CONCURRENT_STREAMS = unlimited (0xFFFFFFFF)
    // - SETTINGS_INITIAL_WINDOW_SIZE = 65535
    // - SETTINGS_MAX_FRAME_SIZE = 16384
    // - SETTINGS_MAX_HEADER_LIST_SIZE = unlimited (0xFFFFFFFF)
    
    let mut buf = BytesMut::with_capacity(9 + 6 * 6); // Header + 6 settings * 6 bytes each
    
    // Frame header: 6 settings * 6 bytes = 36 bytes, SETTINGS type, no flags, stream 0
    buf.put_slice(&build_frame_header(36, SETTINGS, 0, 0));
    
    // SETTINGS_HEADER_TABLE_SIZE = 1
    buf.put_u16(0x1);
    buf.put_u32(4096);
    
    // SETTINGS_ENABLE_PUSH = 2
    buf.put_u16(0x2);
    buf.put_u32(0); // Disable push
    
    // SETTINGS_MAX_CONCURRENT_STREAMS = 3
    buf.put_u16(0x3);
    buf.put_u32(u32::MAX);
    
    // SETTINGS_INITIAL_WINDOW_SIZE = 4
    buf.put_u16(0x4);
    buf.put_u32(65535);
    
    // SETTINGS_MAX_FRAME_SIZE = 5
    buf.put_u16(0x5);
    buf.put_u32(16384);
    
    // SETTINGS_MAX_HEADER_LIST_SIZE = 6
    buf.put_u16(0x6);
    buf.put_u32(u32::MAX);
    
    buf.freeze()
}

/// Build a SETTINGS acknowledgment frame
///
/// # Returns
/// Bytes containing a SETTINGS ACK frame
pub fn build_settings_ack() -> Bytes {
    let mut buf = BytesMut::with_capacity(9);
    buf.put_slice(&build_frame_header(0, SETTINGS, FLAG_ACK, 0));
    buf.freeze()
}

/// Build a HEADERS frame
///
/// # Arguments
/// * `stream_id` - Stream identifier
/// * `header_block` - HPACK-encoded header block
/// * `end_stream` - Whether this frame ends the stream
/// * `end_headers` - Whether this frame ends the headers
///
/// # Returns
/// Bytes containing a HEADERS frame
pub fn build_headers_frame(
    stream_id: u32,
    header_block: &[u8],
    end_stream: bool,
    end_headers: bool,
) -> Bytes {
    let mut flags = 0;
    if end_stream {
        flags |= FLAG_END_STREAM;
    }
    if end_headers {
        flags |= FLAG_END_HEADERS;
    }
    
    let mut buf = BytesMut::with_capacity(9 + header_block.len());
    buf.put_slice(&build_frame_header(header_block.len() as u32, HEADERS, flags, stream_id));
    buf.put_slice(header_block);
    
    buf.freeze()
}

/// Build a RST_STREAM frame
///
/// # Arguments
/// * `stream_id` - Stream identifier to reset
/// * `error_code` - Error code (see HTTP/2 spec)
///
/// # Returns
/// Bytes containing a RST_STREAM frame
pub fn build_rst_stream_frame(stream_id: u32, error_code: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(9 + 4);
    buf.put_slice(&build_frame_header(4, RST_STREAM, 0, stream_id));
    buf.put_u32(error_code);
    
    buf.freeze()
}

/// Build a PING frame
///
/// # Arguments
/// * `payload` - 8-byte ping payload
/// * `ack` - Whether this is a PING acknowledgment
///
/// # Returns
/// Bytes containing a PING frame
pub fn build_ping_frame(payload: [u8; 8], ack: bool) -> Bytes {
    let flags = if ack { FLAG_ACK } else { 0 };
    
    let mut buf = BytesMut::with_capacity(9 + 8);
    buf.put_slice(&build_frame_header(8, PING, flags, 0));
    buf.put_slice(&payload);
    
    buf.freeze()
}

/// Build a WINDOW_UPDATE frame
///
/// # Arguments
/// * `stream_id` - Stream identifier (0 for connection-level)
/// * `increment` - Window size increment (1 to 2^31-1)
///
/// # Returns
/// Bytes containing a WINDOW_UPDATE frame
pub fn build_window_update_frame(stream_id: u32, increment: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(9 + 4);
    buf.put_slice(&build_frame_header(4, WINDOW_UPDATE, 0, stream_id));
    buf.put_u32(increment & 0x7FFF_FFFF); // 31-bit only
    
    buf.freeze()
}

/// Build a CONTINUATION frame
///
/// # Arguments
/// * `stream_id` - Stream identifier
/// * `header_block` - HPACK-encoded header block continuation
/// * `end_headers` - Whether this frame ends the headers
///
/// # Returns
/// Bytes containing a CONTINUATION frame
pub fn build_continuation_frame(
    stream_id: u32,
    header_block: &[u8],
    end_headers: bool,
) -> Bytes {
    let flags = if end_headers { FLAG_END_HEADERS } else { 0 };
    
    let mut buf = BytesMut::with_capacity(9 + header_block.len());
    buf.put_slice(&build_frame_header(header_block.len() as u32, CONTINUATION, flags, stream_id));
    buf.put_slice(header_block);
    
    buf.freeze()
}

/// Create a minimal HPACK-encoded GET request header block
///
/// This manually encodes a simple GET request using HPACK static table indices.
///
/// # Arguments
/// * `host` - The :authority (host) value
/// * `path` - The :path value
///
/// # Returns
/// HPACK-encoded header block as Vec<u8>
pub fn minimal_hpack_get_request(host: &str, path: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    
    // HPACK encoding for headers using static table indices:
    // Index 2: :method: GET
    // Index 1: :authority (host)
    // Index 5: :path
    // Index 6: :scheme: https
    
    // :method: GET (static index 2)
    buf.push(0x82); // 1000 0010 - Indexed header field (7-bit prefix)
    
    // :scheme: https (static index 6)
    buf.push(0x86); // 1000 0110
    
    // :path (static index 5) - literal with incremental indexing (4-bit prefix)
    // 0x04 = 0000 0100: literal header field with incremental indexing, index 5
    buf.push(0x44); // 0100 0100: literal header field with incremental indexing (4-bit), index 5
    encode_hpack_string(path, &mut buf);
    
    // :authority (static index 1) - literal with incremental indexing
    buf.push(0x41); // 0100 0001: literal header field with incremental indexing (4-bit), index 1
    encode_hpack_string(host, &mut buf);
    
    buf
}

/// Helper function to encode HPACK string literals
fn encode_hpack_string(s: &str, buf: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    if bytes.len() < 127 {
        // Length fits in 7 bits
        buf.push(bytes.len() as u8);
    } else {
        // Extended length encoding
        buf.push(0x7F); // 127 with continuation bit
        let mut len = bytes.len();
        while len > 0 {
            let byte = (len & 0x7F) as u8;
            len >>= 7;
            if len > 0 {
                buf.push(byte | 0x80); // Set continuation bit
            } else {
                buf.push(byte);
            }
        }
    }
    buf.extend_from_slice(bytes);
}

/// Represents a parsed HTTP/2 frame
#[derive(Debug, Clone)]
pub struct Frame {
    /// Frame length (payload only)
    pub length: u32,
    /// Frame type
    pub frame_type: u8,
    /// Frame flags
    pub flags: u8,
    /// Stream identifier
    pub stream_id: u32,
    /// Frame payload
    pub payload: Bytes,
}

impl Frame {
    /// Parse a frame from bytes
    pub fn parse(mut data: Bytes) -> std::result::Result<Self, PhoenixError> {
        if data.len() < 9 {
            return Err(PhoenixError::frame("Frame too short"));
        }
        
        let length = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
        let frame_type = data[3];
        let flags = data[4];
        let stream_id = ((data[5] as u32) << 24) |
                       ((data[6] as u32) << 16) |
                       ((data[7] as u32) << 8) |
                       (data[8] as u32);
        
        if data.len() < 9 + length as usize {
            return Err(PhoenixError::frame("Incomplete frame payload"));
        }
        
        let mut payload = data.split_off(9);
        if payload.len() > length as usize {
            // Truncate to declared length
            let _ = payload.split_off(length as usize);
        }
        
        Ok(Self {
            length,
            frame_type,
            flags,
            stream_id,
            payload,
        })
    }
}