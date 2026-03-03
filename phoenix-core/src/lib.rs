//! Phoenix Core - Foundation crate for HTTP/2 stress testing framework
//!
//! This crate provides low-level HTTP/2 connection handling, frame construction,
//! connection pooling, and configuration for the Phoenix stress testing tool.

pub mod config;
pub mod connection;
pub mod error;
pub mod frame;
pub mod pool;

// Re-export commonly used types
pub use config::{AttackConfig, TargetConfig};
pub use connection::{RawH2Connection, RawH2TlsConnection};
pub use error::PhoenixError;
pub use frame::{build_frame_header, minimal_hpack_get_request};
pub use pool::ConnectionPool;

/// Result type alias for Phoenix operations
pub type Result<T> = std::result::Result<T, PhoenixError>;