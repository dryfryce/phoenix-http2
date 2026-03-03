//! Error types for Phoenix HTTP/2 stress testing framework

use std::io;
use thiserror::Error;

/// Main error type for Phoenix operations
#[derive(Error, Debug)]
pub enum PhoenixError {
    /// Connection-related errors (TCP, TLS, etc.)
    #[error("Connection error: {0}")]
    Connection(#[source] anyhow::Error),

    /// TLS-specific errors
    #[error("TLS error: {0}")]
    Tls(#[source] anyhow::Error),

    /// HTTP/2 protocol violations
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Timeout errors
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Frame parsing/construction errors
    #[error("Frame error: {0}")]
    Frame(String),

    /// URL parsing errors
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
}

impl PhoenixError {
    /// Create a new protocol error
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    /// Create a new timeout error
    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::Timeout(msg.into())
    }

    /// Create a new configuration error
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create a new frame error
    pub fn frame(msg: impl Into<String>) -> Self {
        Self::Frame(msg.into())
    }
}

impl From<anyhow::Error> for PhoenixError {
    fn from(err: anyhow::Error) -> Self {
        Self::Connection(err)
    }
}