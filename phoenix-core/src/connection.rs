//! Raw HTTP/2 connection handling
//!
//! This module provides low-level HTTP/2 connection management
//! with TLS support and manual frame read/write operations.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use rustls::ClientConfig;
use rustls::pki_types::{ServerName, CertificateDer, UnixTime};
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::DigitallySignedStruct;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

/// No-op TLS certificate verifier — accepts any cert including self-signed.
/// Used for testing against targets with self-signed certificates.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

use crate::error::PhoenixError;
use crate::frame::{Frame, build_settings_frame, build_settings_ack};
use crate::Result;

/// HTTP/2 connection preface bytes
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Raw HTTP/2 connection
///
/// This struct manages a single HTTP/2 connection with manual
/// frame read/write capabilities, bypassing the standard `h2` crate.
pub struct RawH2Connection<T> {
    /// Writer half of the connection
    writer: WriteHalf<T>,
    /// Reader half of the connection
    reader: ReadHalf<T>,
    /// Next available stream ID (odd numbers for client-initiated streams)
    next_stream_id: u32,
    /// Target URL for this connection
    target: String,
}

/// Type alias for commonly used connection type
pub type RawH2TlsConnection = RawH2Connection<tokio_rustls::client::TlsStream<TcpStream>>;

impl<T> RawH2Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new connection from split reader/writer
    pub fn new(reader: ReadHalf<T>, writer: WriteHalf<T>, target: String) -> Self {
        Self {
            reader,
            writer,
            next_stream_id: 1,
            target,
        }
    }
    
    /// Send a raw HTTP/2 frame
    ///
    /// # Arguments
    /// * `frame` - Frame bytes to send
    pub async fn send_frame(&mut self, frame: Bytes) -> Result<()> {
        self.writer.write_all(&frame).await
            .map_err(|e| PhoenixError::Io(e))?;
        self.writer.flush().await
            .map_err(|e| PhoenixError::Io(e))?;
        
        Ok(())
    }
    
    /// Read a raw HTTP/2 frame
    ///
    /// # Returns
    /// Parsed `Frame` structure
    pub async fn read_frame(&mut self) -> Result<Frame> {
        // Read frame header (9 bytes)
        let mut header = [0u8; 9];
        self.reader.read_exact(&mut header).await
            .map_err(|e| PhoenixError::Io(e))?;
        
        // Parse header
        let length = ((header[0] as u32) << 16) | ((header[1] as u32) << 8) | (header[2] as u32);
        let frame_type = header[3];
        let flags = header[4];
        let stream_id = ((header[5] as u32) << 24) |
                       ((header[6] as u32) << 16) |
                       ((header[7] as u32) << 8) |
                       (header[8] as u32);
        
        // Read payload
        let mut payload = vec![0u8; length as usize];
        if length > 0 {
            self.reader.read_exact(&mut payload).await
                .map_err(|e| PhoenixError::Io(e))?;
        }
        
        Ok(Frame {
            length,
            frame_type,
            flags,
            stream_id,
            payload: Bytes::from(payload),
        })
    }
    
    /// Read a frame with timeout
    ///
    /// # Arguments
    /// * `duration` - Timeout duration
    ///
    /// # Returns
    /// Parsed `Frame` or timeout error
    pub async fn read_frame_timeout(&mut self, duration: Duration) -> Result<Frame> {
        timeout(duration, self.read_frame()).await
            .map_err(|_| PhoenixError::timeout("Frame read timeout"))?
    }
    
    /// Get the next available stream ID and increment
    ///
    /// # Returns
    /// Next stream ID (odd number for client streams)
    pub fn next_stream_id(&mut self) -> u32 {
        let id = self.next_stream_id;
        self.next_stream_id += 2; // Client streams are odd numbers
        id
    }
    
    /// Get the target URL for this connection
    pub fn target(&self) -> &str {
        &self.target
    }
}

impl RawH2TlsConnection {
    /// Connect to a URL and establish an HTTP/2 connection
    ///
    /// # Arguments
    /// * `url` - Target URL (must be HTTPS)
    ///
    /// # Returns
    /// A connected `RawH2Connection` instance
    pub async fn connect(url: &Url) -> Result<Self> {
        if url.scheme() != "https" {
            return Err(PhoenixError::config("Only HTTPS URLs are supported"));
        }

        let host = url.host_str().ok_or_else(|| {
            PhoenixError::config("URL must have a host")
        })?;
        
        let port = url.port().unwrap_or(443);
        
        // Establish TCP connection
        let addr = format!("{}:{}", host, port);
        let tcp_stream = TcpStream::connect(&addr).await
            .map_err(|e| PhoenixError::Connection(e.into()))?;
        
        // Set TCP_NODELAY for better performance
        let _ = tcp_stream.set_nodelay(true);
        
        // Setup TLS with ALPN for HTTP/2
        let tls_stream = Self::setup_tls(tcp_stream, host).await?;
        
        // Split into reader/writer
        let (reader, writer) = tokio::io::split(tls_stream);
        
        let mut conn = Self::new(reader, writer, url.to_string());
        
        // Perform HTTP/2 handshake
        conn.perform_handshake().await?;
        
        Ok(conn)
    }
    
    /// Setup TLS connection with HTTP/2 ALPN
    async fn setup_tls(
        tcp_stream: TcpStream,
        host: &str,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        // Use no-op verifier — accepts self-signed certs for test targets.
        // For production scanning, swap NoVerifier for webpki_roots store.
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| PhoenixError::Tls(e.into()))?;
        
        let connector = TlsConnector::from(Arc::new(config));
        let tls_stream = connector.connect(server_name, tcp_stream).await
            .map_err(|e| PhoenixError::Tls(e.into()))?;
        
        // Verify ALPN protocol is h2
        let (_, connection) = tls_stream.get_ref();
        let alpn_protocol = connection.alpn_protocol();
        if alpn_protocol != Some(b"h2") {
            return Err(PhoenixError::protocol(
                format!("Server does not support HTTP/2, ALPN: {:?}", alpn_protocol)
            ));
        }
        
        Ok(tls_stream)
    }
    
    /// Perform HTTP/2 handshake (preface + SETTINGS exchange)
    pub async fn perform_handshake(&mut self) -> Result<()> {
        // Send connection preface
        self.writer.write_all(HTTP2_PREFACE).await
            .map_err(|e| PhoenixError::Io(e))?;
        
        // Send initial SETTINGS frame
        let settings_frame = build_settings_frame();
        self.send_frame(settings_frame).await?;
        
        // Read and acknowledge server's SETTINGS
        let server_frame = self.read_frame().await?;
        if server_frame.frame_type != crate::frame::SETTINGS {
            return Err(PhoenixError::protocol(
                format!("Expected SETTINGS frame, got type {}", server_frame.frame_type)
            ));
        }
        
        // Send SETTINGS ACK
        let settings_ack = build_settings_ack();
        self.send_frame(settings_ack).await?;
        
        Ok(())
    }
}

// Implement AsyncRead/AsyncWrite for trait object compatibility
impl<T> AsyncRead for RawH2Connection<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for RawH2Connection<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.writer).poll_write(cx, buf)
    }
    
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }
    
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}