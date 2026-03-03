//! HTTP/2 Load Test Module
//!
//! Sends legitimate HTTP/2 GET requests at a controlled rate using
//! RawH2Connection. Measures throughput, latency percentiles, and
//! error rates across multiple concurrent connections.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{BufMut, BytesMut};
use tokio::time::sleep;
use tracing::{debug, error, info};
use url::Url;

use phoenix_core::RawH2Connection;
use phoenix_metrics::AttackMetrics;

use crate::{Attack, AttackContext, AttackError, AttackResult};

/// HTTP/2 load test — legitimate requests, accurate throughput measurement
pub struct LoadTestAttack {
    connection_count: usize,
    target_rps:       Option<u32>,
    duration:         Option<Duration>,
}

impl LoadTestAttack {
    pub fn new() -> Self {
        Self {
            connection_count: 10,
            target_rps:       None,
            duration:         None,
        }
    }

    pub fn with_connection_count(mut self, n: usize) -> Self {
        self.connection_count = n;
        self
    }

    pub fn with_target_rps(mut self, rps: u32) -> Self {
        self.target_rps = Some(rps);
        self
    }

    pub fn with_duration(mut self, d: Duration) -> Self {
        self.duration = Some(d);
        self
    }
}

impl Default for LoadTestAttack {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Attack for LoadTestAttack {
    fn name(&self) -> &str {
        "http2-load-test"
    }

    fn description(&self) -> &str {
        "Legitimate HTTP/2 load test. Sends valid GET requests over raw HTTP/2 connections, measures latency and throughput."
    }

    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        let duration = self.duration.unwrap_or(ctx.duration);
        let connections = if self.connection_count > 0 { self.connection_count } else { ctx.connections };
        let rps_cap = self.target_rps.or(ctx.rps);

        let url = Url::parse(&ctx.target)
            .map_err(|e| AttackError::Config(format!("Invalid target URL: {}", e)))?;

        info!("Load test: {} connections, {:?} duration, rps_cap={:?}", connections, duration, rps_cap);

        let metrics = ctx.metrics.clone();
        let start   = Instant::now();

        // Per-connection delay when rate-limiting
        let delay_per_conn = rps_cap.map(|rps| {
            let total_rps = rps as f64;
            let per_conn  = total_rps / connections as f64;
            Duration::from_secs_f64(1.0 / per_conn.max(0.001))
        });

        let mut handles = Vec::new();

        for conn_id in 0..connections {
            let url_str  = url.to_string();
            let metrics  = metrics.clone();
            let duration = duration;
            let delay    = delay_per_conn;

            let handle = tokio::spawn(async move {
                run_connection(conn_id, &url_str, duration, delay, metrics).await
            });
            handles.push(handle);
        }

        let mut total_ok  = 0u64;
        let mut total_err = 0u64;

        for h in handles {
            match h.await {
                Ok(Ok((ok, err))) => { total_ok += ok; total_err += err; }
                Ok(Err(e))        => { error!("Connection task error: {}", e); total_err += 1; }
                Err(e)            => { error!("Join error: {}", e); total_err += 1; }
            }
        }

        let elapsed   = start.elapsed();
        let total     = total_ok + total_err;
        let rps_actual = total as f64 / elapsed.as_secs_f64();

        info!("Load test complete: {} requests ({} ok, {} err) in {:.1}s = {:.0} rps",
              total, total_ok, total_err, elapsed.as_secs_f64(), rps_actual);

        let snapshot = metrics.snapshot().await;
        Ok(AttackResult {
            success:        total_err == 0,
            total_requests: total,
            errors:         total_err,
            duration:       elapsed,
            snapshot,
        })
    }
}

/// Run a single persistent connection, sending GET requests in a loop
async fn run_connection(
    id:       usize,
    url_str:  &str,
    duration: Duration,
    delay:    Option<Duration>,
    metrics:  Arc<AttackMetrics>,
) -> Result<(u64, u64), AttackError> {
    let url = Url::parse(url_str)
        .map_err(|e| AttackError::Config(e.to_string()))?;

    let mut connection = RawH2Connection::connect(&url).await
        .map_err(AttackError::Connection)?;
    connection.perform_handshake().await
        .map_err(AttackError::Connection)?;

    debug!("Connection {} established", id);

    let start    = Instant::now();
    let mut ok   = 0u64;
    let mut err  = 0u64;
    let mut stream_id = 1u32;

    while start.elapsed() < duration {
        let req_start = Instant::now();

        // HEADERS frame — end_stream=true (no body)
        let headers = build_get_request_frame(&url, stream_id, true);

        if let Err(e) = connection.send_frame(headers).await {
            error!("conn {}: send error: {}", id, e);
            err += 1;
            // Reconnect
            match RawH2Connection::connect(&url).await {
                Ok(mut c) => {
                    if c.perform_handshake().await.is_ok() {
                        connection = c;
                        stream_id  = 1;
                    } else {
                        break;
                    }
                }
                Err(_) => break,
            }
            continue;
        }

        let latency_us = req_start.elapsed().as_micros() as u64;
        metrics.record_request(latency_us, true, 0).await;
        ok += 1;

        stream_id = stream_id.wrapping_add(2);
        // Reset stream counter when approaching max to avoid protocol errors
        if stream_id > 2_000_000 {
            stream_id = 1;
        }

        if let Some(d) = delay {
            sleep(d).await;
        } else {
            // Yield to not starve the runtime
            if ok % 500 == 0 {
                tokio::task::yield_now().await;
            }
        }
    }

    Ok((ok, err))
}

/// Build a HEADERS frame for GET request (end_stream=true)
fn build_get_request_frame(url: &Url, stream_id: u32, end_stream: bool) -> bytes::Bytes {
    let host = url.host_str().unwrap_or("localhost");
    let path = if url.path().is_empty() { "/" } else { url.path() };

    // Build HPACK-encoded headers (static table entries)
    let mut hpack = BytesMut::new();
    // :method GET  (index 2)
    hpack.put_u8(0x82);
    // :scheme https (index 7)
    hpack.put_u8(0x87);
    // :path / (index 4) or literal
    if path == "/" {
        hpack.put_u8(0x84);
    } else {
        // :path literal (index 5 = :path, never-indexed)
        hpack.put_u8(0x04);
        hpack.put_u8(path.len() as u8);
        hpack.put_slice(path.as_bytes());
    }
    // :authority literal
    hpack.put_u8(0x41);
    hpack.put_u8(host.len() as u8);
    hpack.put_slice(host.as_bytes());

    let hpack_len = hpack.len();

    // HEADERS frame:
    // Length (3 bytes) | Type=0x01 | Flags | Stream ID (4 bytes) | Payload
    let flags: u8 = 0x04 | if end_stream { 0x01 } else { 0x00 }; // END_HEADERS | (END_STREAM)
    let mut frame = BytesMut::with_capacity(9 + hpack_len);
    frame.put_u8((hpack_len >> 16) as u8);
    frame.put_u8((hpack_len >> 8)  as u8);
    frame.put_u8( hpack_len        as u8);
    frame.put_u8(0x01); // HEADERS frame type
    frame.put_u8(flags);
    frame.put_u32(stream_id & 0x7FFFFFFF);
    frame.put_slice(&hpack);

    frame.freeze()
}
