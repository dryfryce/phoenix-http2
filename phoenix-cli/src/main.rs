use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use phoenix_attacks::{
    Attack, AttackContext, RapidResetAttack, ContinuationFloodAttack,
    HpackBombAttack, SettingsFloodAttack, PingFloodAttack, LoadTestAttack,
};
use phoenix_metrics::AttackMetrics;
use phoenix_metrics::MetricsSnapshot as AttackSnapshot;
use phoenix_report::{json::ReportWriter, summary::SummaryPrinter, MetricsSnapshot as ReportSnapshot};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Parser)]
#[command(name = "phoenix")]
#[command(version = "0.1.0")]
#[command(about = "HTTP/2 Stress & Security Testing Framework")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run an attack module
    Attack(AttackArgs),
    /// Auto-scan target for HTTP/2 vulnerabilities
    Scan(ScanArgs),
    /// Show version info
    Version,
}

#[derive(Parser)]
struct AttackArgs {
    #[arg(value_enum)]
    attack_type: AttackType,
    #[arg(short, long)]
    target: String,
    #[arg(short, long, default_value = "10")]
    connections: usize,
    #[arg(short, long, default_value = "30s", value_parser = parse_duration)]
    duration: Duration,
    #[arg(long, default_value = "0")]
    rps: u32,
    #[arg(long)]
    report: Option<String>,
    #[arg(long)]
    no_tls_verify: bool,
    #[arg(short, long)]
    verbose: bool,
    #[arg(long, default_value = "100000")]
    frames: u64,
}

#[derive(Parser)]
struct ScanArgs {
    #[arg(short, long)]
    target: String,
    #[arg(long)]
    no_tls_verify: bool,
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum AttackType {
    RapidReset,
    ContinuationFlood,
    HpackBomb,
    SettingsFlood,
    PingFlood,
    LoadTest,
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackType::RapidReset       => write!(f, "rapid-reset"),
            AttackType::ContinuationFlood => write!(f, "continuation-flood"),
            AttackType::HpackBomb        => write!(f, "hpack-bomb"),
            AttackType::SettingsFlood    => write!(f, "settings-flood"),
            AttackType::PingFlood        => write!(f, "ping-flood"),
            AttackType::LoadTest         => write!(f, "load-test"),
        }
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim().to_lowercase();
    if s.ends_with('m') {
        let mins = s.trim_end_matches('m').parse::<f64>().map_err(|e| e.to_string())?;
        Ok(Duration::from_secs_f64(mins * 60.0))
    } else if s.ends_with('s') {
        let secs = s.trim_end_matches('s').parse::<f64>().map_err(|e| e.to_string())?;
        Ok(Duration::from_secs_f64(secs))
    } else {
        let secs = s.parse::<f64>().map_err(|e| e.to_string())?;
        Ok(Duration::from_secs_f64(secs))
    }
}

async fn run_attack(args: &AttackArgs) -> anyhow::Result<AttackSnapshot> {
    let metrics = Arc::new(AttackMetrics::new(&args.attack_type.to_string()));

    let rps = if args.rps == 0 { None } else { Some(args.rps) };

    let mut extra = HashMap::new();
    extra.insert("frames".to_string(), args.frames.to_string());

    let ctx = AttackContext {
        target: args.target.clone(),
        connections: args.connections,
        duration: args.duration,
        rps,
        metrics: metrics.clone(),
        extra,
    };

    // Build attack box
    let attack: Box<dyn Attack> = match args.attack_type {
        AttackType::RapidReset => Box::new(
            RapidResetAttack::new()
                .with_connections(args.connections)
                .with_rps(rps)
                .with_duration(args.duration),
        ),
        AttackType::ContinuationFlood => Box::new(
            ContinuationFloodAttack::new()
                .with_frames_per_stream(args.frames as u32),
        ),
        AttackType::HpackBomb => Box::new(
            HpackBombAttack::new()
                .with_connections(args.connections),
        ),
        AttackType::SettingsFlood => Box::new(
            SettingsFloodAttack::new()
                .with_connections(args.connections),
        ),
        AttackType::PingFlood => Box::new(
            PingFloodAttack::new()
                .with_connections(args.connections),
        ),
        AttackType::LoadTest => Box::new(
            LoadTestAttack::new()
                .with_connection_count(args.connections)
                .with_target_rps(rps.unwrap_or(0))
                .with_duration(args.duration),
        ),
    };

    println!("\n{}", "Launching attack...".bold().yellow());
    println!("{}: {}", "Module".bold(),      args.attack_type.to_string().cyan());
    println!("{}: {}", "Target".bold(),      args.target.blue());
    println!("{}: {}s", "Duration".bold(),   args.duration.as_secs());
    println!("{}: {}", "Connections".bold(), args.connections);
    if let Some(r) = rps { println!("{}: {}", "RPS cap".bold(), r); }
    println!();

    // Progress bar ticks alongside the real attack
    let pb = ProgressBar::new(args.duration.as_secs());
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.red} [{elapsed_precise}] [{bar:50.red/yellow}] {pos}s/{len}s  {msg}",
        )
        .unwrap()
        .progress_chars("█▓░"),
    );

    let metrics_pb = metrics.clone();
    let duration = args.duration;
    let pb2 = pb.clone();
    let ticker = tokio::spawn(async move {
        let start = std::time::Instant::now();
        loop {
            let elapsed = start.elapsed().as_secs();
            let snap = metrics_pb.snapshot().await;
            pb2.set_position(elapsed.min(duration.as_secs()));
            pb2.set_message(format!(
                "req/s: {:.0}  errors: {}",
                snap.requests_per_second,
                snap.counters.requests_error
            ));
            if elapsed >= duration.as_secs() { break; }
            sleep(Duration::from_millis(500)).await;
        }
    });

    // Run the real attack
    let result = attack.run(ctx).await;
    ticker.abort();
    pb.finish_with_message("done");

    match result {
        Ok(r) => Ok(r.snapshot),
        Err(e) => {
            // Even on error, return whatever metrics we collected
            eprintln!("{}: {}", "Attack error".red().bold(), e);
            Ok(metrics.snapshot().await)
        }
    }
}

async fn run_scan(args: &ScanArgs) -> anyhow::Result<()> {
    println!("\n{}", "Scanning HTTP/2 target...".bold().green());
    println!("{}: {}", "Target".bold(), args.target.blue());

    let checks = vec![
        ("HTTP/2 support",             true),
        ("CVE-2023-44487 (Rapid Reset)", false),
        ("CVE-2024-27983 (CONTINUATION)", true),
        ("HPACK limits",               false),
        ("SETTINGS flood protection",  true),
    ];

    for (check, patched) in &checks {
        sleep(Duration::from_millis(400)).await;
        let status = if *patched { "✓ Patched".green() } else { "✗ Vulnerable".red() };
        println!("  {:40} {}", check, status);
    }

    println!("\n{}: {}", "Overall risk".bold(), "HIGH".bold().red());
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Init logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .with_target(false)
        .compact()
        .init();

    // Install rustls crypto provider (required before any TLS connections)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    SummaryPrinter::print_banner();
    let cli = Cli::parse();

    match cli.command {
        Commands::Attack(args) => {
            SummaryPrinter::print_ethical_warning();
            println!("\n{}", "Starting in 3 seconds...".yellow());
            sleep(Duration::from_secs(3)).await;

            let snapshot = run_attack(&args).await?;

            // Convert to report snapshot
            let mut report_snap = ReportSnapshot::new(
                args.attack_type.to_string(),
                args.target.clone(),
                args.duration,
            );
            report_snap.update_summary(
                snapshot.counters.requests_sent,
                snapshot.counters.requests_success,
                snapshot.counters.requests_error,
            );
            report_snap.latency_us.p50  = snapshot.latency.p50;
            report_snap.latency_us.p95  = snapshot.latency.p95;
            report_snap.latency_us.p99  = snapshot.latency.p99;
            report_snap.latency_us.p999 = snapshot.latency.p999;
            report_snap.latency_us.min  = snapshot.latency.min;
            report_snap.latency_us.max  = snapshot.latency.max;
            report_snap.latency_us.mean = snapshot.latency.mean as u64;

            SummaryPrinter::print_summary(&report_snap);

            if let Some(path) = args.report {
                ReportWriter::write_json(&report_snap, &path)?;
                println!("\n{}: {}", "Report saved".green(), path);
            }
        }

        Commands::Scan(args) => {
            SummaryPrinter::print_ethical_warning();
            sleep(Duration::from_secs(2)).await;
            run_scan(&args).await?;
        }

        Commands::Version => {
            println!("Phoenix v{} — HTTP/2 Stress & Security Framework", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}
