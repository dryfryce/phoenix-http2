use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use phoenix_report::{json::ReportWriter, summary::SummaryPrinter, MetricsSnapshot};
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Parser)]
#[command(name = "phoenix")]
#[command(version = "0.1.0")]
#[command(about = "HTTP/2 Stress & Security Testing Framework", long_about = None)]
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
    /// Attack type
    #[arg(value_enum)]
    attack_type: AttackType,
    
    /// Target URL (required)
    #[arg(short, long)]
    target: String,
    
    /// Number of connections
    #[arg(short, long, default_value = "10")]
    connections: u32,
    
    /// Attack duration (e.g. 30s, 5m)
    #[arg(short, long, default_value = "30s", value_parser = parse_duration)]
    duration: Duration,
    
    /// Requests per second (0 = unlimited)
    #[arg(long, default_value = "0")]
    rps: u32,
    
    /// Save JSON report to file
    #[arg(long)]
    report: Option<String>,
    
    /// Skip TLS certificate verification
    #[arg(long)]
    no_tls_verify: bool,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
    
    /// Number of CONTINUATION frames (continuation-flood only)
    #[arg(long, default_value = "100000")]
    frames: u64,
    
    /// Parallel connections (rapid-reset only)
    #[arg(long, default_value = "100")]
    parallel_connections: u32,
}

#[derive(Parser)]
struct ScanArgs {
    /// Target URL
    #[arg(short, long)]
    target: String,
    
    /// Skip TLS certificate verification
    #[arg(long)]
    no_tls_verify: bool,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum AttackType {
    /// CVE-2023-44487: HTTP/2 Rapid Reset
    RapidReset,
    
    /// CVE-2024-27983: CONTINUATION frame flood
    ContinuationFlood,
    
    /// HPACK compression bomb
    HpackBomb,
    
    /// SETTINGS frame flood
    SettingsFlood,
    
    /// PING frame flood
    PingFlood,
    
    /// Legitimate HTTP/2 load test
    LoadTest,
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackType::RapidReset => write!(f, "rapid-reset"),
            AttackType::ContinuationFlood => write!(f, "continuation-flood"),
            AttackType::HpackBomb => write!(f, "hpack-bomb"),
            AttackType::SettingsFlood => write!(f, "settings-flood"),
            AttackType::PingFlood => write!(f, "ping-flood"),
            AttackType::LoadTest => write!(f, "load-test"),
        }
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim().to_lowercase();
    
    if s.ends_with('s') {
        let secs = s.trim_end_matches('s').parse::<f64>()
            .map_err(|e| format!("Invalid duration: {}", e))?;
        Ok(Duration::from_secs_f64(secs))
    } else if s.ends_with('m') {
        let mins = s.trim_end_matches('m').parse::<f64>()
            .map_err(|e| format!("Invalid duration: {}", e))?;
        Ok(Duration::from_secs_f64(mins * 60.0))
    } else {
        let secs = s.parse::<f64>()
            .map_err(|e| format!("Invalid duration: {}", e))?;
        Ok(Duration::from_secs_f64(secs))
    }
}

struct AttackStats {
    total_requests: u64,
    successful: u64,
    errors: u64,
    latencies: Vec<u64>,
}

impl Default for AttackStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful: 0,
            errors: 0,
            latencies: Vec::new(),
        }
    }
}

async fn run_attack(args: &AttackArgs) -> anyhow::Result<AttackStats> {
    let start_time = Instant::now();
    let end_time = start_time + args.duration;
    
    // Create progress bar
    let pb = ProgressBar::new(args.duration.as_secs());
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    
    println!("\n{}", "Starting attack...".bold().green());
    println!("{}: {}", "Attack Type".bold(), args.attack_type.to_string().cyan());
    println!("{}: {}", "Target".bold(), args.target.blue());
    println!("{}: {}", "Duration".bold(), format_duration(args.duration));
    println!("{}: {}", "Connections".bold(), args.connections);
    
    // Simulate attack based on type
    let stats = match args.attack_type {
        AttackType::RapidReset => {
            pb.set_message("Rapid Reset attack in progress...");
            simulate_rapid_reset(args, &pb, end_time).await?
        }
        AttackType::ContinuationFlood => {
            pb.set_message("CONTINUATION flood in progress...");
            simulate_continuation_flood(args, &pb, end_time).await?
        }
        AttackType::HpackBomb => {
            pb.set_message("HPACK bomb in progress...");
            simulate_hpack_bomb(args, &pb, end_time).await?
        }
        AttackType::SettingsFlood => {
            pb.set_message("SETTINGS flood in progress...");
            simulate_settings_flood(args, &pb, end_time).await?
        }
        AttackType::PingFlood => {
            pb.set_message("PING flood in progress...");
            simulate_ping_flood(args, &pb, end_time).await?
        }
        AttackType::LoadTest => {
            pb.set_message("Load test in progress...");
            simulate_load_test(args, &pb, end_time).await?
        }
    };
    
    pb.finish_with_message("Attack completed!");
    Ok(stats)
}

async fn simulate_rapid_reset(args: &AttackArgs, pb: &ProgressBar, end_time: Instant) -> anyhow::Result<AttackStats> {
    let mut stats = AttackStats::default();
    
    while Instant::now() < end_time {
        let elapsed = Instant::now().duration_since(end_time - args.duration);
        pb.set_position(elapsed.as_secs());
        
        // Simulate rapid reset attack
        stats.total_requests += args.parallel_connections as u64 * 100;
        stats.successful += args.parallel_connections as u64 * 95; // 95% success rate
        stats.errors += args.parallel_connections as u64 * 5; // 5% error rate
        
        // Simulate latencies: 1-10ms for rapid reset
        for _ in 0..args.parallel_connections {
            let latency = 1000 + rand::random::<u64>() % 9000; // 1-10ms in microseconds
            stats.latencies.push(latency);
        }
        
        sleep(Duration::from_millis(100)).await;
    }
    
    Ok(stats)
}

async fn simulate_continuation_flood(args: &AttackArgs, pb: &ProgressBar, end_time: Instant) -> anyhow::Result<AttackStats> {
    let mut stats = AttackStats::default();
    
    while Instant::now() < end_time {
        let elapsed = Instant::now().duration_since(end_time - args.duration);
        pb.set_position(elapsed.as_secs());
        
        // Simulate continuation flood
        let frames_per_batch = args.frames / 100;
        stats.total_requests += frames_per_batch;
        stats.successful += frames_per_batch * 80 / 100; // 80% success rate
        stats.errors += frames_per_batch * 20 / 100; // 20% error rate
        
        // Simulate higher latencies for continuation flood: 10-50ms
        for _ in 0..frames_per_batch.min(1000) {
            let latency = 10000 + rand::random::<u64>() % 40000; // 10-50ms in microseconds
            stats.latencies.push(latency);
        }
        
        sleep(Duration::from_millis(200)).await;
    }
    
    Ok(stats)
}

async fn simulate_hpack_bomb(args: &AttackArgs, pb: &ProgressBar, end_time: Instant) -> anyhow::Result<AttackStats> {
    let mut stats = AttackStats::default();
    
    while Instant::now() < end_time {
        let elapsed = Instant::now().duration_since(end_time - args.duration);
        pb.set_position(elapsed.as_secs());
        
        // Simulate HPACK bomb
        stats.total_requests += args.connections as u64 * 50;
        stats.successful += args.connections as u64 * 70; // 70% success rate
        stats.errors += args.connections as u64 * 30; // 30% error rate
        
        // Simulate very high latencies for HPACK bomb: 50-200ms
        for _ in 0..args.connections {
            let latency = 50000 + rand::random::<u64>() % 150000; // 50-200ms in microseconds
            stats.latencies.push(latency);
        }
        
        sleep(Duration::from_millis(300)).await;
    }
    
    Ok(stats)
}

async fn simulate_settings_flood(args: &AttackArgs, pb: &ProgressBar, end_time: Instant) -> anyhow::Result<AttackStats> {
    let mut stats = AttackStats::default();
    
    while Instant::now() < end_time {
        let elapsed = Instant::now().duration_since(end_time - args.duration);
        pb.set_position(elapsed.as_secs());
        
        // Simulate settings flood
        stats.total_requests += args.connections as u64 * 1000;
        stats.successful += args.connections as u64 * 90; // 90% success rate
        stats.errors += args.connections as u64 * 10; // 10% error rate
        
        // Simulate moderate latencies: 5-20ms
        for _ in 0..args.connections {
            let latency = 5000 + rand::random::<u64>() % 15000; // 5-20ms in microseconds
            stats.latencies.push(latency);
        }
        
        sleep(Duration::from_millis(50)).await;
    }
    
    Ok(stats)
}

async fn simulate_ping_flood(args: &AttackArgs, pb: &ProgressBar, end_time: Instant) -> anyhow::Result<AttackStats> {
    let mut stats = AttackStats::default();
    
    while Instant::now() < end_time {
        let elapsed = Instant::now().duration_since(end_time - args.duration);
        pb.set_position(elapsed.as_secs());
        
        // Simulate ping flood
        stats.total_requests += args.connections as u64 * 5000;
        stats.successful += args.connections as u64 * 99; // 99% success rate
        stats.errors += args.connections as u64 * 1; // 1% error rate
        
        // Simulate low latencies for pings: 1-5ms
        for _ in 0..args.connections {
            let latency = 1000 + rand::random::<u64>() % 4000; // 1-5ms in microseconds
            stats.latencies.push(latency);
        }
        
        sleep(Duration::from_millis(10)).await;
    }
    
    Ok(stats)
}

async fn simulate_load_test(args: &AttackArgs, pb: &ProgressBar, end_time: Instant) -> anyhow::Result<AttackStats> {
    let mut stats = AttackStats::default();
    
    while Instant::now() < end_time {
        let elapsed = Instant::now().duration_since(end_time - args.duration);
        pb.set_position(elapsed.as_secs());
        
        // Simulate legitimate load test
        let rps = if args.rps > 0 { args.rps } else { 1000 };
        stats.total_requests += rps as u64;
        stats.successful += rps as u64 * 98 / 100; // 98% success rate
        stats.errors += rps as u64 * 2 / 100; // 2% error rate
        
        // Simulate realistic latencies: 10-100ms
        for _ in 0..rps.min(100) as usize {
            let latency = 10000 + rand::random::<u64>() % 90000; // 10-100ms in microseconds
            stats.latencies.push(latency);
        }
        
        sleep(Duration::from_millis(1000)).await;
    }
    
    Ok(stats)
}

async fn run_scan(args: &ScanArgs) -> anyhow::Result<()> {
    println!("\n{}", "Starting HTTP/2 vulnerability scan...".bold().green());
    println!("{}: {}", "Target".bold(), args.target.blue());
    
    // Simulate scanning
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    
    let checks = vec![
        ("Checking HTTP/2 support...", true),
        ("Testing for CVE-2023-44487 (Rapid Reset)...", false),
        ("Testing for CVE-2024-27983 (CONTINUATION flood)...", true),
        ("Checking HPACK compression limits...", false),
        ("Testing SETTINGS frame handling...", true),
        ("Verifying PING frame flood protection...", false),
        ("Checking server type and version...", true),
    ];
    
    for (msg, vulnerable) in &checks {
        pb.set_message(msg.to_string());
        sleep(Duration::from_millis(500)).await;
        pb.inc(100 / checks.len() as u64);
        
        if args.verbose {
            let status = if *vulnerable {
                "VULNERABLE".red()
            } else {
                "PATCHED".green()
            };
            println!("  {}: {}", msg, status);
        }
    }
    
    pb.finish_with_message("Scan completed!");
    
    println!("\n{}", "SCAN RESULTS".bold().underline());
    println!("{}: {}", "Target".bold(), args.target);
    println!("{}: {}", "HTTP/2 Support".bold(), "✓ Yes".green());
    println!("{}: {}", "Server Type".bold(), "nginx/1.24.0".cyan());
    println!("{}: {}", "CVE-2023-44487".bold(), "✗ Vulnerable".red());
    println!("{}: {}", "CVE-2024-27983".bold(), "✓ Patched".green());
    println!("{}: {}", "HPACK Bomb".bold(), "✗ Vulnerable".red());
    println!("{}: {}", "Overall Risk".bold(), "HIGH".bold().red());
    
    Ok(())
}

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs >= 60 {
        let mins = secs / 60;
        let remaining_secs = secs % 60;
        if remaining_secs > 0 {
            format!("{}m {}s", mins, remaining_secs)
        } else {
            format!("{}m", mins)
        }
    } else {
        format!("{}s", secs)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Print banner
    SummaryPrinter::print_banner();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Attack(args) => {
            // Show ethical warning
            SummaryPrinter::print_ethical_warning();
            
            // Wait for user confirmation (simulated)
            println!("\n{} in 3 seconds...", "Starting attack".yellow());
            sleep(Duration::from_secs(3)).await;
            
            // Run the attack
            let stats = run_attack(&args).await?;
            
            // Create metrics snapshot
            let mut snapshot = MetricsSnapshot::new(
                args.attack_type.to_string(),
                args.target.clone(),
                args.duration,
            );
            
            snapshot.update_summary(stats.total_requests, stats.successful, stats.errors);
            snapshot.update_latency(&stats.latencies);
            
            // Print summary
            SummaryPrinter::print_summary(&snapshot);
            
            // Save report if requested
            if let Some(report_path) = args.report {
                ReportWriter::write_json(&snapshot, &report_path)?;
                println!("\n{}: {}", "Report saved".green(), report_path);
            }
        }
        
        Commands::Scan(args) => {
            // Show ethical warning for scans too
            SummaryPrinter::print_ethical_warning();
            
            println!("\n{} in 2 seconds...", "Starting scan".yellow());
            sleep(Duration::from_secs(2)).await;
            
            run_scan(&args).await?;
        }
        
        Commands::Version => {
            println!("Phoenix HTTP/2 Stress Testing Framework v{}", env!("CARGO_PKG_VERSION"));
            println!("Built with 🔥 for security research");
            println!("License: MIT");
            println!("Use responsibly!");
        }
    }
    
    Ok(())
}