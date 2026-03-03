//! Terminal summary printer for Phoenix attack results

use crate::MetricsSnapshot;
use colored::*;

/// Terminal summary printer
pub struct SummaryPrinter;

impl SummaryPrinter {
    /// Print a nicely formatted attack summary
    pub fn print_summary(snapshot: &MetricsSnapshot) {
        println!("\n{}", "=".repeat(60).cyan());
        println!("{}", " PHOENIX ATTACK SUMMARY ".bold().on_cyan().black());
        println!("{}", "=".repeat(60).cyan());
        
        // Basic info
        println!("{}: {}", "Attack".bold(), snapshot.attack.green());
        println!("{}: {}", "Target".bold(), snapshot.target.blue());
        println!("{}: {:.2}s", "Duration".bold(), snapshot.duration_secs);
        println!("{}: {}", "Started".bold(), snapshot.started_at.format("%Y-%m-%d %H:%M:%S UTC"));
        
        println!("\n{}", "-".repeat(60).dimmed());
        
        // Summary statistics
        let summary = &snapshot.summary;
        println!("{}", "PERFORMANCE STATISTICS".bold().underline());
        
        let rps_color = if summary.requests_per_second > 1000.0 {
            Color::Green
        } else if summary.requests_per_second > 100.0 {
            Color::Yellow
        } else {
            Color::Red
        };
        
        let error_color = if summary.error_rate_pct < 1.0 {
            Color::Green
        } else if summary.error_rate_pct < 5.0 {
            Color::Yellow
        } else {
            Color::Red
        };
        
        println!("{}: {:>12}", "Total Requests".bold(), summary.total_requests.to_string().cyan());
        println!("{}: {:>12}", "Successful".bold(), summary.successful.to_string().green());
        println!("{}: {:>12}", "Errors".bold(), summary.errors.to_string().red());
        println!("{}: {:>12.1}", "Requests/sec".bold(), summary.requests_per_second.to_string().color(rps_color));
        println!("{}: {:>12.2}%", "Error Rate".bold(), summary.error_rate_pct.to_string().color(error_color));
        
        println!("\n{}", "-".repeat(60).dimmed());
        
        // Latency statistics
        let latency = &snapshot.latency_us;
        println!("{}", "LATENCY STATISTICS (μs)".bold().underline());
        
        if latency.mean > 0 {
            let latency_table = vec![
                ("Min".to_string(), latency.min, Color::Green),
                ("Mean".to_string(), latency.mean, Color::Yellow),
                ("p50".to_string(), latency.p50, Color::Cyan),
                ("p95".to_string(), latency.p95, Color::Magenta),
                ("p99".to_string(), latency.p99, Color::Red),
                ("p999".to_string(), latency.p999, Color::Red),
                ("Max".to_string(), latency.max, Color::Red),
            ];
            
            for (label, value, color) in latency_table {
                println!("  {:>6}: {:>12}", label.bold(), value.to_string().color(color));
            }
            
            // Add latency interpretation
            println!("\n{}", "LATENCY INTERPRETATION".dimmed().italic());
            if latency.p95 < 1000 {
                println!("  {} Excellent performance (<1ms p95)", "✓".green());
            } else if latency.p95 < 5000 {
                println!("  {} Good performance (<5ms p95)", "✓".yellow());
            } else if latency.p95 < 10000 {
                println!("  {} Moderate performance (<10ms p95)", "⚠".yellow());
            } else {
                println!("  {} Poor performance (≥10ms p95)", "✗".red());
            }
        } else {
            println!("  {} No latency data available", "⚠".yellow());
        }
        
        println!("\n{}", "=".repeat(60).cyan());
        
        // Final status
        if summary.error_rate_pct > 10.0 {
            println!("{}", "⚠  HIGH ERROR RATE DETECTED".bold().on_yellow().black());
        } else if summary.requests_per_second > 10000.0 {
            println!("{}", "✓  HIGH THROUGHPUT ACHIEVED".bold().on_green().black());
        } else {
            println!("{}", "✓  ATTACK COMPLETED".bold().on_blue().black());
        }
        
        println!("{}", "=".repeat(60).cyan());
    }

    /// Print a warning message before starting an attack
    pub fn print_ethical_warning() {
        println!("\n{}", "⚠".repeat(60).yellow());
        println!("{}", " ETHICAL WARNING ".bold().on_yellow().black());
        println!("{}", "⚠".repeat(60).yellow());
        
        let warnings = vec![
            "This tool is for authorized security testing only.",
            "You MUST have explicit permission to test the target system.",
            "Unauthorized testing is illegal and unethical.",
            "Use only on systems you own or have authorization to test.",
            "You are responsible for complying with all applicable laws.",
        ];
        
        for warning in warnings {
            println!("  {} {}", "•".yellow(), warning.red());
        }
        
        println!("\n{}", "By continuing, you acknowledge and accept these terms.".bold());
        println!("{}", "Press Ctrl+C to abort.".italic().dimmed());
        println!("{}", "⚠".repeat(60).yellow());
    }

    /// Print the Phoenix banner
    pub fn print_banner() {
        let banner = r#"
 ██████╗ ██╗  ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗
 ██╔══██╗██║  ██║██╔═══██╗██╔════╝████╗  ██║██║╚██╗██╔╝
 ██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║██║ ╚███╔╝ 
 ██╔═══╝ ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ 
 ██║     ██║  ██║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗
 ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
 HTTP/2 Stress & Security Testing Framework 🔥
 USE ONLY ON SYSTEMS YOU OWN OR HAVE AUTHORIZATION TO TEST
"#;
        
        println!("{}", banner.cyan());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_summary_printer() {
        let mut snapshot = MetricsSnapshot::new(
            "rapid-reset".to_string(),
            "https://example.com".to_string(),
            Duration::from_secs(30),
        );
        
        snapshot.update_summary(1234567, 1200000, 34567);
        snapshot.update_latency(&[234, 1234, 5678, 12345, 45678, 98765, 2345]);
        
        // This should not panic
        SummaryPrinter::print_summary(&snapshot);
    }
}