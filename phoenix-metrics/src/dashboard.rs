//! Terminal dashboard for live monitoring of HTTP/2 stress tests

use std::sync::Arc;
use std::time::Duration;
use std::io::{self, stdout};
use std::error::Error;

use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, Gauge},
    Frame, Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use crate::metrics::{AttackMetrics, MetricsSnapshot};

/// Terminal dashboard for monitoring HTTP/2 stress tests
pub struct PhoenixDashboard {
    attack_name: String,
    target_url: String,
    status_log: Vec<String>,
}

impl PhoenixDashboard {
    /// Create a new dashboard for the given attack
    pub fn new(attack_name: &str, target_url: &str) -> Self {
        Self {
            attack_name: attack_name.to_string(),
            target_url: target_url.to_string(),
            status_log: Vec::new(),
        }
    }

    /// Add a status message to the log (keeps last 5 messages)
    fn add_status(&mut self, message: String) {
        self.status_log.push(message);
        if self.status_log.len() > 5 {
            self.status_log.remove(0);
        }
    }

    /// Run the dashboard with the given metrics for the specified duration
    pub async fn run(
        &mut self,
        metrics: Arc<AttackMetrics>,
        duration: Duration,
    ) -> Result<(), Box<dyn Error>> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let start_time = std::time::Instant::now();
        let mut last_update = std::time::Instant::now();
        
        self.add_status("Dashboard started".to_string());
        self.add_status(format!("Attack: {}", self.attack_name));
        self.add_status(format!("Target: {}", self.target_url));

        // Main render loop
        let result = loop {
            // Check if duration has elapsed
            if start_time.elapsed() >= duration {
                self.add_status("Attack completed".to_string());
                break Ok(());
            }

            // Update at 10Hz
            if last_update.elapsed() >= Duration::from_millis(100) {
                terminal.draw(|f| {
                    let snapshot = futures::executor::block_on(metrics.snapshot());
                    Self::render(f, &snapshot, &self);
                })?;
                last_update = std::time::Instant::now();
            }

            // Handle keyboard events
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            self.add_status("Dashboard stopped by user".to_string());
                            break Ok(());
                        }
                        KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                            self.add_status("Dashboard stopped by Ctrl+C".to_string());
                            break Ok(());
                        }
                        _ => {}
                    }
                }
            }
        };

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }

    /// Render the dashboard UI
    pub fn render<B: Backend>(frame: &mut Frame<B>, snapshot: &MetricsSnapshot, dashboard: &PhoenixDashboard) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Length(2),  // Attack info
                Constraint::Length(4),  // Live counters
                Constraint::Length(8),  // Latency table
                Constraint::Length(3),  // Progress bar
                Constraint::Length(7),  // Status log
                Constraint::Min(0),     // Spacer
            ])
            .split(frame.size());

        // Header with fire colors
        let header = Paragraph::new("PHOENIX HTTP/2 STRESS FRAMEWORK")
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
            .alignment(ratatui::layout::Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(header, chunks[0]);

        // Attack info
        let attack_info = vec![
            Line::from(vec![
                Span::styled("Attack: ", Style::default().fg(Color::Yellow)),
                Span::raw(&dashboard.attack_name),
            ]),
            Line::from(vec![
                Span::styled("Target: ", Style::default().fg(Color::Yellow)),
                Span::raw(&dashboard.target_url),
            ]),
            Line::from(vec![
                Span::styled("Duration: ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{:.1}s", snapshot.elapsed_seconds)),
            ]),
        ];
        let info_block = Paragraph::new(attack_info)
            .block(Block::default().borders(Borders::ALL).title("Attack Info"));
        frame.render_widget(info_block, chunks[1]);

        // Live counters
        let counters_data = vec![
            Row::new(vec![
                "Req/s",
                &format!("{:.1}", snapshot.requests_per_second),
            ]),
            Row::new(vec![
                "Total Requests",
                &format!("{}", snapshot.counters.requests_sent),
            ]),
            Row::new(vec![
                "Success",
                &format!("{}", snapshot.counters.requests_success),
            ]),
            Row::new(vec![
                "Errors",
                &format!("{}", snapshot.counters.requests_error),
            ]),
            Row::new(vec![
                "Active Connections",
                &format!("{}", snapshot.counters.connections_active),
            ]),
            Row::new(vec![
                "Bytes Sent",
                &format!("{:.2} MB", snapshot.counters.bytes_sent as f64 / 1_000_000.0),
            ]),
            Row::new(vec![
                "Bytes Received",
                &format!("{:.2} MB", snapshot.counters.bytes_received as f64 / 1_000_000.0),
            ]),
        ];
        
        let counters_table = Table::new(counters_data, &[Constraint::Length(20), Constraint::Length(20)])
            .block(Block::default().borders(Borders::ALL).title("Live Counters"))
            .style(Style::default().fg(Color::White))
            .column_spacing(1);
        frame.render_widget(counters_table, chunks[2]);

        // Latency table
        let latency_data = vec![
            Row::new(vec![
                "p50",
                &format!("{:.2} ms", snapshot.latency.p50 as f64 / 1000.0),
            ]),
            Row::new(vec![
                "p95",
                &format!("{:.2} ms", snapshot.latency.p95 as f64 / 1000.0),
            ]),
            Row::new(vec![
                "p99",
                &format!("{:.2} ms", snapshot.latency.p99 as f64 / 1000.0),
            ]),
            Row::new(vec![
                "p99.9",
                &format!("{:.2} ms", snapshot.latency.p999 as f64 / 1000.0),
            ]),
            Row::new(vec![
                "Min",
                &format!("{:.2} ms", snapshot.latency.min as f64 / 1000.0),
            ]),
            Row::new(vec![
                "Max",
                &format!("{:.2} ms", snapshot.latency.max as f64 / 1000.0),
            ]),
            Row::new(vec![
                "Mean",
                &format!("{:.2} ms", snapshot.latency.mean as f64 / 1000.0),
            ]),
        ];
        
        let latency_table = Table::new(latency_data, &[Constraint::Length(10), Constraint::Length(15)])
            .block(Block::default().borders(Borders::ALL).title("Latency (ms)"))
            .style(Style::default().fg(Color::Cyan))
            .column_spacing(1);
        frame.render_widget(latency_table, chunks[3]);

        // Progress bar (simulated - in real usage would show attack progress)
        let progress = (snapshot.elapsed_seconds % 10.0) / 10.0; // Simulated progress
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Progress"))
            .gauge_style(Style::default().fg(Color::Green))
            .percent((progress * 100.0) as u16);
        frame.render_widget(gauge, chunks[4]);

        // Status log
        let status_lines: Vec<Line> = dashboard.status_log
            .iter()
            .map(|msg| Line::from(Span::raw(msg)))
            .collect();
        
        let status_block = Paragraph::new(status_lines)
            .block(Block::default().borders(Borders::ALL).title("Status Log"))
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(status_block, chunks[5]);

        // Help text at the bottom
        let help_text = Paragraph::new("Press 'q' or ESC to quit | Ctrl+C to stop")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(help_text, chunks[6]);
    }
}