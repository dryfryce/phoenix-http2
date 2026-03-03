//! JSON report writer for Phoenix metrics

use crate::MetricsSnapshot;
use anyhow::Result;
use serde_json;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Report writer that writes MetricsSnapshot to JSON file
pub struct ReportWriter;

impl ReportWriter {
    /// Write metrics snapshot to JSON file
    pub fn write_json<P: AsRef<Path>>(snapshot: &MetricsSnapshot, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(snapshot)?;
        
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        
        Ok(())
    }

    /// Write metrics snapshot to JSON string
    pub fn to_json_string(snapshot: &MetricsSnapshot) -> Result<String> {
        Ok(serde_json::to_string_pretty(snapshot)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    #[test]
    fn test_write_json() {
        let mut snapshot = MetricsSnapshot::new(
            "rapid-reset".to_string(),
            "https://example.com".to_string(),
            Duration::from_secs(30),
        );
        
        snapshot.update_summary(1234567, 1200000, 34567);
        snapshot.update_latency(&[234, 1234, 5678, 12345, 45678, 98765, 2345]);
        
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        
        assert!(ReportWriter::write_json(&snapshot, path).is_ok());
        
        // Verify file contains expected data
        let content = std::fs::read_to_string(path).unwrap();
        assert!(content.contains("\"attack\": \"rapid-reset\""));
        assert!(content.contains("\"target\": \"https://example.com\""));
        assert!(content.contains("\"total_requests\": 1234567"));
    }

    #[test]
    fn test_to_json_string() {
        let mut snapshot = MetricsSnapshot::new(
            "continuation-flood".to_string(),
            "https://test.com".to_string(),
            Duration::from_secs(15),
        );
        
        snapshot.update_summary(500000, 490000, 10000);
        
        let json = ReportWriter::to_json_string(&snapshot).unwrap();
        assert!(json.contains("\"continuation-flood\""));
        assert!(json.contains("\"https://test.com\""));
        assert!(json.contains("\"duration_secs\": 15.0"));
    }
}