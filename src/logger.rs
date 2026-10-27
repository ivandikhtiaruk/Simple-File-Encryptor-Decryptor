use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

pub enum Operation {
    Encrypt,
    Decrypt,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Encrypt => write!(f, "ENCRYPT"),
            Operation::Decrypt => write!(f, "DECRYPT"),
        }
    }
}

pub struct AuditLogger;

impl AuditLogger {
    const LOG_FILE: &'static str = "security_audit.log";

    pub fn log_event(
        op: Operation,
        filepath: &Path,
        filesize: u64,
        success: bool,
        details: &str,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let status_str = if success { "SUCCESS" } else { "FAILED" };
        let path_str = filepath.to_string_lossy();

        let log_entry = format!(
            "[{}] OP={} | FILE=\"{}\" | SIZE={} B | STATUS={} | MSG=\"{}\"\n",
            timestamp, op, path_str, filesize, status_str, details
        );

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(Self::LOG_FILE)
        {
            let _ = file.write_all(log_entry.as_bytes());
            let _ = file.flush();
        }
    }
}
