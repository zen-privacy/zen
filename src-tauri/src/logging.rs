//! Logging infrastructure for capturing and buffering sing-box logs
//!
//! This module provides log capture, buffering, and retrieval functionality
//! for the VPN application, enabling users to view and export diagnostic logs.

// Allow unused code for infrastructure that may be used in future features
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of log entries to keep in the circular buffer
const MAX_LOG_ENTRIES: usize = 1000;

/// Log severity levels matching sing-box output levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Panic,
}

impl LogLevel {
    /// Parse a log level from a string
    pub fn from_str(s: &str) -> Option<LogLevel> {
        match s.to_lowercase().as_str() {
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "warn" | "warning" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            "fatal" => Some(LogLevel::Fatal),
            "panic" => Some(LogLevel::Panic),
            _ => None,
        }
    }

    /// Get the string representation of the log level
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Fatal => "fatal",
            LogLevel::Panic => "panic",
        }
    }

    /// Get the numeric priority of the log level (higher = more severe)
    pub fn priority(&self) -> u8 {
        match self {
            LogLevel::Debug => 0,
            LogLevel::Info => 1,
            LogLevel::Warn => 2,
            LogLevel::Error => 3,
            LogLevel::Fatal => 4,
            LogLevel::Panic => 5,
        }
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

/// A single log entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// Log severity level
    pub level: LogLevel,
    /// Log message content
    pub message: String,
    /// Source of the log (e.g., "sing-box", "app")
    pub source: String,
}

impl LogEntry {
    /// Create a new log entry with the current timestamp
    pub fn new(level: LogLevel, message: String, source: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        LogEntry {
            timestamp,
            level,
            message,
            source,
        }
    }

    /// Create a new log entry from sing-box output
    pub fn from_singbox(level: LogLevel, message: String) -> Self {
        Self::new(level, message, "sing-box".to_string())
    }

    /// Create a new log entry from the application
    pub fn from_app(level: LogLevel, message: String) -> Self {
        Self::new(level, message, "app".to_string())
    }
}

/// A thread-safe circular buffer for storing log entries
///
/// This buffer maintains a fixed maximum size and automatically
/// removes the oldest entries when the limit is reached.
#[derive(Debug, Clone)]
pub struct CircularLogBuffer {
    entries: Arc<RwLock<VecDeque<LogEntry>>>,
    max_size: usize,
}

impl Default for CircularLogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl CircularLogBuffer {
    /// Create a new circular log buffer with the default capacity (1000 entries)
    pub fn new() -> Self {
        Self::with_capacity(MAX_LOG_ENTRIES)
    }

    /// Create a new circular log buffer with a custom capacity
    pub fn with_capacity(max_size: usize) -> Self {
        CircularLogBuffer {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(max_size))),
            max_size,
        }
    }

    /// Add a log entry to the buffer
    ///
    /// If the buffer is full, the oldest entry will be removed.
    pub fn push(&self, entry: LogEntry) {
        if let Ok(mut entries) = self.entries.write() {
            if entries.len() >= self.max_size {
                entries.pop_front();
            }
            entries.push_back(entry);
        }
    }

    /// Add a log entry with the given level and message
    pub fn log(&self, level: LogLevel, message: String, source: &str) {
        self.push(LogEntry::new(level, message, source.to_string()));
    }

    /// Get all log entries
    pub fn get_all(&self) -> Vec<LogEntry> {
        self.entries
            .read()
            .map(|entries| entries.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get log entries filtered by minimum log level
    pub fn get_filtered(&self, min_level: LogLevel) -> Vec<LogEntry> {
        self.entries
            .read()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.level.priority() >= min_level.priority())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the most recent N log entries
    pub fn get_recent(&self, count: usize) -> Vec<LogEntry> {
        self.entries
            .read()
            .map(|entries| {
                let skip = entries.len().saturating_sub(count);
                entries.iter().skip(skip).cloned().collect()
            })
            .unwrap_or_default()
    }

    /// Get log entries since a given timestamp
    pub fn get_since(&self, timestamp: u64) -> Vec<LogEntry> {
        self.entries
            .read()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.timestamp > timestamp)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Clear all log entries
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
    }

    /// Get the current number of entries in the buffer
    pub fn len(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Export all logs as a formatted string for saving to file
    pub fn export_as_text(&self) -> String {
        self.entries
            .read()
            .map(|entries| {
                entries
                    .iter()
                    .map(|e| {
                        let datetime = format_timestamp(e.timestamp);
                        format!(
                            "[{}] [{}] [{}] {}",
                            datetime,
                            e.level.as_str().to_uppercase(),
                            e.source,
                            e.message
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }
}

/// Thread-safe state for managing log level filter settings
///
/// This struct allows the UI to control the minimum log level displayed.
#[derive(Debug)]
pub struct LogFilterState {
    min_level: Mutex<LogLevel>,
}

impl Default for LogFilterState {
    fn default() -> Self {
        Self::new()
    }
}

impl LogFilterState {
    /// Create a new LogFilterState with default level (Info)
    pub fn new() -> Self {
        LogFilterState {
            min_level: Mutex::new(LogLevel::Info),
        }
    }

    /// Get the current minimum log level
    pub fn get_level(&self) -> LogLevel {
        *self.min_level.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Set the minimum log level
    pub fn set_level(&self, level: LogLevel) {
        if let Ok(mut current) = self.min_level.lock() {
            *current = level;
        }
    }
}

/// Format a Unix timestamp in milliseconds to a human-readable string
fn format_timestamp(timestamp_ms: u64) -> String {
    use std::time::Duration;

    let secs = timestamp_ms / 1000;
    let millis = timestamp_ms % 1000;

    // Simple ISO-like format without external dependencies
    let duration = Duration::from_secs(secs);
    let total_secs = duration.as_secs();

    let seconds = total_secs % 60;
    let minutes = (total_secs / 60) % 60;
    let hours = (total_secs / 3600) % 24;
    let days = total_secs / 86400;

    // Calculate approximate date from days since epoch
    let (year, month, day) = days_to_date(days);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        year, month, day, hours, minutes, seconds, millis
    )
}

/// Convert days since Unix epoch to (year, month, day)
fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Simple calculation - not handling leap years perfectly but good enough for logs
    let mut remaining_days = days;
    let mut year = 1970u64;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u64;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;

    (year, month, day)
}

/// Check if a year is a leap year
fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Strip ANSI escape codes from a string
///
/// Handles both standard ESC[...m sequences and bare [...m sequences
/// that sing-box outputs when logging to a file.
fn strip_ansi_codes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        // Check for ESC (0x1b) followed by [
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            // Skip ESC[...m sequence
            i += 2;
            while i < bytes.len() && bytes[i] != b'm' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // skip 'm'
            }
        // Check for bare [ followed by digits/semicolons and m
        } else if bytes[i] == b'[' {
            // Look ahead to see if this is an ANSI-like sequence [NNm or [NN;NN;NNm
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b';') {
                j += 1;
            }
            if j > i + 1 && j < bytes.len() && bytes[j] == b'm' {
                // This is an ANSI code like [36m or [38;5;178m - skip it
                i = j + 1;
            } else {
                result.push(bytes[i]);
                i += 1;
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8(result).unwrap_or_else(|_| s.to_string())
}

/// Parse a single line of sing-box log output
///
/// Sing-box log formats (various):
/// `2024-01-15T12:34:56.789+0000 info router: message here`
/// `+0300 2026-02-08 07:39:36 INFO network: updated default interface`
/// `info[0000] message here`
/// `WARN[0000] message here`
pub fn parse_singbox_line(line: &str) -> Option<LogEntry> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Strip ANSI color codes first (sing-box outputs colored logs even to files)
    let clean = strip_ansi_codes(line);
    let clean = clean.trim();
    if clean.is_empty() {
        return None;
    }

    // Try to parse offset timestamp format: "+0300 2026-02-08 07:39:36 level message"
    if let Some(entry) = parse_offset_timestamp_line(clean) {
        return Some(entry);
    }

    // Try to parse ISO timestamped format: "2024-01-15T12:34:56.789+0000 level message"
    if let Some(entry) = parse_timestamped_line(clean) {
        return Some(entry);
    }

    // Try to parse bracket format: "level[0000] message"
    if let Some(entry) = parse_bracket_line(clean) {
        return Some(entry);
    }

    // Try to parse simple format: "level message" or "level: message"
    if let Some(entry) = parse_simple_line(clean) {
        return Some(entry);
    }

    // Fallback: treat the entire line as an info message
    Some(LogEntry::from_singbox(LogLevel::Info, clean.to_string()))
}

/// Parse offset timestamp format sing-box log line
/// Format: "+0300 2026-02-08 07:39:36 INFO network: updated default interface"
/// The timezone offset comes first, then date, then time, then level
fn parse_offset_timestamp_line(line: &str) -> Option<LogEntry> {
    // Must start with + or - (timezone offset)
    if !line.starts_with('+') && !line.starts_with('-') {
        return None;
    }

    // Split into parts: ["+0300", "2026-02-08", "07:39:36", "INFO", ...]
    let parts: Vec<&str> = line.splitn(5, ' ').collect();
    if parts.len() < 4 {
        return None;
    }

    // Validate: parts[0] should be timezone offset like +0300
    let offset = parts[0];
    if offset.len() < 4 || !offset[1..].chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    // parts[1] should look like a date (YYYY-MM-DD)
    if !parts[1].contains('-') || parts[1].len() < 8 {
        return None;
    }

    // parts[3] is the log level
    let level = LogLevel::from_str(parts[3])?;

    let message = if parts.len() > 4 {
        parts[4].to_string()
    } else {
        String::new()
    };

    Some(LogEntry::from_singbox(level, message))
}

/// Parse timestamped sing-box log line
/// Format: "2024-01-15T12:34:56.789+0000 info router: message"
fn parse_timestamped_line(line: &str) -> Option<LogEntry> {
    // Check if line starts with a timestamp pattern (YYYY-MM-DD)
    if line.len() < 25 || !line.chars().next()?.is_ascii_digit() {
        return None;
    }

    // Find the space after the timestamp
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }

    let timestamp_str = parts[0];
    // Validate timestamp format (should contain 'T' for ISO format)
    if !timestamp_str.contains('T') {
        return None;
    }

    let level_str = parts[1];
    let level = LogLevel::from_str(level_str)?;

    let message = if parts.len() > 2 {
        parts[2].to_string()
    } else {
        String::new()
    };

    Some(LogEntry::from_singbox(level, message))
}

/// Parse bracket format sing-box log line
/// Format: "info[0000] message" or "error[router] message"
fn parse_bracket_line(line: &str) -> Option<LogEntry> {
    let bracket_start = line.find('[')?;
    let bracket_end = line.find(']')?;

    if bracket_start == 0 || bracket_end <= bracket_start {
        return None;
    }

    let level_str = &line[..bracket_start];
    let level = LogLevel::from_str(level_str)?;

    let message = if bracket_end + 1 < line.len() {
        line[bracket_end + 1..].trim().to_string()
    } else {
        String::new()
    };

    Some(LogEntry::from_singbox(level, message))
}

/// Parse simple format sing-box log line
/// Format: "level message" or "level: message"
fn parse_simple_line(line: &str) -> Option<LogEntry> {
    // Try "level: message" format first
    if let Some(colon_pos) = line.find(':') {
        let potential_level = line[..colon_pos].trim();
        // Only treat as level if it's a single word (no spaces)
        if !potential_level.contains(' ') {
            if let Some(level) = LogLevel::from_str(potential_level) {
                let message = line[colon_pos + 1..].trim().to_string();
                return Some(LogEntry::from_singbox(level, message));
            }
        }
    }

    // Try "level message" format (first word is level)
    let mut parts = line.splitn(2, ' ');
    let level_str = parts.next()?;
    let level = LogLevel::from_str(level_str)?;
    let message = parts.next().unwrap_or("").to_string();

    Some(LogEntry::from_singbox(level, message))
}

/// Process multiple lines of sing-box output and add to buffer
pub fn process_singbox_output(buffer: &CircularLogBuffer, output: &str) {
    for line in output.lines() {
        if let Some(entry) = parse_singbox_line(line) {
            buffer.push(entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_str() {
        assert_eq!(LogLevel::from_str("debug"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::from_str("INFO"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("warn"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_str("fatal"), Some(LogLevel::Fatal));
        assert_eq!(LogLevel::from_str("panic"), Some(LogLevel::Panic));
        assert_eq!(LogLevel::from_str("unknown"), None);
    }

    #[test]
    fn test_log_level_priority() {
        assert!(LogLevel::Debug.priority() < LogLevel::Info.priority());
        assert!(LogLevel::Info.priority() < LogLevel::Warn.priority());
        assert!(LogLevel::Warn.priority() < LogLevel::Error.priority());
        assert!(LogLevel::Error.priority() < LogLevel::Fatal.priority());
        assert!(LogLevel::Fatal.priority() < LogLevel::Panic.priority());
    }

    #[test]
    fn test_circular_buffer_basic() {
        let buffer = CircularLogBuffer::with_capacity(3);
        assert!(buffer.is_empty());

        buffer.log(LogLevel::Info, "msg1".to_string(), "test");
        buffer.log(LogLevel::Warn, "msg2".to_string(), "test");
        buffer.log(LogLevel::Error, "msg3".to_string(), "test");

        assert_eq!(buffer.len(), 3);

        let entries = buffer.get_all();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].message, "msg1");
        assert_eq!(entries[1].message, "msg2");
        assert_eq!(entries[2].message, "msg3");
    }

    #[test]
    fn test_circular_buffer_overflow() {
        let buffer = CircularLogBuffer::with_capacity(3);

        buffer.log(LogLevel::Info, "msg1".to_string(), "test");
        buffer.log(LogLevel::Info, "msg2".to_string(), "test");
        buffer.log(LogLevel::Info, "msg3".to_string(), "test");
        buffer.log(LogLevel::Info, "msg4".to_string(), "test");

        assert_eq!(buffer.len(), 3);

        let entries = buffer.get_all();
        assert_eq!(entries[0].message, "msg2");
        assert_eq!(entries[1].message, "msg3");
        assert_eq!(entries[2].message, "msg4");
    }

    #[test]
    fn test_filter_by_level() {
        let buffer = CircularLogBuffer::new();

        buffer.log(LogLevel::Debug, "debug msg".to_string(), "test");
        buffer.log(LogLevel::Info, "info msg".to_string(), "test");
        buffer.log(LogLevel::Warn, "warn msg".to_string(), "test");
        buffer.log(LogLevel::Error, "error msg".to_string(), "test");

        let filtered = buffer.get_filtered(LogLevel::Warn);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].message, "warn msg");
        assert_eq!(filtered[1].message, "error msg");
    }

    #[test]
    fn test_get_recent() {
        let buffer = CircularLogBuffer::new();

        for i in 0..10 {
            buffer.log(LogLevel::Info, format!("msg{}", i), "test");
        }

        let recent = buffer.get_recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].message, "msg7");
        assert_eq!(recent[1].message, "msg8");
        assert_eq!(recent[2].message, "msg9");
    }

    #[test]
    fn test_clear() {
        let buffer = CircularLogBuffer::new();

        buffer.log(LogLevel::Info, "msg1".to_string(), "test");
        buffer.log(LogLevel::Info, "msg2".to_string(), "test");

        assert_eq!(buffer.len(), 2);

        buffer.clear();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_parse_timestamped_line() {
        let line = "2024-01-15T12:34:56.789+0000 info router: started";
        let entry = parse_singbox_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, "router: started");
        assert_eq!(entry.source, "sing-box");
    }

    #[test]
    fn test_parse_timestamped_line_debug() {
        let line = "2024-01-15T12:34:56.789+0000 debug inbound/tun[tun-in]: started";
        let entry = parse_singbox_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Debug);
        assert!(entry.message.contains("inbound/tun"));
    }

    #[test]
    fn test_parse_bracket_line() {
        let line = "info[0000] router started";
        let entry = parse_singbox_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, "router started");
    }

    #[test]
    fn test_parse_bracket_line_error() {
        let line = "error[router] connection failed";
        let entry = parse_singbox_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Error);
        assert_eq!(entry.message, "connection failed");
    }

    #[test]
    fn test_parse_simple_line() {
        let line = "warn connection timeout";
        let entry = parse_singbox_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Warn);
        assert_eq!(entry.message, "connection timeout");
    }

    #[test]
    fn test_parse_empty_line() {
        assert!(parse_singbox_line("").is_none());
        assert!(parse_singbox_line("   ").is_none());
    }

    #[test]
    fn test_parse_unknown_format_fallback() {
        let line = "some random log message without level";
        let entry = parse_singbox_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, line);
    }

    #[test]
    fn test_process_singbox_output() {
        let buffer = CircularLogBuffer::new();
        let output = "2024-01-15T12:00:00.000+0000 info started\n\
                      2024-01-15T12:00:01.000+0000 debug processing\n\
                      2024-01-15T12:00:02.000+0000 error failed";

        process_singbox_output(&buffer, output);

        assert_eq!(buffer.len(), 3);
        let entries = buffer.get_all();
        assert_eq!(entries[0].level, LogLevel::Info);
        assert_eq!(entries[1].level, LogLevel::Debug);
        assert_eq!(entries[2].level, LogLevel::Error);
    }
}
