//! Atomic file writes and encrypted storage utilities

use std::fs;
use std::io::Write;
use std::path::Path;

/// Atomically write data to a file.
/// Writes to a `.tmp` file first, fsyncs, then renames over the target.
/// This prevents corrupted files on crash/power loss.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp_path = path.with_extension("tmp");

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    // Write to temp file
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| format!("Failed to create temp file: {}", e))?;
    file.write_all(data)
        .map_err(|e| format!("Failed to write temp file: {}", e))?;
    file.sync_all()
        .map_err(|e| format!("Failed to fsync temp file: {}", e))?;
    drop(file);

    // Atomic rename
    fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to rename temp file: {}", e))?;

    Ok(())
}

/// Atomically write a string to a file
pub fn atomic_write_str(path: &Path, content: &str) -> Result<(), String> {
    atomic_write(path, content.as_bytes())
}

/// Atomically write a JSON-serializable value to a file
pub fn atomic_write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| format!("Failed to serialize JSON: {}", e))?;
    atomic_write_str(path, &json)
}
