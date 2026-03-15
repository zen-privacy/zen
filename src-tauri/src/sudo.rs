//! Encrypted sudo password storage and privilege escalation for Linux and macOS
//!
//! Stores the user's sudo password encrypted with AES-256-GCM in ~/.config/zen-vpn/sudo.enc.
//!
//! Flow:
//! 1. First launch: frontend shows password input dialog
//! 2. Password validated via `sudo -S -k -v`
//! 3. Encrypted and saved to sudo.enc
//! 4. Subsequent launches: read + decrypt + use via `sudo -S`
//! 5. If password becomes invalid: delete file, ask again

#[cfg(unix)]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
#[cfg(unix)]
use base64::Engine;
#[cfg(unix)]
use sha2::{Digest, Sha256};

use std::path::PathBuf;

/// Error codes for frontend to detect password prompts
pub const SUDO_PASSWORD_REQUIRED: &str = "SUDO_PASSWORD_REQUIRED";
pub const SUDO_PASSWORD_INVALID: &str = "SUDO_PASSWORD_INVALID";

fn get_sudo_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zen-vpn")
        .join("sudo.enc")
}

// ==================== Unix (Linux + macOS) implementation ====================

#[cfg(unix)]
const NONCE_LEN: usize = 12;

#[cfg(unix)]
fn derive_key() -> [u8; 32] {
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zen-vpn");

    let mut hasher = Sha256::new();
    hasher.update(config_dir.to_string_lossy().as_bytes());
    hasher.update(b"|zen-privacy|sudo|v1");
    let digest = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

#[cfg(unix)]
fn encrypt_password(password: &str) -> Result<String, String> {
    use rand::RngCore;

    let key = derive_key();
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Cipher init failed: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, password.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(combined))
}

#[cfg(unix)]
fn decrypt_password(encoded: &str) -> Result<String, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Decode failed: {}", e))?;

    if raw.len() <= NONCE_LEN {
        return Err("Corrupted password data".to_string());
    }

    let (nonce_bytes, cipher_bytes) = raw.split_at(NONCE_LEN);
    let key = derive_key();
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Cipher init failed: {}", e))?;

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), cipher_bytes)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext)
        .map_err(|e| format!("Invalid UTF-8: {}", e))
}

/// Validate a sudo password by running `sudo -S -k -v`
#[cfg(unix)]
fn validate_password(password: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("sudo")
        .args(["-S", "-k", "-p", "", "-v"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run sudo: {}", e))?;

    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(password.as_bytes());
        let _ = stdin.write_all(b"\n");
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for sudo: {}", e))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if stderr.contains("sorry")
        || stderr.contains("incorrect")
        || stderr.contains("authentication failure")
        || stderr.contains("try again")
    {
        return Err(SUDO_PASSWORD_INVALID.to_string());
    }

    Err(format!("sudo validation failed: {}", stderr.trim()))
}

/// Check if sudo can run without a password
#[cfg(unix)]
fn can_sudo_non_interactive() -> bool {
    use std::process::Stdio;
    std::process::Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ==================== Tauri commands ====================

/// Check if a saved sudo password exists
#[tauri::command]
pub fn sudo_has_password() -> bool {
    #[cfg(unix)]
    { get_sudo_path().exists() }

    #[cfg(not(unix))]
    { false }
}

/// Save a sudo password (validates first, then encrypts and stores)
#[tauri::command]
pub fn sudo_set_password(password: String) -> Result<(), String> {
    #[cfg(unix)]
    {
        validate_password(&password)?;
        let encrypted = encrypt_password(&password)?;
        crate::storage::atomic_write_str(&get_sudo_path(), &encrypted)
    }

    #[cfg(not(unix))]
    {
        let _ = password;
        Ok(())
    }
}

/// Clear the saved sudo password
#[tauri::command]
pub fn sudo_clear_password() -> Result<(), String> {
    let path = get_sudo_path();
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to remove sudo password: {}", e))?;
    }
    Ok(())
}

/// Load the saved password (internal)
#[cfg(unix)]
pub fn load_password() -> Result<Option<String>, String> {
    let path = get_sudo_path();
    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read sudo password: {}", e))?;

    match decrypt_password(content.trim()) {
        Ok(pwd) if !pwd.is_empty() => Ok(Some(pwd)),
        Ok(_) => Ok(None),
        Err(_) => {
            let _ = std::fs::remove_file(&path);
            Ok(None)
        }
    }
}

/// Get the saved password, returning error code if not available.
#[cfg(unix)]
pub fn get_validated_password() -> Result<String, String> {
    if can_sudo_non_interactive() {
        return Ok(String::new());
    }

    let password = load_password()?;
    match password {
        Some(pwd) => Ok(pwd),
        None => Err(SUDO_PASSWORD_REQUIRED.to_string()),
    }
}

/// Run a command with sudo using saved password
#[cfg(unix)]
pub fn sudo_exec(args: &[&str]) -> Result<std::process::Output, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if can_sudo_non_interactive() {
        return Command::new("sudo")
            .arg("-n")
            .arg("--")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("sudo exec failed: {}", e));
    }

    let password = get_validated_password()?;
    if password.is_empty() {
        return Err(SUDO_PASSWORD_REQUIRED.to_string());
    }

    let mut child = Command::new("sudo")
        .args(["-S", "-p", "", "--"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("sudo exec failed: {}", e))?;

    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(password.as_bytes());
        let _ = stdin.write_all(b"\n");
    }

    child
        .wait_with_output()
        .map_err(|e| format!("sudo wait failed: {}", e))
}

/// Spawn a long-running process with sudo
#[cfg(unix)]
pub fn sudo_spawn(args: &[&str]) -> Result<std::process::Child, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if can_sudo_non_interactive() {
        return Command::new("sudo")
            .arg("-n")
            .arg("--")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("sudo spawn failed: {}", e));
    }

    let password = get_validated_password()?;
    if password.is_empty() {
        return Err(SUDO_PASSWORD_REQUIRED.to_string());
    }

    let mut child = Command::new("sudo")
        .args(["-S", "-p", "", "--"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("sudo spawn failed: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(password.as_bytes());
        let _ = stdin.write_all(b"\n");
        drop(stdin);
    }

    Ok(child)
}
