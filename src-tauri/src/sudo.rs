//! Sudo privilege escalation for Linux and macOS
//!
//! - macOS: validates password, stores in macOS Keychain (encrypted by OS, visible in Keychain Access)
//!   On subsequent connects, password is read from Keychain automatically.
//!   If password becomes invalid (user changed it), Keychain entry is deleted and dialog shown again.
//! - Linux: keeps password in process memory, frontend shows custom dialog
//!
//! Flow (macOS):
//! 1. First connect: frontend shows password dialog
//! 2. Password validated via `sudo -S -k -v`
//! 3. Stored in macOS Keychain ("Zen Privacy" entry)
//! 4. Subsequent connects: read from Keychain, no dialog
//!
//! Flow (Linux):
//! 1. On connect: if no password in memory → frontend shows dialog
//! 2. Password validated via `sudo -S -k -v`, held in memory
//! 3. Cleared on app exit

/// Error codes for frontend to detect password prompts
pub const SUDO_PASSWORD_REQUIRED: &str = "SUDO_PASSWORD_REQUIRED";
pub const SUDO_PASSWORD_INVALID: &str = "SUDO_PASSWORD_INVALID";

// ==================== macOS: Keychain storage ====================

#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "Zen Privacy";
#[cfg(target_os = "macos")]
const KEYCHAIN_ACCOUNT: &str = "sudo-password";

#[cfg(target_os = "macos")]
fn keychain_load() -> Option<String> {
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE, "-w"])
        .output()
        .ok()?;
    if output.status.success() {
        let pwd = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !pwd.is_empty() { Some(pwd) } else { None }
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn keychain_save(password: &str) -> Result<(), String> {
    let output = std::process::Command::new("security")
        .args(["add-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE, "-w", password, "-U"])
        .output()
        .map_err(|e| format!("Keychain save failed: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("Keychain save failed: {}", String::from_utf8_lossy(&output.stderr).trim()))
    }
}

#[cfg(target_os = "macos")]
fn keychain_delete() -> Result<(), String> {
    let _ = std::process::Command::new("security")
        .args(["delete-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE])
        .output();
    Ok(())
}

// ==================== Linux: in-memory storage ====================

#[cfg(all(unix, not(target_os = "macos")))]
static PASSWORD: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

// ==================== Shared unix helpers ====================

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

/// Check if sudo can run without a password (e.g. NOPASSWD in sudoers)
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

/// Check if a sudo password is available
#[tauri::command]
pub fn sudo_has_password() -> bool {
    #[cfg(target_os = "macos")]
    { keychain_load().is_some() }

    #[cfg(all(unix, not(target_os = "macos")))]
    { PASSWORD.lock().unwrap().is_some() }

    #[cfg(not(unix))]
    { false }
}

/// Validate and store a sudo password
#[tauri::command]
pub fn sudo_set_password(password: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        validate_password(&password)?;
        keychain_save(&password)?;
        // Clean up legacy sudo.enc if it exists
        let legacy = dirs::config_dir()
            .unwrap_or_default()
            .join("zen-vpn")
            .join("sudo.enc");
        let _ = std::fs::remove_file(legacy);
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        validate_password(&password)?;
        *PASSWORD.lock().unwrap() = Some(password);
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = password;
        Ok(())
    }
}

/// Clear the stored sudo password
#[tauri::command]
pub fn sudo_clear_password() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    { keychain_delete()?; }

    #[cfg(all(unix, not(target_os = "macos")))]
    { *PASSWORD.lock().unwrap() = None; }

    Ok(())
}

// ==================== Privilege execution ====================

/// Get the stored password, returning error code if not available.
/// If the password is in Keychain/memory but no longer valid, clears it and returns REQUIRED.
#[cfg(unix)]
fn get_password() -> Result<String, String> {
    if can_sudo_non_interactive() {
        return Ok(String::new());
    }

    #[cfg(target_os = "macos")]
    {
        match keychain_load() {
            Some(pwd) => Ok(pwd),
            None => Err(SUDO_PASSWORD_REQUIRED.to_string()),
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let guard = PASSWORD.lock().unwrap();
        match guard.as_deref() {
            Some(pwd) if !pwd.is_empty() => Ok(pwd.to_string()),
            _ => Err(SUDO_PASSWORD_REQUIRED.to_string()),
        }
    }
}

/// Invalidate stored password (called when sudo rejects it at runtime)
#[cfg(unix)]
fn invalidate_password() {
    #[cfg(target_os = "macos")]
    { let _ = keychain_delete(); }

    #[cfg(all(unix, not(target_os = "macos")))]
    { *PASSWORD.lock().unwrap() = None; }
}

/// Run a command with elevated privileges and wait for output.
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

    let password = get_password()?;
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

    let output = child
        .wait_with_output()
        .map_err(|e| format!("sudo wait failed: {}", e))?;

    // If sudo rejected the password, clear it so frontend re-prompts
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
        if stderr.contains("sorry") || stderr.contains("incorrect") || stderr.contains("try again") {
            invalidate_password();
            return Err(SUDO_PASSWORD_REQUIRED.to_string());
        }
    }

    Ok(output)
}

/// Spawn a long-running process with elevated privileges.
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

    let password = get_password()?;
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
