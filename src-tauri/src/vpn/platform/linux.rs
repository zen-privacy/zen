//! Linux-specific VPN operations
//!
//! - Uses sudo with saved password for privilege escalation
//! - Uses pgrep for process detection
//! - Uses nftables/iptables for kill switch (via killswitch module)

use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::fs;

use tauri::AppHandle;
use tokio::process::Child;

use crate::logging::LogLevel;
use crate::notifications::{emit_vpn_event, VpnEvent};
use crate::vpn::manager::{ConnectionState, VpnManager};
use crate::vpn::types::ServerConfig;
use crate::vpn::process::{
    AppState, get_config_dir, get_singbox_binary_path, get_singbox_config_path,
    get_log_path, resolve_server_ip, generate_singbox_config,
    copy_resource_file, spawn_log_reader, spawn_auto_reconnect_monitor,
    auto_enable_killswitch, cleanup_firewall, check_process_health,
    ProcessHealthStatus, GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
};

/// Detect the physical (non-tunnel) network interface on Linux.
pub fn detect_physical_interface() -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(dev_idx) = parts.iter().position(|&p| p == "dev") {
            if let Some(iface) = parts.get(dev_idx + 1) {
                let is_tunnel = iface.starts_with("tun")
                    || iface.starts_with("tap")
                    || iface.starts_with("wg")
                    || iface.starts_with("tailscale")
                    || iface.starts_with("utun")
                    || iface.starts_with("docker")
                    || iface.starts_with("br-")
                    || iface.starts_with("veth")
                    || iface.starts_with("zen-");

                if !is_tunnel {
                    return Some(iface.to_string());
                }
            }
        }
    }

    None
}

/// Execute a command with elevated privileges via sudo (using saved password)
pub fn elevated_command(cmd: &str) -> Result<std::process::Output, String> {
    crate::sudo::sudo_exec(&["sh", "-c", cmd])
}

/// Check if the sing-box process is running
pub fn is_process_running() -> bool {
    std::process::Command::new("pgrep")
        .arg("-x")
        .arg("sing-box")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Start sing-box on Linux via sudo (using saved password)
pub async fn platform_start_singbox(
    _config: &ServerConfig,
    state: &AppState,
    _vpn_manager: &Arc<VpnManager>,
    app_handle: &AppHandle,
) -> Result<Child, String> {
    let singbox_path = get_singbox_binary_path();
    let config_path = get_singbox_config_path();
    let log_path = get_log_path();

    // Use sudo with saved password instead of pkexec (no GUI dialog)
    let cmd = build_singbox_run_cmd(&singbox_path, &config_path, &log_path);

    let std_child = crate::sudo::sudo_spawn(&["sh", "-c", &cmd])
        .map_err(|e| {
            state.log(LogLevel::Error, format!("Failed to start sing-box: {}", e));
            emit_vpn_event(app_handle, VpnEvent::error(format!("Failed to start sing-box: {}", e), Some("START_FAILED".to_string())));
            e
        })?;

    // sudo child handle is unreliable (it's the sudo wrapper, not sing-box itself).
    // Drop it and poll for sing-box via pgrep in platform_wait_for_start.
    drop(std_child);

    // Return a dummy child to satisfy the interface — wait_for_start ignores it on Linux
    let dummy = tokio::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .map_err(|e| format!("Failed to create placeholder: {}", e))?;

    Ok(dummy)
}

/// Wait for sing-box to come up on Linux by polling pgrep
pub async fn platform_wait_for_start(
    mut dummy_child: Child,  // dummy from platform_start — kill it when done
    config: &ServerConfig,
    state: &AppState,
    vpn_manager: &Arc<VpnManager>,
    app_handle: &AppHandle,
) -> Result<(), String> {

    for _ in 0..300 {
        tokio::time::sleep(Duration::from_millis(100)).await;

        if is_process_running() {
            state.log(LogLevel::Info, format!("VPN connected to {}", config.address));
            emit_vpn_event(app_handle, VpnEvent::connected(config.name.clone(), config.address.clone()));

            if !config.diag_no_killswitch.unwrap_or(false) {
                auto_enable_killswitch(&config.address, app_handle);
                state.log(LogLevel::Info, "Kill switch auto-enabled".to_string());
                emit_vpn_event(app_handle, VpnEvent::killswitch_changed(true));
            }

            vpn_manager.set_state(ConnectionState::Connected);

            let state_arc = Arc::new(AppState {
                singbox_process: Mutex::new(None),
                log_buffer: state.log_buffer.clone(),
                health_monitor: Mutex::new(None),
                current_config: Mutex::new(state.get_config()),
            });

            let monitor = spawn_auto_reconnect_monitor(
                state_arc,
                Arc::clone(vpn_manager),
                app_handle.clone(),
            );
            state.set_health_monitor(Some(monitor));

            let _ = dummy_child.kill().await;
            return Ok(());
        }
    }

    let _ = dummy_child.kill().await;
    state.log(LogLevel::Error, "Connection timeout".to_string());
    emit_vpn_event(app_handle, VpnEvent::error("Connection timeout", Some("TIMEOUT".to_string())));
    vpn_manager.set_state(ConnectionState::Failed);
    Err("Connection timeout".to_string())
}

/// Stop sing-box on Linux
pub async fn platform_stop_singbox(
    state: &AppState,
) -> Result<(), String> {
    graceful_kill_external_process().await?;

    if let Err(e) = cleanup_firewall() {
        state.log(LogLevel::Warn, format!("Failed to cleanup firewall: {}", e));
    }

    Ok(())
}

/// Reconnect sing-box on Linux (regenerate config + restart)
pub async fn platform_reconnect_singbox(
    state: &AppState,
    config: &ServerConfig,
) -> Result<(), String> {
    // Log file is appended, not cleared on reconnect — preserves pre-reconnect logs for diagnostics

    let config_json = generate_singbox_config(config.clone())?;
    let config_dir = get_config_dir();
    fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;

    let config_path = get_singbox_config_path();
    fs::write(&config_path, config_json).map_err(|e| e.to_string())?;

    let singbox_path = get_singbox_binary_path();
    if !singbox_path.exists() {
        return Err("sing-box not installed".to_string());
    }

    let log_path = get_log_path();
    let cmd = build_singbox_run_cmd(&singbox_path, &config_path, &log_path);

    let _std_child = crate::sudo::sudo_spawn(&["sh", "-c", &cmd])
        .map_err(|e| format!("Failed to start sing-box: {}", e))?;

    // Poll for sing-box to appear via pgrep (sudo child handle is not reliable)
    for _ in 0..300 {
        tokio::time::sleep(Duration::from_millis(100)).await;

        if is_process_running() {
            return Ok(());
        }
    }

    // Timeout — kill any leftover
    let _ = elevated_command("killall -KILL sing-box");
    Err("Reconnection timeout".to_string())
}

/// Restore DNS settings on Linux
pub fn restore_dns() -> Result<(), String> {
    if std::path::Path::new("/run/systemd/resolve").exists() {
        let _ = std::process::Command::new("systemd-resolve")
            .arg("--flush-caches")
            .output();
        let _ = std::process::Command::new("resolvectl")
            .arg("flush-caches")
            .output();
    }
    Ok(())
}

/// Graceful shutdown of external sing-box process on Linux
async fn graceful_kill_external_process() -> Result<(), String> {
    let sigterm = elevated_command("killall -TERM sing-box");

    if sigterm.is_ok() {
        for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if !is_process_running() {
                return Ok(());
            }
        }
    }

    // Force kill
    let _ = elevated_command("killall -KILL sing-box");
    Ok(())
}

/// Synchronous graceful shutdown for event handlers (tray close, etc.)
pub fn graceful_shutdown_sync() {
    let sigterm_result = elevated_command("killall -TERM sing-box");

    if sigterm_result.is_ok() {
        for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if !is_process_running() {
                let _ = cleanup_firewall();
                let _ = restore_dns();
                return;
            }
        }
    }

    let _ = elevated_command("killall -KILL sing-box");
    let _ = cleanup_firewall();
    let _ = restore_dns();
}

/// Check process health on Linux
pub fn check_platform_process_health() -> ProcessHealthStatus {
    if is_process_running() {
        ProcessHealthStatus::Running
    } else {
        ProcessHealthStatus::NotRunning
    }
}

/// Platform-specific TUN and routing constants for Linux
pub const TUN_INTERFACE_NAME: &str = "zen-tun";
pub const TUN_ADDRESS: &str = "100.64.0.1/30";
pub const TUN_STRICT_ROUTE: bool = true;
pub const TUN_DEFAULT_STACK: &str = "gvisor";

/// Build the shell command for running sing-box.
/// All paths MUST be single-quoted to handle spaces.
pub fn build_singbox_run_cmd(
    singbox_path: &std::path::Path,
    config_path: &std::path::Path,
    log_path: &std::path::Path,
) -> String {
    format!(
        "'{}' run -c '{}' >> '{}' 2>&1",
        singbox_path.to_string_lossy(),
        config_path.to_string_lossy(),
        log_path.to_string_lossy()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_build_cmd_quotes_all_paths() {
        let cmd = build_singbox_run_cmd(
            &PathBuf::from("/opt/my app/sing-box"),
            &PathBuf::from("/home/user/.config/zen vpn/config.json"),
            &PathBuf::from("/home/user/.config/zen vpn/singbox.log"),
        );
        assert!(cmd.starts_with("'/opt/my app/sing-box'"),
            "singbox_path must be single-quoted. Got: {}", cmd);
        assert!(cmd.contains("-c '/home/user/.config/zen vpn/config.json'"),
            "config_path must be single-quoted. Got: {}", cmd);
        assert!(cmd.contains(">> '/home/user/.config/zen vpn/singbox.log'"),
            "log_path must be single-quoted. Got: {}", cmd);
    }
}
