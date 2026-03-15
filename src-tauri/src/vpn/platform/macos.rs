//! macOS-specific VPN operations
//!
//! - Uses sudo with saved password for privilege escalation (no osascript popups)
//! - Uses pgrep for process detection
//! - Uses pfctl for kill switch (via killswitch module)
//! - Random utun naming to avoid conflicts
//! - Direct process management (no launchd)

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
    get_log_path, clear_log_file, resolve_server_ip, generate_singbox_config,
    spawn_auto_reconnect_monitor, auto_enable_killswitch, cleanup_firewall,
    ProcessHealthStatus, GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
};

/// Generate a random utun interface name (utun5-utun94) to avoid conflicts
fn random_utun_name() -> String {
    use std::time::SystemTime;
    let ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let idx = (ms % 90) + 5; // utun5 to utun94
    format!("utun{}", idx)
}

/// Detect the physical (non-tunnel) network interface on macOS.
pub fn detect_physical_interface() -> Option<String> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let line = line.trim();
        if let Some(iface) = line.strip_prefix("interface:") {
            let iface = iface.trim();
            let is_tunnel = iface.starts_with("utun")
                || iface.starts_with("tun")
                || iface.starts_with("tap")
                || iface.starts_with("bridge")
                || iface.starts_with("vmnet");

            if !is_tunnel {
                return Some(iface.to_string());
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

/// Validate sing-box config before launching
fn validate_config(singbox_path: &std::path::Path, config_path: &std::path::Path) -> Result<(), String> {
    let output = std::process::Command::new(singbox_path)
        .args(["check", "-c", &config_path.to_string_lossy()])
        .output()
        .map_err(|e| format!("Failed to validate config: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Config validation failed: {}", stderr.trim()));
    }
    Ok(())
}

/// Start sing-box on macOS via sudo (no launchd, no osascript)
pub async fn platform_start_singbox(
    _config: &ServerConfig,
    state: &AppState,
    _vpn_manager: &Arc<VpnManager>,
    app_handle: &AppHandle,
) -> Result<Child, String> {
    let singbox_path = get_singbox_binary_path();
    let config_path = get_singbox_config_path();
    let log_path = get_log_path();

    // Validate config before launch
    if let Err(e) = validate_config(&singbox_path, &config_path) {
        state.log(LogLevel::Error, format!("Config invalid: {}", e));
        emit_vpn_event(app_handle, VpnEvent::error(&e, Some("CONFIG_INVALID".to_string())));
        return Err(e);
    }

    // Set up host route to VPN server via physical gateway
    if let Some(config) = state.get_config() {
        let server_ip = resolve_server_ip(&config.address);
        let gw_output = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output();
        if let Ok(out) = gw_output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if let Some(gw) = line.trim().strip_prefix("gateway:") {
                    let gw = gw.trim();
                    let _ = elevated_command(&format!(
                        "route delete -host '{}' 2>/dev/null; route add -host '{}' '{}'",
                        server_ip, server_ip, gw
                    ));
                    break;
                }
            }
        }
    }

    let cmd = format!(
        "{} run -c '{}' > '{}' 2>&1",
        singbox_path.to_string_lossy(),
        config_path.to_string_lossy(),
        log_path.to_string_lossy()
    );

    let std_child = crate::sudo::sudo_spawn(&["sh", "-c", &cmd])
        .map_err(|e| {
            state.log(LogLevel::Error, format!("Failed to start sing-box: {}", e));
            emit_vpn_event(app_handle, VpnEvent::error(format!("Failed to start sing-box: {}", e), Some("START_FAILED".to_string())));
            e
        })?;

    drop(std_child);

    let dummy = tokio::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .map_err(|e| format!("Failed to create placeholder: {}", e))?;

    Ok(dummy)
}

/// Wait for sing-box to come up on macOS by polling pgrep
pub async fn platform_wait_for_start(
    mut dummy_child: Child,
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

/// Stop sing-box on macOS
pub async fn platform_stop_singbox(
    state: &AppState,
) -> Result<(), String> {
    graceful_kill_external_process().await?;

    // Clean up host route
    if let Some(config) = state.get_config() {
        let server_ip = resolve_server_ip(&config.address);
        let _ = elevated_command(&format!("route delete -host '{}' 2>/dev/null; true", server_ip));
    }

    // Clean up pf rules
    let _ = elevated_command("pfctl -a 'com.zen.vpn' -F all 2>/dev/null; true");

    if let Err(e) = cleanup_firewall() {
        state.log(LogLevel::Warn, format!("Failed to cleanup firewall: {}", e));
    }

    Ok(())
}

/// Reconnect sing-box on macOS — full stop + start with fresh config
pub async fn platform_reconnect_singbox(
    state: &AppState,
    config: &ServerConfig,
) -> Result<(), String> {
    // Stop existing
    platform_stop_singbox(state).await?;

    // Regenerate config with fresh network detection
    clear_log_file()?;
    let config_json = generate_singbox_config(config.clone())?;
    let config_dir = get_config_dir();
    fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;

    let config_path = get_singbox_config_path();
    fs::write(&config_path, config_json).map_err(|e| e.to_string())?;

    let singbox_path = get_singbox_binary_path();
    if !singbox_path.exists() {
        return Err("sing-box not installed".to_string());
    }

    // Validate config
    validate_config(&singbox_path, &config_path)?;

    // Set up host route
    let server_ip = resolve_server_ip(&config.address);
    let gw_output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output();
    if let Ok(out) = gw_output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if let Some(gw) = line.trim().strip_prefix("gateway:") {
                let gw = gw.trim();
                let _ = elevated_command(&format!(
                    "route delete -host '{}' 2>/dev/null; route add -host '{}' '{}'",
                    server_ip, server_ip, gw
                ));
                break;
            }
        }
    }

    let log_path = get_log_path();
    let cmd = format!(
        "{} run -c '{}' > '{}' 2>&1",
        singbox_path.to_string_lossy(),
        config_path.to_string_lossy(),
        log_path.to_string_lossy()
    );

    let _std_child = crate::sudo::sudo_spawn(&["sh", "-c", &cmd])
        .map_err(|e| format!("Failed to start sing-box: {}", e))?;

    for _ in 0..300 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if is_process_running() {
            return Ok(());
        }
    }

    let _ = elevated_command("killall -KILL sing-box");
    Err("Reconnection timeout".to_string())
}

/// Restore DNS settings on macOS (flush cache only — we no longer override system DNS)
pub fn restore_dns() -> Result<(), String> {
    let _ = std::process::Command::new("dscacheutil")
        .arg("-flushcache")
        .output();
    let _ = std::process::Command::new("killall")
        .args(["-HUP", "mDNSResponder"])
        .output();
    Ok(())
}

/// Graceful shutdown of external sing-box process on macOS
async fn graceful_kill_external_process() -> Result<(), String> {
    let sigterm = elevated_command("killall -TERM sing-box 2>/dev/null; true");

    if sigterm.is_ok() {
        for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if !is_process_running() {
                return Ok(());
            }
        }
    }

    let _ = elevated_command("killall -KILL sing-box 2>/dev/null; true");
    Ok(())
}

/// Synchronous graceful shutdown for event handlers (tray close, etc.)
pub fn graceful_shutdown_sync() {
    let _ = elevated_command("killall -TERM sing-box 2>/dev/null; true");

    for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if !is_process_running() {
            let _ = cleanup_firewall();
            let _ = restore_dns();
            return;
        }
    }

    let _ = elevated_command("killall -KILL sing-box 2>/dev/null; true");
    let _ = cleanup_firewall();
    let _ = restore_dns();
}

/// Check process health on macOS
pub fn check_platform_process_health() -> ProcessHealthStatus {
    if is_process_running() {
        ProcessHealthStatus::Running
    } else {
        ProcessHealthStatus::NotRunning
    }
}

/// Platform-specific TUN and routing constants for macOS
/// Note: TUN_INTERFACE_NAME is generated at runtime via random_utun_name()
/// but we need a compile-time constant for config generation.
/// The actual name is set in generate_singbox_config via tun_interface_name().
pub const TUN_INTERFACE_NAME: &str = "utun99"; // fallback, overridden at runtime
pub const TUN_ADDRESS: &str = "100.64.0.1/30";
pub const TUN_STRICT_ROUTE: bool = true; // prevent traffic leaks
pub const TUN_DEFAULT_STACK: &str = "mixed"; // gVisor TCP + system UDP, best for macOS

/// Get a runtime TUN interface name (random to avoid conflicts)
pub fn tun_interface_name() -> String {
    random_utun_name()
}
