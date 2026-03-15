//! Windows-specific VPN operations
//!
//! - App runs as admin (requireAdministrator manifest), so no separate elevation needed
//! - Uses tasklist/taskkill for process management
//! - Uses netsh advfirewall for kill switch (via killswitch module)

use std::process::Stdio;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::fs;
use std::os::windows::process::CommandExt;

use tauri::{AppHandle, Manager, State};
use tokio::process::{Child, Command};

use crate::logging::LogLevel;
use crate::notifications::{emit_vpn_event, VpnEvent};
use crate::vpn::manager::{ConnectionState, VpnManager};
use crate::vpn::types::ServerConfig;
use crate::vpn::process::{
    AppState, get_config_dir, get_singbox_binary_path, get_singbox_config_path,
    get_log_path, clear_log_file, resolve_server_ip, generate_singbox_config,
    spawn_auto_reconnect_monitor, cleanup_firewall, check_process_health,
    ProcessHealthStatus, GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
};

const CREATE_NO_WINDOW: u32 = 0x08000000;

/// On Windows, auto_detect_interface works fine — no manual detection needed.
pub fn detect_physical_interface() -> Option<String> {
    None
}

/// Check if the sing-box process is running
pub fn is_process_running() -> bool {
    std::process::Command::new("tasklist")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["/FI", "IMAGENAME eq sing-box.exe"])
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).contains("sing-box.exe"))
        .unwrap_or(false)
}

/// Start sing-box on Windows (already running as admin)
pub async fn platform_start_singbox(
    config: &ServerConfig,
    state: &AppState,
    vpn_manager: &Arc<VpnManager>,
    app_handle: &AppHandle,
) -> Result<Child, String> {
    let singbox_path = get_singbox_binary_path();
    let config_path = get_singbox_config_path();
    let log_path = get_log_path();

    let log_file = fs::File::create(&log_path).map_err(|e| {
        state.log(LogLevel::Error, format!("Failed to create log file: {}", e));
        e.to_string()
    })?;

    let child = Command::new(&singbox_path)
        .creation_flags(CREATE_NO_WINDOW)
        .args(["run", "-c", &config_path.to_string_lossy()])
        .stdout(log_file.try_clone().map_err(|e| e.to_string())?)
        .stderr(log_file)
        .spawn()
        .map_err(|e| {
            state.log(LogLevel::Error, format!("Failed to start sing-box: {}", e));
            emit_vpn_event(app_handle, VpnEvent::error(format!("Failed to start sing-box: {}", e), Some("START_FAILED".to_string())));
            format!("Failed to start sing-box: {}", e)
        })?;

    Ok(child)
}

/// Wait for sing-box to come up on Windows by checking log output
pub async fn platform_wait_for_start(
    child: Child,
    config: &ServerConfig,
    state: &AppState,
    vpn_manager: &Arc<VpnManager>,
    app_handle: &AppHandle,
) -> Result<(), String> {
    let log_path = get_log_path();

    {
        let mut process = state.singbox_process.lock().unwrap();
        *process = Some(child);
    }

    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(100)).await;

        if let Ok(log_content) = fs::read_to_string(&log_path) {
            if log_content.contains("sing-box started") {
                state.log(LogLevel::Info, format!("VPN connected to {}", config.address));
                emit_vpn_event(app_handle, VpnEvent::connected(config.name.clone(), config.address.clone()));

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

                return Ok(());
            }
            if log_content.contains("fatal") || log_content.contains("error") {
                let error_msg = log_content.lines().last().unwrap_or("Unknown error").to_string();
                state.log(LogLevel::Error, format!("sing-box failed: {}", error_msg));
                emit_vpn_event(app_handle, VpnEvent::error(format!("sing-box error: {}", error_msg), Some("SINGBOX_ERROR".to_string())));

                let child_to_kill = {
                    let mut process = state.singbox_process.lock().unwrap();
                    process.take()
                };
                if let Some(mut c) = child_to_kill {
                    let _ = c.kill().await;
                }
                vpn_manager.set_state(ConnectionState::Failed);
                return Err(format!("sing-box failed: {}", error_msg));
            }
        }
    }

    // Timeout
    let child_to_kill = {
        let mut process = state.singbox_process.lock().unwrap();
        process.take()
    };
    if let Some(mut c) = child_to_kill {
        let _ = c.kill().await;
    }
    state.log(LogLevel::Error, "Connection timeout".to_string());
    emit_vpn_event(app_handle, VpnEvent::error("Connection timeout", Some("TIMEOUT".to_string())));
    vpn_manager.set_state(ConnectionState::Failed);
    Err("Connection timeout".to_string())
}

/// Stop sing-box on Windows with graceful shutdown
pub async fn platform_stop_singbox(
    state: &AppState,
) -> Result<(), String> {
    graceful_kill_external_process().await?;

    if let Err(e) = cleanup_firewall() {
        state.log(LogLevel::Warn, format!("Failed to cleanup firewall: {}", e));
    }

    Ok(())
}

/// Reconnect sing-box on Windows (regenerate config + restart)
pub async fn platform_reconnect_singbox(
    state: &AppState,
    config: &ServerConfig,
) -> Result<(), String> {
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

    let log_path = get_log_path();
    let log_file = fs::File::create(&log_path).map_err(|e| e.to_string())?;

    let child = Command::new(&singbox_path)
        .creation_flags(CREATE_NO_WINDOW)
        .args(["run", "-c", &config_path.to_string_lossy()])
        .stdout(log_file.try_clone().map_err(|e| e.to_string())?)
        .stderr(log_file)
        .spawn()
        .map_err(|e| format!("Failed to start sing-box: {}", e))?;

    {
        let mut process = state.singbox_process.lock().unwrap();
        *process = Some(child);
    }

    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;

        if let Ok(log_content) = fs::read_to_string(&log_path) {
            if log_content.contains("sing-box started") {
                return Ok(());
            }
        }
    }

    let child_to_kill = {
        let mut process = state.singbox_process.lock().unwrap();
        process.take()
    };
    if let Some(mut child) = child_to_kill {
        let _ = child.kill().await;
    }
    Err("Reconnection timeout".to_string())
}

/// Restore DNS settings on Windows (flush cache)
pub fn restore_dns() -> Result<(), String> {
    let _ = std::process::Command::new("ipconfig")
        .creation_flags(CREATE_NO_WINDOW)
        .arg("/flushdns")
        .output();
    Ok(())
}

/// Graceful shutdown of external sing-box process on Windows
async fn graceful_kill_external_process() -> Result<(), String> {
    // Try graceful termination (no /F, with /T to catch child tree)
    let _ = std::process::Command::new("taskkill")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["/IM", "sing-box.exe", "/T"])
        .output();

    // Wait briefly for clean exit
    for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !is_process_running() {
            return Ok(());
        }
    }

    // Elevate and force kill if still running
    let _ = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-Command",
            "Start-Process -FilePath 'taskkill' -ArgumentList '/F /T /IM sing-box.exe' -Verb RunAs -WindowStyle Hidden -Wait"
        ])
        .output();

    if is_process_running() {
        return Err("Failed to stop sing-box after force kill".to_string());
    }

    Ok(())
}

/// Synchronous graceful shutdown for event handlers (tray close, etc.)
pub fn graceful_shutdown_sync() {
    // First try graceful termination (no /F, but with /T)
    let _ = std::process::Command::new("taskkill")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["/IM", "sing-box.exe", "/T"])
        .output();

    for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if !is_process_running() {
            let _ = cleanup_firewall();
            let _ = restore_dns();
            return;
        }
    }

    // Force kill elevated if still running
    let _ = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-Command",
            "Start-Process -FilePath 'taskkill' -ArgumentList '/F /T /IM sing-box.exe' -Verb RunAs -WindowStyle Hidden -Wait"
        ])
        .output();

    if !is_process_running() {
        let _ = cleanup_firewall();
        let _ = restore_dns();
    }
}

/// Check process health on Windows
pub fn check_platform_process_health() -> ProcessHealthStatus {
    if is_process_running() {
        ProcessHealthStatus::Running
    } else {
        ProcessHealthStatus::NotRunning
    }
}

/// No elevated_command needed on Windows — app runs as admin.
/// But we provide it for consistency with the platform API.
pub fn elevated_command(cmd: &str) -> Result<std::process::Output, String> {
    std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-Command", cmd])
        .output()
        .map_err(|e| format!("Failed to execute command: {}", e))
}

/// Platform-specific TUN and routing constants for Windows
pub const TUN_INTERFACE_NAME: &str = "zen-tun";
pub const TUN_ADDRESS: &str = "172.19.0.1/30";
pub const TUN_STRICT_ROUTE: bool = true;
pub const TUN_DEFAULT_STACK: &str = "gvisor";
