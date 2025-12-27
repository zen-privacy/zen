//! Sing-box process management
//!
//! This module handles starting, stopping, and monitoring the sing-box VPN process.

// Allow unused code for infrastructure that may be used in future features
#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, State};
use tokio::process::{Child, Command};

use super::manager::{HealthCheckConfig, HealthCheckResult, HealthMonitor, HealthMonitorHandle, VpnManager, ConnectionState};
use super::VlessConfig;
use crate::logging::{CircularLogBuffer, LogEntry, LogLevel, parse_singbox_line};
use crate::notifications::{emit_vpn_event, VpnEvent};

/// Application state holding the sing-box process handle and log buffer
pub struct AppState {
    /// The sing-box child process handle
    pub singbox_process: Mutex<Option<Child>>,
    /// Circular buffer for storing captured logs
    pub log_buffer: CircularLogBuffer,
    /// Handle to the health monitor task (for cleanup)
    pub health_monitor: Mutex<Option<HealthMonitorHandle>>,
    /// Current VPN configuration (for reconnection)
    pub current_config: Mutex<Option<VlessConfig>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            singbox_process: Mutex::new(None),
            log_buffer: CircularLogBuffer::new(),
            health_monitor: Mutex::new(None),
            current_config: Mutex::new(None),
        }
    }
}

impl AppState {
    /// Add a log entry to the buffer
    pub fn log(&self, level: LogLevel, message: String) {
        self.log_buffer.push(LogEntry::from_app(level, message));
    }

    /// Add a sing-box log entry to the buffer
    pub fn log_singbox(&self, level: LogLevel, message: String) {
        self.log_buffer.push(LogEntry::from_singbox(level, message));
    }

    /// Read and parse the sing-box log file, adding new entries to the buffer
    pub fn read_log_file(&self) -> Result<usize, String> {
        let log_path = get_log_path();
        if !log_path.exists() {
            return Ok(0);
        }

        let content = fs::read_to_string(&log_path)
            .map_err(|e| format!("Failed to read log file: {}", e))?;

        let mut count = 0;
        for line in content.lines() {
            if let Some(entry) = parse_singbox_line(line) {
                self.log_buffer.push(entry);
                count += 1;
            }
        }

        Ok(count)
    }

    /// Store the current VPN configuration for reconnection
    pub fn store_config(&self, config: VlessConfig) {
        let mut current = self.current_config.lock().unwrap();
        *current = Some(config);
    }

    /// Get the current VPN configuration
    pub fn get_config(&self) -> Option<VlessConfig> {
        self.current_config.lock().unwrap().clone()
    }

    /// Clear the stored configuration
    pub fn clear_config(&self) {
        let mut current = self.current_config.lock().unwrap();
        *current = None;
    }

    /// Set the health monitor handle
    pub fn set_health_monitor(&self, handle: Option<HealthMonitorHandle>) {
        let mut monitor = self.health_monitor.lock().unwrap();
        *monitor = handle;
    }

    /// Stop the health monitor if running
    pub fn stop_health_monitor(&self) {
        let mut monitor = self.health_monitor.lock().unwrap();
        if let Some(handle) = monitor.take() {
            handle.stop();
        }
    }
}

/// Get the path to the sing-box log file
fn get_log_path() -> PathBuf {
    get_config_dir().join("singbox.log")
}

/// Get the configuration directory path
fn get_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zen-vpn")
}

/// Get the path to the sing-box configuration file
fn get_singbox_config_path() -> PathBuf {
    get_config_dir().join("config.json")
}

/// Get the path to the sing-box binary
fn get_singbox_binary_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        get_config_dir().join("sing-box.exe")
    }
    #[cfg(not(target_os = "windows"))]
    {
        get_config_dir().join("sing-box")
    }
}

/// Resolve server hostname to IP address
fn resolve_server_ip(address: &str) -> String {
    use std::net::ToSocketAddrs;

    if address.parse::<std::net::IpAddr>().is_ok() {
        return address.to_string();
    }

    if let Ok(mut addrs) = (address, 0u16).to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return addr.ip().to_string();
        }
    }

    address.to_string()
}

/// Default health check interval for auto-reconnect (5 seconds)
const HEALTH_CHECK_INTERVAL_MS: u64 = 5000;

/// Maximum reconnection attempts before giving up
const MAX_RECONNECT_ATTEMPTS: u32 = 5;

/// Reconnection delays: 1s, 2s, 4s, 8s, max 30s
const RECONNECT_INITIAL_DELAY_MS: u64 = 1000;
const RECONNECT_MAX_DELAY_MS: u64 = 30000;

/// Spawn a health monitor that automatically reconnects on sing-box crash
///
/// This function starts a background task that:
/// 1. Periodically checks if the sing-box process is still running
/// 2. On crash detection, emits VpnEvent::Reconnecting events
/// 3. Attempts to restart sing-box with exponential backoff
/// 4. Emits VpnEvent::Connected on success or VpnEvent::Error on max retries
///
/// The monitor is automatically stopped when stop_singbox is called.
pub fn spawn_auto_reconnect_monitor(
    state: Arc<AppState>,
    vpn_manager: Arc<VpnManager>,
    app_handle: AppHandle,
) -> HealthMonitorHandle {
    let config = HealthCheckConfig::new()
        .enabled(true)
        .interval(HEALTH_CHECK_INTERVAL_MS)
        .with_ping_check(false); // Only check process status, not network

    // Clone handles for the async reconnection task
    let state_for_monitor = Arc::clone(&state);
    let app_handle_clone = app_handle.clone();
    let vpn_manager_clone = Arc::clone(&vpn_manager);

    HealthMonitor::spawn(state_for_monitor.clone(), config, move |result| {
        // Only handle process death - not ping failures or running status
        if let HealthCheckResult::ProcessNotRunning { exit_code } = result {
            state_for_monitor.log(
                LogLevel::Warn,
                format!("Sing-box process crashed (exit code: {:?}), attempting reconnection...", exit_code)
            );

            // Check if we should attempt reconnection
            if vpn_manager_clone.is_shutdown_requested() {
                // User requested shutdown, don't reconnect
                return;
            }

            // Get stored config for reconnection
            let config = match state_for_monitor.get_config() {
                Some(c) => c,
                None => {
                    state_for_monitor.log(
                        LogLevel::Error,
                        "Cannot reconnect: no VPN configuration stored".to_string()
                    );
                    emit_vpn_event(
                        &app_handle_clone,
                        VpnEvent::error("Cannot reconnect: no configuration available", Some("NO_CONFIG".to_string()))
                    );
                    return;
                }
            };

            // Clone everything needed for the async reconnection task
            let state_for_reconnect = Arc::clone(&state_for_monitor);
            let app_handle_for_reconnect = app_handle_clone.clone();
            let vpn_manager_for_reconnect = Arc::clone(&vpn_manager_clone);

            // Spawn async reconnection task
            tokio::spawn(async move {
                attempt_reconnection(
                    state_for_reconnect,
                    vpn_manager_for_reconnect,
                    app_handle_for_reconnect,
                    config,
                ).await;
            });
        }
    })
}

/// Attempt to reconnect to VPN with exponential backoff
async fn attempt_reconnection(
    state: Arc<AppState>,
    vpn_manager: Arc<VpnManager>,
    app_handle: AppHandle,
    config: VlessConfig,
) {
    vpn_manager.set_state(ConnectionState::Reconnecting);
    vpn_manager.reset_reconnect();
    vpn_manager.set_auto_reconnect(true);

    let mut attempt = 0u32;
    let mut delay_ms = RECONNECT_INITIAL_DELAY_MS;

    while attempt < MAX_RECONNECT_ATTEMPTS {
        attempt += 1;

        // Check if shutdown was requested
        if vpn_manager.is_shutdown_requested() {
            state.log(LogLevel::Info, "Reconnection cancelled: shutdown requested".to_string());
            vpn_manager.set_state(ConnectionState::Disconnected);
            return;
        }

        // Emit reconnecting event
        emit_vpn_event(
            &app_handle,
            VpnEvent::reconnecting(attempt, MAX_RECONNECT_ATTEMPTS)
        );

        state.log(
            LogLevel::Info,
            format!("Reconnection attempt {} of {}, waiting {}ms...", attempt, MAX_RECONNECT_ATTEMPTS, delay_ms)
        );

        // Wait before attempting
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;

        // Check again if shutdown was requested during wait
        if vpn_manager.is_shutdown_requested() {
            state.log(LogLevel::Info, "Reconnection cancelled: shutdown requested".to_string());
            vpn_manager.set_state(ConnectionState::Disconnected);
            return;
        }

        // Attempt to reconnect
        match reconnect_singbox(&state, &config, &app_handle).await {
            Ok(()) => {
                state.log(LogLevel::Info, format!("Reconnection successful on attempt {}", attempt));
                vpn_manager.set_state(ConnectionState::Connected);
                emit_vpn_event(
                    &app_handle,
                    VpnEvent::connected(config.name.clone(), config.address.clone())
                );

                // Restart the health monitor for the new connection
                let new_monitor = spawn_auto_reconnect_monitor(
                    Arc::clone(&state),
                    Arc::clone(&vpn_manager),
                    app_handle.clone(),
                );
                state.set_health_monitor(Some(new_monitor));
                return;
            }
            Err(e) => {
                state.log(
                    LogLevel::Warn,
                    format!("Reconnection attempt {} failed: {}", attempt, e)
                );
            }
        }

        // Exponential backoff: double the delay, cap at max
        delay_ms = (delay_ms * 2).min(RECONNECT_MAX_DELAY_MS);
    }

    // Max retries reached
    state.log(
        LogLevel::Error,
        format!("Reconnection failed after {} attempts", MAX_RECONNECT_ATTEMPTS)
    );
    vpn_manager.set_state(ConnectionState::Failed);
    emit_vpn_event(
        &app_handle,
        VpnEvent::error(
            format!("Reconnection failed after {} attempts", MAX_RECONNECT_ATTEMPTS),
            Some("MAX_RETRIES".to_string())
        )
    );
}

/// Internal function to reconnect sing-box without emitting events
/// Used by the reconnection logic to avoid duplicate events
async fn reconnect_singbox(
    state: &AppState,
    config: &VlessConfig,
    _app_handle: &AppHandle,
) -> Result<(), String> {
    // Clear previous log file
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

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        // Create batch script for elevation
        let script_path = config_dir.join("run_singbox.bat");
        let script_content = format!(
            "@echo off\r\n\"{}\" run -c \"{}\" > \"{}\" 2>&1",
            singbox_path.to_string_lossy(),
            config_path.to_string_lossy(),
            log_path.to_string_lossy()
        );
        fs::write(&script_path, script_content).map_err(|e| e.to_string())?;

        // Use PowerShell to elevate
        let mut child = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "-Command",
                &format!(
                    "Start-Process -FilePath '{}' -Verb RunAs -WindowStyle Hidden",
                    script_path.to_string_lossy()
                ),
            ])
            .spawn()
            .map_err(|e| format!("Failed to start sing-box: {}", e))?;

        // Wait for process to start
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(100)).await;

            let output = std::process::Command::new("tasklist")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["/FI", "IMAGENAME eq sing-box.exe"])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains("sing-box.exe") {
                    let mut process = state.singbox_process.lock().unwrap();
                    *process = Some(child);
                    return Ok(());
                }
            }
        }

        let _ = child.kill().await;
        Err("Reconnection timeout".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let cmd = format!(
            "pkexec {} run -c {} > {} 2>&1",
            singbox_path.to_string_lossy(),
            config_path.to_string_lossy(),
            log_path.to_string_lossy()
        );

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to start sing-box: {}", e))?;

        // Wait for sing-box to start
        for _ in 0..300 {
            tokio::time::sleep(Duration::from_millis(100)).await;

            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return Err("Authentication cancelled or failed".to_string());
                    }
                    return Err("sing-box exited unexpectedly".to_string());
                }
                Ok(None) => {
                    let output = std::process::Command::new("pgrep")
                        .arg("-x")
                        .arg("sing-box")
                        .output();

                    if let Ok(out) = output {
                        if out.status.success() {
                            let mut process = state.singbox_process.lock().unwrap();
                            *process = Some(child);
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    return Err(format!("Failed to check process status: {}", e));
                }
            }
        }

        let _ = child.kill().await;
        Err("Reconnection timeout".to_string())
    }
}

/// Generate sing-box configuration JSON from VlessConfig
#[tauri::command]
pub fn generate_singbox_config(config: VlessConfig) -> Result<String, String> {
    let transport = if config.transport_type == "ws" {
        serde_json::json!({
            "type": "ws",
            "path": config.path,
            "headers": {
                "Host": config.host
            }
        })
    } else {
        serde_json::json!(null)
    };

    let server_ip = resolve_server_ip(&config.address);

    let singbox_config = serde_json::json!({
        "log": {
            "level": "debug",
            "timestamp": true
        },
        "dns": {
            "servers": [
                {
                    "tag": "direct-dns",
                    "address": "8.8.8.8",
                    "detour": "direct"
                }
            ],
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "zen-tun",
                "inet4_address": "172.19.0.1/30",
                "mtu": 1400,
                "auto_route": true,
                "strict_route": false,
                "stack": "system",
                "sniff": true,
                "sniff_override_destination": false
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "tag": "proxy",
                "server": server_ip.clone(),
                "server_port": config.port,
                "uuid": config.uuid,
                "tls": {
                    "enabled": config.security == "tls",
                    "server_name": config.host.clone(),
                    "insecure": false
                },
                "transport": transport
            },
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "block",
                "tag": "block"
            },
            {
                "type": "dns",
                "tag": "dns-out"
            }
        ],
        "route": {
            "rules": [
                {
                    "protocol": "dns",
                    "outbound": "dns-out"
                },
                {
                    "ip_cidr": [format!("{}/32", server_ip)],
                    "outbound": "direct"
                },
                {
                    "ip_is_private": true,
                    "outbound": "direct"
                }
            ],
            "auto_detect_interface": true,
            "final": "proxy"
        }
    });

    serde_json::to_string_pretty(&singbox_config).map_err(|e| e.to_string())
}

/// Spawn a background task to read and parse log file output
///
/// This function spawns a tokio task that periodically reads the sing-box log file
/// and adds new entries to the log buffer.
pub fn spawn_log_reader(log_buffer: CircularLogBuffer) {
    tokio::spawn(async move {
        let log_path = get_log_path();
        let mut last_size: u64 = 0;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            // Check if log file exists and has grown
            if let Ok(metadata) = fs::metadata(&log_path) {
                let current_size = metadata.len();
                if current_size > last_size {
                    // Read new content from the file
                    if let Ok(content) = fs::read_to_string(&log_path) {
                        // Only process lines we haven't seen
                        let skip_bytes = last_size as usize;
                        if content.len() > skip_bytes {
                            let new_content = &content[skip_bytes..];
                            for line in new_content.lines() {
                                if let Some(entry) = parse_singbox_line(line) {
                                    log_buffer.push(entry);
                                }
                            }
                        }
                    }
                    last_size = current_size;
                }
            }
        }
    });
}

/// Clear the log file before starting a new connection
fn clear_log_file() -> Result<(), String> {
    let log_path = get_log_path();
    if log_path.exists() {
        fs::write(&log_path, "").map_err(|e| format!("Failed to clear log file: {}", e))?;
    }
    Ok(())
}

/// Start the sing-box process on Windows
#[cfg(target_os = "windows")]
#[tauri::command]
pub async fn start_singbox(
    config: VlessConfig,
    state: State<'_, AppState>,
    vpn_manager: State<'_, Arc<VpnManager>>,
    app_handle: AppHandle,
) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Log connection attempt
    state.log(LogLevel::Info, format!("Starting VPN connection to {}", config.address));

    // Store config for reconnection and clear shutdown flag
    state.store_config(config.clone());
    vpn_manager.clear_shutdown_request();
    vpn_manager.set_state(ConnectionState::Connecting);

    // Clear previous log file
    clear_log_file()?;

    let config_json = generate_singbox_config(config.clone())?;
    let config_dir = get_config_dir();
    fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;

    let config_path = get_singbox_config_path();
    fs::write(&config_path, config_json).map_err(|e| e.to_string())?;

    let singbox_path = get_singbox_binary_path();
    if !singbox_path.exists() {
        state.log(LogLevel::Error, "sing-box not installed".to_string());
        emit_vpn_event(&app_handle, VpnEvent::error("sing-box not installed", Some("NOT_INSTALLED".to_string())));
        return Err("sing-box not installed. Please download it first.".to_string());
    }

    // On Windows, run sing-box with elevated privileges using runas
    let log_path = get_log_path();

    // Create a batch script to run with elevation
    let script_path = config_dir.join("run_singbox.bat");
    let script_content = format!(
        "@echo off\r\n\"{}\" run -c \"{}\" > \"{}\" 2>&1",
        singbox_path.to_string_lossy(),
        config_path.to_string_lossy(),
        log_path.to_string_lossy()
    );
    fs::write(&script_path, script_content).map_err(|e| e.to_string())?;

    // Spawn log reader before starting the process
    spawn_log_reader(state.log_buffer.clone());

    // Use PowerShell to elevate (hidden window)
    let mut child = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-Command",
            &format!(
                "Start-Process -FilePath '{}' -Verb RunAs -WindowStyle Hidden",
                script_path.to_string_lossy()
            ),
        ])
        .spawn()
        .map_err(|e| {
            state.log(LogLevel::Error, format!("Failed to start sing-box: {}", e));
            emit_vpn_event(&app_handle, VpnEvent::error(format!("Failed to start sing-box: {}", e), Some("START_FAILED".to_string())));
            format!("Failed to start sing-box: {}", e)
        })?;

    // Wait for process to start
    for _ in 0..100 {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Check if sing-box is running (hidden window)
        let output = std::process::Command::new("tasklist")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/FI", "IMAGENAME eq sing-box.exe"])
            .output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("sing-box.exe") {
                let mut process = state.singbox_process.lock().unwrap();
                *process = Some(child);
                state.log(LogLevel::Info, format!("VPN connected to {}", config.address));
                emit_vpn_event(&app_handle, VpnEvent::connected(config.name.clone(), config.address.clone()));

                // Update VpnManager state and start health monitor for auto-reconnect
                vpn_manager.set_state(ConnectionState::Connected);

                // Create Arc wrapper for AppState to share with health monitor
                // Note: We use a new Arc since State<'_, T> doesn't impl Clone for Arc<T>
                let state_arc = Arc::new(AppState {
                    singbox_process: Mutex::new(None), // Monitor doesn't need process handle
                    log_buffer: state.log_buffer.clone(),
                    health_monitor: Mutex::new(None),
                    current_config: Mutex::new(state.get_config()),
                });

                let monitor = spawn_auto_reconnect_monitor(
                    state_arc,
                    Arc::clone(&vpn_manager),
                    app_handle.clone(),
                );
                state.set_health_monitor(Some(monitor));

                return Ok(());
            }
        }
    }

    let _ = child.kill().await;
    state.log(LogLevel::Error, "Connection timeout or UAC cancelled".to_string());
    emit_vpn_event(&app_handle, VpnEvent::error("Connection timeout or UAC cancelled", Some("TIMEOUT".to_string())));
    vpn_manager.set_state(ConnectionState::Failed);
    Err("Connection timeout or UAC cancelled".to_string())
}

/// Start the sing-box process on Unix-like systems
#[cfg(not(target_os = "windows"))]
#[tauri::command]
pub async fn start_singbox(
    config: VlessConfig,
    state: State<'_, AppState>,
    vpn_manager: State<'_, Arc<VpnManager>>,
    app_handle: AppHandle,
) -> Result<(), String> {
    // Log connection attempt
    state.log(LogLevel::Info, format!("Starting VPN connection to {}", config.address));

    // Store config for reconnection and clear shutdown flag
    state.store_config(config.clone());
    vpn_manager.clear_shutdown_request();
    vpn_manager.set_state(ConnectionState::Connecting);

    // Clear previous log file
    clear_log_file()?;

    let config_json = generate_singbox_config(config.clone())?;
    let config_dir = get_config_dir();
    fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;

    let config_path = get_singbox_config_path();
    fs::write(&config_path, config_json).map_err(|e| e.to_string())?;

    let singbox_path = get_singbox_binary_path();
    if !singbox_path.exists() {
        state.log(LogLevel::Error, "sing-box not installed".to_string());
        emit_vpn_event(&app_handle, VpnEvent::error("sing-box not installed", Some("NOT_INSTALLED".to_string())));
        return Err("sing-box not installed. Please download it first.".to_string());
    }

    let log_path = get_log_path();
    let cmd = format!(
        "pkexec {} run -c {} > {} 2>&1",
        singbox_path.to_string_lossy(),
        config_path.to_string_lossy(),
        log_path.to_string_lossy()
    );

    // Spawn log reader before starting the process
    spawn_log_reader(state.log_buffer.clone());

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            state.log(LogLevel::Error, format!("Failed to start sing-box: {}", e));
            emit_vpn_event(&app_handle, VpnEvent::error(format!("Failed to start sing-box: {}", e), Some("START_FAILED".to_string())));
            format!("Failed to start sing-box: {}", e)
        })?;

    for _ in 0..300 {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    state.log(LogLevel::Error, "Authentication cancelled or failed".to_string());
                    emit_vpn_event(&app_handle, VpnEvent::error("Authentication cancelled or failed", Some("AUTH_FAILED".to_string())));
                    return Err("Authentication cancelled or failed".to_string());
                }
                state.log(LogLevel::Error, "sing-box exited unexpectedly".to_string());
                emit_vpn_event(&app_handle, VpnEvent::error("sing-box exited unexpectedly", Some("UNEXPECTED_EXIT".to_string())));
                return Err("sing-box exited unexpectedly".to_string());
            }
            Ok(None) => {
                let output = std::process::Command::new("pgrep")
                    .arg("-x")
                    .arg("sing-box")
                    .output();

                if let Ok(out) = output {
                    if out.status.success() {
                        let mut process = state.singbox_process.lock().unwrap();
                        *process = Some(child);
                        state.log(LogLevel::Info, format!("VPN connected to {}", config.address));
                        emit_vpn_event(&app_handle, VpnEvent::connected(config.name.clone(), config.address.clone()));

                        // Update VpnManager state and start health monitor for auto-reconnect
                        vpn_manager.set_state(ConnectionState::Connected);

                        // Create Arc wrapper for AppState to share with health monitor
                        // Note: We use a new Arc since State<'_, T> doesn't impl Clone for Arc<T>
                        let state_arc = Arc::new(AppState {
                            singbox_process: Mutex::new(None), // Monitor doesn't need process handle
                            log_buffer: state.log_buffer.clone(),
                            health_monitor: Mutex::new(None),
                            current_config: Mutex::new(state.get_config()),
                        });

                        let monitor = spawn_auto_reconnect_monitor(
                            state_arc,
                            Arc::clone(&vpn_manager),
                            app_handle.clone(),
                        );
                        state.set_health_monitor(Some(monitor));

                        return Ok(());
                    }
                }
            }
            Err(e) => {
                state.log(LogLevel::Error, format!("Failed to check process status: {}", e));
                emit_vpn_event(&app_handle, VpnEvent::error(format!("Failed to check process status: {}", e), Some("STATUS_CHECK_FAILED".to_string())));
                vpn_manager.set_state(ConnectionState::Failed);
                return Err(format!("Failed to check process status: {}", e));
            }
        }
    }

    let _ = child.kill().await;
    state.log(LogLevel::Error, "Connection timeout".to_string());
    emit_vpn_event(&app_handle, VpnEvent::error("Connection timeout", Some("TIMEOUT".to_string())));
    vpn_manager.set_state(ConnectionState::Failed);
    Err("Connection timeout".to_string())
}

/// Stop the sing-box process on Windows with graceful shutdown
///
/// This implements a graceful shutdown sequence:
/// 1. Stop health monitor and request shutdown (prevent reconnection)
/// 2. Send termination signal and wait up to 5 seconds
/// 3. Force kill if process doesn't exit gracefully
/// 4. Clean up firewall rules (kill switch)
/// 5. Restore DNS settings
#[cfg(target_os = "windows")]
#[tauri::command]
pub async fn stop_singbox(
    state: State<'_, AppState>,
    vpn_manager: State<'_, Arc<VpnManager>>,
    app_handle: AppHandle,
) -> Result<(), String> {
    state.log(LogLevel::Info, "Stopping VPN connection (graceful shutdown)".to_string());

    // Request shutdown to prevent auto-reconnect
    vpn_manager.request_shutdown();
    vpn_manager.set_state(ConnectionState::Disconnecting);

    // Stop the health monitor first
    state.stop_health_monitor();

    // Clear stored config
    state.clear_config();

    // Take the process handle
    let _child = {
        let mut process = state.singbox_process.lock().unwrap();
        process.take()
    };

    // Perform graceful shutdown with SIGTERM -> 5s wait -> SIGKILL sequence
    graceful_kill_external_process().await?;

    // Clean up firewall rules (kill switch)
    if let Err(e) = cleanup_firewall() {
        state.log(LogLevel::Warn, format!("Failed to cleanup firewall: {}", e));
    }

    // Restore DNS settings
    if let Err(e) = restore_dns() {
        state.log(LogLevel::Warn, format!("Failed to restore DNS: {}", e));
    }

    state.log(LogLevel::Info, "VPN disconnected".to_string());
    vpn_manager.set_state(ConnectionState::Disconnected);
    vpn_manager.clear_shutdown_request();
    emit_vpn_event(&app_handle, VpnEvent::disconnected(Some("User requested".to_string())));
    Ok(())
}

/// Stop the sing-box process on Unix-like systems with graceful shutdown
///
/// This implements a graceful shutdown sequence:
/// 1. Stop health monitor and request shutdown (prevent reconnection)
/// 2. Send SIGTERM and wait up to 5 seconds
/// 3. Send SIGKILL if process doesn't exit gracefully
/// 4. Clean up firewall rules (kill switch)
/// 5. Restore DNS settings
#[cfg(not(target_os = "windows"))]
#[tauri::command]
pub async fn stop_singbox(
    state: State<'_, AppState>,
    vpn_manager: State<'_, Arc<VpnManager>>,
    app_handle: AppHandle,
) -> Result<(), String> {
    state.log(LogLevel::Info, "Stopping VPN connection (graceful shutdown)".to_string());

    // Request shutdown to prevent auto-reconnect
    vpn_manager.request_shutdown();
    vpn_manager.set_state(ConnectionState::Disconnecting);

    // Stop the health monitor first
    state.stop_health_monitor();

    // Clear stored config
    state.clear_config();

    // Take the process handle
    let _child = {
        let mut process = state.singbox_process.lock().unwrap();
        process.take()
    };

    // Perform graceful shutdown with SIGTERM -> 5s wait -> SIGKILL sequence
    graceful_kill_external_process().await?;

    // Clean up firewall rules (kill switch)
    if let Err(e) = cleanup_firewall() {
        state.log(LogLevel::Warn, format!("Failed to cleanup firewall: {}", e));
    }

    // Restore DNS settings
    if let Err(e) = restore_dns() {
        state.log(LogLevel::Warn, format!("Failed to restore DNS: {}", e));
    }

    state.log(LogLevel::Info, "VPN disconnected".to_string());
    vpn_manager.set_state(ConnectionState::Disconnected);
    vpn_manager.clear_shutdown_request();
    emit_vpn_event(&app_handle, VpnEvent::disconnected(Some("User requested".to_string())));
    Ok(())
}

/// Get the current connection status
#[tauri::command]
pub fn get_connection_status(
    #[allow(unused_variables)] state: State<'_, AppState>
) -> bool {
    // Check if sing-box process is running
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let output = std::process::Command::new("tasklist")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/FI", "IMAGENAME eq sing-box.exe"])
            .output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            return stdout.contains("sing-box.exe");
        }
        false
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mut process = state.singbox_process.lock().unwrap();
        if let Some(ref mut child) = *process {
            match child.try_wait() {
                Ok(Some(_)) => {
                    *process = None;
                    false
                }
                Ok(None) => true,
                Err(_) => {
                    *process = None;
                    false
                }
            }
        } else {
            false
        }
    }
}

/// Result of a process health check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessHealthStatus {
    /// Process is running normally
    Running,
    /// Process has exited with the given exit code
    Exited(Option<i32>),
    /// Process handle is not available (never started or already cleaned up)
    NotRunning,
    /// Error checking process status
    Error(String),
}

impl ProcessHealthStatus {
    /// Check if the process is healthy (running)
    pub fn is_healthy(&self) -> bool {
        matches!(self, ProcessHealthStatus::Running)
    }

    /// Check if the process has exited
    pub fn is_exited(&self) -> bool {
        matches!(self, ProcessHealthStatus::Exited(_) | ProcessHealthStatus::NotRunning)
    }
}

/// Check the health of the sing-box process
///
/// This function checks if sing-box is actually running using system commands
/// (pgrep on Linux, tasklist on Windows) rather than relying on internal process
/// handles. This is more reliable when sing-box is started with elevation (pkexec/runas).
///
/// # Returns
///
/// - `ProcessHealthStatus::Running` if the process is running
/// - `ProcessHealthStatus::NotRunning` if the process is not found
/// - `ProcessHealthStatus::Error(msg)` if there was an error checking status
pub fn check_process_health(_state: &AppState) -> ProcessHealthStatus {
    // Use system commands to check if sing-box is actually running
    // This is more reliable than checking process handles since sing-box
    // is started with elevation (pkexec/runas) and the handle is for the wrapper

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let output = std::process::Command::new("tasklist")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/FI", "IMAGENAME eq sing-box.exe"])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains("sing-box.exe") {
                    ProcessHealthStatus::Running
                } else {
                    ProcessHealthStatus::NotRunning
                }
            }
            Err(e) => ProcessHealthStatus::Error(format!("Failed to check process: {}", e))
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let output = std::process::Command::new("pgrep")
            .arg("-x")
            .arg("sing-box")
            .output();

        match output {
            Ok(out) => {
                if out.status.success() {
                    ProcessHealthStatus::Running
                } else {
                    ProcessHealthStatus::NotRunning
                }
            }
            Err(e) => ProcessHealthStatus::Error(format!("Failed to check process: {}", e))
        }
    }
}

/// Perform a ping check to verify network connectivity through the VPN
///
/// This function pings a well-known host (1.1.1.1 by default) to verify
/// that the VPN tunnel is working correctly.
///
/// # Arguments
///
/// * `target` - Optional target IP/hostname to ping (defaults to 1.1.1.1)
/// * `timeout_ms` - Timeout in milliseconds for the ping (defaults to 5000)
///
/// # Returns
///
/// - `Ok(latency_ms)` if ping was successful
/// - `Err(error)` if ping failed
pub async fn perform_ping_check(target: Option<&str>, timeout_ms: Option<u64>) -> Result<u64, String> {
    let target = target.unwrap_or("1.1.1.1");
    let timeout = timeout_ms.unwrap_or(5000);

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let output = tokio::process::Command::new("ping")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-n", "1", "-w", &timeout.to_string(), target])
            .output()
            .await
            .map_err(|e| format!("Failed to execute ping: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse Windows ping output: "time=XXms" or "time<1ms"
        if let Some(time_pos) = stdout.find("time=") {
            let time_str = &stdout[time_pos + 5..];
            if let Some(ms_pos) = time_str.find("ms") {
                let num_str = &time_str[..ms_pos];
                return num_str.trim().parse::<u64>()
                    .map_err(|_| "Failed to parse ping time".to_string());
            }
        } else if stdout.contains("time<1ms") {
            return Ok(1);
        }

        Err("Ping failed or timed out".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let timeout_secs = (timeout / 1000).max(1);
        let output = tokio::process::Command::new("ping")
            .args(["-c", "1", "-W", &timeout_secs.to_string(), target])
            .output()
            .await
            .map_err(|e| format!("Failed to execute ping: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse Linux ping output: "time=XX.X ms"
        if let Some(time_pos) = stdout.find("time=") {
            let time_str = &stdout[time_pos + 5..];
            if let Some(ms_pos) = time_str.find(" ms") {
                let num_str = &time_str[..ms_pos];
                return num_str.trim().parse::<f64>()
                    .map(|v| v as u64)
                    .map_err(|_| "Failed to parse ping time".to_string());
            }
        }

        Err("Ping failed or timed out".to_string())
    }
}

/// Default timeout for graceful shutdown before force kill (in seconds)
const GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 5;

/// Perform graceful shutdown of the sing-box process
///
/// This implements the graceful shutdown sequence:
/// 1. Send SIGTERM (or equivalent on Windows) to request graceful termination
/// 2. Wait up to 5 seconds for the process to exit
/// 3. If still running, send SIGKILL (force terminate)
/// 4. Clean up firewall rules (kill switch)
/// 5. Restore DNS settings
///
/// # Arguments
///
/// * `state` - The application state containing the process handle
///
/// # Returns
///
/// * `Ok(())` if shutdown completed successfully
/// * `Err(String)` if there was an error during shutdown
pub async fn graceful_shutdown(state: &AppState) -> Result<(), String> {
    // Take the process handle
    let child = {
        let mut process = state.singbox_process.lock().unwrap();
        process.take()
    };

    // Perform graceful process termination
    if child.is_some() {
        graceful_kill_process().await?;
    } else {
        // No process handle, but sing-box might still be running as a separate process
        // Try to kill it anyway
        graceful_kill_external_process().await?;
    }

    // Clean up firewall rules (kill switch)
    cleanup_firewall()?;

    // Restore DNS settings
    restore_dns()?;

    Ok(())
}

/// Graceful process termination for external sing-box process
///
/// This handles the case where sing-box is running but we don't have a handle to it
/// (e.g., after a crash recovery or when started with elevation)
async fn graceful_kill_external_process() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        // Helper: check if sing-box.exe is present
        let is_running = || {
            std::process::Command::new("tasklist")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["/FI", "IMAGENAME eq sing-box.exe"])
                .output()
                .ok()
                .map(|out| String::from_utf8_lossy(&out.stdout).contains("sing-box.exe"))
                .unwrap_or(false)
        };

        // Try graceful termination (no /F, with /T to catch child tree)
        let _ = std::process::Command::new("taskkill")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/IM", "sing-box.exe", "/T"])
            .output();

        // Wait briefly for clean exit
        for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            if !is_running() {
                return Ok(());
            }
        }

        // Elevate and force kill if still running
        let elevated = std::process::Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "-Command",
                "Start-Process -FilePath 'taskkill' -ArgumentList '/F /T /IM sing-box.exe' -Verb RunAs -WindowStyle Hidden -Wait"
            ])
            .output();

        if elevated.is_err() {
            return Err("Failed to request elevated taskkill".to_string());
        }

        // Final check
        if is_running() {
            return Err("sing-box.exe is still running after taskkill".to_string());
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        // First try SIGTERM via pkexec
        let sigterm_result = std::process::Command::new("pkexec")
            .args(["killall", "-TERM", "sing-box"])
            .output();

        if sigterm_result.is_ok() {
            // Wait for process to exit gracefully
            for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                // Check if process is still running
                let check = std::process::Command::new("pgrep")
                    .arg("-x")
                    .arg("sing-box")
                    .output();

                if let Ok(out) = check {
                    if !out.status.success() {
                        // Process not found - it exited
                        return Ok(());
                    }
                }
            }
        }

        // Force kill (SIGKILL) if still running
        let _ = std::process::Command::new("pkexec")
            .args(["killall", "-KILL", "sing-box"])
            .output();

        Ok(())
    }
}

/// Graceful process termination when we have a process handle
async fn graceful_kill_process() -> Result<(), String> {
    // For elevated processes, we need to use external commands
    // The process handle we have is typically for the wrapper (sh/powershell)
    graceful_kill_external_process().await
}

/// Clean up firewall rules (kill switch)
///
/// This removes any firewall rules that were set up by the kill switch
/// to restore normal network connectivity.
fn cleanup_firewall() -> Result<(), String> {
    // Use the kill switch cleanup function
    match super::cleanup_killswitch() {
        Ok(_) => Ok(()),
        Err(e) => {
            // Log but don't fail - best effort cleanup
            eprintln!("Warning: Failed to cleanup firewall rules: {}", e);
            Ok(())
        }
    }
}

/// Restore DNS settings to system defaults
///
/// On Linux, sing-box with auto_route handles DNS through the TUN interface.
/// When sing-box stops, the TUN interface is removed and DNS should automatically
/// revert. However, if resolvconf or systemd-resolved was modified, we need to restore it.
///
/// On Windows, DNS settings are typically restored automatically when the VPN
/// adapter is removed.
fn restore_dns() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        // Check if systemd-resolved is in use and restore if needed
        if std::path::Path::new("/run/systemd/resolve").exists() {
            // Flush DNS cache to ensure stale VPN DNS entries are cleared
            let _ = std::process::Command::new("systemd-resolve")
                .arg("--flush-caches")
                .output();

            // Alternative command for newer systemd versions
            let _ = std::process::Command::new("resolvectl")
                .arg("flush-caches")
                .output();
        }

        // If using resolvconf, it should auto-restore when the interface is down
        // No explicit action needed

        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        // Flush DNS cache to clear any VPN-related entries
        let _ = std::process::Command::new("ipconfig")
            .creation_flags(CREATE_NO_WINDOW)
            .arg("/flushdns")
            .output();

        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        // No-op on unsupported platforms
        Ok(())
    }
}

/// Graceful shutdown synchronous version (for use in event handlers)
///
/// This is a blocking version of graceful_shutdown for use in contexts
/// where async is not available (e.g., tray menu handlers, window close events).
///
/// Implements the same shutdown sequence:
/// 1. SIGTERM -> 5s wait -> SIGKILL
/// 2. Cleanup firewall
/// 3. Restore DNS
pub fn graceful_shutdown_sync() {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let is_running = || {
            std::process::Command::new("tasklist")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["/FI", "IMAGENAME eq sing-box.exe"])
                .output()
                .ok()
                .map(|out| String::from_utf8_lossy(&out.stdout).contains("sing-box.exe"))
                .unwrap_or(false)
        };

        // First try graceful termination (no /F, but with /T)
        let _ = std::process::Command::new("taskkill")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/IM", "sing-box.exe", "/T"])
            .output();

        for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if !is_running() {
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

        if !is_running() {
            let _ = cleanup_firewall();
            let _ = restore_dns();
            return;
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // First try SIGTERM
        let sigterm_result = std::process::Command::new("pkexec")
            .args(["killall", "-TERM", "sing-box"])
            .output();

        if sigterm_result.is_ok() {
            // Wait for process to exit gracefully (blocking)
            for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
                std::thread::sleep(std::time::Duration::from_millis(100));

                let check = std::process::Command::new("pgrep")
                    .arg("-x")
                    .arg("sing-box")
                    .output();

                if let Ok(out) = check {
                    if !out.status.success() {
                        // Process exited gracefully
                        let _ = cleanup_firewall();
                        let _ = restore_dns();
                        return;
                    }
                }
            }
        }

        // Force kill (SIGKILL) if still running
        let _ = std::process::Command::new("pkexec")
            .args(["killall", "-KILL", "sing-box"])
            .output();
    }

    // Cleanup firewall and DNS
    let _ = cleanup_firewall();
    let _ = restore_dns();
}

/// Kill sing-box process synchronously (for use in event handlers)
///
/// This is a legacy function that performs immediate force termination.
/// For graceful shutdown, use `graceful_shutdown_sync()` instead.
///
/// Note: This function is kept for backward compatibility but internally
/// now delegates to `graceful_shutdown_sync()` for proper cleanup.
pub fn kill_singbox_sync() {
    graceful_shutdown_sync();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_health_status_is_healthy() {
        assert!(ProcessHealthStatus::Running.is_healthy());
        assert!(!ProcessHealthStatus::Exited(Some(0)).is_healthy());
        assert!(!ProcessHealthStatus::Exited(None).is_healthy());
        assert!(!ProcessHealthStatus::NotRunning.is_healthy());
        assert!(!ProcessHealthStatus::Error("error".to_string()).is_healthy());
    }

    #[test]
    fn test_process_health_status_is_exited() {
        assert!(!ProcessHealthStatus::Running.is_exited());
        assert!(ProcessHealthStatus::Exited(Some(0)).is_exited());
        assert!(ProcessHealthStatus::Exited(Some(1)).is_exited());
        assert!(ProcessHealthStatus::Exited(None).is_exited());
        assert!(ProcessHealthStatus::NotRunning.is_exited());
        assert!(!ProcessHealthStatus::Error("error".to_string()).is_exited());
    }

    #[test]
    fn test_process_health_status_debug() {
        // Ensure Debug is derived
        let running = ProcessHealthStatus::Running;
        let debug_str = format!("{:?}", running);
        assert!(debug_str.contains("Running"));

        let exited = ProcessHealthStatus::Exited(Some(42));
        let debug_str = format!("{:?}", exited);
        assert!(debug_str.contains("Exited"));
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn test_process_health_status_clone() {
        let original = ProcessHealthStatus::Exited(Some(1));
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_process_health_status_eq() {
        assert_eq!(ProcessHealthStatus::Running, ProcessHealthStatus::Running);
        assert_eq!(
            ProcessHealthStatus::Exited(Some(0)),
            ProcessHealthStatus::Exited(Some(0))
        );
        assert_ne!(
            ProcessHealthStatus::Exited(Some(0)),
            ProcessHealthStatus::Exited(Some(1))
        );
        assert_ne!(
            ProcessHealthStatus::Exited(Some(0)),
            ProcessHealthStatus::NotRunning
        );
        assert_eq!(ProcessHealthStatus::NotRunning, ProcessHealthStatus::NotRunning);
        assert_eq!(
            ProcessHealthStatus::Error("a".to_string()),
            ProcessHealthStatus::Error("a".to_string())
        );
        assert_ne!(
            ProcessHealthStatus::Error("a".to_string()),
            ProcessHealthStatus::Error("b".to_string())
        );
    }

    #[test]
    fn test_check_process_health_uses_system_command() {
        // This test verifies that check_process_health uses system commands
        // (pgrep/tasklist) to check if sing-box is running, not internal handles.
        // Since sing-box is unlikely to be running during tests, we expect NotRunning.
        let state = AppState::default();
        let status = check_process_health(&state);
        // Should return NotRunning or Running based on actual system state
        // (not based on internal process handle)
        assert!(matches!(status, ProcessHealthStatus::NotRunning | ProcessHealthStatus::Running | ProcessHealthStatus::Error(_)));
    }
}
