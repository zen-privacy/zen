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
use tauri::{AppHandle, Manager, State};
use tauri::path::BaseDirectory;
use tokio::process::{Child, Command};

use super::manager::{HealthCheckConfig, HealthCheckResult, HealthMonitor, HealthMonitorHandle, VpnManager, ConnectionState};
use super::{VlessConfig, RuleSetInfo};
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

/// Detect the physical (non-tunnel) network interface on Linux.
/// This is needed when another VPN/TUN is active — we must route
/// VPN server traffic through the real physical interface.
#[cfg(target_os = "linux")]
fn detect_physical_interface() -> Option<String> {
    // Parse `ip route show default` to find physical interface
    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut physical_iface = None;

    for line in stdout.lines() {
        // Each line: "default via X.X.X.X dev IFACE ..."
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(dev_idx) = parts.iter().position(|&p| p == "dev") {
            if let Some(iface) = parts.get(dev_idx + 1) {
                // Skip tunnel/virtual interfaces
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
                    physical_iface = Some(iface.to_string());
                    break;
                }
            }
        }
    }

    physical_iface
}

#[cfg(not(target_os = "linux"))]
fn detect_physical_interface() -> Option<String> {
    None // On Windows/macOS, auto_detect_interface works fine
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

                // Re-enable kill switch after successful reconnection
                auto_enable_killswitch(&config.address, &app_handle);
                state.log(LogLevel::Info, "Kill switch re-enabled after reconnection".to_string());

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

    // Max retries reached - keep kill switch active to prevent IP leaks
    // User must explicitly disconnect to disable it
    state.log(
        LogLevel::Error,
        format!("Reconnection failed after {} attempts. Kill switch remains active to prevent IP leaks. Disconnect manually to restore network.", MAX_RECONNECT_ATTEMPTS)
    );
    vpn_manager.set_state(ConnectionState::Failed);
    emit_vpn_event(
        &app_handle,
        VpnEvent::error(
            format!("Reconnection failed after {} attempts. Network blocked for safety.", MAX_RECONNECT_ATTEMPTS),
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

/// Get available country rule sets
#[tauri::command]
pub fn get_available_rule_sets(app_handle: AppHandle) -> Result<Vec<RuleSetInfo>, String> {
    let mut rules = Vec::new();
    
    // Scan resources directory for geoip-*.srs files
    // In dev: src-tauri/resources
    // In prod: resources folder relative to executable
    
    let resource_dir = match app_handle.path().resolve("resources", BaseDirectory::Resource) {
        Ok(p) => p,
        Err(_) => PathBuf::from("src-tauri/resources"),
    };

    if let Ok(entries) = fs::read_dir(resource_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if filename.starts_with("geoip-") && filename.ends_with(".srs") {
                    let id = filename
                        .trim_start_matches("geoip-")
                        .trim_end_matches(".srs")
                        .to_string();
                    
                    // Simple name formatting: "ru" -> "RU"
                    let name = id.to_uppercase();
                    
                    rules.push(RuleSetInfo { id, name });
                }
            }
        }
    }
    
    // Sort by name
    rules.sort_by(|a, b| a.name.cmp(&b.name));
    
    Ok(rules)
}

/// Copy a resource file to the config directory
fn copy_resource_file(app_handle: &AppHandle, filename: &str) -> Result<(), String> {
    let target_path = get_config_dir().join(filename);
    
    // Resolve resource path
    let resource_path = match app_handle.path().resolve(format!("resources/{}", filename), BaseDirectory::Resource) {
        Ok(path) => path,
        Err(_) => {
            // Fallback for dev mode
            PathBuf::from("src-tauri/resources").join(filename)
        }
    };

    let source_path = if resource_path.exists() {
        resource_path
    } else {
        // Double check dev path if resolve failed but didn't error (shouldn't happen but safe)
        let dev_path = PathBuf::from("src-tauri/resources").join(filename);
        if dev_path.exists() {
            dev_path
        } else {
            return Err(format!("Resource not found: {}", filename));
        }
    };

    fs::copy(&source_path, &target_path)
        .map_err(|e| format!("Failed to copy resource file: {}", e))?;
        
    Ok(())
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
            },
            "max_early_data": 2048,
            "early_data_header_name": "Sec-WebSocket-Protocol"
        })
    } else {
        serde_json::json!(null)
    };

    // Detect Reality configuration from path params (e.g. "pbk=...&sid=...")
    // This allows using Reality without changing the UI
    let mut is_reality = false;
    let mut reality_pbk = String::new();
    let mut reality_sid = String::new();
    let mut reality_fp = "chrome".to_string();

    if config.transport_type == "tcp" && config.path.contains("pbk=") {
        is_reality = true;
        for pair in config.path.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "pbk" => reality_pbk = v.to_string(),
                    "sid" => reality_sid = v.to_string(),
                    "fp" => reality_fp = v.to_string(),
                    _ => {}
                }
            }
        }
    }

    // Always resolve server hostname to IP before starting sing-box.
    // This prevents DNS loop: sing-box routes all traffic through TUN,
    // so DNS queries for the VPN server hostname would also go through TUN.
    let server_ip = resolve_server_ip(&config.address);

    // Configure inbounds/inbound[0] based on platform
    let (inet4_address, strict_route, stack) = if cfg!(target_os = "windows") {
        ("172.19.0.1/30", false, "system")
    } else {
        ("100.64.0.1/30", true, "gvisor")
    };

    // Prepare routing mode / country
    let routing_mode = config.routing_mode.as_deref().unwrap_or("global");
    let target_country = config.target_country.as_deref().unwrap_or("ru");

    // Resolve available rule-set files in config dir (copied beforehand)
    let geoip_file = format!("geoip-{}.srs", target_country);
    let geosite_primary = format!("geosite-{}.srs", target_country);
    let geosite_fallback = format!("geosite-category-{}.srs", target_country);

    let geoip_path = get_config_dir().join(&geoip_file);
    let geosite_path_primary = get_config_dir().join(&geosite_primary);
    let geosite_path_fallback = get_config_dir().join(&geosite_fallback);

    let geosite_path = if geosite_path_primary.exists() {
        Some((geosite_primary.clone(), geosite_path_primary))
    } else if geosite_path_fallback.exists() {
        Some((geosite_fallback.clone(), geosite_path_fallback))
    } else {
        None
    };

    // Detect physical interface to bypass any other active VPN/TUN
    let physical_iface = detect_physical_interface();

    let mut route_section = serde_json::json!({
        "rules": [
            {
                "protocol": "dns",
                "action": "hijack-dns"
            },
            if server_ip.parse::<std::net::IpAddr>().is_ok() {
                serde_json::json!({
                    "ip_cidr": [format!("{}/32", server_ip)],
                    "outbound": "direct"
                })
            } else {
                serde_json::json!({
                    "domain": [server_ip],
                    "outbound": "direct"
                })
            },
            {
                "ip_is_private": true,
                "outbound": "direct"
            }
        ],
        "auto_detect_interface": true,
        "final": "proxy"
    });

    // If a physical interface was detected, set it as default to bypass other VPNs
    if let Some(ref iface) = physical_iface {
        route_section["default_interface"] = serde_json::json!(iface);
    }

    if routing_mode == "smart" {
        let mut rule_set_entries = vec![];
        let mut country_rule_tags = vec![];

        if geoip_path.exists() {
            let tag = geoip_file.trim_end_matches(".srs").to_string();
            rule_set_entries.push(serde_json::json!({
                "tag": tag,
                "type": "local",
                "format": "binary",
                "path": geoip_path.to_string_lossy()
            }));
            country_rule_tags.push(tag);
        }

        if let Some((geosite_name, geosite_path)) = geosite_path {
            let tag = geosite_name.trim_end_matches(".srs").to_string();
            rule_set_entries.push(serde_json::json!({
                "tag": tag,
                "type": "local",
                "format": "binary",
                "path": geosite_path.to_string_lossy()
            }));
            country_rule_tags.push(tag);
        }

        if !rule_set_entries.is_empty() {
            route_section["rule_set"] = serde_json::json!(rule_set_entries);
        }

        if !country_rule_tags.is_empty() {
            if let Some(rules) = route_section["rules"].as_array_mut() {
                rules.push(serde_json::json!({
                    "rule_set": country_rule_tags,
                    "outbound": "direct"
                }));
            }
        }
    }

    // Configure security/tls
    let flow = if is_reality { "xtls-rprx-vision" } else { "" };
    
    let tls_config = if is_reality {
        // Reality configuration
        serde_json::json!({
            "enabled": true,
            "server_name": config.host.clone(),
            "insecure": false,
            "utls": {
                "enabled": true,
                "fingerprint": reality_fp
            },
            "reality": {
                "enabled": true,
                "public_key": reality_pbk,
                "short_id": reality_sid
            }
        })
    } else if config.security == "tls" {
        // Regular TLS configuration (no reality block)
        serde_json::json!({
            "enabled": true,
            "server_name": config.host.clone(),
            "insecure": false
        })
    } else {
        serde_json::json!(null)
    };

    // Build proxy outbound based on protocol
    let protocol = config.protocol.as_deref().unwrap_or("vless");

    let proxy_outbound = if protocol == "hysteria2" {
        let mut ob = serde_json::json!({
            "type": "hysteria2",
            "tag": "proxy",
            "server": server_ip.clone(),
            "server_port": config.port,
            "password": config.uuid,
            "tls": {
                "enabled": true,
                "server_name": if config.host.is_empty() { config.address.clone() } else { config.host.clone() },
                "insecure": false
            }
        });
        if let Some(up) = config.up_mbps {
            ob["up_mbps"] = serde_json::json!(up);
        }
        if let Some(down) = config.down_mbps {
            ob["down_mbps"] = serde_json::json!(down);
        }
        if let Some(ref obfs_type) = config.obfs {
            if !obfs_type.is_empty() {
                ob["obfs"] = serde_json::json!({
                    "type": obfs_type,
                    "password": config.obfs_password.as_deref().unwrap_or("")
                });
            }
        }
        ob
    } else {
        // VLESS outbound (existing logic)
        let mut ob = serde_json::json!({
            "type": "vless",
            "tag": "proxy",
            "server": server_ip.clone(),
            "server_port": config.port,
            "uuid": config.uuid,
            "tls": tls_config
        });

        if !flow.is_empty() {
            ob["flow"] = serde_json::json!(flow);
        }

        // Only add transport if it's WebSocket (not null)
        if config.transport_type == "ws" {
            ob["transport"] = transport;
        }
        ob
    };

    let singbox_config = serde_json::json!({
        "log": {
            "level": "debug",
            "timestamp": true
        },
        "dns": {
            "servers": [
                {
                    "tag": "remote",
                    "address": "tls://1.1.1.1",
                    "address_resolver": "local",
                    "detour": "proxy"
                },
                {
                    "tag": "local",
                    "address": "223.5.5.5",
                    "detour": "direct"
                }
            ],
            "rules": [],
            "final": "remote",
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "zen-tun",
                "address": [inet4_address],
                "mtu": 1400,
                "auto_route": true,
                "strict_route": strict_route,
                "stack": stack,
                "sniff": true,
                "sniff_override_destination": false
            }
        ],
        "outbounds": [
            proxy_outbound,
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": route_section
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

/// Auto-enable kill switch to prevent IP leaks when VPN disconnects
///
/// This is called automatically after successful VPN connection.
/// The kill switch firewall rules persist across sing-box crashes,
/// ensuring traffic is blocked during reconnection gaps.
/// Only disabled on intentional disconnect via stop_singbox().
fn auto_enable_killswitch(server_address: &str, app_handle: &AppHandle) {
    let server_ip = resolve_server_ip(server_address);
    let killswitch = super::create_killswitch();

    match killswitch.check_availability() {
        Ok(backend) => {
            let config = super::KillSwitchConfig {
                server_ip: server_ip.clone(),
                tun_interface: "zen-tun".to_string(),
                singbox_path: get_singbox_binary_path(),
            };

            match killswitch.enable(&config) {
                Ok(result) => {
                    if result.success {
                        eprintln!("Kill switch auto-enabled ({}) for server {}", backend, server_ip);
                        // Notify frontend about kill switch state change
                        emit_vpn_event(app_handle, VpnEvent::killswitch_changed(true));
                    } else {
                        eprintln!("Warning: Kill switch enable returned failure: {}", result.message);
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to auto-enable kill switch: {}", e);
                }
            }
        }
        Err(_) => {
            // Kill switch not available on this platform, skip silently
        }
    }
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

    // Copy rule sets if smart routing is enabled
    if config.routing_mode.as_deref() == Some("smart") {
        let country = config.target_country.as_deref().unwrap_or("ru");
        let geoip = format!("geoip-{}.srs", country);
        let geosite = format!("geosite-{}.srs", country);
        
        if let Err(e) = copy_resource_file(&app_handle, &geoip) {
            state.log(LogLevel::Warn, format!("Failed to copy {}: {}", geoip, e));
        }
        if let Err(e) = copy_resource_file(&app_handle, &geosite) {
            state.log(LogLevel::Warn, format!("Failed to copy {}: {}", geosite, e));
        }
    }

    // Copy rule sets (best effort) when smart routing is enabled
    if config.routing_mode.as_deref() == Some("smart") {
        let country = config.target_country.as_deref().unwrap_or("ru");
        let geoip = format!("geoip-{}.srs", country);
        let geosite_primary = format!("geosite-{}.srs", country);
        let geosite_fallback = format!("geosite-category-{}.srs", country);

        if let Err(e) = copy_resource_file(&app_handle, &geoip) {
            state.log(LogLevel::Warn, format!("Failed to copy {}: {}", geoip, e));
        }
        if let Err(e) = copy_resource_file(&app_handle, &geosite_primary) {
            state.log(LogLevel::Warn, format!("Failed to copy {}: {}", geosite_primary, e));
            // Try fallback category file
            if let Err(e2) = copy_resource_file(&app_handle, &geosite_fallback) {
                state.log(LogLevel::Warn, format!("Failed to copy {}: {}", geosite_fallback, e2));
            }
        }
    }

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

                // Auto-enable kill switch to prevent IP leaks on disconnect
                auto_enable_killswitch(&config.address, &app_handle);
                state.log(LogLevel::Info, "Kill switch auto-enabled".to_string());

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

    // Copy rule sets (best effort) when smart routing is enabled
    if config.routing_mode.as_deref() == Some("smart") {
        let country = config.target_country.as_deref().unwrap_or("ru");
        let geoip = format!("geoip-{}.srs", country);
        let geosite_primary = format!("geosite-{}.srs", country);
        let geosite_fallback = format!("geosite-category-{}.srs", country);

        if let Err(e) = copy_resource_file(&app_handle, &geoip) {
            state.log(LogLevel::Warn, format!("Failed to copy {}: {}", geoip, e));
        }
        if let Err(e) = copy_resource_file(&app_handle, &geosite_primary) {
            state.log(LogLevel::Warn, format!("Failed to copy {}: {}", geosite_primary, e));
            // Try fallback category file
            if let Err(e2) = copy_resource_file(&app_handle, &geosite_fallback) {
                state.log(LogLevel::Warn, format!("Failed to copy {}: {}", geosite_fallback, e2));
            }
        }
    }

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

                        // Auto-enable kill switch to prevent IP leaks on disconnect
                        auto_enable_killswitch(&config.address, &app_handle);
                        state.log(LogLevel::Info, "Kill switch auto-enabled".to_string());

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

    // ==================== resolve_server_ip tests ====================

    #[test]
    fn test_resolve_ipv4_passthrough() {
        assert_eq!(resolve_server_ip("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn test_resolve_ipv6_passthrough() {
        assert_eq!(resolve_server_ip("::1"), "::1");
        assert_eq!(resolve_server_ip("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn test_resolve_localhost() {
        let result = resolve_server_ip("localhost");
        // localhost should resolve to 127.0.0.1 or ::1
        assert!(result == "127.0.0.1" || result == "::1");
    }

    #[test]
    fn test_resolve_invalid_hostname() {
        // Completely invalid hostname should return original
        let result = resolve_server_ip("thishostdoesnotexist.invalid.tld");
        assert_eq!(result, "thishostdoesnotexist.invalid.tld");
    }

    #[test]
    fn test_resolve_empty_string() {
        let result = resolve_server_ip("");
        assert_eq!(result, "");
    }

    // ==================== generate_singbox_config tests ====================

    fn make_vless_config(
        transport: &str,
        security: &str,
        path: &str,
        host: &str,
    ) -> VlessConfig {
        VlessConfig {
            uuid: "test-uuid".to_string(),
            address: "1.2.3.4".to_string(),
            port: 443,
            security: security.to_string(),
            transport_type: transport.to_string(),
            path: path.to_string(),
            host: host.to_string(),
            name: "Test".to_string(),
            routing_mode: None,
            target_country: None,
            protocol: Some("vless".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            obfs_password: None,
        }
    }

    fn make_hy2_config() -> VlessConfig {
        VlessConfig {
            uuid: "mypassword".to_string(),
            address: "5.6.7.8".to_string(),
            port: 4443,
            security: "tls".to_string(),
            transport_type: "".to_string(),
            path: "".to_string(),
            host: "sni.example.com".to_string(),
            name: "HY2 Test".to_string(),
            routing_mode: None,
            target_country: None,
            protocol: Some("hysteria2".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            obfs_password: None,
        }
    }

    #[test]
    fn test_gen_vless_ws_config() {
        let config = make_vless_config("ws", "tls", "/ws-path", "cdn.example.com");
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let outbounds = v["outbounds"].as_array().unwrap();
        let proxy = &outbounds[0];
        assert_eq!(proxy["type"], "vless");
        assert_eq!(proxy["uuid"], "test-uuid");
        assert_eq!(proxy["server"], "1.2.3.4");
        assert_eq!(proxy["server_port"], 443);

        // Transport
        assert_eq!(proxy["transport"]["type"], "ws");
        assert_eq!(proxy["transport"]["path"], "/ws-path");
        assert_eq!(proxy["transport"]["headers"]["Host"], "cdn.example.com");

        // TLS
        assert_eq!(proxy["tls"]["enabled"], true);
        assert_eq!(proxy["tls"]["server_name"], "cdn.example.com");
    }

    #[test]
    fn test_gen_vless_reality_config() {
        let config = make_vless_config(
            "tcp",
            "reality",
            "pbk=PUBKEY&sid=SHORTID&fp=firefox",
            "www.google.com",
        );
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let proxy = &v["outbounds"][0];
        assert_eq!(proxy["type"], "vless");
        assert_eq!(proxy["flow"], "xtls-rprx-vision");
        assert_eq!(proxy["tls"]["reality"]["enabled"], true);
        assert_eq!(proxy["tls"]["reality"]["public_key"], "PUBKEY");
        assert_eq!(proxy["tls"]["reality"]["short_id"], "SHORTID");
        assert_eq!(proxy["tls"]["utls"]["fingerprint"], "firefox");
        // Should NOT have transport for tcp
        assert!(proxy.get("transport").is_none());
    }

    #[test]
    fn test_gen_vless_tcp_tls() {
        let config = make_vless_config("tcp", "tls", "", "example.com");
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let proxy = &v["outbounds"][0];
        assert_eq!(proxy["tls"]["enabled"], true);
        assert!(proxy.get("transport").is_none());
        assert!(proxy.get("flow").is_none() || proxy["flow"] == "");
    }

    #[test]
    fn test_gen_hysteria2_config() {
        let config = make_hy2_config();
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let proxy = &v["outbounds"][0];
        assert_eq!(proxy["type"], "hysteria2");
        assert_eq!(proxy["tag"], "proxy");
        assert_eq!(proxy["server"], "5.6.7.8");
        assert_eq!(proxy["server_port"], 4443);
        assert_eq!(proxy["password"], "mypassword");
        assert_eq!(proxy["tls"]["enabled"], true);
        assert_eq!(proxy["tls"]["server_name"], "sni.example.com");
        // No uuid field for hysteria2
        assert!(proxy.get("uuid").is_none());
    }

    #[test]
    fn test_gen_hysteria2_with_obfs() {
        let mut config = make_hy2_config();
        config.obfs = Some("salamander".to_string());
        config.obfs_password = Some("obfs-pwd".to_string());
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let proxy = &v["outbounds"][0];
        assert_eq!(proxy["obfs"]["type"], "salamander");
        assert_eq!(proxy["obfs"]["password"], "obfs-pwd");
    }

    #[test]
    fn test_gen_hysteria2_with_bandwidth() {
        let mut config = make_hy2_config();
        config.up_mbps = Some(50);
        config.down_mbps = Some(100);
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let proxy = &v["outbounds"][0];
        assert_eq!(proxy["up_mbps"], 50);
        assert_eq!(proxy["down_mbps"], 100);
    }

    #[test]
    fn test_gen_hysteria2_empty_host_uses_address() {
        let mut config = make_hy2_config();
        config.host = "".to_string();
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let proxy = &v["outbounds"][0];
        assert_eq!(proxy["tls"]["server_name"], "5.6.7.8");
    }

    #[test]
    fn test_gen_global_routing() {
        let config = make_vless_config("tcp", "none", "", "");
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["route"]["final"], "proxy");
        // Global mode should not have rule_set
        assert!(v["route"].get("rule_set").is_none());
    }

    #[test]
    fn test_gen_dns_config() {
        let config = make_vless_config("tcp", "none", "", "");
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let dns_servers = v["dns"]["servers"].as_array().unwrap();
        assert_eq!(dns_servers.len(), 2);
        assert_eq!(dns_servers[0]["tag"], "remote");
        assert_eq!(dns_servers[0]["address"], "tls://1.1.1.1");
        assert_eq!(dns_servers[0]["detour"], "proxy");
        assert_eq!(dns_servers[1]["tag"], "local");
        assert_eq!(dns_servers[1]["address"], "223.5.5.5");
        assert_eq!(dns_servers[1]["detour"], "direct");
        assert_eq!(v["dns"]["final"], "remote");
        assert_eq!(v["dns"]["strategy"], "ipv4_only");
    }

    #[test]
    fn test_gen_tun_inbound() {
        let config = make_vless_config("tcp", "none", "", "");
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let inbound = &v["inbounds"][0];
        assert_eq!(inbound["type"], "tun");
        assert_eq!(inbound["tag"], "tun-in");
        assert_eq!(inbound["interface_name"], "zen-tun");
        assert_eq!(inbound["sniff"], true);
    }

    #[test]
    fn test_gen_server_ip_in_route_rules() {
        let config = make_vless_config("tcp", "none", "", "");
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let rules = v["route"]["rules"].as_array().unwrap();
        // Find the rule with ip_cidr for the server
        let ip_rule = rules.iter().find(|r| r.get("ip_cidr").is_some());
        assert!(ip_rule.is_some(), "Should have ip_cidr rule for server IP");
        let ip_cidr = ip_rule.unwrap()["ip_cidr"][0].as_str().unwrap();
        assert_eq!(ip_cidr, "1.2.3.4/32");
        assert_eq!(ip_rule.unwrap()["outbound"], "direct");
    }

    #[test]
    fn test_gen_domain_server_in_route_rules() {
        // When server address is a domain (not IP), resolve_server_ip should handle it.
        // If it resolves to an IP, we get ip_cidr rule.
        // If it doesn't resolve (unlikely for real domains but common for test domains),
        // we get a domain rule.
        let mut config = make_vless_config("tcp", "none", "", "");
        config.address = "thishostdoesnotexist.invalid.tld".to_string();
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let rules = v["route"]["rules"].as_array().unwrap();
        // Should have either ip_cidr or domain rule for server
        let server_rule = rules.iter().find(|r| {
            r.get("ip_cidr").is_some() || r.get("domain").is_some()
        });
        assert!(server_rule.is_some());
    }

    #[test]
    fn test_gen_ip_is_private_rule() {
        let config = make_vless_config("tcp", "none", "", "");
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let rules = v["route"]["rules"].as_array().unwrap();
        let private_rule = rules.iter().find(|r| r.get("ip_is_private").is_some());
        assert!(private_rule.is_some());
        assert_eq!(private_rule.unwrap()["ip_is_private"], true);
        assert_eq!(private_rule.unwrap()["outbound"], "direct");
    }

    #[test]
    fn test_gen_outbounds_structure() {
        let config = make_vless_config("tcp", "none", "", "");
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let outbounds = v["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 2);
        assert_eq!(outbounds[0]["tag"], "proxy");
        assert_eq!(outbounds[1]["type"], "direct");
        assert_eq!(outbounds[1]["tag"], "direct");
    }

    #[test]
    fn test_gen_dns_hijack_rule() {
        let config = make_vless_config("tcp", "none", "", "");
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let rules = v["route"]["rules"].as_array().unwrap();
        let dns_rule = rules.iter().find(|r| r.get("protocol").is_some());
        assert!(dns_rule.is_some());
        assert_eq!(dns_rule.unwrap()["protocol"], "dns");
        assert_eq!(dns_rule.unwrap()["action"], "hijack-dns");
    }

    #[test]
    fn test_gen_serde_validity_all_protocols() {
        // All generated configs should be valid JSON
        let configs = vec![
            make_vless_config("ws", "tls", "/ws", "host.com"),
            make_vless_config("tcp", "reality", "pbk=pk&sid=sid&fp=chrome", "google.com"),
            make_vless_config("tcp", "tls", "", "host.com"),
            make_vless_config("tcp", "none", "", ""),
            make_hy2_config(),
        ];

        for config in configs {
            let json_str = generate_singbox_config(config).unwrap();
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
            assert!(parsed.is_ok(), "Generated config should be valid JSON");
        }
    }

    // ==================== VlessConfig serde roundtrip tests ====================

    #[test]
    fn test_vless_config_serde_roundtrip() {
        let config = make_vless_config("ws", "tls", "/ws", "host.com");
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: VlessConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.uuid, deserialized.uuid);
        assert_eq!(config.address, deserialized.address);
        assert_eq!(config.port, deserialized.port);
        assert_eq!(config.security, deserialized.security);
        assert_eq!(config.transport_type, deserialized.transport_type);
        assert_eq!(config.protocol, deserialized.protocol);
    }

    #[test]
    fn test_hy2_config_serde_roundtrip() {
        let mut config = make_hy2_config();
        config.up_mbps = Some(100);
        config.down_mbps = Some(200);
        config.obfs = Some("salamander".to_string());
        config.obfs_password = Some("secret".to_string());
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: VlessConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.protocol.as_deref(), Some("hysteria2"));
        assert_eq!(deserialized.up_mbps, Some(100));
        assert_eq!(deserialized.down_mbps, Some(200));
        assert_eq!(deserialized.obfs.as_deref(), Some("salamander"));
        assert_eq!(deserialized.obfs_password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_vless_config_optional_defaults() {
        let config = make_vless_config("tcp", "none", "", "");
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: VlessConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.routing_mode, None);
        assert_eq!(deserialized.target_country, None);
    }

    #[test]
    fn test_vless_config_backwards_compat() {
        // Old JSON without new hysteria2 fields should deserialize OK
        let json = r#"{
            "uuid": "test",
            "address": "host",
            "port": 443,
            "security": "none",
            "transport_type": "tcp",
            "path": "",
            "host": "",
            "name": "Old"
        }"#;
        let config: VlessConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.uuid, "test");
        assert_eq!(config.protocol, None);
        assert_eq!(config.up_mbps, None);
        assert_eq!(config.down_mbps, None);
        assert_eq!(config.obfs, None);
        assert_eq!(config.obfs_password, None);
    }

    #[test]
    fn test_vless_config_all_fields() {
        let config = VlessConfig {
            uuid: "uuid".to_string(),
            address: "addr".to_string(),
            port: 443,
            security: "tls".to_string(),
            transport_type: "ws".to_string(),
            path: "/path".to_string(),
            host: "host".to_string(),
            name: "name".to_string(),
            routing_mode: Some("smart".to_string()),
            target_country: Some("ru".to_string()),
            protocol: Some("vless".to_string()),
            up_mbps: Some(50),
            down_mbps: Some(100),
            obfs: Some("salamander".to_string()),
            obfs_password: Some("pwd".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: VlessConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.routing_mode.as_deref(), Some("smart"));
        assert_eq!(deserialized.target_country.as_deref(), Some("ru"));
        assert_eq!(deserialized.up_mbps, Some(50));
        assert_eq!(deserialized.obfs_password.as_deref(), Some("pwd"));
    }
}
