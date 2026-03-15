//! Sing-box process management
//!
//! This module handles starting, stopping, and monitoring the sing-box VPN process.
//! Platform-specific code lives in the `platform` submodules (linux, macos, windows).

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Manager, State};
use tauri::path::BaseDirectory;
use tokio::process::Child;

use super::manager::{HealthMonitorHandle, VpnManager, ConnectionState};
use super::platform;
use super::{ServerConfig, RuleSetInfo};
use crate::logging::{CircularLogBuffer, LogEntry, LogLevel, parse_singbox_line};
use crate::notifications::{emit_vpn_event, VpnEvent};

// ==================== Constants ====================

/// Default health check interval for auto-reconnect (5 seconds)
pub const HEALTH_CHECK_INTERVAL_MS: u64 = 5000;

/// Maximum reconnection attempts before giving up
pub const MAX_RECONNECT_ATTEMPTS: u32 = 5;

/// Reconnection delays: 1s, 2s, 4s, 8s, max 30s
pub const RECONNECT_INITIAL_DELAY_MS: u64 = 1000;
pub const RECONNECT_MAX_DELAY_MS: u64 = 30000;

/// Default timeout for graceful shutdown before force kill (in seconds)
pub const GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 5;

/// Number of consecutive connectivity probe failures before triggering self-heal restart
const CONNECTIVITY_FAIL_THRESHOLD: u32 = 3;

/// Warmup period after connection before connectivity probes start (seconds)
const CONNECTIVITY_WARMUP_SECS: u64 = 15;

/// Cooldown after a self-heal restart before allowing another (seconds)
const SELF_HEAL_COOLDOWN_SECS: u64 = 90;

// ==================== AppState ====================

/// Application state holding the sing-box process handle and log buffer
pub struct AppState {
    pub singbox_process: Mutex<Option<Child>>,
    pub log_buffer: CircularLogBuffer,
    pub health_monitor: Mutex<Option<HealthMonitorHandle>>,
    pub current_config: Mutex<Option<ServerConfig>>,
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
    pub fn log(&self, level: LogLevel, message: String) {
        self.log_buffer.push(LogEntry::from_app(level, message));
    }

    pub fn log_singbox(&self, level: LogLevel, message: String) {
        self.log_buffer.push(LogEntry::from_singbox(level, message));
    }

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

    pub fn store_config(&self, config: ServerConfig) {
        let mut current = self.current_config.lock().unwrap();
        *current = Some(config);
    }

    pub fn get_config(&self) -> Option<ServerConfig> {
        self.current_config.lock().unwrap().clone()
    }

    pub fn clear_config(&self) {
        let mut current = self.current_config.lock().unwrap();
        *current = None;
    }

    pub fn set_health_monitor(&self, handle: Option<HealthMonitorHandle>) {
        let mut monitor = self.health_monitor.lock().unwrap();
        *monitor = handle;
    }

    pub fn stop_health_monitor(&self) {
        let mut monitor = self.health_monitor.lock().unwrap();
        if let Some(handle) = monitor.take() {
            handle.stop();
        }
    }
}

// ==================== Path helpers ====================

pub fn get_log_path() -> PathBuf {
    get_config_dir().join("singbox.log")
}

pub fn get_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zen-vpn")
}

pub fn get_singbox_config_path() -> PathBuf {
    get_config_dir().join("config.json")
}

pub fn get_singbox_binary_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    { get_config_dir().join("sing-box.exe") }
    #[cfg(not(target_os = "windows"))]
    { get_config_dir().join("sing-box") }
}

/// Resolve server hostname to IP address
pub fn resolve_server_ip(address: &str) -> String {
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

// ==================== Config generation ====================

/// Generate sing-box configuration JSON from ServerConfig (Hysteria2 only)
#[tauri::command]
pub fn generate_singbox_config(config: ServerConfig) -> Result<String, String> {
    let server_ip = resolve_server_ip(&config.address);

    // Use platform constants for TUN config
    let inet4_address = platform::TUN_ADDRESS;
    let strict_route = platform::TUN_STRICT_ROUTE;
    let default_stack = platform::TUN_DEFAULT_STACK;

    // On macOS, use a random utun name to avoid conflicts
    #[cfg(target_os = "macos")]
    let tun_interface_owned = platform::tun_interface_name();
    #[cfg(not(target_os = "macos"))]
    let tun_interface_owned = platform::TUN_INTERFACE_NAME.to_string();
    let tun_interface = tun_interface_owned.as_str();

    // Diagnostic overrides
    let stack = config.diag_stack.as_deref().unwrap_or(default_stack);
    let mtu = config.diag_mtu.unwrap_or(1280);
    let sniff = config.diag_sniff.unwrap_or(true);
    let plain_dns = config.diag_plain_dns.unwrap_or(false);
    let udp_timeout = config.diag_udp_timeout;
    let endpoint_independent_nat = config.diag_endpoint_independent_nat.unwrap_or(true);

    // Routing mode / country
    let routing_mode = config.routing_mode.as_deref().unwrap_or("global");
    let target_country = config.target_country.as_deref().unwrap_or("ru");

    // Resolve available rule-set files
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

    // Detect physical interface
    let physical_iface = platform::detect_physical_interface();

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
        "final": "proxy",
        "default_domain_resolver": {
            "server": "local"
        }
    });

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

    // Build Hysteria2 proxy outbound
    let mut proxy_outbound = {
        let mut obj = serde_json::json!({
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
        if let Some(ref iface) = physical_iface {
            obj["bind_interface"] = serde_json::json!(iface);
        }
        obj
    };
    if let Some(up) = config.up_mbps {
        proxy_outbound["up_mbps"] = serde_json::json!(up);
    }
    if let Some(down) = config.down_mbps {
        proxy_outbound["down_mbps"] = serde_json::json!(down);
    }
    if let Some(ref obfs_type) = config.obfs {
        if !obfs_type.is_empty() {
            proxy_outbound["obfs"] = serde_json::json!({
                "type": obfs_type,
                "password": config.obfs_password.as_deref().unwrap_or("")
            });
        }
    }
    if let Some(timeout) = udp_timeout {
        proxy_outbound["udp_timeout"] = serde_json::json!(format!("{}s", timeout));
    }

    let singbox_config = serde_json::json!({
        "log": {
            "level": "debug",
            "timestamp": true
        },
        "dns": {
            "servers": [
                if plain_dns {
                    serde_json::json!({
                        "tag": "remote",
                        "type": "udp",
                        "server": "1.1.1.1",
                        "detour": "proxy"
                    })
                } else {
                    serde_json::json!({
                        "tag": "remote",
                        "type": "tls",
                        "server": "1.1.1.1",
                        "detour": "proxy"
                    })
                },
                {
                    "tag": "local",
                    "type": "udp",
                    "server": "8.8.8.8"
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
                "interface_name": tun_interface,
                "address": [inet4_address],
                "mtu": mtu,
                "auto_route": true,
                "strict_route": strict_route,
                "stack": stack,
                "sniff": sniff,
                "sniff_override_destination": false,
                "udp_timeout": if let Some(t) = udp_timeout { format!("{}s", t) } else { "5m0s".to_string() },
                "endpoint_independent_nat": endpoint_independent_nat
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

// ==================== Log reader ====================

pub fn spawn_log_reader(log_buffer: CircularLogBuffer) {
    tokio::spawn(async move {
        let log_path = get_log_path();
        let mut last_size: u64 = 0;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            if let Ok(metadata) = fs::metadata(&log_path) {
                let current_size = metadata.len();
                if current_size > last_size {
                    if let Ok(content) = fs::read_to_string(&log_path) {
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

pub fn clear_log_file() -> Result<(), String> {
    let log_path = get_log_path();
    if log_path.exists() {
        if fs::write(&log_path, "").is_err() {
            let _ = fs::remove_file(&log_path);
            let _ = fs::File::create(&log_path);
        }
    }
    Ok(())
}

// ==================== Resource copying ====================

pub fn copy_resource_file(app_handle: &AppHandle, filename: &str) -> Result<(), String> {
    let target_path = get_config_dir().join(filename);

    let resource_path = match app_handle.path().resolve(format!("resources/{}", filename), BaseDirectory::Resource) {
        Ok(path) => path,
        Err(_) => PathBuf::from("src-tauri/resources").join(filename),
    };

    let source_path = if resource_path.exists() {
        resource_path
    } else {
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

/// Get available country rule sets
#[tauri::command]
pub fn get_available_rule_sets(app_handle: AppHandle) -> Result<Vec<RuleSetInfo>, String> {
    let mut rules = Vec::new();

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
                    let name = id.to_uppercase();
                    rules.push(RuleSetInfo { id, name });
                }
            }
        }
    }

    rules.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rules)
}

// ==================== Kill switch helpers ====================

pub fn auto_enable_killswitch(server_address: &str, app_handle: &AppHandle) {
    let server_ip = resolve_server_ip(server_address);
    let killswitch = super::create_killswitch();

    // Read the actual TUN interface name from the generated config
    let tun_name = fs::read_to_string(get_singbox_config_path())
        .ok()
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
        .and_then(|v| v["inbounds"][0]["interface_name"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| platform::TUN_INTERFACE_NAME.to_string());

    match killswitch.check_availability() {
        Ok(backend) => {
            let config = super::KillSwitchConfig {
                server_ip: server_ip.clone(),
                tun_interface: tun_name,
                singbox_path: get_singbox_binary_path(),
            };

            match killswitch.enable(&config) {
                Ok(result) => {
                    if result.success {
                        eprintln!("Kill switch auto-enabled ({}) for server {}", backend, server_ip);
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
        Err(_) => {}
    }
}

pub fn cleanup_firewall() -> Result<(), String> {
    match super::cleanup_killswitch() {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("Warning: Failed to cleanup firewall rules: {}", e);
            Ok(())
        }
    }
}

// ==================== Health monitoring ====================

/// Result of a process health check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessHealthStatus {
    Running,
    Exited(Option<i32>),
    NotRunning,
    Restarting,
    Error(String),
}

impl ProcessHealthStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, ProcessHealthStatus::Running)
    }

    pub fn is_exited(&self) -> bool {
        matches!(self, ProcessHealthStatus::Exited(_) | ProcessHealthStatus::NotRunning)
    }
}

/// Check the health of the sing-box process (delegates to platform)
pub fn check_process_health(_state: &AppState) -> ProcessHealthStatus {
    platform::check_platform_process_health()
}

/// Perform a ping check to verify network connectivity through the VPN
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

// ==================== Connectivity probes ====================

/// Perform a TCP connectivity probe to verify VPN tunnel is actually working.
/// This is more reliable than ping — it doesn't require root and works through TUN.
/// Tries to TCP-connect to well-known hosts. If all fail, the tunnel is broken.
pub async fn connectivity_probe() -> bool {
    let targets = [
        ("1.1.1.1", 443),
        ("8.8.8.8", 53),
        ("93.184.216.34", 80), // example.com
    ];

    for (host, port) in &targets {
        let addr = format!("{}:{}", host, port);
        let timeout = Duration::from_secs(5);

        match tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect(&addr),
        ).await {
            Ok(Ok(_stream)) => return true,  // At least one target reachable
            _ => continue,
        }
    }

    false // All targets unreachable — tunnel is broken
}

// ==================== Auto-reconnect monitor ====================

/// Spawn a health monitor with connectivity probes and auto-reconnect.
///
/// This monitor checks both:
/// 1. Process liveness (is sing-box running?)
/// 2. Connectivity (can we TCP-connect through the tunnel?)
///
/// If the process dies OR connectivity fails 3 times in a row, it triggers
/// a full reconnection with fresh config on ALL platforms (including macOS).
pub fn spawn_auto_reconnect_monitor(
    state: Arc<AppState>,
    vpn_manager: Arc<VpnManager>,
    app_handle: AppHandle,
) -> HealthMonitorHandle {
    let state_clone = Arc::clone(&state);
    let vpn_manager_clone = Arc::clone(&vpn_manager);
    let app_handle_clone = app_handle.clone();

    let task = tokio::spawn(async move {
        let mut consecutive_failures: u32 = 0;
        let start_time = std::time::Instant::now();
        let mut last_self_heal: Option<std::time::Instant> = None;

        loop {
            tokio::time::sleep(Duration::from_millis(HEALTH_CHECK_INTERVAL_MS)).await;

            // Skip if shutdown requested or already reconnecting
            if vpn_manager_clone.is_shutdown_requested()
                || vpn_manager_clone.is_reconnecting()
                || vpn_manager_clone.is_connecting()
            {
                consecutive_failures = 0;
                continue;
            }

            // Check process liveness
            let process_status = check_process_health(&state_clone);

            match process_status {
                ProcessHealthStatus::Running => {
                    // Process alive — check connectivity after warmup period
                    if start_time.elapsed() < Duration::from_secs(CONNECTIVITY_WARMUP_SECS) {
                        consecutive_failures = 0;
                        continue;
                    }

                    if connectivity_probe().await {
                        // All good — reset failure counter
                        if consecutive_failures > 0 {
                            state_clone.log(LogLevel::Info,
                                "Connectivity restored".to_string());
                        }
                        consecutive_failures = 0;
                    } else {
                        consecutive_failures += 1;
                        state_clone.log(LogLevel::Warn,
                            format!("Connectivity probe failed ({}/{})",
                                consecutive_failures, CONNECTIVITY_FAIL_THRESHOLD));

                        if consecutive_failures >= CONNECTIVITY_FAIL_THRESHOLD {
                            // Check cooldown — don't self-heal too rapidly
                            if let Some(last) = last_self_heal {
                                if last.elapsed() < Duration::from_secs(SELF_HEAL_COOLDOWN_SECS) {
                                    state_clone.log(LogLevel::Warn,
                                        format!("Self-heal cooldown active ({}s remaining)",
                                            SELF_HEAL_COOLDOWN_SECS - last.elapsed().as_secs()));
                                    consecutive_failures = 0;
                                    continue;
                                }
                            }
                            last_self_heal = Some(std::time::Instant::now());

                            state_clone.log(LogLevel::Error,
                                "Tunnel broken — triggering self-heal restart".to_string());
                            trigger_reconnection(
                                &state_clone, &vpn_manager_clone, &app_handle_clone,
                                "Tunnel connectivity lost"
                            ).await;
                            return; // Monitor stops; reconnection spawns a new one
                        }
                    }
                }
                ProcessHealthStatus::Restarting => {
                    // macOS launchd is restarting sing-box, give it time
                    consecutive_failures = 0;
                }
                ProcessHealthStatus::NotRunning | ProcessHealthStatus::Exited(_) => {
                    state_clone.log(LogLevel::Warn,
                        format!("Sing-box process died ({:?})", process_status));
                    trigger_reconnection(
                        &state_clone, &vpn_manager_clone, &app_handle_clone,
                        "VPN process died"
                    ).await;
                    return;
                }
                ProcessHealthStatus::Error(ref e) => {
                    state_clone.log(LogLevel::Warn,
                        format!("Health check error: {}", e));
                }
            }
        }
    });

    HealthMonitorHandle::new(task.abort_handle())
}

/// Trigger a full reconnection (used by health monitor for all platforms)
async fn trigger_reconnection(
    state: &Arc<AppState>,
    vpn_manager: &Arc<VpnManager>,
    app_handle: &AppHandle,
    reason: &str,
) {
    let config = match state.get_config() {
        Some(c) => c,
        None => {
            state.log(LogLevel::Error,
                "Cannot reconnect: no VPN configuration stored".to_string());
            emit_vpn_event(app_handle,
                VpnEvent::error("Cannot reconnect: no configuration available",
                    Some("NO_CONFIG".to_string())));
            vpn_manager.set_state(ConnectionState::Failed);
            return;
        }
    };

    state.log(LogLevel::Info, format!("Auto-reconnect triggered: {}", reason));

    // On macOS, stop the launchd daemon first so we can do a clean restart
    // with fresh config (new bind_interface, new gateway, etc.)
    #[cfg(target_os = "macos")]
    {
        if let Err(e) = platform::platform_stop_singbox(state).await {
            state.log(LogLevel::Warn, format!("Stop before reconnect failed: {}", e));
        }
    }

    vpn_manager.set_state(ConnectionState::Reconnecting);

    let state_for_reconnect = Arc::clone(state);
    let vpn_manager_for_reconnect = Arc::clone(vpn_manager);
    let app_handle_for_reconnect = app_handle.clone();

    tokio::spawn(async move {
        attempt_reconnection(
            state_for_reconnect,
            vpn_manager_for_reconnect,
            app_handle_for_reconnect,
            config,
        ).await;
    });
}

/// Attempt to reconnect to VPN with exponential backoff
async fn attempt_reconnection(
    state: Arc<AppState>,
    vpn_manager: Arc<VpnManager>,
    app_handle: AppHandle,
    config: ServerConfig,
) {
    vpn_manager.set_state(ConnectionState::Reconnecting);
    vpn_manager.reset_reconnect();
    vpn_manager.set_auto_reconnect(true);

    let mut attempt = 0u32;
    let mut delay_ms = RECONNECT_INITIAL_DELAY_MS;

    while attempt < MAX_RECONNECT_ATTEMPTS {
        attempt += 1;

        if vpn_manager.is_shutdown_requested() {
            state.log(LogLevel::Info, "Reconnection cancelled: shutdown requested".to_string());
            vpn_manager.set_state(ConnectionState::Disconnected);
            return;
        }

        emit_vpn_event(
            &app_handle,
            VpnEvent::reconnecting(attempt, MAX_RECONNECT_ATTEMPTS)
        );

        state.log(
            LogLevel::Info,
            format!("Reconnection attempt {} of {}, waiting {}ms...", attempt, MAX_RECONNECT_ATTEMPTS, delay_ms)
        );

        tokio::time::sleep(Duration::from_millis(delay_ms)).await;

        if vpn_manager.is_shutdown_requested() {
            state.log(LogLevel::Info, "Reconnection cancelled: shutdown requested".to_string());
            vpn_manager.set_state(ConnectionState::Disconnected);
            return;
        }

        match platform::platform_reconnect_singbox(&state, &config).await {
            Ok(()) => {
                state.log(LogLevel::Info, format!("Reconnection successful on attempt {}", attempt));

                // Re-enable kill switch on platforms that use external firewall rules
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                if !config.diag_no_killswitch.unwrap_or(false) {
                    auto_enable_killswitch(&config.address, &app_handle);
                    state.log(LogLevel::Info, "Kill switch re-enabled after reconnection".to_string());
                }

                vpn_manager.set_state(ConnectionState::Connected);
                emit_vpn_event(
                    &app_handle,
                    VpnEvent::connected(config.name.clone(), config.address.clone())
                );

                let new_monitor = spawn_auto_reconnect_monitor(
                    Arc::clone(&state),
                    Arc::clone(&vpn_manager),
                    app_handle.clone(),
                );
                state.set_health_monitor(Some(new_monitor));
                return;
            }
            Err(e) => {
                if e.contains("User canceled") || e.contains("(-128)") {
                    state.log(
                        LogLevel::Info,
                        "Reconnection cancelled by user (password dialog dismissed)".to_string()
                    );
                    vpn_manager.set_state(ConnectionState::Disconnected);
                    vpn_manager.request_shutdown();
                    state.stop_health_monitor();
                    emit_vpn_event(
                        &app_handle,
                        VpnEvent::disconnected(Some("User cancelled authentication".to_string()))
                    );
                    return;
                }

                state.log(
                    LogLevel::Warn,
                    format!("Reconnection attempt {} failed: {}", attempt, e)
                );
            }
        }

        delay_ms = (delay_ms * 2).min(RECONNECT_MAX_DELAY_MS);
    }

    state.stop_health_monitor();
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

// ==================== Tauri commands ====================

/// Copy rule sets for smart routing
fn copy_smart_routing_resources(config: &ServerConfig, state: &AppState, app_handle: &AppHandle) {
    if config.routing_mode.as_deref() != Some("smart") {
        return;
    }

    let country = config.target_country.as_deref().unwrap_or("ru");
    let geoip = format!("geoip-{}.srs", country);
    let geosite_primary = format!("geosite-{}.srs", country);
    let geosite_fallback = format!("geosite-category-{}.srs", country);

    if let Err(e) = copy_resource_file(app_handle, &geoip) {
        state.log(LogLevel::Warn, format!("Failed to copy {}: {}", geoip, e));
    }
    if let Err(e) = copy_resource_file(app_handle, &geosite_primary) {
        state.log(LogLevel::Warn, format!("Failed to copy {}: {}", geosite_primary, e));
        if let Err(e2) = copy_resource_file(app_handle, &geosite_fallback) {
            state.log(LogLevel::Warn, format!("Failed to copy {}: {}", geosite_fallback, e2));
        }
    }
}

/// Start the sing-box process (cross-platform)
#[tauri::command]
pub async fn start_singbox(
    config: ServerConfig,
    state: State<'_, AppState>,
    vpn_manager: State<'_, Arc<VpnManager>>,
    app_handle: AppHandle,
) -> Result<(), String> {
    state.log(LogLevel::Info, format!("Starting VPN connection to {}", config.address));

    // Kill any existing sing-box process before starting a new one
    if platform::is_process_running() {
        state.log(LogLevel::Info, "Stopping existing sing-box process".to_string());
        state.stop_health_monitor();
        let _ = platform::platform_stop_singbox(&state).await;
        // Wait briefly for cleanup
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if !platform::is_process_running() { break; }
        }
    }

    state.store_config(config.clone());
    vpn_manager.clear_shutdown_request();
    vpn_manager.set_state(ConnectionState::Connecting);

    // Copy rule sets if smart routing
    copy_smart_routing_resources(&config, &state, &app_handle);

    // Clear previous log file
    clear_log_file()?;

    // Generate and write config
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

    // Spawn log reader before starting
    spawn_log_reader(state.log_buffer.clone());

    // Platform-specific start
    let child = platform::platform_start_singbox(&config, &state, &vpn_manager, &app_handle).await?;

    // Platform-specific wait for startup
    platform::platform_wait_for_start(child, &config, &state, &vpn_manager, &app_handle).await
}

/// Stop the sing-box process (cross-platform)
#[tauri::command]
pub async fn stop_singbox(
    state: State<'_, AppState>,
    vpn_manager: State<'_, Arc<VpnManager>>,
    app_handle: AppHandle,
) -> Result<(), String> {
    state.log(LogLevel::Info, "Stopping VPN connection (graceful shutdown)".to_string());

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

    // Platform-specific stop
    platform::platform_stop_singbox(&state).await?;

    // Restore DNS settings
    if let Err(e) = platform::restore_dns() {
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
    #[cfg(target_os = "windows")]
    { platform::is_process_running() }

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

/// Graceful shutdown synchronous version (for use in event handlers)
pub fn graceful_shutdown_sync() {
    platform::graceful_shutdown_sync();
}

/// Kill sing-box process synchronously (legacy wrapper)
pub fn kill_singbox_sync() {
    graceful_shutdown_sync();
}

// ==================== Tests ====================

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
        let state = AppState::default();
        let status = check_process_health(&state);
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
        assert!(result == "127.0.0.1" || result == "::1");
    }

    #[test]
    fn test_resolve_invalid_hostname() {
        let result = resolve_server_ip("thishostdoesnotexist.invalid.tld");
        assert_eq!(result, "thishostdoesnotexist.invalid.tld");
    }

    #[test]
    fn test_resolve_empty_string() {
        let result = resolve_server_ip("");
        assert_eq!(result, "");
    }

    // ==================== generate_singbox_config tests ====================

    fn make_hy2_config() -> ServerConfig {
        ServerConfig {
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
            diag_mtu: None,
            diag_sniff: None,
            diag_stack: None,
            diag_plain_dns: None,
            diag_udp_timeout: None,
            diag_no_killswitch: None,
            diag_endpoint_independent_nat: None,
        }
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
        let config = make_hy2_config();
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["route"]["final"], "proxy");
        assert!(v["route"].get("rule_set").is_none());
    }

    #[test]
    fn test_gen_dns_config() {
        let config = make_hy2_config();
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let dns_servers = v["dns"]["servers"].as_array().unwrap();
        assert_eq!(dns_servers.len(), 2);
        assert_eq!(dns_servers[0]["tag"], "remote");
        assert_eq!(dns_servers[0]["type"], "tls");
        assert_eq!(dns_servers[0]["server"], "1.1.1.1");
        assert_eq!(dns_servers[0]["detour"], "proxy");
        assert_eq!(dns_servers[1]["tag"], "local");
        assert_eq!(dns_servers[1]["type"], "udp");
        assert_eq!(dns_servers[1]["server"], "8.8.8.8");
        assert_eq!(v["dns"]["final"], "remote");
        assert_eq!(v["dns"]["strategy"], "ipv4_only");
    }

    #[test]
    fn test_gen_tun_inbound() {
        let config = make_hy2_config();
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let inbound = &v["inbounds"][0];
        assert_eq!(inbound["type"], "tun");
        assert_eq!(inbound["tag"], "tun-in");
        let iface_name = inbound["interface_name"].as_str().unwrap();
        #[cfg(target_os = "macos")]
        assert!(iface_name.starts_with("utun"), "macOS TUN should start with utun");
        #[cfg(not(target_os = "macos"))]
        assert_eq!(iface_name, platform::TUN_INTERFACE_NAME);
        assert_eq!(inbound["sniff"], true);
    }

    #[test]
    fn test_gen_server_ip_in_route_rules() {
        let config = make_hy2_config();
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let rules = v["route"]["rules"].as_array().unwrap();
        let ip_rule = rules.iter().find(|r| r.get("ip_cidr").is_some());
        assert!(ip_rule.is_some(), "Should have ip_cidr rule for server IP");
        let ip_cidr = ip_rule.unwrap()["ip_cidr"][0].as_str().unwrap();
        assert_eq!(ip_cidr, "5.6.7.8/32");
        assert_eq!(ip_rule.unwrap()["outbound"], "direct");
    }

    #[test]
    fn test_gen_domain_server_in_route_rules() {
        let mut config = make_hy2_config();
        config.address = "thishostdoesnotexist.invalid.tld".to_string();
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let rules = v["route"]["rules"].as_array().unwrap();
        let server_rule = rules.iter().find(|r| {
            r.get("ip_cidr").is_some() || r.get("domain").is_some()
        });
        assert!(server_rule.is_some());
    }

    #[test]
    fn test_gen_ip_is_private_rule() {
        let config = make_hy2_config();
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
        let config = make_hy2_config();
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
        let config = make_hy2_config();
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let rules = v["route"]["rules"].as_array().unwrap();
        let dns_rule = rules.iter().find(|r| r.get("protocol").is_some());
        assert!(dns_rule.is_some());
        assert_eq!(dns_rule.unwrap()["protocol"], "dns");
        assert_eq!(dns_rule.unwrap()["action"], "hijack-dns");
    }

    #[test]
    fn test_gen_serde_validity() {
        let config = make_hy2_config();
        let json_str = generate_singbox_config(config).unwrap();
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
        assert!(parsed.is_ok(), "Generated config should be valid JSON");
    }

    // ==================== Config serde roundtrip tests ====================

    #[test]
    fn test_hy2_config_serde_roundtrip() {
        let mut config = make_hy2_config();
        config.up_mbps = Some(100);
        config.down_mbps = Some(200);
        config.obfs = Some("salamander".to_string());
        config.obfs_password = Some("secret".to_string());
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.protocol.as_deref(), Some("hysteria2"));
        assert_eq!(deserialized.up_mbps, Some(100));
        assert_eq!(deserialized.down_mbps, Some(200));
        assert_eq!(deserialized.obfs.as_deref(), Some("salamander"));
        assert_eq!(deserialized.obfs_password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_config_optional_defaults() {
        let config = make_hy2_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.routing_mode, None);
        assert_eq!(deserialized.target_country, None);
    }

    #[test]
    fn test_config_backwards_compat() {
        let json = r#"{
            "uuid": "test",
            "address": "host",
            "port": 443,
            "security": "tls",
            "transport_type": "",
            "path": "",
            "host": "",
            "name": "Old"
        }"#;
        let config: ServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.uuid, "test");
        assert_eq!(config.protocol, None);
        assert_eq!(config.up_mbps, None);
        assert_eq!(config.down_mbps, None);
        assert_eq!(config.obfs, None);
        assert_eq!(config.obfs_password, None);
    }

    #[test]
    fn test_config_all_fields() {
        let config = ServerConfig {
            uuid: "password".to_string(),
            address: "addr".to_string(),
            port: 443,
            security: "tls".to_string(),
            transport_type: "".to_string(),
            path: "".to_string(),
            host: "host".to_string(),
            name: "name".to_string(),
            routing_mode: Some("smart".to_string()),
            target_country: Some("ru".to_string()),
            protocol: Some("hysteria2".to_string()),
            up_mbps: Some(50),
            down_mbps: Some(100),
            obfs: Some("salamander".to_string()),
            obfs_password: Some("pwd".to_string()),
            diag_mtu: None,
            diag_sniff: None,
            diag_stack: None,
            diag_plain_dns: None,
            diag_udp_timeout: None,
            diag_no_killswitch: None,
            diag_endpoint_independent_nat: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.routing_mode.as_deref(), Some("smart"));
        assert_eq!(deserialized.target_country.as_deref(), Some("ru"));
        assert_eq!(deserialized.up_mbps, Some(50));
        assert_eq!(deserialized.obfs_password.as_deref(), Some("pwd"));
    }
}
