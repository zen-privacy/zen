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

#[cfg(target_os = "macos")]
fn detect_physical_interface() -> Option<String> {
    // Parse `route get default` to find physical interface on macOS
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let line = line.trim();
        if let Some(iface) = line.strip_prefix("interface:") {
            let iface = iface.trim();
            // Skip tunnel/virtual interfaces
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

#[cfg(target_os = "windows")]
fn detect_physical_interface() -> Option<String> {
    None // On Windows, auto_detect_interface works fine
}

/// Default health check interval for auto-reconnect (5 seconds)
const HEALTH_CHECK_INTERVAL_MS: u64 = 5000;

/// Maximum reconnection attempts before giving up
const MAX_RECONNECT_ATTEMPTS: u32 = 5;

/// Reconnection delays: 1s, 2s, 4s, 8s, max 30s
const RECONNECT_INITIAL_DELAY_MS: u64 = 1000;
const RECONNECT_MAX_DELAY_MS: u64 = 30000;

/// macOS LaunchDaemon label and install path
#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "com.zen.vpn";
#[cfg(target_os = "macos")]
const LAUNCHD_PLIST_INSTALL_PATH: &str = "/Library/LaunchDaemons/com.zen.vpn.plist";

#[cfg(target_os = "macos")]
fn get_launcher_script_path() -> PathBuf {
    get_config_dir().join("zen-vpn-launcher.sh")
}

#[cfg(target_os = "macos")]
fn get_launchd_plist_path() -> PathBuf {
    get_config_dir().join("com.zen.vpn.plist")
}

/// Check if the launchd job is currently loaded in the system domain
#[cfg(target_os = "macos")]
fn is_launchd_job_loaded() -> bool {
    std::process::Command::new("launchctl")
        .args(["print", &format!("system/{}", LAUNCHD_LABEL)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Generate the launcher script that launchd runs.
/// Sets up routes + pfctl, then execs sing-box so launchd tracks the real PID.
#[cfg(target_os = "macos")]
fn generate_launcher_script(
    server_address: &str,
    singbox_path: &PathBuf,
    config_path: &PathBuf,
    pf_conf_path: &PathBuf,
    skip_killswitch: bool,
) -> String {
    format!(
        r#"#!/bin/bash
SERVER="{server}"
SINGBOX="{singbox}"
CONFIG="{config}"
PF_CONF="{pf_conf}"
SKIP_KS="{skip_ks}"
DNS_BACKUP="{dns_backup}"

# Routes
GW=$(route -n get default 2>/dev/null | grep gateway | awk '{{print $2}}')
if [ -n "$GW" ]; then
    route delete -host "$SERVER" >/dev/null 2>&1
    route add -host "$SERVER" "$GW" >/dev/null 2>&1
fi

# Kill switch
if [ "$SKIP_KS" != "1" ] && [ -f "$PF_CONF" ]; then
    pfctl -a 'com.zen.vpn' -f "$PF_CONF" 2>/dev/null
    pfctl -e 2>/dev/null
fi

# Override system DNS to prevent leaks (save original first)
for svc in $(networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*'); do
    old_dns=$(networksetup -getdnsservers "$svc" 2>/dev/null)
    if echo "$old_dns" | grep -q "any DNS"; then
        echo "$svc=empty" >> "$DNS_BACKUP"
    else
        echo "$svc=$(echo $old_dns | tr '\n' ',')" >> "$DNS_BACKUP"
    fi
    networksetup -setdnsservers "$svc" 223.5.5.5 1.1.1.1 2>/dev/null
done
dscacheutil -flushcache 2>/dev/null
killall -HUP mDNSResponder 2>/dev/null

# Replace this process with sing-box (launchd tracks the PID)
exec "$SINGBOX" run -c "$CONFIG"
"#,
        server = server_address,
        singbox = singbox_path.to_string_lossy(),
        config = config_path.to_string_lossy(),
        pf_conf = pf_conf_path.to_string_lossy(),
        skip_ks = if skip_killswitch { "1" } else { "0" },
        dns_backup = get_config_dir().join("dns-backup.txt").to_string_lossy(),
    )
}

/// Generate the launchd plist XML for the sing-box daemon
#[cfg(target_os = "macos")]
fn generate_launchd_plist(launcher_path: &PathBuf, log_path: &PathBuf) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>{launcher}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>3</integer>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>"#,
        label = LAUNCHD_LABEL,
        launcher = launcher_path.to_string_lossy(),
        log = log_path.to_string_lossy(),
    )
}

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
            // Skip if reconnection is already in progress or shutdown requested
            if vpn_manager_clone.is_reconnecting() || vpn_manager_clone.is_connecting() || vpn_manager_clone.is_shutdown_requested() {
                return;
            }

            state_for_monitor.log(
                LogLevel::Warn,
                format!("Sing-box process died (exit code: {:?})", exit_code)
            );

            // On macOS, launchd handles restarts via KeepAlive. If we get here,
            // it means both sing-box AND the launchd job are gone — launchd gave up.
            // Report failure; user needs to reconnect manually.
            #[cfg(target_os = "macos")]
            {
                vpn_manager_clone.set_state(ConnectionState::Failed);
                emit_vpn_event(
                    &app_handle_clone,
                    VpnEvent::error(
                        "VPN process died. Please reconnect.",
                        Some("DAEMON_DIED".to_string())
                    )
                );
                state_for_monitor.stop_health_monitor();
                return;
            }

            // On Linux/Windows, attempt reconnection ourselves
            #[cfg(not(target_os = "macos"))]
            {
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

                vpn_manager_clone.set_state(ConnectionState::Reconnecting);

                let state_for_reconnect = Arc::clone(&state_for_monitor);
                let app_handle_for_reconnect = app_handle_clone.clone();
                let vpn_manager_for_reconnect = Arc::clone(&vpn_manager_clone);

                tokio::spawn(async move {
                    attempt_reconnection(
                        state_for_reconnect,
                        vpn_manager_for_reconnect,
                        app_handle_for_reconnect,
                        config,
                    ).await;
                });
            }
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

                // On macOS, reconnect_singbox already sets up pfctl rules in the same
                // osascript session, so we don't need a separate auto_enable_killswitch call.
                // On Linux, re-enable real firewall kill switch. On Windows, strict_route handles it.
                #[cfg(target_os = "linux")]
                if !config.diag_no_killswitch.unwrap_or(false) {
                    auto_enable_killswitch(&config.address, &app_handle);
                    state.log(LogLevel::Info, "Kill switch re-enabled after reconnection".to_string());
                }

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
                // If user cancelled the osascript password dialog, stop reconnecting
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

        // Exponential backoff: double the delay, cap at max
        delay_ms = (delay_ms * 2).min(RECONNECT_MAX_DELAY_MS);
    }

    // Max retries reached - stop health monitor to prevent further reconnection cycles
    // Keep kill switch active to prevent IP leaks
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

/// Internal function to reconnect sing-box without emitting events
/// Used by the reconnection logic to avoid duplicate events
async fn reconnect_singbox(
    #[allow(unused_variables)] state: &AppState,
    #[allow(unused_variables)] config: &VlessConfig,
    _app_handle: &AppHandle,
) -> Result<(), String> {
    // On macOS, launchd handles restart — we just wait. On other platforms, we
    // need to regenerate config and restart the process ourselves.
    #[cfg(target_os = "macos")]
    {
        // Config file is already updated by the caller (attempt_reconnection).
        // LaunchDaemon handles auto-restart via KeepAlive. Just wait for it.
        if !is_launchd_job_loaded() {
            return Err("LaunchDaemon is not loaded — cannot reconnect".to_string());
        }

        for _ in 0..150 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let check = std::process::Command::new("pgrep").arg("-x").arg("sing-box").output();
            if let Ok(out) = check {
                if out.status.success() {
                    return Ok(());
                }
            }
            if !is_launchd_job_loaded() {
                return Err("LaunchDaemon was removed during reconnection".to_string());
            }
        }

        return Err("Reconnection timeout".to_string());
    }

    // Non-macOS: regenerate config and restart process
    #[cfg(not(target_os = "macos"))]
    {
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

    #[cfg(target_os = "linux")]
    {
        let cmd = format!(
            "pkexec '{}' run -c '{}' > '{}' 2>&1",
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

        for _ in 0..300 {
            tokio::time::sleep(Duration::from_millis(100)).await;

            match child.try_wait() {
                Ok(Some(status)) => {
                    let detail = match child.wait_with_output().await {
                        Ok(output) => {
                            let stderr_str = String::from_utf8_lossy(&output.stderr);
                            let stdout_str = String::from_utf8_lossy(&output.stdout);
                            if !stderr_str.trim().is_empty() {
                                stderr_str.trim().to_string()
                            } else if !stdout_str.trim().is_empty() {
                                stdout_str.trim().to_string()
                            } else {
                                format!("exit code: {}", status)
                            }
                        }
                        Err(_) => format!("exit code: {}", status),
                    };
                    if !status.success() {
                        return Err(format!("Authentication or launch failed: {}", detail));
                    }
                    return Err(format!("sing-box exited unexpectedly: {}", detail));
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
    } // end #[cfg(not(target_os = "macos"))]
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

/// Generate sing-box configuration JSON from VlessConfig (Hysteria2 only)
#[tauri::command]
pub fn generate_singbox_config(config: VlessConfig) -> Result<String, String> {
    // Always resolve server hostname to IP before starting sing-box.
    // This prevents DNS loop: sing-box routes all traffic through TUN,
    // so DNS queries for the VPN server hostname would also go through TUN.
    let server_ip = resolve_server_ip(&config.address);

    // Configure inbounds/inbound[0] based on platform
    let (inet4_address, strict_route, default_stack) = if cfg!(target_os = "windows") {
        ("172.19.0.1/30", true, "gvisor")
    } else if cfg!(target_os = "macos") {
        // On macOS, strict_route causes routing loops: it captures ALL packets
        // at the OS level (including traffic to the VPN server itself) before
        // sing-box routing rules can bypass them via direct outbound.
        ("100.64.0.1/30", false, "system")
    } else {
        // Linux
        ("100.64.0.1/30", true, "gvisor")
    };

    // Diagnostic overrides
    let stack = config.diag_stack.as_deref().unwrap_or(default_stack);
    let mtu = config.diag_mtu.unwrap_or(1400);
    let sniff = config.diag_sniff.unwrap_or(true);
    let plain_dns = config.diag_plain_dns.unwrap_or(false);
    let udp_timeout = config.diag_udp_timeout;
    let endpoint_independent_nat = config.diag_endpoint_independent_nat.unwrap_or(true);

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
        "final": "proxy",
        "default_domain_resolver": {
            "server": "local"
        }
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

    // Build Hysteria2 proxy outbound
    // On macOS, bind_interface forces sing-box to use the physical NIC for its
    // own UDP connection to the VPN server, bypassing the TUN route created by
    // auto_route (which would otherwise loop sing-box's own traffic back into
    // the tunnel).
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
                    "server": "223.5.5.5"
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
                "interface_name": if cfg!(target_os = "macos") { "utun99" } else { "zen-tun" },
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
        // Log file may be owned by root (created via osascript with admin privileges).
        // Try to remove and recreate it instead of truncating.
        if fs::write(&log_path, "").is_err() {
            let _ = fs::remove_file(&log_path);
            let _ = fs::File::create(&log_path);
        }
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
                tun_interface: if cfg!(target_os = "macos") { "utun99".to_string() } else { "zen-tun".to_string() },
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

    let log_path = get_log_path();

    // Spawn log reader before starting the process
    spawn_log_reader(state.log_buffer.clone());

    // App runs as admin (requireAdministrator manifest), so launch sing-box directly
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
            emit_vpn_event(&app_handle, VpnEvent::error(format!("Failed to start sing-box: {}", e), Some("START_FAILED".to_string())));
            format!("Failed to start sing-box: {}", e)
        })?;

    {
        let mut process = state.singbox_process.lock().unwrap();
        *process = Some(child);
    }

    // Wait for sing-box to start by checking log output
    for _ in 0..150 {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        if let Ok(log_content) = fs::read_to_string(&log_path) {
            if log_content.contains("sing-box started") {
                state.log(LogLevel::Info, format!("VPN connected to {}", config.address));
                emit_vpn_event(&app_handle, VpnEvent::connected(config.name.clone(), config.address.clone()));

                // Kill switch is handled by strict_route in sing-box config

                // Update VpnManager state and start health monitor for auto-reconnect
                vpn_manager.set_state(ConnectionState::Connected);

                let state_arc = Arc::new(AppState {
                    singbox_process: Mutex::new(None),
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
            if log_content.contains("fatal") || log_content.contains("error") {
                let error_msg = log_content.lines().last().unwrap_or("Unknown error").to_string();
                state.log(LogLevel::Error, format!("sing-box failed: {}", error_msg));
                emit_vpn_event(&app_handle, VpnEvent::error(format!("sing-box error: {}", error_msg), Some("SINGBOX_ERROR".to_string())));

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
    emit_vpn_event(&app_handle, VpnEvent::error("Connection timeout", Some("TIMEOUT".to_string())));
    vpn_manager.set_state(ConnectionState::Failed);
    Err("Connection timeout".to_string())
}

/// Start the sing-box process on Unix-like systems (Linux & macOS)
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

    #[cfg(target_os = "macos")]
    let cmd = {
        // Generate pf kill switch config
        let pf_conf_path = get_config_dir().join("pf-killswitch.conf");
        let server_ip = resolve_server_ip(&config.address);
        let skip_killswitch = config.diag_no_killswitch.unwrap_or(false);
        if !skip_killswitch {
            let tun_iface = "utun99";
            let pf_rules = format!(
                "pass quick on lo0 all\n\
                 pass quick on {tun} all\n\
                 pass out quick on ! {tun} proto {{ tcp, udp }} from any to {ip} no state\n\
                 pass in quick on ! {tun} proto {{ tcp, udp }} from {ip} to any no state\n\
                 pass out quick proto udp from any to any port 67\n\
                 pass in quick proto udp from any port 67 to any\n\
                 pass out quick proto {{ tcp, udp }} from any to 1.1.1.1 port 53\n\
                 pass out quick proto {{ tcp, udp }} from any to 8.8.8.8 port 53\n\
                 block drop out all\n\
                 block drop in all\n",
                tun = tun_iface, ip = server_ip
            );
            let _ = fs::write(&pf_conf_path, &pf_rules);
        }

        // Generate launcher script (routes + pfctl + exec sing-box)
        let launcher_path = get_launcher_script_path();
        let launcher_script = generate_launcher_script(
            &config.address,
            &singbox_path,
            &config_path,
            &pf_conf_path,
            skip_killswitch,
        );
        fs::write(&launcher_path, &launcher_script)
            .map_err(|e| format!("Failed to write launcher script: {}", e))?;

        // Generate launchd plist
        let plist_staging = get_launchd_plist_path();
        let plist_content = generate_launchd_plist(&launcher_path, &log_path);
        fs::write(&plist_staging, &plist_content)
            .map_err(|e| format!("Failed to write launchd plist: {}", e))?;

        // Single osascript: unload any old daemon, install plist, bootstrap
        let inner_cmd = format!(
            "launchctl bootout system/{label} 2>/dev/null; \
             cp '{staging}' '{install}' && \
             chmod +x '{launcher}' && \
             launchctl bootstrap system '{install}'",
            label = LAUNCHD_LABEL,
            staging = plist_staging.to_string_lossy(),
            install = LAUNCHD_PLIST_INSTALL_PATH,
            launcher = launcher_path.to_string_lossy(),
        );
        let escaped = inner_cmd.replace('\\', "\\\\").replace('"', "\\\"").replace('\'', "'\\''");
        format!(
            "osascript -e 'do shell script \"{}\" with administrator privileges'",
            escaped
        )
    };

    #[cfg(not(target_os = "macos"))]
    let cmd = format!(
        "pkexec '{}' run -c '{}' > '{}' 2>&1",
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

    // On macOS, osascript launches the wrapper in the background and exits quickly.
    // We wait for osascript to finish, then poll for sing-box to start.
    // On Linux, the child IS the sing-box process (via pkexec).
    #[cfg(target_os = "macos")]
    {
        // Wait for osascript to complete (should be fast — it backgrounds the wrapper)
        let output = child.wait_with_output().await.map_err(|e| {
            let msg = format!("Failed waiting for osascript: {}", e);
            state.log(LogLevel::Error, msg.clone());
            msg
        })?;

        if !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            let detail = if !stderr_str.trim().is_empty() {
                stderr_str.trim().to_string()
            } else if !stdout_str.trim().is_empty() {
                stdout_str.trim().to_string()
            } else {
                format!("exit code: {}", output.status)
            };
            let msg = if detail.contains("User canceled") || detail.contains("(-128)") {
                "Authentication cancelled by user".to_string()
            } else {
                format!("Authentication failed: {}", detail)
            };
            state.log(LogLevel::Error, msg.clone());
            emit_vpn_event(&app_handle, VpnEvent::error(&msg, Some("AUTH_FAILED".to_string())));
            vpn_manager.set_state(ConnectionState::Failed);
            return Err(msg);
        }

        // osascript succeeded — wrapper is running in background.
        // Poll for sing-box to appear (wrapper starts it).
        for _ in 0..300 {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            let output = std::process::Command::new("pgrep")
                .arg("-x")
                .arg("sing-box")
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    state.log(LogLevel::Info, format!("VPN connected to {}", config.address));
                    emit_vpn_event(&app_handle, VpnEvent::connected(config.name.clone(), config.address.clone()));

                    if !config.diag_no_killswitch.unwrap_or(false) {
                        emit_vpn_event(&app_handle, VpnEvent::killswitch_changed(true));
                        state.log(LogLevel::Info, "Kill switch auto-enabled".to_string());
                    } else {
                        state.log(LogLevel::Info, "Kill switch skipped (diag_no_killswitch)".to_string());
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
                        Arc::clone(&vpn_manager),
                        app_handle.clone(),
                    );
                    state.set_health_monitor(Some(monitor));

                    return Ok(());
                }
            }

            // Check if launchd job died early (e.g. sing-box binary missing)
            if !is_launchd_job_loaded() {
                let msg = "LaunchDaemon exited unexpectedly — check sing-box installation".to_string();
                state.log(LogLevel::Error, msg.clone());
                emit_vpn_event(&app_handle, VpnEvent::error(&msg, Some("DAEMON_DIED".to_string())));
                vpn_manager.set_state(ConnectionState::Failed);
                return Err(msg);
            }
        }

        state.log(LogLevel::Error, "Connection timeout".to_string());
        emit_vpn_event(&app_handle, VpnEvent::error("Connection timeout", Some("TIMEOUT".to_string())));
        vpn_manager.set_state(ConnectionState::Failed);
        Err("Connection timeout".to_string())
    }

    #[cfg(not(target_os = "macos"))]
    {
        for _ in 0..300 {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            match child.try_wait() {
                Ok(Some(status)) => {
                    let detail = match child.wait_with_output().await {
                        Ok(output) => {
                            let stderr_str = String::from_utf8_lossy(&output.stderr);
                            let stdout_str = String::from_utf8_lossy(&output.stdout);
                            if !stderr_str.trim().is_empty() {
                                stderr_str.trim().to_string()
                            } else if !stdout_str.trim().is_empty() {
                                stdout_str.trim().to_string()
                            } else {
                                format!("exit code: {}", status)
                            }
                        }
                        Err(_) => format!("exit code: {}", status),
                    };
                    if !status.success() {
                        let msg = format!("Authentication or launch failed: {}", detail);
                        state.log(LogLevel::Error, msg.clone());
                        emit_vpn_event(&app_handle, VpnEvent::error(&msg, Some("AUTH_FAILED".to_string())));
                        return Err(msg);
                    }
                    let msg = format!("sing-box exited unexpectedly: {}", detail);
                    state.log(LogLevel::Error, msg.clone());
                    emit_vpn_event(&app_handle, VpnEvent::error(&msg, Some("UNEXPECTED_EXIT".to_string())));
                    return Err(msg);
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

                            if !config.diag_no_killswitch.unwrap_or(false) {
                                auto_enable_killswitch(&config.address, &app_handle);
                                state.log(LogLevel::Info, "Kill switch auto-enabled".to_string());
                            } else {
                                state.log(LogLevel::Info, "Kill switch skipped (diag_no_killswitch)".to_string());
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

    // Perform graceful shutdown and cleanup
    #[cfg(target_os = "macos")]
    {
        // Single elevated command: bootout daemon + cleanup pfctl + routes + plist
        let server_ip = state.get_config()
            .map(|c| resolve_server_ip(&c.address))
            .unwrap_or_default();

        let bootout_cmd = format!(
            "launchctl bootout system/{label} 2>/dev/null; \
             pfctl -a 'com.zen.vpn' -F all 2>/dev/null; \
             route delete -host '{server}' 2>/dev/null; \
             rm -f '{plist}'; \
             true",
            label = LAUNCHD_LABEL,
            server = server_ip,
            plist = LAUNCHD_PLIST_INSTALL_PATH,
        );
        if let Err(e) = elevated_command(&bootout_cmd) {
            state.log(LogLevel::Warn, format!("LaunchDaemon bootout failed: {}", e));
        }

        // Wait for sing-box to disappear
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let check = std::process::Command::new("pgrep")
                .arg("-x").arg("sing-box").output();
            if let Ok(out) = check {
                if !out.status.success() { break; }
            }
        }

        // Clean up local state files
        let config_dir = get_config_dir();
        let _ = std::fs::remove_file(config_dir.join("pf-killswitch.conf"));
        let _ = std::fs::remove_file(config_dir.join("killswitch.state"));
        let _ = std::fs::remove_file(config_dir.join("com.zen.vpn.plist"));
        let _ = std::fs::remove_file(config_dir.join("zen-vpn-launcher.sh"));
    }

    #[cfg(not(target_os = "macos"))]
    {
        // On Linux: separate calls are fine (pkexec caches credentials)
        graceful_kill_external_process().await?;

        if let Err(e) = cleanup_firewall() {
            state.log(LogLevel::Warn, format!("Failed to cleanup firewall: {}", e));
        }
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
    /// Process is being restarted by the wrapper (macOS only)
    Restarting,
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
                    // On macOS, check if the launchd job is still loaded — it may be
                    // restarting sing-box automatically (brief gap between restarts)
                    #[cfg(target_os = "macos")]
                    if is_launchd_job_loaded() {
                        return ProcessHealthStatus::Restarting;
                    }
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
        // First try SIGTERM via platform-specific elevation
        let sigterm_result = elevated_command("killall -TERM sing-box");

        if sigterm_result.is_ok() {
            // Wait for process to exit gracefully
            for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                let check = std::process::Command::new("pgrep")
                    .arg("-x")
                    .arg("sing-box")
                    .output();

                if let Ok(out) = check {
                    if !out.status.success() {
                        return Ok(());
                    }
                }
            }
        }

        // Force kill (SIGKILL) if still running
        let _ = elevated_command("killall -KILL sing-box");

        Ok(())
    }
}

/// Run a command with privilege elevation (pkexec on Linux, osascript on macOS)
#[cfg(not(target_os = "windows"))]
fn elevated_command(cmd: &str) -> Result<std::process::Output, String> {
    #[cfg(target_os = "macos")]
    {
        let escaped = cmd.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            escaped
        );
        std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .output()
            .map_err(|e| format!("Failed to execute elevated command: {}", e))
    }

    #[cfg(not(target_os = "macos"))]
    {
        std::process::Command::new("pkexec")
            .arg("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .map_err(|e| format!("Failed to execute elevated command: {}", e))
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

    #[cfg(target_os = "macos")]
    {
        // Restore DNS from backup file (created by launcher script)
        let backup_path = get_config_dir().join("dns-backup.txt");
        if backup_path.exists() {
            if let Ok(content) = fs::read_to_string(&backup_path) {
                for line in content.lines() {
                    if let Some((svc, dns)) = line.split_once('=') {
                        if dns == "empty" {
                            // Restore to "no DNS set" (DHCP default)
                            let _ = std::process::Command::new("networksetup")
                                .args(["-setdnsservers", svc, "empty"])
                                .output();
                        } else {
                            let servers: Vec<&str> = dns.split(',').filter(|s| !s.is_empty()).collect();
                            if !servers.is_empty() {
                                let mut args = vec!["-setdnsservers", svc];
                                args.extend(servers);
                                let _ = std::process::Command::new("networksetup")
                                    .args(&args)
                                    .output();
                            }
                        }
                    }
                }
            }
            let _ = fs::remove_file(&backup_path);
        }

        // Flush DNS cache
        let _ = std::process::Command::new("dscacheutil")
            .arg("-flushcache")
            .output();
        let _ = std::process::Command::new("killall")
            .args(["-HUP", "mDNSResponder"])
            .output();
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
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

    #[cfg(target_os = "macos")]
    {
        // Bootout the launchd daemon — it sends SIGTERM to sing-box and cleans up
        let bootout_cmd = format!(
            "launchctl bootout system/{label} 2>/dev/null; \
             pfctl -a 'com.zen.vpn' -F all 2>/dev/null; \
             rm -f '{plist}'; \
             true",
            label = LAUNCHD_LABEL,
            plist = LAUNCHD_PLIST_INSTALL_PATH,
        );
        let _ = elevated_command(&bootout_cmd);

        // Wait for sing-box to disappear
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let check = std::process::Command::new("pgrep")
                .arg("-x").arg("sing-box").output();
            if let Ok(out) = check {
                if !out.status.success() { break; }
            }
        }

        // Force kill if still alive
        let check = std::process::Command::new("pgrep").arg("-x").arg("sing-box").output();
        if check.map(|o| o.status.success()).unwrap_or(false) {
            let _ = elevated_command("killall -KILL sing-box 2>/dev/null; true");
        }

        let config_dir = get_config_dir();
        let _ = std::fs::remove_file(config_dir.join("pf-killswitch.conf"));
        let _ = std::fs::remove_file(config_dir.join("killswitch.state"));
        let _ = std::fs::remove_file(config_dir.join("com.zen.vpn.plist"));
        let _ = std::fs::remove_file(config_dir.join("zen-vpn-launcher.sh"));
    }

    #[cfg(target_os = "linux")]
    {
        // On Linux: pkexec caches credentials, separate calls are fine
        let sigterm_result = elevated_command("killall -TERM sing-box");

        if sigterm_result.is_ok() {
            for _ in 0..(GRACEFUL_SHUTDOWN_TIMEOUT_SECS * 10) {
                std::thread::sleep(std::time::Duration::from_millis(100));

                let check = std::process::Command::new("pgrep")
                    .arg("-x")
                    .arg("sing-box")
                    .output();

                if let Ok(out) = check {
                    if !out.status.success() {
                        let _ = cleanup_firewall();
                        let _ = restore_dns();
                        return;
                    }
                }
            }
        }

        let _ = elevated_command("killall -KILL sing-box");
        let _ = cleanup_firewall();
    }

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
        let config = make_hy2_config();
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["route"]["final"], "proxy");
        // Global mode should not have rule_set
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
        assert_eq!(dns_servers[1]["server"], "223.5.5.5");
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
        let expected_iface = if cfg!(target_os = "macos") { "utun99" } else { "zen-tun" };
        assert_eq!(inbound["interface_name"], expected_iface);
        assert_eq!(inbound["sniff"], true);
    }

    #[test]
    fn test_gen_server_ip_in_route_rules() {
        let config = make_hy2_config();
        let json_str = generate_singbox_config(config).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let rules = v["route"]["rules"].as_array().unwrap();
        // Find the rule with ip_cidr for the server
        let ip_rule = rules.iter().find(|r| r.get("ip_cidr").is_some());
        assert!(ip_rule.is_some(), "Should have ip_cidr rule for server IP");
        let ip_cidr = ip_rule.unwrap()["ip_cidr"][0].as_str().unwrap();
        assert_eq!(ip_cidr, "5.6.7.8/32");
        assert_eq!(ip_rule.unwrap()["outbound"], "direct");
    }

    #[test]
    fn test_gen_domain_server_in_route_rules() {
        // When server address is a domain (not IP), resolve_server_ip should handle it.
        // If it resolves to an IP, we get ip_cidr rule.
        // If it doesn't resolve (unlikely for real domains but common for test domains),
        // we get a domain rule.
        let mut config = make_hy2_config();
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
        // Generated config should be valid JSON
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
        let deserialized: VlessConfig = serde_json::from_str(&json).unwrap();
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
        let deserialized: VlessConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.routing_mode, None);
        assert_eq!(deserialized.target_country, None);
    }

    #[test]
    fn test_config_backwards_compat() {
        // Old JSON without hysteria2-specific fields should deserialize OK
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
        let config: VlessConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.uuid, "test");
        assert_eq!(config.protocol, None);
        assert_eq!(config.up_mbps, None);
        assert_eq!(config.down_mbps, None);
        assert_eq!(config.obfs, None);
        assert_eq!(config.obfs_password, None);
    }

    #[test]
    fn test_config_all_fields() {
        let config = VlessConfig {
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
        let deserialized: VlessConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.routing_mode.as_deref(), Some("smart"));
        assert_eq!(deserialized.target_country.as_deref(), Some("ru"));
        assert_eq!(deserialized.up_mbps, Some(50));
        assert_eq!(deserialized.obfs_password.as_deref(), Some("pwd"));
    }
}
