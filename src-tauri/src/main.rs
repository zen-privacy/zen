#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod logging;
mod notifications;
mod vpn;
mod updates;

use std::fs::{self, File};
use std::io;
use std::path::PathBuf;
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, State,
};

use logging::{LogEntry, LogFilterState, LogLevel};
use vpn::{
    create_killswitch, create_vpn_manager, generate_singbox_config, get_connection_status,
    kill_singbox_sync, start_singbox, stop_singbox, AppState, AppStatus, KillSwitchConfig,
    Profile, TrafficStats, VlessConfig,
};
use updates::{check_for_update, install_update};

const SINGBOX_VERSION: &str = "1.10.1";

fn get_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zen-vpn")
}

fn get_profiles_path() -> PathBuf {
    get_config_dir().join("profiles.json")
}

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

#[tauri::command]
fn check_singbox_installed() -> AppStatus {
    let singbox_path = get_singbox_binary_path();
    let installed = singbox_path.exists();

    AppStatus {
        singbox_installed: installed,
        singbox_path: singbox_path.to_string_lossy().to_string(),
        downloading: false,
    }
}

#[tauri::command]
async fn download_singbox() -> Result<String, String> {
    let config_dir = get_config_dir();
    fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;

    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        return Err("Unsupported architecture".to_string());
    };

    #[cfg(target_os = "windows")]
    let (url, is_zip) = (
        format!(
            "https://github.com/SagerNet/sing-box/releases/download/v{}/sing-box-{}-windows-{}.zip",
            SINGBOX_VERSION, SINGBOX_VERSION, arch
        ),
        true,
    );

    #[cfg(target_os = "macos")]
    let (url, is_zip) = (
        format!(
            "https://github.com/SagerNet/sing-box/releases/download/v{}/sing-box-{}-darwin-{}.tar.gz",
            SINGBOX_VERSION, SINGBOX_VERSION, arch
        ),
        false,
    );

    #[cfg(target_os = "linux")]
    let (url, is_zip) = (
        format!(
            "https://github.com/SagerNet/sing-box/releases/download/v{}/sing-box-{}-linux-{}.tar.gz",
            SINGBOX_VERSION, SINGBOX_VERSION, arch
        ),
        false,
    );

    let singbox_path = get_singbox_binary_path();
    let config_dir_clone = config_dir.clone();

    let result = tokio::task::spawn_blocking(move || {
        // Download sing-box
        let response = reqwest::blocking::get(&url).map_err(|e| format!("Download failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Download failed: HTTP {}", response.status()));
        }

        let bytes = response
            .bytes()
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if is_zip {
            // Windows: extract from ZIP
            extract_from_zip(&bytes, &singbox_path)?;
        } else {
            // Linux/macOS: extract from tar.gz
            extract_from_targz(&bytes, &singbox_path)?;
        }

        // On Windows, also download WinTun driver
        #[cfg(target_os = "windows")]
        {
            download_wintun(&config_dir_clone, arch)?;
        }

        #[cfg(not(target_os = "windows"))]
        let _ = config_dir_clone; // Suppress unused warning

        Ok(singbox_path.to_string_lossy().to_string())
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?;

    result
}

#[cfg(target_os = "windows")]
fn download_wintun(config_dir: &PathBuf, arch: &str) -> Result<(), String> {
    use std::io::Cursor;

    let wintun_path = config_dir.join("wintun.dll");

    // Skip if already exists
    if wintun_path.exists() {
        return Ok(());
    }

    // Download WinTun from official source
    let wintun_url = "https://www.wintun.net/builds/wintun-0.14.1.zip";

    let response = reqwest::blocking::get(wintun_url)
        .map_err(|e| format!("WinTun download failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("WinTun download failed: HTTP {}", response.status()));
    }

    let bytes = response
        .bytes()
        .map_err(|e| format!("Failed to read WinTun: {}", e))?;

    // Extract wintun.dll for the correct architecture
    let reader = Cursor::new(&bytes[..]);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| e.to_string())?;

    let dll_path_in_zip = format!("wintun/bin/{}/wintun.dll", arch);

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = file.name().to_string();

        if name == dll_path_in_zip {
            let mut outfile = File::create(&wintun_path).map_err(|e| e.to_string())?;
            io::copy(&mut file, &mut outfile).map_err(|e| e.to_string())?;
            return Ok(());
        }
    }

    Err("wintun.dll not found in archive".to_string())
}

fn extract_from_zip(bytes: &[u8], singbox_path: &PathBuf) -> Result<(), String> {
    use std::io::Cursor;

    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| e.to_string())?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = file.name().to_string();

        if name.ends_with("sing-box.exe") {
            let mut outfile = File::create(singbox_path).map_err(|e| e.to_string())?;
            io::copy(&mut file, &mut outfile).map_err(|e| e.to_string())?;
            return Ok(());
        }
    }

    Err("sing-box.exe not found in archive".to_string())
}

#[cfg(not(target_os = "windows"))]
fn extract_from_targz(bytes: &[u8], singbox_path: &PathBuf) -> Result<(), String> {
    use flate2::read::GzDecoder;
    use std::os::unix::fs::PermissionsExt;
    use tar::Archive;

    let tar = GzDecoder::new(bytes);
    let mut archive = Archive::new(tar);

    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path().map_err(|e| e.to_string())?;

        if path.ends_with("sing-box") {
            let mut file = File::create(singbox_path).map_err(|e| e.to_string())?;
            io::copy(&mut entry, &mut file).map_err(|e| e.to_string())?;

            // Make executable
            let mut perms = fs::metadata(singbox_path)
                .map_err(|e| e.to_string())?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(singbox_path, perms).map_err(|e| e.to_string())?;

            return Ok(());
        }
    }

    Err("sing-box binary not found in archive".to_string())
}

#[cfg(target_os = "windows")]
fn extract_from_targz(_bytes: &[u8], _singbox_path: &PathBuf) -> Result<(), String> {
    Err("tar.gz extraction not supported on Windows".to_string())
}

#[tauri::command]
fn parse_vless_link(link: String) -> Result<VlessConfig, String> {
    if !link.starts_with("vless://") {
        return Err("Invalid VLESS link".to_string());
    }

    let without_prefix = link.strip_prefix("vless://").unwrap();

    let (main_part, name) = if let Some(idx) = without_prefix.find('#') {
        let (main, name) = without_prefix.split_at(idx);
        (
            main,
            urlencoding::decode(&name[1..])
                .unwrap_or_default()
                .to_string(),
        )
    } else {
        (without_prefix, "Unnamed".to_string())
    };

    let (uuid, rest) = main_part
        .split_once('@')
        .ok_or("Invalid format: missing @")?;

    let (addr_port, params_str) = rest.split_once('?').ok_or("Invalid format: missing ?")?;

    let (address, port_str) = addr_port
        .rsplit_once(':')
        .ok_or("Invalid format: missing port")?;

    let port: u16 = port_str.parse().map_err(|_| "Invalid port number")?;

    let params: std::collections::HashMap<String, String> = params_str
        .split('&')
        .filter_map(|p| {
            let mut parts = p.splitn(2, '=');
            Some((
                parts.next()?.to_string(),
                urlencoding::decode(parts.next().unwrap_or(""))
                    .unwrap_or_default()
                    .to_string(),
            ))
        })
        .collect();

    Ok(VlessConfig {
        uuid: uuid.to_string(),
        address: address.to_string(),
        port,
        security: params
            .get("security")
            .cloned()
            .unwrap_or_else(|| "none".to_string()),
        transport_type: params
            .get("type")
            .cloned()
            .unwrap_or_else(|| "tcp".to_string()),
        path: params.get("path").cloned().unwrap_or_default(),
        host: params
            .get("host")
            .cloned()
            .unwrap_or_else(|| address.to_string()),
        name,
    })
}

#[tauri::command]
fn save_profile(profile: Profile) -> Result<(), String> {
    let config_dir = get_config_dir();
    fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;

    let profiles_path = get_profiles_path();
    let mut profiles: Vec<Profile> = if profiles_path.exists() {
        let content = fs::read_to_string(&profiles_path).map_err(|e| e.to_string())?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    };

    if let Some(existing) = profiles.iter_mut().find(|p| p.id == profile.id) {
        *existing = profile;
    } else {
        profiles.push(profile);
    }

    let content = serde_json::to_string_pretty(&profiles).map_err(|e| e.to_string())?;
    fs::write(profiles_path, content).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
fn load_profiles() -> Result<Vec<Profile>, String> {
    let profiles_path = get_profiles_path();
    if !profiles_path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(profiles_path).map_err(|e| e.to_string())?;
    serde_json::from_str(&content).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_profile(id: String) -> Result<(), String> {
    let profiles_path = get_profiles_path();
    if !profiles_path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&profiles_path).map_err(|e| e.to_string())?;
    let mut profiles: Vec<Profile> = serde_json::from_str(&content).unwrap_or_default();
    profiles.retain(|p| p.id != id);

    let content = serde_json::to_string_pretty(&profiles).map_err(|e| e.to_string())?;
    fs::write(profiles_path, content).map_err(|e| e.to_string())?;

    Ok(())
}

#[cfg(target_os = "windows")]
#[tauri::command]
async fn ping_server(address: String) -> Result<u64, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Validate and extract the hostname/IP from the address
    let target = if address.is_empty() {
        "1.1.1.1".to_string() // Fallback to Cloudflare DNS
    } else {
        // Remove any port suffix if present
        address.split(':').next().unwrap_or(&address).to_string()
    };

    // Use system ping command for accurate latency measurement
    // -n 1: send 1 ping, -w 5000: 5 second timeout in milliseconds
    let output = std::process::Command::new("ping")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-n", "1", "-w", "5000", &target])
        .output()
        .map_err(|e| format!("Ping failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("Ping failed: {} unreachable", target));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Windows ping output formats:
    // English: "Reply from X.X.X.X: bytes=32 time=15ms TTL=57"
    // Or: "Reply from X.X.X.X: bytes=32 time<1ms TTL=57" (for very fast responses)
    // Parse "time=XXms" or "time<1ms"
    for part in stdout.split_whitespace() {
        if part.starts_with("time=") {
            // Format: time=15ms
            let time_str = part.trim_start_matches("time=").trim_end_matches("ms");
            if let Ok(ms) = time_str.parse::<u64>() {
                return Ok(ms);
            }
        } else if part.starts_with("time<") {
            // Format: time<1ms (very fast response, return 1ms)
            return Ok(1);
        }
    }

    Err("Could not parse ping time".to_string())
}

#[cfg(not(target_os = "windows"))]
#[tauri::command]
async fn ping_server(address: String) -> Result<u64, String> {
    // Validate and extract the hostname/IP from the address
    let target = if address.is_empty() {
        "1.1.1.1".to_string() // Fallback to Cloudflare DNS
    } else {
        // Remove any port suffix if present
        address.split(':').next().unwrap_or(&address).to_string()
    };

    let output = std::process::Command::new("ping")
        .args(["-c", "1", "-W", "5", &target])
        .output()
        .map_err(|e| format!("Ping failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("Ping failed: {} unreachable", target));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    for part in stdout.split_whitespace() {
        if part.starts_with("time=") {
            let time_str = part.trim_start_matches("time=");
            if let Ok(ms) = time_str.parse::<f64>() {
                return Ok(ms.round() as u64);
            }
        }
    }

    Err("Could not parse ping time".to_string())
}

#[cfg(target_os = "windows")]
static CACHED_IF_INDEX: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[cfg(target_os = "windows")]
fn find_interface_index() -> Result<u32, String> {
    use std::sync::atomic::Ordering;
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, GAA_FLAG_INCLUDE_ALL_INTERFACES,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    const TARGET_INTERFACE: &str = "zen-tun";

    // Check cache first
    let cached = CACHED_IF_INDEX.load(Ordering::Relaxed);
    if cached != 0 {
        return Ok(cached);
    }

    let mut buffer_len: u32 = 15_000;
    let mut buffer: Vec<u8> = vec![0; buffer_len as usize];

    loop {
        let adapter_ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
                None,
                Some(adapter_ptr),
                &mut buffer_len,
            )
        };

        if result == ERROR_BUFFER_OVERFLOW.0 {
            buffer.resize(buffer_len as usize, 0);
            continue;
        }

        if result != NO_ERROR.0 {
            return Err(format!("GetAdaptersAddresses failed: {}", result));
        }

        let mut current = adapter_ptr;
        while !current.is_null() {
            if let Ok(name) = unsafe { (*current).FriendlyName.to_string() } {
                if name.eq_ignore_ascii_case(TARGET_INTERFACE) {
                    let idx = unsafe { (*current).Anonymous1.Anonymous.IfIndex };
                    CACHED_IF_INDEX.store(idx, Ordering::Relaxed);
                    return Ok(idx);
                }
            }
            current = unsafe { (*current).Next };
        }

        return Err("Interface not found".to_string());
    }
}

#[cfg(target_os = "windows")]
#[tauri::command]
async fn get_traffic_stats() -> Result<TrafficStats, String> {
    use std::mem::zeroed;
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};

    let if_index = find_interface_index()?;

    let mut row: MIB_IF_ROW2 = unsafe { zeroed() };
    row.InterfaceIndex = if_index;

    let status = unsafe { GetIfEntry2(&mut row) };
    if status != NO_ERROR {
        // Interface might have been recreated - clear cache and retry
        CACHED_IF_INDEX.store(0, std::sync::atomic::Ordering::Relaxed);
        return Err(format!("GetIfEntry2 failed: {:?}", status));
    }

    Ok(TrafficStats {
        rx_bytes: row.InOctets,
        tx_bytes: row.OutOctets,
    })
}

#[cfg(not(target_os = "windows"))]
#[tauri::command]
async fn get_traffic_stats() -> Result<TrafficStats, String> {
    // On Linux, read from /sys/class/net/zen-tun/statistics/
    let rx_path = "/sys/class/net/zen-tun/statistics/rx_bytes";
    let tx_path = "/sys/class/net/zen-tun/statistics/tx_bytes";

    let rx_bytes = std::fs::read_to_string(rx_path)
        .map_err(|_| "Interface not found".to_string())?
        .trim()
        .parse::<u64>()
        .unwrap_or(0);

    let tx_bytes = std::fs::read_to_string(tx_path)
        .map_err(|_| "Interface not found".to_string())?
        .trim()
        .parse::<u64>()
        .unwrap_or(0);

    Ok(TrafficStats { rx_bytes, tx_bytes })
}

/// Response structure for get_logs command
#[derive(serde::Serialize)]
struct LogsResponse {
    entries: Vec<LogEntry>,
    total_count: usize,
    filter_level: String,
}

/// Get logs from the application log buffer
///
/// Returns log entries filtered by the current log level setting.
/// Optionally can limit the number of entries returned with the `count` parameter.
#[tauri::command]
fn get_logs(
    state: State<'_, AppState>,
    filter_state: State<'_, LogFilterState>,
    count: Option<usize>,
) -> LogsResponse {
    let min_level = filter_state.get_level();
    let filtered = state.log_buffer.get_filtered(min_level);
    let total_count = filtered.len();

    let entries = match count {
        Some(n) if n < total_count => {
            let skip = total_count.saturating_sub(n);
            filtered.into_iter().skip(skip).collect()
        }
        _ => filtered,
    };

    LogsResponse {
        entries,
        total_count,
        filter_level: min_level.as_str().to_string(),
    }
}

/// Export logs to a file
///
/// Exports all log entries to the specified file path as formatted text.
/// If no path is provided, exports to the default logs directory.
#[tauri::command]
fn export_logs(state: State<'_, AppState>, file_path: Option<String>) -> Result<String, String> {
    let export_content = state.log_buffer.export_as_text();

    let path = match file_path {
        Some(p) => PathBuf::from(p),
        None => {
            let config_dir = get_config_dir();
            fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;
            config_dir.join("exported_logs.txt")
        }
    };

    fs::write(&path, export_content).map_err(|e| format!("Failed to write logs: {}", e))?;

    Ok(path.to_string_lossy().to_string())
}

/// Set the minimum log level for filtering
///
/// Sets the minimum log level that will be returned by get_logs.
/// Valid levels: debug, info, warn, error, fatal, panic
#[tauri::command]
fn set_log_level(filter_state: State<'_, LogFilterState>, level: String) -> Result<String, String> {
    let log_level =
        LogLevel::from_str(&level).ok_or_else(|| format!("Invalid log level: {}", level))?;

    filter_state.set_level(log_level);

    Ok(log_level.as_str().to_string())
}

/// Kill switch status for frontend
#[derive(serde::Serialize)]
struct KillSwitchStatus {
    /// Whether the kill switch is currently enabled
    enabled: bool,
    /// Whether the kill switch is available on this platform
    available: bool,
    /// The firewall backend being used (e.g., "nftables", "iptables", "netsh")
    backend: String,
    /// Status message
    message: String,
}

/// Enable the kill switch to block traffic when VPN disconnects
///
/// This sets up firewall rules to:
/// 1. Block all outbound traffic by default
/// 2. Allow traffic to the VPN server IP
/// 3. Allow traffic through the VPN tunnel interface
/// 4. Allow loopback traffic
#[tauri::command]
fn enable_killswitch(server_ip: String) -> Result<KillSwitchStatus, String> {
    let killswitch = create_killswitch();

    // Check availability first
    let backend = match killswitch.check_availability() {
        Ok(b) => b,
        Err(e) => {
            return Ok(KillSwitchStatus {
                enabled: false,
                available: false,
                backend: "none".to_string(),
                message: format!("Kill switch not available: {}", e),
            });
        }
    };

    // Configure the kill switch
    let config = KillSwitchConfig {
        server_ip: server_ip.clone(),
        tun_interface: "zen-tun".to_string(),
        singbox_path: get_singbox_binary_path(),
    };

    // Enable the kill switch
    match killswitch.enable(&config) {
        Ok(result) => Ok(KillSwitchStatus {
            enabled: result.success,
            available: true,
            backend,
            message: result.message,
        }),
        Err(e) => Err(e),
    }
}

/// Disable the kill switch and restore normal network connectivity
///
/// This removes all firewall rules added by the kill switch.
#[tauri::command]
fn disable_killswitch() -> Result<KillSwitchStatus, String> {
    let killswitch = create_killswitch();

    // Check availability first
    let backend = match killswitch.check_availability() {
        Ok(b) => b,
        Err(_) => "none".to_string(),
    };

    // Disable the kill switch
    match killswitch.disable() {
        Ok(result) => Ok(KillSwitchStatus {
            enabled: false,
            available: backend != "none",
            backend,
            message: result.message,
        }),
        Err(e) => Err(e),
    }
}

/// Get the current kill switch status
///
/// Returns information about whether the kill switch is enabled,
/// available, and which backend is being used.
#[tauri::command]
fn get_killswitch_status() -> KillSwitchStatus {
    let killswitch = create_killswitch();

    // Check availability
    let (available, backend) = match killswitch.check_availability() {
        Ok(b) => (true, b),
        Err(_) => (false, "none".to_string()),
    };

    // Check if kill switch is enabled by looking at the state file
    // The in-memory state is reset on each call since create_killswitch() creates a new instance
    // The state file persists the actual enabled state
    let enabled = vpn::state_file_exists();

    let message = if !available {
        "Kill switch not available on this platform".to_string()
    } else if enabled {
        format!("Kill switch active ({})", backend)
    } else {
        format!("Kill switch ready ({})", backend)
    };

    KillSwitchStatus {
        enabled,
        available,
        backend,
        message,
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(AppState::default())
        .manage(LogFilterState::default())
        .manage(create_vpn_manager())
        .setup(|app| {
            let icon_data = include_bytes!("../icons/icon.png");
            let icon = Image::from_bytes(icon_data)?;

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_icon(icon.clone());
            }

            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;

            let _tray = TrayIconBuilder::new()
                .icon(icon)
                .menu(&menu)
                .tooltip("Zen VPN")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        kill_singbox_sync();
                        app.exit(0);
                    }
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            parse_vless_link,
            generate_singbox_config,
            save_profile,
            load_profiles,
            delete_profile,
            start_singbox,
            stop_singbox,
            get_connection_status,
            check_singbox_installed,
            download_singbox,
            ping_server,
            get_traffic_stats,
            get_logs,
            export_logs,
            set_log_level,
            enable_killswitch,
            disable_killswitch,
            get_killswitch_status,
            check_for_update,
            install_update,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
