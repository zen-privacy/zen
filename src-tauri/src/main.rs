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
    cleanup_killswitch, create_killswitch, create_vpn_manager, generate_singbox_config,
    get_available_rule_sets, get_connection_status, kill_singbox_sync, recover_killswitch, start_singbox,
    stop_singbox, AppState, AppStatus, KillSwitchConfig, Profile, TrafficStats, VlessConfig,
};
use updates::{check_for_update, install_update};

const SINGBOX_VERSION: &str = "1.12.20";

/// Detect if the system is using a dark theme
fn detect_dark_theme() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check GTK theme via gsettings
        if let Ok(output) = std::process::Command::new("gsettings")
            .args(["get", "org.gnome.desktop.interface", "color-scheme"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("dark") {
                return true;
            }
        }
        // Fallback: check GTK theme name
        if let Ok(output) = std::process::Command::new("gsettings")
            .args(["get", "org.gnome.desktop.interface", "gtk-theme"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if stdout.contains("dark") {
                return true;
            }
        }
        false
    }

    #[cfg(target_os = "windows")]
    {
        // Check Windows registry for dark mode
        use std::process::Command;
        if let Ok(output) = Command::new("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                "/v", "SystemUsesLightTheme",
            ])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Value 0x0 = dark theme, 0x1 = light theme
            if stdout.contains("0x0") {
                return true;
            }
        }
        false
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

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

    let current_version = if installed {
        get_installed_singbox_version(&singbox_path)
    } else {
        String::new()
    };

    let needs_update = installed && current_version != SINGBOX_VERSION && !current_version.is_empty();

    AppStatus {
        singbox_installed: installed,
        singbox_path: singbox_path.to_string_lossy().to_string(),
        downloading: false,
        needs_update,
        current_version,
        required_version: SINGBOX_VERSION.to_string(),
    }
}

fn get_installed_singbox_version(path: &PathBuf) -> String {
    std::process::Command::new(path)
        .arg("version")
        .output()
        .ok()
        .and_then(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Parse "sing-box version 1.12.20" -> "1.12.20"
            stdout.lines().next().and_then(|line| {
                line.strip_prefix("sing-box version ").map(|v| v.trim().to_string())
            })
        })
        .unwrap_or_default()
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

    // Determine security type
    let security = params
        .get("security")
        .cloned()
        .unwrap_or_else(|| "none".to_string());

    // For Reality, construct path with pbk, sid, fp parameters
    // This is parsed by generate_singbox_config
    let path = if security == "reality" {
        let pbk = params.get("pbk").cloned().unwrap_or_default();
        let sid = params.get("sid").cloned().unwrap_or_default();
        let fp = params.get("fp").cloned().unwrap_or_else(|| "chrome".to_string());
        format!("pbk={}&sid={}&fp={}", pbk, sid, fp)
    } else {
        params.get("path").cloned().unwrap_or_default()
    };

    // For Reality, use sni parameter; otherwise use host
    let host = params
        .get("sni")
        .cloned()
        .or_else(|| params.get("host").cloned())
        .unwrap_or_else(|| address.to_string());

    Ok(VlessConfig {
        uuid: uuid.to_string(),
        address: address.to_string(),
        port,
        security,
        transport_type: params
            .get("type")
            .cloned()
            .unwrap_or_else(|| "tcp".to_string()),
        path,
        host,
        name,
        routing_mode: None,
        target_country: None,
    })
}

#[derive(serde::Deserialize)]
struct SingboxOutbound {
    #[serde(rename = "type")]
    outbound_type: String,
    tag: Option<String>,
    server: Option<String>,
    server_port: Option<u16>,
    uuid: Option<String>,
    tls: Option<SingboxTls>,
    transport: Option<SingboxTransport>,
}

#[derive(serde::Deserialize)]
struct SingboxTls {
    enabled: Option<bool>,
    server_name: Option<String>,
    reality: Option<SingboxReality>,
}

#[derive(serde::Deserialize)]
struct SingboxReality {
    enabled: Option<bool>,
    public_key: Option<String>,
    short_id: Option<String>,
    fingerprint: Option<String>,
}

#[derive(serde::Deserialize)]
struct SingboxTransport {
    #[serde(rename = "type")]
    transport_type: Option<String>,
    path: Option<String>,
    headers: Option<std::collections::HashMap<String, String>>,
    service_name: Option<String>,
}

#[derive(serde::Deserialize)]
struct SingboxConfig {
    outbounds: Vec<SingboxOutbound>,
}

#[tauri::command]
fn import_config_json(json_content: String) -> Result<VlessConfig, String> {
    // Try to parse as full config first
    let outbound = if let Ok(config) = serde_json::from_str::<SingboxConfig>(&json_content) {
        config
            .outbounds
            .into_iter()
            .find(|o| o.outbound_type == "vless")
            .ok_or("No vless outbound found in config")?
    } else if let Ok(outbound) = serde_json::from_str::<SingboxOutbound>(&json_content) {
        // Try parsing as single outbound object
        if outbound.outbound_type != "vless" {
            return Err("Config is not a vless outbound".to_string());
        }
        outbound
    } else {
        return Err("Invalid JSON format".to_string());
    };

    let address = outbound.server.ok_or("Missing server address")?;
    let port = outbound.server_port.ok_or("Missing server port")?;
    let uuid = outbound.uuid.ok_or("Missing UUID")?;

    let mut security = "none".to_string();
    let mut path = String::new();
    let mut host = String::new();
    let mut transport_type = "tcp".to_string();

    if let Some(tls) = outbound.tls {
        if tls.enabled.unwrap_or(false) {
            security = "tls".to_string();
            if let Some(sni) = tls.server_name {
                host = sni;
            }

            if let Some(reality) = tls.reality {
                if reality.enabled.unwrap_or(false) {
                    security = "reality".to_string();
                    // Map Reality fields to path as per application convention
                    let pbk = reality.public_key.unwrap_or_default();
                    let sid = reality.short_id.unwrap_or_default();
                    let fp = reality.fingerprint.unwrap_or_else(|| "chrome".to_string());
                    path = format!("pbk={}&sid={}&fp={}", pbk, sid, fp);
                }
            }
        }
    }

    if let Some(transport) = outbound.transport {
        if let Some(tt) = transport.transport_type {
            transport_type = tt;
        }
        
        // If NOT reality, use path/headers from transport
        if security != "reality" {
            if let Some(p) = transport.path {
                path = p;
            } else if let Some(sn) = transport.service_name {
                // grpc service name
                path = sn; 
            }
            
            if host.is_empty() {
                if let Some(headers) = transport.headers {
                    if let Some(h) = headers.get("Host") {
                        host = h.clone();
                    }
                }
            }
        }
    }

    Ok(VlessConfig {
        uuid,
        address,
        port,
        security,
        transport_type,
        path,
        host,
        name: outbound.tag.unwrap_or_else(|| "Imported Server".to_string()),
        routing_mode: None,
        target_country: None,
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
        .invoke_handler(tauri::generate_handler![
            check_singbox_installed,
            download_singbox,
            parse_vless_link,
            import_config_json,
            save_profile,
            load_profiles,
            delete_profile,
            start_singbox,
            stop_singbox,
            get_traffic_stats,
            get_connection_status,
            get_available_rule_sets,
            get_logs,
            export_logs,
            set_log_level,
            ping_server,
            enable_killswitch,
            disable_killswitch,
            get_killswitch_status,
            check_for_update,
            install_update
        ])
        .setup(|app| {
            // Attempt to recover from previous crash by cleaning up stale killswitch rules
            if let Err(e) = recover_killswitch() {
                eprintln!("Failed to recover kill switch: {}", e);
            }

            // Choose tray icon based on system theme
            // Light theme = dark icon (for light backgrounds)
            // Dark theme = light icon (for dark backgrounds)
            let icon_light = include_bytes!("../icons/light/icon.png");
            let icon_dark = include_bytes!("../icons/dark/icon.png");

            let is_dark_theme = detect_dark_theme();
            let tray_icon_data: &[u8] = if is_dark_theme { icon_dark } else { icon_light };
            let tray_icon = Image::from_bytes(tray_icon_data)?;

            // Window/taskbar icon also follows system theme
            let window_icon = Image::from_bytes(tray_icon_data)?;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_icon(window_icon);
            }

            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;

            let _tray = TrayIconBuilder::new()
                .icon(tray_icon)
                .menu(&menu)
                .tooltip("Zen Privacy")
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

        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
