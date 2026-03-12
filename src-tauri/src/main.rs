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

    #[cfg(target_os = "macos")]
    {
        // Check macOS dark mode via defaults
        if let Ok(output) = std::process::Command::new("defaults")
            .args(["read", "-g", "AppleInterfaceStyle"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if stdout.contains("dark") {
                return true;
            }
        }
        false
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
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
        protocol: Some("vless".to_string()),
        up_mbps: None,
        down_mbps: None,
        obfs: None,
        obfs_password: None,
    })
}

#[tauri::command]
fn parse_hysteria2_link(link: String) -> Result<VlessConfig, String> {
    let without_prefix = link
        .strip_prefix("hysteria2://")
        .or_else(|| link.strip_prefix("hy2://"))
        .ok_or("Invalid Hysteria2 link")?;

    // Split off fragment (#Name)
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

    // Split auth@host:port/?params
    let (auth, rest) = main_part
        .split_once('@')
        .ok_or("Invalid format: missing @")?;

    let password = urlencoding::decode(auth)
        .unwrap_or_default()
        .to_string();

    // Split host:port from query params
    let (addr_port, params_str) = if let Some(idx) = rest.find('?') {
        let (ap, ps) = rest.split_at(idx);
        (ap, &ps[1..]) // skip '?'
    } else {
        // Strip trailing slash if present
        (rest.trim_end_matches('/'), "")
    };

    let (address, port_str) = addr_port
        .rsplit_once(':')
        .ok_or("Invalid format: missing port")?;

    let port: u16 = port_str.parse().map_err(|_| "Invalid port number")?;

    // Parse query parameters
    let params: std::collections::HashMap<String, String> = params_str
        .split('&')
        .filter(|p| !p.is_empty())
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

    let host = params
        .get("sni")
        .cloned()
        .unwrap_or_else(|| address.to_string());

    let obfs = params.get("obfs").cloned().filter(|s| !s.is_empty());
    let obfs_password = params.get("obfs-password").cloned().filter(|s| !s.is_empty());

    Ok(VlessConfig {
        protocol: Some("hysteria2".to_string()),
        uuid: password, // reuse uuid field as password
        address: address.to_string(),
        port,
        security: "tls".to_string(),
        transport_type: "".to_string(),
        path: "".to_string(),
        host,
        name,
        routing_mode: None,
        target_country: None,
        up_mbps: None,
        down_mbps: None,
        obfs,
        obfs_password,
    })
}

#[tauri::command]
fn parse_share_link(link: String) -> Result<VlessConfig, String> {
    let trimmed = link.trim();
    if trimmed.starts_with("vless://") {
        parse_vless_link(trimmed.to_string())
    } else if trimmed.starts_with("hysteria2://") || trimmed.starts_with("hy2://") {
        parse_hysteria2_link(trimmed.to_string())
    } else {
        Err("Unsupported link format. Use vless:// or hysteria2://".to_string())
    }
}

#[derive(serde::Deserialize)]
struct SingboxOutbound {
    #[serde(rename = "type")]
    outbound_type: String,
    tag: Option<String>,
    server: Option<String>,
    server_port: Option<u16>,
    uuid: Option<String>,
    password: Option<String>,
    up_mbps: Option<u32>,
    down_mbps: Option<u32>,
    obfs: Option<SingboxObfs>,
    tls: Option<SingboxTls>,
    transport: Option<SingboxTransport>,
}

#[derive(serde::Deserialize)]
struct SingboxObfs {
    #[serde(rename = "type")]
    obfs_type: Option<String>,
    password: Option<String>,
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
    let supported_types = ["vless", "hysteria2"];

    // Try to parse as full config first
    let outbound = if let Ok(config) = serde_json::from_str::<SingboxConfig>(&json_content) {
        config
            .outbounds
            .into_iter()
            .find(|o| supported_types.contains(&o.outbound_type.as_str()))
            .ok_or("No vless or hysteria2 outbound found in config")?
    } else if let Ok(outbound) = serde_json::from_str::<SingboxOutbound>(&json_content) {
        if !supported_types.contains(&outbound.outbound_type.as_str()) {
            return Err("Config is not a vless or hysteria2 outbound".to_string());
        }
        outbound
    } else {
        return Err("Invalid JSON format".to_string());
    };

    let address = outbound.server.ok_or("Missing server address")?;
    let port = outbound.server_port.ok_or("Missing server port")?;
    let name = outbound.tag.unwrap_or_else(|| "Imported Server".to_string());

    // Handle Hysteria2 outbound
    if outbound.outbound_type == "hysteria2" {
        let password = outbound.password.ok_or("Missing password")?;
        let mut host = address.clone();

        if let Some(tls) = outbound.tls {
            if let Some(sni) = tls.server_name {
                host = sni;
            }
        }

        let obfs = outbound.obfs.as_ref().and_then(|o| o.obfs_type.clone());
        let obfs_password = outbound.obfs.as_ref().and_then(|o| o.password.clone());

        return Ok(VlessConfig {
            protocol: Some("hysteria2".to_string()),
            uuid: password,
            address,
            port,
            security: "tls".to_string(),
            transport_type: "".to_string(),
            path: "".to_string(),
            host,
            name,
            routing_mode: None,
            target_country: None,
            up_mbps: outbound.up_mbps,
            down_mbps: outbound.down_mbps,
            obfs,
            obfs_password,
        });
    }

    // Handle VLESS outbound
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

        if security != "reality" {
            if let Some(p) = transport.path {
                path = p;
            } else if let Some(sn) = transport.service_name {
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
        protocol: Some("vless".to_string()),
        uuid,
        address,
        port,
        security,
        transport_type,
        path,
        host,
        name,
        routing_mode: None,
        target_country: None,
        up_mbps: None,
        down_mbps: None,
        obfs: None,
        obfs_password: None,
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "macos")]
#[tauri::command]
async fn get_traffic_stats() -> Result<TrafficStats, String> {
    // On macOS, use netstat -ib to read interface stats for utun (sing-box TUN)
    let output = std::process::Command::new("netstat")
        .args(["-ib", "-n"])
        .output()
        .map_err(|e| format!("Failed to run netstat: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find the zen-tun or utun interface line
    // netstat -ib columns: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        // sing-box creates utun interfaces on macOS
        let iface = parts[0];
        if iface.starts_with("utun") && parts.len() >= 10 {
            // Check if this is a Link-level entry (has Ibytes/Obytes)
            if let (Ok(rx), Ok(tx)) = (parts[6].parse::<u64>(), parts[9].parse::<u64>()) {
                if rx > 0 || tx > 0 {
                    return Ok(TrafficStats { rx_bytes: rx, tx_bytes: tx });
                }
            }
        }
    }

    Err("Interface not found".to_string())
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
            parse_hysteria2_link,
            parse_share_link,
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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== parse_vless_link tests ====================

    #[test]
    fn test_parse_vless_ws_full() {
        let link = "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com&sni=cdn.example.com#My%20Server";
        let config = parse_vless_link(link.to_string()).unwrap();
        assert_eq!(config.uuid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(config.address, "example.com");
        assert_eq!(config.port, 443);
        assert_eq!(config.security, "tls");
        assert_eq!(config.transport_type, "ws");
        assert_eq!(config.path, "/ws");
        assert_eq!(config.host, "cdn.example.com");
        assert_eq!(config.name, "My Server");
        assert_eq!(config.protocol.as_deref(), Some("vless"));
    }

    #[test]
    fn test_parse_vless_reality() {
        let link = "vless://uuid123@1.2.3.4:443?security=reality&type=tcp&sni=www.google.com&fp=chrome&pbk=PUBKEY123&sid=SHORTID#Reality";
        let config = parse_vless_link(link.to_string()).unwrap();
        assert_eq!(config.uuid, "uuid123");
        assert_eq!(config.address, "1.2.3.4");
        assert_eq!(config.port, 443);
        assert_eq!(config.security, "reality");
        assert_eq!(config.transport_type, "tcp");
        assert_eq!(config.host, "www.google.com");
        assert!(config.path.contains("pbk=PUBKEY123"));
        assert!(config.path.contains("sid=SHORTID"));
        assert!(config.path.contains("fp=chrome"));
        assert_eq!(config.name, "Reality");
    }

    #[test]
    fn test_parse_vless_tcp_no_security() {
        let link = "vless://myuuid@10.0.0.1:8080?type=tcp#Plain";
        let config = parse_vless_link(link.to_string()).unwrap();
        assert_eq!(config.security, "none");
        assert_eq!(config.transport_type, "tcp");
        assert_eq!(config.path, "");
    }

    #[test]
    fn test_parse_vless_url_encoded_name() {
        let link = "vless://uuid@host:443?type=tcp#%D0%A1%D0%B5%D1%80%D0%B2%D0%B5%D1%80";
        let config = parse_vless_link(link.to_string()).unwrap();
        assert_eq!(config.name, "Сервер");
    }

    #[test]
    fn test_parse_vless_no_fragment() {
        let link = "vless://uuid@host:443?type=tcp";
        let config = parse_vless_link(link.to_string()).unwrap();
        assert_eq!(config.name, "Unnamed");
    }

    #[test]
    fn test_parse_vless_wrong_prefix() {
        let result = parse_vless_link("https://example.com".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid VLESS link"));
    }

    #[test]
    fn test_parse_vless_missing_at() {
        let result = parse_vless_link("vless://uuidhost:443?type=tcp".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_vless_missing_query() {
        let result = parse_vless_link("vless://uuid@host:443".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_vless_invalid_port() {
        let result = parse_vless_link("vless://uuid@host:abc?type=tcp".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid port"));
    }

    #[test]
    fn test_parse_vless_empty_uuid() {
        let link = "vless://@host:443?type=tcp";
        let config = parse_vless_link(link.to_string()).unwrap();
        assert_eq!(config.uuid, "");
    }

    #[test]
    fn test_parse_vless_default_values() {
        let link = "vless://uuid@host:443?foo=bar";
        let config = parse_vless_link(link.to_string()).unwrap();
        assert_eq!(config.security, "none");
        assert_eq!(config.transport_type, "tcp");
    }

    #[test]
    fn test_parse_vless_protocol_field() {
        let link = "vless://uuid@host:443?type=tcp";
        let config = parse_vless_link(link.to_string()).unwrap();
        assert_eq!(config.protocol, Some("vless".to_string()));
        assert_eq!(config.up_mbps, None);
        assert_eq!(config.down_mbps, None);
        assert_eq!(config.obfs, None);
        assert_eq!(config.obfs_password, None);
    }

    // ==================== parse_hysteria2_link tests ====================

    #[test]
    fn test_parse_hy2_basic() {
        let link = "hysteria2://mypassword@vpn.example.com:4443?sni=vpn.example.com#HY2%20Server";
        let config = parse_hysteria2_link(link.to_string()).unwrap();
        assert_eq!(config.uuid, "mypassword"); // password stored in uuid field
        assert_eq!(config.address, "vpn.example.com");
        assert_eq!(config.port, 4443);
        assert_eq!(config.host, "vpn.example.com");
        assert_eq!(config.security, "tls");
        assert_eq!(config.name, "HY2 Server");
        assert_eq!(config.protocol.as_deref(), Some("hysteria2"));
    }

    #[test]
    fn test_parse_hy2_with_obfs() {
        let link = "hysteria2://pass@server:443?sni=sni.com&obfs=salamander&obfs-password=obfspwd#Obfs";
        let config = parse_hysteria2_link(link.to_string()).unwrap();
        assert_eq!(config.obfs.as_deref(), Some("salamander"));
        assert_eq!(config.obfs_password.as_deref(), Some("obfspwd"));
    }

    #[test]
    fn test_parse_hy2_short_prefix() {
        let link = "hy2://pass@server:443?sni=host#Short";
        let config = parse_hysteria2_link(link.to_string()).unwrap();
        assert_eq!(config.uuid, "pass");
        assert_eq!(config.address, "server");
        assert_eq!(config.name, "Short");
    }

    #[test]
    fn test_parse_hy2_no_params() {
        let link = "hysteria2://pass@server:443";
        let config = parse_hysteria2_link(link.to_string()).unwrap();
        assert_eq!(config.host, "server"); // defaults to address
        assert_eq!(config.obfs, None);
        assert_eq!(config.name, "Unnamed");
    }

    #[test]
    fn test_parse_hy2_url_encoded_password() {
        let link = "hysteria2://p%40ss%3Aword@server:443?sni=host#Test";
        let config = parse_hysteria2_link(link.to_string()).unwrap();
        assert_eq!(config.uuid, "p@ss:word");
    }

    #[test]
    fn test_parse_hy2_trailing_slash() {
        let link = "hysteria2://pass@server:443/";
        let config = parse_hysteria2_link(link.to_string()).unwrap();
        assert_eq!(config.address, "server");
        assert_eq!(config.port, 443);
    }

    #[test]
    fn test_parse_hy2_missing_at() {
        let result = parse_hysteria2_link("hysteria2://passserver:443".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hy2_missing_port() {
        let result = parse_hysteria2_link("hysteria2://pass@server".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hy2_invalid_prefix() {
        let result = parse_hysteria2_link("vless://uuid@host:443?type=tcp".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hy2_security_always_tls() {
        let link = "hysteria2://pass@server:443#Test";
        let config = parse_hysteria2_link(link.to_string()).unwrap();
        assert_eq!(config.security, "tls");
        assert_eq!(config.transport_type, "");
        assert_eq!(config.path, "");
    }

    // ==================== parse_share_link tests ====================

    #[test]
    fn test_share_link_routes_vless() {
        let link = "vless://uuid@host:443?type=tcp#Name";
        let config = parse_share_link(link.to_string()).unwrap();
        assert_eq!(config.protocol.as_deref(), Some("vless"));
    }

    #[test]
    fn test_share_link_routes_hysteria2() {
        let link = "hysteria2://pass@host:443#Name";
        let config = parse_share_link(link.to_string()).unwrap();
        assert_eq!(config.protocol.as_deref(), Some("hysteria2"));
    }

    #[test]
    fn test_share_link_routes_hy2() {
        let link = "hy2://pass@host:443#Name";
        let config = parse_share_link(link.to_string()).unwrap();
        assert_eq!(config.protocol.as_deref(), Some("hysteria2"));
    }

    #[test]
    fn test_share_link_whitespace_trimming() {
        let link = "  vless://uuid@host:443?type=tcp#Name  ";
        let config = parse_share_link(link.to_string()).unwrap();
        assert_eq!(config.protocol.as_deref(), Some("vless"));
    }

    #[test]
    fn test_share_link_unknown_prefix() {
        let result = parse_share_link("ss://base64@host:443".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported link format"));
    }

    // ==================== import_config_json tests ====================

    #[test]
    fn test_import_full_singbox_config_vless() {
        let json = r#"{
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "proxy",
                    "server": "1.2.3.4",
                    "server_port": 443,
                    "uuid": "test-uuid-123",
                    "tls": {
                        "enabled": true,
                        "server_name": "example.com"
                    },
                    "transport": {
                        "type": "ws",
                        "path": "/ws",
                        "headers": {"Host": "cdn.example.com"}
                    }
                },
                {"type": "direct", "tag": "direct"}
            ]
        }"#;
        let config = import_config_json(json.to_string()).unwrap();
        assert_eq!(config.uuid, "test-uuid-123");
        assert_eq!(config.address, "1.2.3.4");
        assert_eq!(config.port, 443);
        assert_eq!(config.security, "tls");
        assert_eq!(config.transport_type, "ws");
        assert_eq!(config.path, "/ws");
        assert_eq!(config.host, "example.com"); // TLS server_name takes priority
        assert_eq!(config.name, "proxy");
        assert_eq!(config.protocol.as_deref(), Some("vless"));
    }

    #[test]
    fn test_import_single_vless_outbound() {
        let json = r#"{
            "type": "vless",
            "tag": "my-server",
            "server": "10.0.0.1",
            "server_port": 8443,
            "uuid": "abc-def"
        }"#;
        let config = import_config_json(json.to_string()).unwrap();
        assert_eq!(config.uuid, "abc-def");
        assert_eq!(config.address, "10.0.0.1");
        assert_eq!(config.port, 8443);
        assert_eq!(config.security, "none");
        assert_eq!(config.transport_type, "tcp");
        assert_eq!(config.name, "my-server");
    }

    #[test]
    fn test_import_vless_reality() {
        let json = r#"{
            "type": "vless",
            "server": "5.6.7.8",
            "server_port": 443,
            "uuid": "uuid-reality",
            "tls": {
                "enabled": true,
                "server_name": "www.google.com",
                "reality": {
                    "enabled": true,
                    "public_key": "abc123",
                    "short_id": "deadbeef",
                    "fingerprint": "firefox"
                }
            }
        }"#;
        let config = import_config_json(json.to_string()).unwrap();
        assert_eq!(config.security, "reality");
        assert!(config.path.contains("pbk=abc123"));
        assert!(config.path.contains("sid=deadbeef"));
        assert!(config.path.contains("fp=firefox"));
        assert_eq!(config.host, "www.google.com");
    }

    #[test]
    fn test_import_vless_ws_transport() {
        let json = r#"{
            "type": "vless",
            "server": "server.com",
            "server_port": 443,
            "uuid": "uuid-ws",
            "tls": {"enabled": true, "server_name": "cdn.com"},
            "transport": {
                "type": "ws",
                "path": "/path"
            }
        }"#;
        let config = import_config_json(json.to_string()).unwrap();
        assert_eq!(config.transport_type, "ws");
        assert_eq!(config.path, "/path");
        assert_eq!(config.host, "cdn.com");
    }

    #[test]
    fn test_import_hysteria2_outbound() {
        let json = r#"{
            "type": "hysteria2",
            "tag": "hy2-proxy",
            "server": "hy2.example.com",
            "server_port": 4443,
            "password": "secret123",
            "tls": {
                "enabled": true,
                "server_name": "sni.example.com"
            }
        }"#;
        let config = import_config_json(json.to_string()).unwrap();
        assert_eq!(config.protocol.as_deref(), Some("hysteria2"));
        assert_eq!(config.uuid, "secret123"); // password in uuid field
        assert_eq!(config.address, "hy2.example.com");
        assert_eq!(config.port, 4443);
        assert_eq!(config.host, "sni.example.com");
        assert_eq!(config.security, "tls");
        assert_eq!(config.name, "hy2-proxy");
    }

    #[test]
    fn test_import_hysteria2_with_obfs() {
        let json = r#"{
            "type": "hysteria2",
            "server": "server.com",
            "server_port": 443,
            "password": "pwd",
            "up_mbps": 100,
            "down_mbps": 200,
            "obfs": {
                "type": "salamander",
                "password": "obfs-secret"
            },
            "tls": {"enabled": true, "server_name": "sni.com"}
        }"#;
        let config = import_config_json(json.to_string()).unwrap();
        assert_eq!(config.up_mbps, Some(100));
        assert_eq!(config.down_mbps, Some(200));
        assert_eq!(config.obfs.as_deref(), Some("salamander"));
        assert_eq!(config.obfs_password.as_deref(), Some("obfs-secret"));
    }

    #[test]
    fn test_import_no_supported_outbound() {
        let json = r#"{
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"}
            ]
        }"#;
        let result = import_config_json(json.to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No vless or hysteria2 outbound"));
    }

    #[test]
    fn test_import_invalid_json() {
        let result = import_config_json("not json at all".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid JSON"));
    }

    #[test]
    fn test_import_missing_server() {
        let json = r#"{
            "type": "vless",
            "server_port": 443,
            "uuid": "test"
        }"#;
        let result = import_config_json(json.to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing server"));
    }

    #[test]
    fn test_import_missing_port() {
        let json = r#"{
            "type": "vless",
            "server": "host.com",
            "uuid": "test"
        }"#;
        let result = import_config_json(json.to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing server port"));
    }

    #[test]
    fn test_import_default_tag_name() {
        let json = r#"{
            "type": "vless",
            "server": "host.com",
            "server_port": 443,
            "uuid": "test"
        }"#;
        let config = import_config_json(json.to_string()).unwrap();
        assert_eq!(config.name, "Imported Server");
    }

    #[test]
    fn test_import_hysteria2_missing_password() {
        let json = r#"{
            "type": "hysteria2",
            "server": "host.com",
            "server_port": 443
        }"#;
        let result = import_config_json(json.to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing password"));
    }

    #[test]
    fn test_import_vless_missing_uuid() {
        let json = r#"{
            "type": "vless",
            "server": "host.com",
            "server_port": 443
        }"#;
        let result = import_config_json(json.to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing UUID"));
    }

    #[test]
    fn test_import_unsupported_type_single() {
        let json = r#"{
            "type": "shadowsocks",
            "server": "host.com",
            "server_port": 443,
            "password": "test"
        }"#;
        let result = import_config_json(json.to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a vless or hysteria2"));
    }

    #[test]
    fn test_import_reality_default_fingerprint() {
        let json = r#"{
            "type": "vless",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "uuid",
            "tls": {
                "enabled": true,
                "server_name": "example.com",
                "reality": {
                    "enabled": true,
                    "public_key": "pk123",
                    "short_id": "sid"
                }
            }
        }"#;
        let config = import_config_json(json.to_string()).unwrap();
        assert!(config.path.contains("fp=chrome")); // default fingerprint
    }
}
