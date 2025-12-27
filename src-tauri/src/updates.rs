use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::{env, fs};
use tauri::AppHandle;

const MANIFEST_URL: &str =
    "https://github.com/netsky-prod/zen/releases/latest/download/manifest.json";

#[derive(Deserialize, Debug, Clone)]
struct AssetEntry {
    url: String,
    sha256: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[allow(dead_code)]
struct Assets {
    #[serde(default)]
    windows: Option<AssetEntry>,
    #[serde(default)]
    deb: Option<AssetEntry>,
    #[serde(default)]
    rpm: Option<AssetEntry>,
}

#[derive(Deserialize, Debug, Clone)]
struct Manifest {
    version: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    assets: Assets,
}

#[derive(serde::Serialize)]
pub struct UpdateInfo {
    available: bool,
    current_version: String,
    latest_version: String,
    notes: Option<String>,
    asset_url: Option<String>,
    sha256: Option<String>,
    platform: String,
    downloaded_path: Option<String>,
}

fn current_version() -> String {
    // Falls back to Cargo package version; ideally kept in sync with tauri.conf.json
    env!("CARGO_PKG_VERSION").to_string()
}

fn choose_platform_asset(manifest: &Manifest) -> (String, Option<AssetEntry>) {
    #[cfg(target_os = "windows")]
    {
        ("windows".to_string(), manifest.assets.windows.clone())
    }

    #[cfg(target_os = "linux")]
    {
        // Prefer rpm for RHEL-like, otherwise deb
        if let Some(rpm) = &manifest.assets.rpm {
            return ("linux-rpm".to_string(), Some(rpm.clone()));
        }
        if let Some(deb) = &manifest.assets.deb {
            return ("linux-deb".to_string(), Some(deb.clone()));
        }
        ("linux".to_string(), None)
    }
}

#[tauri::command]
pub async fn check_for_update() -> Result<UpdateInfo, String> {
    let client = Client::new();
    let manifest: Manifest = client
        .get(MANIFEST_URL)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch manifest: {}", e))?
        .json::<Manifest>()
        .await
        .map_err(|e| format!("Failed to parse manifest: {}", e))?;

    let current = Version::parse(&current_version()).unwrap_or_else(|_| Version::new(0, 0, 0));
    let latest = Version::parse(&manifest.version).unwrap_or_else(|_| Version::new(0, 0, 0));

    let (platform, asset_opt) = choose_platform_asset(&manifest);

    let available = latest > current && asset_opt.is_some();
    let (asset_url, sha256) = asset_opt
        .map(|a| (Some(a.url), a.sha256))
        .unwrap_or((None, None));

    Ok(UpdateInfo {
        available,
        current_version: current.to_string(),
        latest_version: manifest.version,
        notes: manifest.notes,
        asset_url,
        sha256,
        platform,
        downloaded_path: None,
    })
}

#[tauri::command]
pub async fn install_update(_app: AppHandle) -> Result<UpdateInfo, String> {
    let info = check_for_update().await?;
    if !info.available {
        return Ok(info);
    }

    let asset_url = info
        .asset_url
        .clone()
        .ok_or_else(|| "No asset for this platform".to_string())?;

    // Download to app cache dir
    let cache_dir = env::temp_dir().join("zen-vpn-cache");
    fs::create_dir_all(&cache_dir).map_err(|e| e.to_string())?;

    let filename = asset_url
        .split('/')
        .last()
        .unwrap_or("update.bin")
        .to_string();
    let target_path: PathBuf = cache_dir.join(filename);

    let client = Client::new();
    let mut resp = client
        .get(&asset_url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {}", e))?;

    let mut file = std::fs::File::create(&target_path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("Download read failed: {}", e))?
    {
        use std::io::Write;
        file.write_all(&chunk).map_err(|e| e.to_string())?;
        hasher.update(&chunk);
    }

    // Verify sha256 if provided
    if let Some(expected) = info.sha256.as_ref() {
        let actual_hex = format!("{:x}", hasher.finalize());
        if !expected.eq_ignore_ascii_case(&actual_hex) {
            return Err(format!(
                "SHA256 mismatch. Expected {}, got {}",
                expected, actual_hex
            ));
        }
    }

    // Windows: launch NSIS installer in silent mode then exit app
    #[cfg(target_os = "windows")]
    {
        if target_path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("exe"))
            .unwrap_or(false)
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            // /S = silent install, will still show UAC prompt
            let result = std::process::Command::new(&target_path)
                .arg("/S")
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();
            
            if result.is_ok() {
                // Give installer a moment to start, then exit app
                std::thread::sleep(std::time::Duration::from_millis(500));
                std::process::exit(0);
            }
        }
    }

    // Linux: we only download; installation (deb/rpm) typically requires root.

    let mut out = info;
    out.downloaded_path = Some(target_path.to_string_lossy().to_string());
    Ok(out)
}

