use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use std::env;

const MANIFEST_URL: &str =
    "https://github.com/zen-privacy/releases/releases/latest/download/manifest.json";

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
    #[serde(default)]
    macos: Option<AssetEntry>,
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
    pub available: bool,
    pub current_version: String,
    pub latest_version: String,
    pub notes: Option<String>,
    /// Direct download URL for the platform-specific installer
    pub asset_url: Option<String>,
    /// GitHub releases page URL (for manual download)
    pub release_url: String,
    pub platform: String,
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

    #[cfg(target_os = "macos")]
    {
        ("macos".to_string(), manifest.assets.macos.clone())
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
    let asset_url = asset_opt.map(|a| a.url);

    let release_url = format!(
        "https://github.com/zen-privacy/releases/releases/tag/v{}",
        manifest.version
    );

    Ok(UpdateInfo {
        available,
        current_version: current.to_string(),
        latest_version: manifest.version,
        notes: manifest.notes,
        asset_url,
        release_url,
        platform,
    })
}

