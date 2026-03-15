//! VPN-related type definitions
//!
//! This module contains all the data structures used for VPN configuration,
//! profiles, and status management.

use serde::{Deserialize, Serialize};

/// Configuration for a Hysteria2 VPN connection
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub uuid: String,
    pub address: String,
    pub port: u16,
    pub security: String,
    pub transport_type: String,
    pub path: String,
    pub host: String,
    pub name: String,
    pub routing_mode: Option<String>,
    pub target_country: Option<String>,
    /// Protocol type (always "hysteria2")
    #[serde(default)]
    pub protocol: Option<String>,
    /// Hysteria2: upload bandwidth in Mbps
    #[serde(default)]
    pub up_mbps: Option<u32>,
    /// Hysteria2: download bandwidth in Mbps
    #[serde(default)]
    pub down_mbps: Option<u32>,
    /// Hysteria2: obfuscation type ("salamander" or none)
    #[serde(default)]
    pub obfs: Option<String>,
    /// Hysteria2: obfuscation password
    #[serde(default)]
    pub obfs_password: Option<String>,

    // --- Diagnostic flags for bisecting real-time UDP issues (e.g. Telegram calls) ---

    /// Override TUN MTU (default: 1400). Try 1200 to test fragmentation.
    #[serde(default)]
    pub diag_mtu: Option<u32>,
    /// Override protocol sniffing (default: true). Set false to test DTLS breakage.
    #[serde(default)]
    pub diag_sniff: Option<bool>,
    /// Override TUN stack: "system", "gvisor", "mixed".
    #[serde(default)]
    pub diag_stack: Option<String>,
    /// Disable DNS hijacking — use plain UDP to 1.1.1.1 instead of DoT.
    #[serde(default)]
    pub diag_plain_dns: Option<bool>,
    /// UDP timeout in seconds for proxy outbound (default: sing-box ~300s). Try 600.
    #[serde(default)]
    pub diag_udp_timeout: Option<u32>,
    /// Disable kill switch for this connection.
    #[serde(default)]
    pub diag_no_killswitch: Option<bool>,
    /// Enable endpoint-independent NAT for TUN (default: false). Required for ICE/STUN (Telegram calls).
    #[serde(default)]
    pub diag_endpoint_independent_nat: Option<bool>,
}

/// A saved VPN profile containing connection configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub config: ServerConfig,
}

/// Application status regarding sing-box installation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppStatus {
    pub singbox_installed: bool,
    pub singbox_path: String,
    pub downloading: bool,
    pub needs_update: bool,
    pub current_version: String,
    pub required_version: String,
}

/// Network traffic statistics
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrafficStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Available routing rule set (country)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleSetInfo {
    pub id: String,
    pub name: String,
}
