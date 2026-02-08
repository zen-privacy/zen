//! VPN-related type definitions
//!
//! This module contains all the data structures used for VPN configuration,
//! profiles, and status management.

use serde::{Deserialize, Serialize};

/// Configuration for a VLESS VPN connection
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VlessConfig {
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
}

/// A saved VPN profile containing connection configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub config: VlessConfig,
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
