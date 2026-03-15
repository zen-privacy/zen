//! VPN module for handling VPN connections and configurations
//!
//! This module contains types, configuration handling, and connection
//! management for VPN functionality.

pub mod killswitch;
pub mod manager;
pub mod platform;
pub mod process;
pub mod types;

// Re-export commonly used types for convenience
pub use types::{AppStatus, Profile, TrafficStats, ServerConfig, RuleSetInfo};

// Re-export process management items (used by main.rs)
pub use process::{
    generate_singbox_config, get_available_rule_sets, get_connection_status, kill_singbox_sync,
    start_singbox, stop_singbox, AppState,
};

// Re-export kill switch items (used by main.rs)
pub use killswitch::{
    cleanup_killswitch, create_killswitch, recover_killswitch, state_file_exists, KillSwitchConfig,
};

// Re-export VPN manager items (used by main.rs)
pub use manager::create_vpn_manager;
