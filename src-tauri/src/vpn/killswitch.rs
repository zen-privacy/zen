//! Kill Switch Implementation
//!
//! This module provides platform-specific firewall rules to block all network traffic
//! when the VPN disconnects unexpectedly, preventing traffic leaks.
//!
//! - Linux: Uses nftables (with iptables fallback detection)
//! - Windows: Uses netsh advfirewall
//!
//! ## Crash Recovery
//!
//! The kill switch persists its state to a file in the config directory. On application
//! startup, `recover_killswitch()` should be called to clean up any stale firewall rules
//! left from a previous crash. The state file contains:
//! - The firewall backend being used
//! - The VPN server IP address

// Allow unused code for infrastructure that may be used in future features
#![allow(dead_code)]
//! - The TUN interface name
//! - (Windows only) The sing-box binary path

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use super::process::{DNS_PRIMARY, DNS_SECONDARY};

/// Kill switch configuration holding the VPN server IP and interface name
#[derive(Debug, Clone)]
pub struct KillSwitchConfig {
    /// The VPN server IP address to allow through the firewall
    pub server_ip: String,
    /// The VPN tunnel interface name (e.g., "zen-tun")
    pub tun_interface: String,
    /// Path to the sing-box binary (needed for Windows firewall rules)
    pub singbox_path: PathBuf,
}

impl Default for KillSwitchConfig {
    fn default() -> Self {
        Self {
            server_ip: String::new(),
            tun_interface: "zen-tun".to_string(),
            singbox_path: PathBuf::new(),
        }
    }
}

/// Result of a kill switch operation
#[derive(Debug, Clone)]
pub struct KillSwitchResult {
    /// Whether the operation succeeded
    pub success: bool,
    /// Optional message describing the result
    pub message: String,
}

impl KillSwitchResult {
    /// Create a successful result
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
        }
    }

    /// Create a failure result
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
        }
    }
}

/// Trait defining the kill switch interface
///
/// This trait provides a common interface for platform-specific kill switch
/// implementations. Each platform (Linux, Windows) has its own implementation
/// that uses the appropriate firewall tools.
pub trait KillSwitch: Send + Sync {
    /// Enable the kill switch with the given configuration
    ///
    /// This will set up firewall rules to:
    /// 1. Block all outbound traffic by default
    /// 2. Allow traffic to the VPN server IP
    /// 3. Allow traffic through the VPN tunnel interface
    /// 4. Allow loopback traffic
    fn enable(&self, config: &KillSwitchConfig) -> Result<KillSwitchResult, String>;

    /// Disable the kill switch and remove all firewall rules
    ///
    /// This will remove all firewall rules added by the kill switch,
    /// restoring normal network connectivity.
    fn disable(&self) -> Result<KillSwitchResult, String>;

    /// Check if the kill switch is currently enabled
    fn is_enabled(&self) -> bool;

    /// Check if the platform's firewall tool is available
    ///
    /// Returns the name of the available tool or an error if none is found.
    fn check_availability(&self) -> Result<String, String>;
}

/// Platform-specific firewall backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    /// Linux nftables (modern, preferred)
    Nftables,
    /// Linux iptables (legacy fallback)
    Iptables,
    /// Windows netsh advfirewall
    Netsh,
    /// macOS pf (Packet Filter)
    Pf,
    /// No firewall backend available
    None,
}

impl std::fmt::Display for FirewallBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallBackend::Nftables => write!(f, "nftables"),
            FirewallBackend::Iptables => write!(f, "iptables"),
            FirewallBackend::Netsh => write!(f, "netsh"),
            FirewallBackend::Pf => write!(f, "pf"),
            FirewallBackend::None => write!(f, "none"),
        }
    }
}

impl Default for FirewallBackend {
    fn default() -> Self {
        FirewallBackend::None
    }
}

/// Kill switch state management
pub struct KillSwitchState {
    /// Whether the kill switch is currently enabled
    enabled: AtomicBool,
    /// The current configuration (if enabled)
    config: Mutex<Option<KillSwitchConfig>>,
    /// The firewall backend being used
    backend: FirewallBackend,
}

impl KillSwitchState {
    /// Create a new kill switch state with the detected backend
    pub fn new(backend: FirewallBackend) -> Self {
        Self {
            enabled: AtomicBool::new(false),
            config: Mutex::new(None),
            backend,
        }
    }

    /// Get the firewall backend
    pub fn backend(&self) -> FirewallBackend {
        self.backend
    }

    /// Check if the kill switch is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Set the enabled state
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }

    /// Store the current configuration
    pub fn set_config(&self, config: Option<KillSwitchConfig>) {
        let mut guard = self.config.lock().unwrap();
        *guard = config;
    }

    /// Get the current configuration
    pub fn get_config(&self) -> Option<KillSwitchConfig> {
        let guard = self.config.lock().unwrap();
        guard.clone()
    }
}

impl Default for KillSwitchState {
    fn default() -> Self {
        Self::new(detect_firewall_backend())
    }
}

/// Detect the available firewall backend for the current platform
///
/// On Linux, this checks for nftables first, then falls back to iptables.
/// On Windows, this checks for netsh.
pub fn detect_firewall_backend() -> FirewallBackend {
    #[cfg(target_os = "windows")]
    {
        detect_windows_backend()
    }

    #[cfg(target_os = "linux")]
    {
        detect_linux_backend()
    }

    #[cfg(target_os = "macos")]
    {
        detect_macos_backend()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        FirewallBackend::None
    }
}

/// Detect the firewall backend on macOS
#[cfg(target_os = "macos")]
fn detect_macos_backend() -> FirewallBackend {
    // pf is always available on macOS (built-in)
    if check_command_exists("pfctl") {
        return FirewallBackend::Pf;
    }
    FirewallBackend::None
}

/// Detect the firewall backend on Linux
#[cfg(target_os = "linux")]
fn detect_linux_backend() -> FirewallBackend {
    // Check for nftables first (modern, preferred)
    if check_command_exists("nft") {
        return FirewallBackend::Nftables;
    }

    // Fall back to iptables (legacy)
    if check_command_exists("iptables") {
        return FirewallBackend::Iptables;
    }

    FirewallBackend::None
}

/// Detect the firewall backend on Windows
#[cfg(target_os = "windows")]
fn detect_windows_backend() -> FirewallBackend {
    // Check for netsh (should always be available on Windows)
    if check_command_exists("netsh") {
        return FirewallBackend::Netsh;
    }

    FirewallBackend::None
}

/// Check if a command exists and is executable
fn check_command_exists(command: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        std::process::Command::new("where")
            .creation_flags(CREATE_NO_WINDOW)
            .arg(command)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("which")
            .arg(command)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

/// Linux kill switch implementation using nftables or iptables
#[cfg(target_os = "linux")]
pub struct LinuxKillSwitch {
    state: KillSwitchState,
}

#[cfg(target_os = "linux")]
impl LinuxKillSwitch {
    /// Create a new Linux kill switch
    pub fn new() -> Self {
        Self {
            state: KillSwitchState::default(),
        }
    }

    /// Create with a specific backend (for testing)
    pub fn with_backend(backend: FirewallBackend) -> Self {
        Self {
            state: KillSwitchState::new(backend),
        }
    }
}

#[cfg(target_os = "linux")]
impl Default for LinuxKillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl KillSwitch for LinuxKillSwitch {
    fn enable(&self, config: &KillSwitchConfig) -> Result<KillSwitchResult, String> {
        match self.state.backend() {
            FirewallBackend::Nftables => self.enable_nftables(config),
            FirewallBackend::Iptables => self.enable_iptables(config),
            _ => Err("No firewall backend available on Linux".to_string()),
        }
    }

    fn disable(&self) -> Result<KillSwitchResult, String> {
        match self.state.backend() {
            FirewallBackend::Nftables => self.disable_nftables(),
            FirewallBackend::Iptables => self.disable_iptables(),
            _ => Err("No firewall backend available on Linux".to_string()),
        }
    }

    fn is_enabled(&self) -> bool {
        self.state.is_enabled()
    }

    fn check_availability(&self) -> Result<String, String> {
        match self.state.backend() {
            FirewallBackend::Nftables => Ok("nftables".to_string()),
            FirewallBackend::Iptables => Ok("iptables".to_string()),
            _ => Err("No firewall backend available".to_string()),
        }
    }
}

#[cfg(target_os = "linux")]
impl LinuxKillSwitch {
    /// Table name for nftables rules
    const NFT_TABLE: &'static str = "zenvpn";

    /// Chain name prefix for iptables rules
    const IPT_CHAIN: &'static str = "ZENVPN";

    /// Execute a shell command and return the result
    fn run_command(&self, cmd: &str) -> Result<std::process::Output, String> {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .map_err(|e| format!("Failed to execute command: {}", e))
    }

    /// Execute a command with sudo using saved password
    fn run_privileged_command(&self, cmd: &str) -> Result<std::process::Output, String> {
        crate::sudo::sudo_exec(&["sh", "-c", cmd])
    }

    /// Resolve a hostname to IP addresses
    /// If the input is already an IP address, returns it as-is
    fn resolve_hostname(&self, hostname: &str) -> Vec<String> {
        use std::net::ToSocketAddrs;

        // First check if it's already an IP address
        if hostname.parse::<std::net::IpAddr>().is_ok() {
            return vec![hostname.to_string()];
        }

        // Try to resolve the hostname
        let addr_with_port = format!("{}:443", hostname);
        match addr_with_port.to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<String> = addrs
                    .filter_map(|addr| Some(addr.ip().to_string()))
                    .collect();
                if ips.is_empty() {
                    // Fallback to the original hostname
                    vec![hostname.to_string()]
                } else {
                    ips
                }
            }
            Err(_) => {
                // If resolution fails, try using the hostname as-is
                // (might be an IP address or nftables might handle it)
                vec![hostname.to_string()]
            }
        }
    }

    /// Enable kill switch using nftables
    fn enable_nftables(&self, config: &KillSwitchConfig) -> Result<KillSwitchResult, String> {
        let server_host = &config.server_ip;
        let tun_iface = &config.tun_interface;

        // Resolve hostname to IP addresses
        // This is critical because nftables rules with "ip daddr" require actual IP addresses
        let resolved_ips = self.resolve_hostname(server_host);

        // Build rules for each resolved IP
        let mut server_ip_rules = String::new();
        for ip in &resolved_ips {
            // Allow traffic to this VPN server IP
            server_ip_rules.push_str(&format!(
                "nft add rule inet {} output ip daddr {} accept\n",
                Self::NFT_TABLE, ip
            ));
            server_ip_rules.push_str(&format!(
                "nft add rule inet {} input ip saddr {} accept\n",
                Self::NFT_TABLE, ip
            ));
            // DNS rules for this IP
            server_ip_rules.push_str(&format!(
                "nft add rule inet {} output ip daddr {} udp dport 53 accept\n",
                Self::NFT_TABLE, ip
            ));
            server_ip_rules.push_str(&format!(
                "nft add rule inet {} output ip daddr {} tcp dport 53 accept\n",
                Self::NFT_TABLE, ip
            ));
        }

        // Build the nftables commands as a single script
        // This ensures atomic application of rules
        let nft_script = format!(
            r#"
# Delete existing table if it exists (ignore errors)
nft delete table inet {table} 2>/dev/null || true

# Create table
nft add table inet {table}

# Create output chain with drop policy
nft add chain inet {table} output {{ type filter hook output priority 0 \; policy drop \; }}

# Create input chain with drop policy
nft add chain inet {table} input {{ type filter hook input priority 0 \; policy drop \; }}

# Allow loopback traffic
nft add rule inet {table} output oifname lo accept
nft add rule inet {table} input iifname lo accept

# Allow traffic to VPN server (all resolved IPs)
{server_ip_rules}

# Allow traffic through VPN tunnel interface
nft add rule inet {table} output oifname {tun_iface} accept
nft add rule inet {table} input iifname {tun_iface} accept

# Allow established/related connections (for proper connection tracking)
nft add rule inet {table} input ct state established,related accept
nft add rule inet {table} output ct state established,related accept

# Allow DHCP (needed for network configuration)
nft add rule inet {table} output udp dport 67 accept
nft add rule inet {table} input udp sport 67 accept

# Allow ICMP (ping) - needed for VPN connectivity testing
nft add rule inet {table} output icmp type echo-request accept
nft add rule inet {table} input icmp type echo-reply accept
nft add rule inet {table} output icmpv6 type echo-request accept
nft add rule inet {table} input icmpv6 type echo-reply accept

# Allow DNS through tunnel (for normal operation)
nft add rule inet {table} output oifname {tun_iface} udp dport 53 accept
nft add rule inet {table} output oifname {tun_iface} tcp dport 53 accept

# Allow DNS to configured DNS servers (fallback for connectivity)
nft add rule inet {table} output ip daddr {dns1} udp dport 53 accept
nft add rule inet {table} output ip daddr {dns2} udp dport 53 accept
nft add rule inet {table} output ip daddr {dns1} tcp dport 53 accept
nft add rule inet {table} output ip daddr {dns2} tcp dport 53 accept
"#,
            table = Self::NFT_TABLE,
            server_ip_rules = server_ip_rules,
            tun_iface = tun_iface,
            dns1 = DNS_PRIMARY,
            dns2 = DNS_SECONDARY
        );

        let output = self.run_privileged_command(&nft_script)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to enable nftables kill switch: {}", stderr));
        }

        self.state.set_config(Some(config.clone()));
        self.state.set_enabled(true);

        // Save state to file for crash recovery
        if let Err(e) = self.save_state_file() {
            // Log but don't fail - the kill switch is still active
            eprintln!("Warning: Failed to save kill switch state: {}", e);
        }

        let ips_str = resolved_ips.join(", ");
        Ok(KillSwitchResult::ok(format!(
            "nftables kill switch enabled (server: {} -> [{}], interface: {})",
            server_host, ips_str, tun_iface
        )))
    }

    /// Disable kill switch using nftables
    fn disable_nftables(&self) -> Result<KillSwitchResult, String> {
        // Delete the entire table - this removes all chains and rules
        let cmd = format!("nft delete table inet {} 2>/dev/null || true", Self::NFT_TABLE);

        let output = self.run_privileged_command(&cmd)?;

        // We use || true so this should always succeed, but check anyway
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Only fail if there was an actual error (not just "table doesn't exist")
            if !stderr.is_empty() && !stderr.contains("No such file") {
                return Err(format!("Failed to disable nftables kill switch: {}", stderr));
            }
        }

        self.state.set_config(None);
        self.state.set_enabled(false);

        // Remove state file
        let _ = self.remove_state_file();

        Ok(KillSwitchResult::ok("nftables kill switch disabled"))
    }

    /// Enable kill switch using iptables (legacy fallback)
    fn enable_iptables(&self, config: &KillSwitchConfig) -> Result<KillSwitchResult, String> {
        let server_host = &config.server_ip;
        let tun_iface = &config.tun_interface;

        // Resolve hostname to IP addresses
        // This is critical because iptables rules with "-d" require actual IP addresses
        let resolved_ips = self.resolve_hostname(server_host);

        // Build rules for each resolved IP
        let mut server_ip_rules = String::new();
        for ip in &resolved_ips {
            // Allow traffic to this VPN server IP
            server_ip_rules.push_str(&format!(
                "iptables -A {}_OUTPUT -d {} -j ACCEPT\n",
                Self::IPT_CHAIN, ip
            ));
            server_ip_rules.push_str(&format!(
                "iptables -A {}_INPUT -s {} -j ACCEPT\n",
                Self::IPT_CHAIN, ip
            ));
            // DNS rules for this IP
            server_ip_rules.push_str(&format!(
                "iptables -A {}_OUTPUT -d {} -p udp --dport 53 -j ACCEPT\n",
                Self::IPT_CHAIN, ip
            ));
            server_ip_rules.push_str(&format!(
                "iptables -A {}_OUTPUT -d {} -p tcp --dport 53 -j ACCEPT\n",
                Self::IPT_CHAIN, ip
            ));
        }

        // Build iptables commands as a script
        // We create custom chains to make cleanup easier
        let ipt_script = format!(
            r#"
# Flush and delete existing chains if they exist (ignore errors)
iptables -D OUTPUT -j {chain}_OUTPUT 2>/dev/null || true
iptables -D INPUT -j {chain}_INPUT 2>/dev/null || true
iptables -F {chain}_OUTPUT 2>/dev/null || true
iptables -F {chain}_INPUT 2>/dev/null || true
iptables -X {chain}_OUTPUT 2>/dev/null || true
iptables -X {chain}_INPUT 2>/dev/null || true

# Create custom chains
iptables -N {chain}_OUTPUT
iptables -N {chain}_INPUT

# Allow loopback
iptables -A {chain}_OUTPUT -o lo -j ACCEPT
iptables -A {chain}_INPUT -i lo -j ACCEPT

# Allow traffic to VPN server (all resolved IPs)
{server_ip_rules}

# Allow traffic through VPN tunnel
iptables -A {chain}_OUTPUT -o {tun_iface} -j ACCEPT
iptables -A {chain}_INPUT -i {tun_iface} -j ACCEPT

# Allow established/related connections
iptables -A {chain}_INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A {chain}_OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow DHCP
iptables -A {chain}_OUTPUT -p udp --dport 67 -j ACCEPT
iptables -A {chain}_INPUT -p udp --sport 67 -j ACCEPT

# Allow ICMP (ping) - needed for VPN connectivity testing
iptables -A {chain}_OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A {chain}_INPUT -p icmp --icmp-type echo-reply -j ACCEPT

# Allow DNS through tunnel
iptables -A {chain}_OUTPUT -o {tun_iface} -p udp --dport 53 -j ACCEPT
iptables -A {chain}_OUTPUT -o {tun_iface} -p tcp --dport 53 -j ACCEPT

# Allow DNS to configured DNS servers (fallback for connectivity)
iptables -A {chain}_OUTPUT -d {dns1} -p udp --dport 53 -j ACCEPT
iptables -A {chain}_OUTPUT -d {dns2} -p udp --dport 53 -j ACCEPT
iptables -A {chain}_OUTPUT -d {dns1} -p tcp --dport 53 -j ACCEPT
iptables -A {chain}_OUTPUT -d {dns2} -p tcp --dport 53 -j ACCEPT

# Drop everything else
iptables -A {chain}_OUTPUT -j DROP
iptables -A {chain}_INPUT -j DROP

# Insert our chains at the beginning of the main chains
iptables -I OUTPUT 1 -j {chain}_OUTPUT
iptables -I INPUT 1 -j {chain}_INPUT
"#,
            chain = Self::IPT_CHAIN,
            server_ip_rules = server_ip_rules,
            tun_iface = tun_iface,
            dns1 = DNS_PRIMARY,
            dns2 = DNS_SECONDARY
        );

        let output = self.run_privileged_command(&ipt_script)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Attempt cleanup on failure
            let _ = self.disable_iptables();
            return Err(format!("Failed to enable iptables kill switch: {}", stderr));
        }

        self.state.set_config(Some(config.clone()));
        self.state.set_enabled(true);

        // Save state to file for crash recovery
        if let Err(e) = self.save_state_file() {
            eprintln!("Warning: Failed to save kill switch state: {}", e);
        }

        let ips_str = resolved_ips.join(", ");
        Ok(KillSwitchResult::ok(format!(
            "iptables kill switch enabled (server: {} -> [{}], interface: {})",
            server_host, ips_str, tun_iface
        )))
    }

    /// Disable kill switch using iptables
    fn disable_iptables(&self) -> Result<KillSwitchResult, String> {
        // Remove chains from main chains and delete them
        let ipt_script = format!(
            r#"
# Remove from main chains (ignore errors if not present)
iptables -D OUTPUT -j {chain}_OUTPUT 2>/dev/null || true
iptables -D INPUT -j {chain}_INPUT 2>/dev/null || true

# Flush and delete custom chains
iptables -F {chain}_OUTPUT 2>/dev/null || true
iptables -F {chain}_INPUT 2>/dev/null || true
iptables -X {chain}_OUTPUT 2>/dev/null || true
iptables -X {chain}_INPUT 2>/dev/null || true
"#,
            chain = Self::IPT_CHAIN
        );

        let output = self.run_privileged_command(&ipt_script)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                return Err(format!("Failed to disable iptables kill switch: {}", stderr));
            }
        }

        self.state.set_config(None);
        self.state.set_enabled(false);

        // Remove state file
        let _ = self.remove_state_file();

        Ok(KillSwitchResult::ok("iptables kill switch disabled"))
    }

    /// Save kill switch state to file for crash recovery
    fn save_state_file(&self) -> Result<(), String> {
        let state_path = get_killswitch_state_path();

        // Ensure parent directory exists
        if let Some(parent) = state_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create state directory: {}", e))?;
        }

        let config = self.state.get_config();
        let backend = self.state.backend();

        let state_content = format!(
            "backend={}\nserver_ip={}\ntun_interface={}\n",
            backend,
            config.as_ref().map(|c| c.server_ip.as_str()).unwrap_or(""),
            config.as_ref().map(|c| c.tun_interface.as_str()).unwrap_or("zen-tun")
        );

        std::fs::write(&state_path, state_content)
            .map_err(|e| format!("Failed to write state file: {}", e))
    }

    /// Remove the kill switch state file
    fn remove_state_file(&self) -> Result<(), String> {
        let state_path = get_killswitch_state_path();
        if state_path.exists() {
            std::fs::remove_file(&state_path)
                .map_err(|e| format!("Failed to remove state file: {}", e))?;
        }
        Ok(())
    }

    /// Check if kill switch rules are currently active (for recovery)
    pub fn check_rules_active(&self) -> bool {
        match self.state.backend() {
            FirewallBackend::Nftables => {
                let cmd = format!("nft list table inet {} 2>/dev/null", Self::NFT_TABLE);
                self.run_command(&cmd)
                    .map(|output| output.status.success())
                    .unwrap_or(false)
            }
            FirewallBackend::Iptables => {
                let cmd = format!("iptables -L {} 2>/dev/null", Self::IPT_CHAIN);
                self.run_command(&cmd)
                    .map(|output| output.status.success())
                    .unwrap_or(false)
            }
            _ => false,
        }
    }

    /// Recover from a crash by cleaning up stale rules
    ///
    /// This should be called on application startup to ensure
    /// no stale firewall rules are left from a previous crash.
    pub fn recover_from_crash(&self) -> Result<KillSwitchResult, String> {
        let state_path = get_killswitch_state_path();

        // Check if state file exists (indicates a crash)
        if state_path.exists() {
            // Clean up any existing rules
            let result = self.disable();
            if result.is_ok() {
                return Ok(KillSwitchResult::ok("Recovered from previous crash - firewall rules cleaned up"));
            }
            return result;
        }

        // Also check if rules exist without state file (edge case)
        if self.check_rules_active() {
            let result = self.disable();
            if result.is_ok() {
                return Ok(KillSwitchResult::ok("Cleaned up orphaned firewall rules"));
            }
            return result;
        }

        Ok(KillSwitchResult::ok("No recovery needed"))
    }
}

/// Windows kill switch implementation using netsh advfirewall
#[cfg(target_os = "windows")]
pub struct WindowsKillSwitch {
    state: KillSwitchState,
}

#[cfg(target_os = "windows")]
impl WindowsKillSwitch {
    /// Rule names for Windows Firewall
    const RULE_BLOCK_OUT: &'static str = "ZenVPN-Block-Out";
    const RULE_BLOCK_IN: &'static str = "ZenVPN-Block-In";
    const RULE_ALLOW_SINGBOX: &'static str = "ZenVPN-Allow-SingBox";
    const RULE_ALLOW_SERVER: &'static str = "ZenVPN-Allow-Server";
    const RULE_ALLOW_LOOPBACK_OUT: &'static str = "ZenVPN-Allow-Loopback-Out";
    const RULE_ALLOW_LOOPBACK_IN: &'static str = "ZenVPN-Allow-Loopback-In";
    const RULE_ALLOW_DHCP: &'static str = "ZenVPN-Allow-DHCP";
    const RULE_ALLOW_ICMP_OUT: &'static str = "ZenVPN-Allow-ICMP-Out";
    const RULE_ALLOW_ICMP_IN: &'static str = "ZenVPN-Allow-ICMP-In";
    const RULE_ALLOW_DNS_1: &'static str = "ZenVPN-Allow-DNS-Primary";
    const RULE_ALLOW_DNS_2: &'static str = "ZenVPN-Allow-DNS-Secondary";

    /// Create a new Windows kill switch
    pub fn new() -> Self {
        Self {
            state: KillSwitchState::default(),
        }
    }

    /// Execute a netsh command and return the result
    fn run_netsh_command(&self, args: &[&str]) -> Result<std::process::Output, String> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        std::process::Command::new("netsh")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to execute netsh command: {}", e))
    }

    /// Add a firewall rule
    fn add_rule(&self, name: &str, args: &[&str]) -> Result<(), String> {
        let name_arg = format!("name={}", name);
        let mut full_args = vec!["advfirewall", "firewall", "add", "rule", &name_arg];
        full_args.extend_from_slice(args);

        let output = self.run_netsh_command(&full_args)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(format!(
                "Failed to add firewall rule '{}': {} {}",
                name, stdout, stderr
            ));
        }

        Ok(())
    }

    /// Delete a firewall rule (ignores errors if rule doesn't exist)
    fn delete_rule(&self, name: &str) -> Result<(), String> {
        let name_arg = format!("name={}", name);
        let args = ["advfirewall", "firewall", "delete", "rule", &name_arg];

        // Ignore errors - rule might not exist
        let _ = self.run_netsh_command(&args);
        Ok(())
    }

    /// Resolve a hostname to IP addresses (Windows implementation)
    /// If the input is already an IP address, returns it as-is
    fn resolve_hostname(&self, hostname: &str) -> Vec<String> {
        use std::net::ToSocketAddrs;

        // First check if it's already an IP address
        if hostname.parse::<std::net::IpAddr>().is_ok() {
            return vec![hostname.to_string()];
        }

        // Try to resolve the hostname
        let addr_with_port = format!("{}:443", hostname);
        match addr_with_port.to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<String> = addrs
                    .filter_map(|addr| Some(addr.ip().to_string()))
                    .collect();
                if ips.is_empty() {
                    // Fallback to the original hostname
                    vec![hostname.to_string()]
                } else {
                    ips
                }
            }
            Err(_) => {
                // If resolution fails, try using the hostname as-is
                vec![hostname.to_string()]
            }
        }
    }

    /// Enable kill switch using netsh advfirewall
    fn enable_netsh(&self, config: &KillSwitchConfig) -> Result<KillSwitchResult, String> {
        let server_host = &config.server_ip;
        let tun_iface = &config.tun_interface;
        let singbox_path = config.singbox_path.to_string_lossy();

        // Resolve hostname to IP addresses
        let resolved_ips = self.resolve_hostname(server_host);
        // Windows firewall accepts comma-separated IPs
        let ips_for_rule = resolved_ips.join(",");

        // First, clean up any existing rules
        self.cleanup_rules()?;

        // Order matters: Allow rules must be added BEFORE block rules
        // otherwise traffic will be blocked before allow rules take effect

        // 1. Allow loopback traffic (localhost)
        self.add_rule(
            Self::RULE_ALLOW_LOOPBACK_OUT,
            &["dir=out", "action=allow", "remoteip=127.0.0.0/8", "enable=yes"],
        )?;
        self.add_rule(
            Self::RULE_ALLOW_LOOPBACK_IN,
            &["dir=in", "action=allow", "remoteip=127.0.0.0/8", "enable=yes"],
        )?;

        // 2. Allow DHCP (needed for network configuration)
        self.add_rule(
            Self::RULE_ALLOW_DHCP,
            &["dir=out", "action=allow", "protocol=udp", "remoteport=67", "enable=yes"],
        )?;

        // 3. Allow ICMP (ping) - needed for VPN connectivity testing
        self.add_rule(
            Self::RULE_ALLOW_ICMP_OUT,
            &["dir=out", "action=allow", "protocol=icmpv4:8,any", "enable=yes"],
        )?;
        self.add_rule(
            Self::RULE_ALLOW_ICMP_IN,
            &["dir=in", "action=allow", "protocol=icmpv4:0,any", "enable=yes"],
        )?;

        // 4. Allow DNS to configured DNS servers (for connectivity when tunnel down)
        let dns1_rule = format!("remoteip={}", DNS_PRIMARY);
        let dns2_rule = format!("remoteip={}", DNS_SECONDARY);
        self.add_rule(
            Self::RULE_ALLOW_DNS_1,
            &["dir=out", "action=allow", &dns1_rule, "protocol=udp", "remoteport=53", "enable=yes"],
        )?;
        self.add_rule(
            Self::RULE_ALLOW_DNS_2,
            &["dir=out", "action=allow", &dns2_rule, "protocol=udp", "remoteport=53", "enable=yes"],
        )?;

        // 5. Allow VPN server IP(s) - resolved from hostname (before blocking takes effect)
        self.add_rule(
            Self::RULE_ALLOW_SERVER,
            &["dir=out", "action=allow", &format!("remoteip={}", ips_for_rule), "enable=yes"],
        )?;

        // 6. Allow sing-box process (if path is provided)
        if !singbox_path.is_empty() && config.singbox_path.exists() {
            self.add_rule(
                Self::RULE_ALLOW_SINGBOX,
                &["dir=out", "action=allow", &format!("program={}", singbox_path), "enable=yes"],
            )?;
        }

        // 7. Allow VPN tunnel interface traffic
        // Windows firewall doesn't support filtering by TUN interface name directly,
        // so we allow traffic to/from the TUN subnet. Applications send traffic to the
        // TUN address (172.19.0.0/30), sing-box picks it up and forwards through VPN.
        self.add_rule(
            "ZenVPN-Allow-TUN-Out",
            &["dir=out", "action=allow", "localip=172.19.0.0/30", "enable=yes"],
        )?;
        self.add_rule(
            "ZenVPN-Allow-TUN-In",
            &["dir=in", "action=allow", "localip=172.19.0.0/30", "enable=yes"],
        )?;

        // 8. Block all other outbound traffic
        self.add_rule(
            Self::RULE_BLOCK_OUT,
            &["dir=out", "action=block", "enable=yes"],
        )?;

        // 9. Block all other inbound traffic (optional, for extra security)
        self.add_rule(
            Self::RULE_BLOCK_IN,
            &["dir=in", "action=block", "enable=yes"],
        )?;

        self.state.set_config(Some(config.clone()));
        self.state.set_enabled(true);

        // Save state to file for crash recovery
        if let Err(e) = self.save_state_file() {
            eprintln!("Warning: Failed to save kill switch state: {}", e);
        }

        let ips_str = resolved_ips.join(", ");
        Ok(KillSwitchResult::ok(format!(
            "Windows firewall kill switch enabled (server: {} -> [{}], interface: {})",
            server_host, ips_str, tun_iface
        )))
    }

    /// Disable kill switch by removing all firewall rules
    fn disable_netsh(&self) -> Result<KillSwitchResult, String> {
        self.cleanup_rules()?;

        self.state.set_config(None);
        self.state.set_enabled(false);

        // Remove state file
        let _ = self.remove_state_file();

        Ok(KillSwitchResult::ok("Windows firewall kill switch disabled"))
    }

    /// Clean up all ZenVPN firewall rules
    fn cleanup_rules(&self) -> Result<(), String> {
        // Delete rules in reverse order (block rules first, then allow rules)
        self.delete_rule(Self::RULE_BLOCK_IN)?;
        self.delete_rule(Self::RULE_BLOCK_OUT)?;
        self.delete_rule("ZenVPN-Allow-TUN-In")?;
        self.delete_rule("ZenVPN-Allow-TUN-Out")?;
        self.delete_rule(Self::RULE_ALLOW_SINGBOX)?;
        self.delete_rule(Self::RULE_ALLOW_SERVER)?;
        self.delete_rule(Self::RULE_ALLOW_DNS_2)?;
        self.delete_rule(Self::RULE_ALLOW_DNS_1)?;
        self.delete_rule(Self::RULE_ALLOW_ICMP_IN)?;
        self.delete_rule(Self::RULE_ALLOW_ICMP_OUT)?;
        self.delete_rule(Self::RULE_ALLOW_DHCP)?;
        self.delete_rule(Self::RULE_ALLOW_LOOPBACK_IN)?;
        self.delete_rule(Self::RULE_ALLOW_LOOPBACK_OUT)?;

        Ok(())
    }

    /// Save kill switch state to file for crash recovery
    fn save_state_file(&self) -> Result<(), String> {
        let state_path = get_killswitch_state_path();

        // Ensure parent directory exists
        if let Some(parent) = state_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create state directory: {}", e))?;
        }

        let config = self.state.get_config();
        let backend = self.state.backend();

        let state_content = format!(
            "backend={}\nserver_ip={}\ntun_interface={}\nsingbox_path={}\n",
            backend,
            config.as_ref().map(|c| c.server_ip.as_str()).unwrap_or(""),
            config.as_ref().map(|c| c.tun_interface.as_str()).unwrap_or("zen-tun"),
            config.as_ref().map(|c| c.singbox_path.to_string_lossy().to_string()).unwrap_or_default()
        );

        std::fs::write(&state_path, state_content)
            .map_err(|e| format!("Failed to write state file: {}", e))
    }

    /// Remove the kill switch state file
    fn remove_state_file(&self) -> Result<(), String> {
        let state_path = get_killswitch_state_path();
        if state_path.exists() {
            std::fs::remove_file(&state_path)
                .map_err(|e| format!("Failed to remove state file: {}", e))?;
        }
        Ok(())
    }

    /// Check if ZenVPN firewall rules exist
    pub fn check_rules_active(&self) -> bool {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        // Check if the block rule exists
        let output = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", &format!("name={}", Self::RULE_BLOCK_OUT)])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // If the rule exists, netsh will show its details
                stdout.contains(Self::RULE_BLOCK_OUT)
            }
            Err(_) => false,
        }
    }

    /// Recover from a crash by cleaning up stale rules
    ///
    /// This should be called on application startup to ensure
    /// no stale firewall rules are left from a previous crash.
    pub fn recover_from_crash(&self) -> Result<KillSwitchResult, String> {
        let state_path = get_killswitch_state_path();

        // Check if state file exists (indicates a crash)
        if state_path.exists() {
            // Clean up any existing rules
            let result = self.disable();
            if result.is_ok() {
                return Ok(KillSwitchResult::ok(
                    "Recovered from previous crash - firewall rules cleaned up",
                ));
            }
            return result;
        }

        // Also check if rules exist without state file (edge case)
        if self.check_rules_active() {
            let result = self.disable();
            if result.is_ok() {
                return Ok(KillSwitchResult::ok("Cleaned up orphaned firewall rules"));
            }
            return result;
        }

        Ok(KillSwitchResult::ok("No recovery needed"))
    }
}

#[cfg(target_os = "windows")]
impl Default for WindowsKillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
impl KillSwitch for WindowsKillSwitch {
    fn enable(&self, config: &KillSwitchConfig) -> Result<KillSwitchResult, String> {
        match self.state.backend() {
            FirewallBackend::Netsh => self.enable_netsh(config),
            _ => Err("No firewall backend available on Windows".to_string()),
        }
    }

    fn disable(&self) -> Result<KillSwitchResult, String> {
        match self.state.backend() {
            FirewallBackend::Netsh => self.disable_netsh(),
            _ => Err("No firewall backend available on Windows".to_string()),
        }
    }

    fn is_enabled(&self) -> bool {
        self.state.is_enabled()
    }

    fn check_availability(&self) -> Result<String, String> {
        match self.state.backend() {
            FirewallBackend::Netsh => Ok("netsh".to_string()),
            _ => Err("netsh not available".to_string()),
        }
    }
}

/// Create the platform-specific kill switch implementation
pub fn create_killswitch() -> Box<dyn KillSwitch> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxKillSwitch::new())
    }

    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsKillSwitch::new())
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(MacOSKillSwitch::new())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Box::new(NoOpKillSwitch::new())
    }
}

// ─── macOS Kill Switch (pf - Packet Filter) ────────────────────────────────

#[cfg(target_os = "macos")]
pub struct MacOSKillSwitch {
    state: KillSwitchState,
}

#[cfg(target_os = "macos")]
impl MacOSKillSwitch {
    /// Anchor name used in pf rules
    const PF_ANCHOR: &'static str = "com.zen.vpn";

    pub fn new() -> Self {
        Self {
            state: KillSwitchState::default(),
        }
    }

    pub fn with_backend(backend: FirewallBackend) -> Self {
        Self {
            state: KillSwitchState::new(backend),
        }
    }

    /// Execute a shell command
    fn run_command(&self, cmd: &str) -> Result<std::process::Output, String> {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .map_err(|e| format!("Failed to execute command: {}", e))
    }

    /// Execute a command with privilege elevation via sudo (uses Keychain password on macOS)
    fn run_privileged_command(&self, cmd: &str) -> Result<std::process::Output, String> {
        crate::sudo::sudo_exec(&["sh", "-c", cmd])
    }

    /// Resolve a hostname to IP addresses
    fn resolve_hostname(&self, hostname: &str) -> Vec<String> {
        use std::net::ToSocketAddrs;

        if hostname.parse::<std::net::IpAddr>().is_ok() {
            return vec![hostname.to_string()];
        }

        let addr_with_port = format!("{}:443", hostname);
        match addr_with_port.to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<String> = addrs.map(|addr| addr.ip().to_string()).collect();
                if ips.is_empty() {
                    vec![hostname.to_string()]
                } else {
                    ips
                }
            }
            Err(_) => vec![hostname.to_string()],
        }
    }

    /// Get path to the pf anchor conf file
    fn get_pf_conf_path() -> std::path::PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("zen-vpn")
            .join("pf-killswitch.conf")
    }

    /// Enable kill switch using pf
    fn enable_pf(&self, config: &KillSwitchConfig) -> Result<KillSwitchResult, String> {
        let server_host = &config.server_ip;
        let tun_iface = &config.tun_interface;
        let resolved_ips = self.resolve_hostname(server_host);

        // Build pf rules for the anchor
        let mut server_pass_rules = String::new();
        for ip in &resolved_ips {
            server_pass_rules.push_str(&format!("pass out quick on ! {} proto {{ tcp, udp }} from any to {} no state\n", tun_iface, ip));
            server_pass_rules.push_str(&format!("pass in quick on ! {} proto {{ tcp, udp }} from {} to any no state\n", tun_iface, ip));
        }

        let pf_rules = format!(
            r#"# Zen Privacy Kill Switch rules
# Block all traffic except through VPN tunnel

# Allow loopback
pass quick on lo0 all

# Allow traffic through VPN tunnel interface
pass quick on {tun_iface} all

# Allow traffic to VPN server
{server_pass_rules}

# Allow DHCP
pass out quick proto udp from any to any port 67
pass in quick proto udp from any port 67 to any

# Allow DNS to configured DNS servers (fallback)
pass out quick proto {{ tcp, udp }} from any to {dns1} port 53
pass out quick proto {{ tcp, udp }} from any to {dns2} port 53

# Block everything else
block drop out all
block drop in all
"#,
            tun_iface = tun_iface,
            server_pass_rules = server_pass_rules,
            dns1 = DNS_PRIMARY,
            dns2 = DNS_SECONDARY
        );

        // Write pf rules to config file
        let pf_conf_path = Self::get_pf_conf_path();
        if let Some(parent) = pf_conf_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config dir: {}", e))?;
        }
        std::fs::write(&pf_conf_path, &pf_rules)
            .map_err(|e| format!("Failed to write pf config: {}", e))?;

        // Load the anchor rules and enable pf
        let cmd = format!(
            "pfctl -a '{}' -f '{}' && pfctl -e 2>/dev/null; true",
            Self::PF_ANCHOR,
            pf_conf_path.to_string_lossy()
        );

        let output = self.run_privileged_command(&cmd)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // pfctl -e returns 1 if already enabled, that's fine
            if !stderr.contains("already enabled") && !stderr.is_empty() {
                return Err(format!("Failed to enable pf kill switch: {}", stderr));
            }
        }

        self.state.set_config(Some(config.clone()));
        self.state.set_enabled(true);

        if let Err(e) = self.save_state_file() {
            eprintln!("Warning: Failed to save kill switch state: {}", e);
        }

        let ips_str = resolved_ips.join(", ");
        Ok(KillSwitchResult::ok(format!(
            "pf kill switch enabled (server: {} -> [{}], interface: {})",
            server_host, ips_str, tun_iface
        )))
    }

    /// Disable kill switch using pf
    fn disable_pf(&self) -> Result<KillSwitchResult, String> {
        // Flush the anchor rules
        let cmd = format!(
            "pfctl -a '{}' -F all 2>/dev/null; true",
            Self::PF_ANCHOR
        );

        let _ = self.run_privileged_command(&cmd);

        // Remove the pf conf file
        let pf_conf_path = Self::get_pf_conf_path();
        let _ = std::fs::remove_file(&pf_conf_path);

        self.state.set_config(None);
        self.state.set_enabled(false);

        let _ = self.remove_state_file();

        Ok(KillSwitchResult::ok("pf kill switch disabled"))
    }

    /// Save state file for crash recovery
    fn save_state_file(&self) -> Result<(), String> {
        let state_path = get_killswitch_state_path();

        if let Some(parent) = state_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create state directory: {}", e))?;
        }

        let config = self.state.get_config();
        let backend = self.state.backend();

        let state_content = format!(
            "backend={}\nserver_ip={}\ntun_interface={}\n",
            backend,
            config.as_ref().map(|c| c.server_ip.as_str()).unwrap_or(""),
            config.as_ref().map(|c| c.tun_interface.as_str()).unwrap_or("zen-tun")
        );

        std::fs::write(&state_path, state_content)
            .map_err(|e| format!("Failed to write state file: {}", e))
    }

    /// Remove the kill switch state file
    fn remove_state_file(&self) -> Result<(), String> {
        let state_path = get_killswitch_state_path();
        if state_path.exists() {
            std::fs::remove_file(&state_path)
                .map_err(|e| format!("Failed to remove state file: {}", e))?;
        }
        Ok(())
    }

    /// Check if kill switch rules are currently active
    pub fn check_rules_active(&self) -> bool {
        let cmd = format!("pfctl -a '{}' -s rules 2>/dev/null", Self::PF_ANCHOR);
        self.run_command(&cmd)
            .map(|output| output.status.success() && !output.stdout.is_empty())
            .unwrap_or(false)
    }
}

#[cfg(target_os = "macos")]
impl Default for MacOSKillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl KillSwitch for MacOSKillSwitch {
    fn enable(&self, config: &KillSwitchConfig) -> Result<KillSwitchResult, String> {
        match self.state.backend() {
            FirewallBackend::Pf => self.enable_pf(config),
            _ => Err("No firewall backend available on macOS".to_string()),
        }
    }

    fn disable(&self) -> Result<KillSwitchResult, String> {
        match self.state.backend() {
            FirewallBackend::Pf => self.disable_pf(),
            _ => Err("No firewall backend available on macOS".to_string()),
        }
    }

    fn is_enabled(&self) -> bool {
        self.state.is_enabled()
    }

    fn check_availability(&self) -> Result<String, String> {
        match self.state.backend() {
            FirewallBackend::Pf => Ok("pf".to_string()),
            _ => Err("pf not available".to_string()),
        }
    }
}

/// No-op kill switch for unsupported platforms
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub struct NoOpKillSwitch;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
impl NoOpKillSwitch {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
impl KillSwitch for NoOpKillSwitch {
    fn enable(&self, _config: &KillSwitchConfig) -> Result<KillSwitchResult, String> {
        Err("Kill switch not supported on this platform".to_string())
    }

    fn disable(&self) -> Result<KillSwitchResult, String> {
        Ok(KillSwitchResult::ok("Kill switch not active"))
    }

    fn is_enabled(&self) -> bool {
        false
    }

    fn check_availability(&self) -> Result<String, String> {
        Err("Kill switch not supported on this platform".to_string())
    }
}

/// Get the path to the kill switch state file
///
/// This file is used to persist the kill switch state for crash recovery.
pub fn get_killswitch_state_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zen-vpn")
        .join("killswitch.state")
}

/// Persistent state structure for crash recovery
///
/// This is written to the state file when the kill switch is enabled
/// and read back during crash recovery to properly clean up rules.
#[derive(Debug, Clone, Default)]
pub struct KillSwitchPersistentState {
    /// The firewall backend that was used
    pub backend: FirewallBackend,
    /// The VPN server IP address
    pub server_ip: String,
    /// The TUN interface name
    pub tun_interface: String,
    /// The sing-box binary path (Windows only)
    pub singbox_path: Option<PathBuf>,
}

impl KillSwitchPersistentState {
    /// Parse the state file content into a persistent state struct
    ///
    /// The state file format is a simple key=value format:
    /// ```text
    /// backend=nftables
    /// server_ip=1.2.3.4
    /// tun_interface=zen-tun
    /// singbox_path=/path/to/singbox (optional)
    /// ```
    pub fn parse(content: &str) -> Option<Self> {
        let mut state = Self::default();
        let mut has_data = false;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                has_data = true;

                match key {
                    "backend" => {
                        state.backend = match value {
                            "nftables" => FirewallBackend::Nftables,
                            "iptables" => FirewallBackend::Iptables,
                            "netsh" => FirewallBackend::Netsh,
                            "pf" => FirewallBackend::Pf,
                            _ => FirewallBackend::None,
                        };
                    }
                    "server_ip" => {
                        state.server_ip = value.to_string();
                    }
                    "tun_interface" => {
                        state.tun_interface = value.to_string();
                    }
                    "singbox_path" => {
                        if !value.is_empty() {
                            state.singbox_path = Some(PathBuf::from(value));
                        }
                    }
                    _ => {} // Ignore unknown keys for forward compatibility
                }
            }
        }

        if has_data {
            Some(state)
        } else {
            None
        }
    }

    /// Serialize the state to a string for writing to file
    pub fn serialize(&self) -> String {
        let mut content = format!(
            "backend={}\nserver_ip={}\ntun_interface={}\n",
            self.backend,
            self.server_ip,
            self.tun_interface
        );

        if let Some(ref path) = self.singbox_path {
            content.push_str(&format!("singbox_path={}\n", path.display()));
        }

        content
    }

    /// Convert to KillSwitchConfig
    pub fn to_config(&self) -> KillSwitchConfig {
        KillSwitchConfig {
            server_ip: self.server_ip.clone(),
            tun_interface: self.tun_interface.clone(),
            singbox_path: self.singbox_path.clone().unwrap_or_default(),
        }
    }
}

/// Read and parse the kill switch state file
///
/// Returns Some(state) if the file exists and was parsed successfully,
/// None otherwise.
pub fn read_state_file() -> Option<KillSwitchPersistentState> {
    let state_path = get_killswitch_state_path();

    if !state_path.exists() {
        return None;
    }

    match std::fs::read_to_string(&state_path) {
        Ok(content) => KillSwitchPersistentState::parse(&content),
        Err(_) => None,
    }
}

/// Check if a state file exists (indicating a potential crash recovery scenario)
pub fn state_file_exists() -> bool {
    get_killswitch_state_path().exists()
}

/// Recover from a previous crash by cleaning up stale firewall rules
///
/// This function should be called on application startup. It checks for:
/// 1. A state file left from a previous session (indicates crash)
/// 2. Orphaned firewall rules without a state file (edge case)
///
/// In either case, it will clean up the firewall rules and remove the state file.
///
/// # Returns
///
/// - `Ok(Some(message))` if recovery was performed with a description
/// - `Ok(None)` if no recovery was needed
/// - `Err(message)` if recovery failed
pub fn recover_killswitch() -> Result<Option<String>, String> {
    let state_path = get_killswitch_state_path();

    // Check if state file exists (indicates previous crash)
    let state = read_state_file();

    // Create the appropriate kill switch based on platform
    #[cfg(target_os = "linux")]
    {
        let ks = LinuxKillSwitch::new();
        return recover_with_killswitch(&ks, state, &state_path);
    }

    #[cfg(target_os = "windows")]
    {
        let ks = WindowsKillSwitch::new();
        return recover_with_killswitch(&ks, state, &state_path);
    }

    #[cfg(target_os = "macos")]
    {
        let ks = MacOSKillSwitch::new();
        return recover_with_killswitch(&ks, state, &state_path);
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        // No recovery needed on unsupported platforms
        // Just clean up any stale state file
        if state_path.exists() {
            let _ = std::fs::remove_file(&state_path);
            return Ok(Some("Removed stale state file (platform not supported)".to_string()));
        }
        Ok(None)
    }
}

/// Helper function to perform recovery with a specific kill switch implementation
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
fn recover_with_killswitch<K: KillSwitch + 'static>(
    ks: &K,
    state: Option<KillSwitchPersistentState>,
    state_path: &PathBuf,
) -> Result<Option<String>, String> {
    // If state file exists, we need to recover
    if state.is_some() {
        // Disable the kill switch to clean up any rules
        match ks.disable() {
            Ok(result) => {
                // Clean up state file
                let _ = std::fs::remove_file(state_path);
                return Ok(Some(format!(
                    "Recovered from previous crash - {}",
                    result.message
                )));
            }
            Err(e) => {
                // Try to remove state file anyway
                let _ = std::fs::remove_file(state_path);
                return Err(format!("Recovery failed: {}", e));
            }
        }
    }

    // Check for orphaned rules without state file
    #[cfg(target_os = "linux")]
    {
        if let Some(linux_ks) = (ks as &dyn std::any::Any).downcast_ref::<LinuxKillSwitch>() {
            if linux_ks.check_rules_active() {
                match ks.disable() {
                    Ok(result) => {
                        return Ok(Some(format!(
                            "Cleaned up orphaned firewall rules - {}",
                            result.message
                        )));
                    }
                    Err(e) => {
                        return Err(format!("Failed to clean up orphaned rules: {}", e));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(windows_ks) = (ks as &dyn std::any::Any).downcast_ref::<WindowsKillSwitch>() {
            if windows_ks.check_rules_active() {
                match ks.disable() {
                    Ok(result) => {
                        return Ok(Some(format!(
                            "Cleaned up orphaned firewall rules - {}",
                            result.message
                        )));
                    }
                    Err(e) => {
                        return Err(format!("Failed to clean up orphaned rules: {}", e));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(macos_ks) = (ks as &dyn std::any::Any).downcast_ref::<MacOSKillSwitch>() {
            if macos_ks.check_rules_active() {
                match ks.disable() {
                    Ok(result) => {
                        return Ok(Some(format!(
                            "Cleaned up orphaned firewall rules - {}",
                            result.message
                        )));
                    }
                    Err(e) => {
                        return Err(format!("Failed to clean up orphaned rules: {}", e));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Clean up all kill switch state and rules
///
/// This is a more aggressive cleanup that will:
/// 1. Disable the kill switch on all available backends
/// 2. Remove the state file
///
/// Use this for complete cleanup, e.g., on application uninstall.
pub fn cleanup_killswitch() -> Result<KillSwitchResult, String> {
    let state_path = get_killswitch_state_path();

    // Create platform-specific kill switch and disable it
    #[cfg(target_os = "linux")]
    {
        let ks = LinuxKillSwitch::new();
        let result = ks.disable()?;
        let _ = std::fs::remove_file(&state_path);
        return Ok(result);
    }

    #[cfg(target_os = "windows")]
    {
        let ks = WindowsKillSwitch::new();
        let result = ks.disable()?;
        let _ = std::fs::remove_file(&state_path);
        return Ok(result);
    }

    #[cfg(target_os = "macos")]
    {
        let ks = MacOSKillSwitch::new();
        let result = ks.disable()?;
        let _ = std::fs::remove_file(&state_path);
        return Ok(result);
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = std::fs::remove_file(&state_path);
        Ok(KillSwitchResult::ok("Cleanup complete (no-op on this platform)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_killswitch_config_default() {
        let config = KillSwitchConfig::default();
        assert!(config.server_ip.is_empty());
        assert_eq!(config.tun_interface, "zen-tun");
        assert!(config.singbox_path.as_os_str().is_empty());
    }

    #[test]
    fn test_killswitch_result() {
        let ok_result = KillSwitchResult::ok("success");
        assert!(ok_result.success);
        assert_eq!(ok_result.message, "success");

        let err_result = KillSwitchResult::err("failed");
        assert!(!err_result.success);
        assert_eq!(err_result.message, "failed");
    }

    #[test]
    fn test_firewall_backend_display() {
        assert_eq!(FirewallBackend::Nftables.to_string(), "nftables");
        assert_eq!(FirewallBackend::Iptables.to_string(), "iptables");
        assert_eq!(FirewallBackend::Netsh.to_string(), "netsh");
        assert_eq!(FirewallBackend::Pf.to_string(), "pf");
        assert_eq!(FirewallBackend::None.to_string(), "none");
    }

    #[test]
    fn test_killswitch_state() {
        let state = KillSwitchState::new(FirewallBackend::Nftables);
        assert!(!state.is_enabled());
        assert_eq!(state.backend(), FirewallBackend::Nftables);

        state.set_enabled(true);
        assert!(state.is_enabled());

        let config = KillSwitchConfig {
            server_ip: "1.2.3.4".to_string(),
            tun_interface: "zen-tun".to_string(),
            singbox_path: PathBuf::from("/usr/bin/sing-box"),
        };
        state.set_config(Some(config.clone()));

        let retrieved = state.get_config();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().server_ip, "1.2.3.4");
    }

    #[test]
    fn test_detect_firewall_backend() {
        // This test just ensures the function doesn't panic
        let backend = detect_firewall_backend();
        // On CI/test environments, we might not have firewall tools
        // Just verify we get a valid variant
        match backend {
            FirewallBackend::Nftables
            | FirewallBackend::Iptables
            | FirewallBackend::Netsh
            | FirewallBackend::Pf
            | FirewallBackend::None => {}
        }
    }

    #[test]
    fn test_firewall_backend_default() {
        let backend = FirewallBackend::default();
        assert_eq!(backend, FirewallBackend::None);
    }

    #[test]
    fn test_persistent_state_parse_nftables() {
        let content = "backend=nftables\nserver_ip=1.2.3.4\ntun_interface=zen-tun\n";
        let state = KillSwitchPersistentState::parse(content);

        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.backend, FirewallBackend::Nftables);
        assert_eq!(state.server_ip, "1.2.3.4");
        assert_eq!(state.tun_interface, "zen-tun");
        assert!(state.singbox_path.is_none());
    }

    #[test]
    fn test_persistent_state_parse_iptables() {
        let content = "backend=iptables\nserver_ip=10.0.0.1\ntun_interface=tun0\n";
        let state = KillSwitchPersistentState::parse(content);

        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.backend, FirewallBackend::Iptables);
        assert_eq!(state.server_ip, "10.0.0.1");
        assert_eq!(state.tun_interface, "tun0");
    }

    #[test]
    fn test_persistent_state_parse_netsh() {
        let content = "backend=netsh\nserver_ip=192.168.1.1\ntun_interface=zen-tun\nsingbox_path=C:\\Program Files\\sing-box\\sing-box.exe\n";
        let state = KillSwitchPersistentState::parse(content);

        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.backend, FirewallBackend::Netsh);
        assert_eq!(state.server_ip, "192.168.1.1");
        assert_eq!(state.tun_interface, "zen-tun");
        assert!(state.singbox_path.is_some());
        assert_eq!(
            state.singbox_path.unwrap().to_string_lossy(),
            "C:\\Program Files\\sing-box\\sing-box.exe"
        );
    }

    #[test]
    fn test_persistent_state_parse_empty() {
        let content = "";
        let state = KillSwitchPersistentState::parse(content);
        assert!(state.is_none());
    }

    #[test]
    fn test_persistent_state_parse_whitespace() {
        let content = "  \n  \n  ";
        let state = KillSwitchPersistentState::parse(content);
        assert!(state.is_none());
    }

    #[test]
    fn test_persistent_state_parse_comments() {
        let content = "# This is a comment\nbackend=nftables\n# Another comment\nserver_ip=8.8.8.8\ntun_interface=zen-tun\n";
        let state = KillSwitchPersistentState::parse(content);

        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.backend, FirewallBackend::Nftables);
        assert_eq!(state.server_ip, "8.8.8.8");
    }

    #[test]
    fn test_persistent_state_parse_unknown_keys() {
        // Unknown keys should be ignored for forward compatibility
        let content = "backend=nftables\nserver_ip=1.2.3.4\ntun_interface=zen-tun\nunknown_key=some_value\nfuture_feature=enabled\n";
        let state = KillSwitchPersistentState::parse(content);

        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.backend, FirewallBackend::Nftables);
        assert_eq!(state.server_ip, "1.2.3.4");
    }

    #[test]
    fn test_persistent_state_parse_unknown_backend() {
        let content = "backend=unknown_backend\nserver_ip=1.2.3.4\ntun_interface=zen-tun\n";
        let state = KillSwitchPersistentState::parse(content);

        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.backend, FirewallBackend::None);
    }

    #[test]
    fn test_persistent_state_serialize() {
        let state = KillSwitchPersistentState {
            backend: FirewallBackend::Nftables,
            server_ip: "1.2.3.4".to_string(),
            tun_interface: "zen-tun".to_string(),
            singbox_path: None,
        };

        let serialized = state.serialize();
        assert!(serialized.contains("backend=nftables"));
        assert!(serialized.contains("server_ip=1.2.3.4"));
        assert!(serialized.contains("tun_interface=zen-tun"));
        assert!(!serialized.contains("singbox_path="));
    }

    #[test]
    fn test_persistent_state_serialize_with_path() {
        let state = KillSwitchPersistentState {
            backend: FirewallBackend::Netsh,
            server_ip: "192.168.1.1".to_string(),
            tun_interface: "zen-tun".to_string(),
            singbox_path: Some(PathBuf::from("/usr/bin/sing-box")),
        };

        let serialized = state.serialize();
        assert!(serialized.contains("backend=netsh"));
        assert!(serialized.contains("singbox_path=/usr/bin/sing-box"));
    }

    #[test]
    fn test_persistent_state_roundtrip() {
        // Test that serialize -> parse produces equivalent state
        let original = KillSwitchPersistentState {
            backend: FirewallBackend::Iptables,
            server_ip: "10.0.0.1".to_string(),
            tun_interface: "tun0".to_string(),
            singbox_path: Some(PathBuf::from("/opt/sing-box")),
        };

        let serialized = original.serialize();
        let parsed = KillSwitchPersistentState::parse(&serialized);

        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.backend, original.backend);
        assert_eq!(parsed.server_ip, original.server_ip);
        assert_eq!(parsed.tun_interface, original.tun_interface);
        assert_eq!(parsed.singbox_path, original.singbox_path);
    }

    #[test]
    fn test_persistent_state_to_config() {
        let state = KillSwitchPersistentState {
            backend: FirewallBackend::Nftables,
            server_ip: "1.2.3.4".to_string(),
            tun_interface: "zen-tun".to_string(),
            singbox_path: Some(PathBuf::from("/usr/bin/sing-box")),
        };

        let config = state.to_config();
        assert_eq!(config.server_ip, "1.2.3.4");
        assert_eq!(config.tun_interface, "zen-tun");
        assert_eq!(config.singbox_path, PathBuf::from("/usr/bin/sing-box"));
    }

    #[test]
    fn test_persistent_state_to_config_no_path() {
        let state = KillSwitchPersistentState {
            backend: FirewallBackend::Nftables,
            server_ip: "1.2.3.4".to_string(),
            tun_interface: "zen-tun".to_string(),
            singbox_path: None,
        };

        let config = state.to_config();
        assert_eq!(config.singbox_path, PathBuf::new());
    }

    #[test]
    fn test_killswitch_state_path() {
        let path = get_killswitch_state_path();
        // Should end with killswitch.state
        assert!(path.file_name().is_some());
        assert_eq!(path.file_name().unwrap(), "killswitch.state");
        // Should be in zen-vpn directory
        assert!(path.parent().is_some());
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "zen-vpn");
    }

    #[test]
    fn test_persistent_state_default() {
        let state = KillSwitchPersistentState::default();
        assert_eq!(state.backend, FirewallBackend::None);
        assert!(state.server_ip.is_empty());
        assert!(state.tun_interface.is_empty());
        assert!(state.singbox_path.is_none());
    }
}
