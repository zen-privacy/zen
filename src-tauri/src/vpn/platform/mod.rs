//! Platform-specific VPN operations
//!
//! Each platform module implements the same set of functions for:
//! - Detecting the physical network interface
//! - Starting sing-box with appropriate privilege escalation
//! - Stopping sing-box with graceful shutdown
//! - Synchronous shutdown (for tray/window close handlers)
//! - DNS backup and restore
//! - Privilege escalation (elevated commands)

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(target_os = "windows")]
pub use windows::*;
