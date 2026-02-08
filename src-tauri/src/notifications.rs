//! VPN event notification system for emitting connection state changes to the frontend
//!
//! This module provides a unified way to emit VPN-related events to the Tauri frontend,
//! enabling the UI to react to connection state changes in real-time.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

/// VPN connection state events
///
/// These events are emitted to the frontend to notify about VPN connection state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum VpnEvent {
    /// VPN connection established successfully
    Connected {
        /// Name of the connected profile
        profile_name: String,
        /// Server address
        server: String,
    },
    /// VPN connection terminated
    Disconnected {
        /// Reason for disconnection (if known)
        reason: Option<String>,
    },
    /// VPN connection error occurred
    Error {
        /// Error message describing what went wrong
        message: String,
        /// Error code (if available)
        code: Option<String>,
    },
    /// VPN is attempting to reconnect
    Reconnecting {
        /// Current attempt number
        attempt: u32,
        /// Maximum number of attempts
        max_attempts: u32,
    },
    /// Kill switch state changed (auto-enabled or disabled)
    KillSwitchChanged {
        /// Whether the kill switch is now enabled
        enabled: bool,
    },
}

impl VpnEvent {
    /// Create a Connected event
    pub fn connected(profile_name: impl Into<String>, server: impl Into<String>) -> Self {
        VpnEvent::Connected {
            profile_name: profile_name.into(),
            server: server.into(),
        }
    }

    /// Create a Disconnected event
    pub fn disconnected(reason: Option<String>) -> Self {
        VpnEvent::Disconnected { reason }
    }

    /// Create an Error event
    pub fn error(message: impl Into<String>, code: Option<String>) -> Self {
        VpnEvent::Error {
            message: message.into(),
            code,
        }
    }

    /// Create a Reconnecting event
    pub fn reconnecting(attempt: u32, max_attempts: u32) -> Self {
        VpnEvent::Reconnecting {
            attempt,
            max_attempts,
        }
    }

    /// Create a KillSwitchChanged event
    pub fn killswitch_changed(enabled: bool) -> Self {
        VpnEvent::KillSwitchChanged { enabled }
    }

    /// Get the event type as a string for logging purposes
    pub fn event_type(&self) -> &'static str {
        match self {
            VpnEvent::Connected { .. } => "connected",
            VpnEvent::Disconnected { .. } => "disconnected",
            VpnEvent::Error { .. } => "error",
            VpnEvent::Reconnecting { .. } => "reconnecting",
            VpnEvent::KillSwitchChanged { .. } => "killswitch_changed",
        }
    }
}

/// Event name used for VPN events on the frontend
const VPN_EVENT_NAME: &str = "vpn-event";

/// Emit a VPN event to the frontend
///
/// This function sends a VPN event to all listening frontend windows.
/// The event can be listened to in the frontend using Tauri's event system.
///
/// # Arguments
///
/// * `app` - The Tauri application handle
/// * `event` - The VPN event to emit
///
/// # Example
///
/// ```rust,ignore
/// use notifications::{emit_vpn_event, VpnEvent};
///
/// // Emit a connected event
/// emit_vpn_event(&app_handle, VpnEvent::connected("My Profile", "server.example.com"));
///
/// // Emit an error event
/// emit_vpn_event(&app_handle, VpnEvent::error("Connection timeout", Some("E001".to_string())));
/// ```
pub fn emit_vpn_event(app: &AppHandle, event: VpnEvent) {
    if let Err(e) = app.emit(VPN_EVENT_NAME, &event) {
        eprintln!(
            "Failed to emit VPN event '{}': {}",
            event.event_type(),
            e
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vpn_event_connected() {
        let event = VpnEvent::connected("Test Profile", "test.server.com");
        match event {
            VpnEvent::Connected { profile_name, server } => {
                assert_eq!(profile_name, "Test Profile");
                assert_eq!(server, "test.server.com");
            }
            _ => panic!("Expected Connected event"),
        }
    }

    #[test]
    fn test_vpn_event_disconnected() {
        let event = VpnEvent::disconnected(Some("User requested".to_string()));
        match event {
            VpnEvent::Disconnected { reason } => {
                assert_eq!(reason, Some("User requested".to_string()));
            }
            _ => panic!("Expected Disconnected event"),
        }

        let event_no_reason = VpnEvent::disconnected(None);
        match event_no_reason {
            VpnEvent::Disconnected { reason } => {
                assert_eq!(reason, None);
            }
            _ => panic!("Expected Disconnected event"),
        }
    }

    #[test]
    fn test_vpn_event_error() {
        let event = VpnEvent::error("Connection failed", Some("E001".to_string()));
        match event {
            VpnEvent::Error { message, code } => {
                assert_eq!(message, "Connection failed");
                assert_eq!(code, Some("E001".to_string()));
            }
            _ => panic!("Expected Error event"),
        }
    }

    #[test]
    fn test_vpn_event_reconnecting() {
        let event = VpnEvent::reconnecting(2, 5);
        match event {
            VpnEvent::Reconnecting { attempt, max_attempts } => {
                assert_eq!(attempt, 2);
                assert_eq!(max_attempts, 5);
            }
            _ => panic!("Expected Reconnecting event"),
        }
    }

    #[test]
    fn test_event_type() {
        assert_eq!(VpnEvent::connected("", "").event_type(), "connected");
        assert_eq!(VpnEvent::disconnected(None).event_type(), "disconnected");
        assert_eq!(VpnEvent::error("", None).event_type(), "error");
        assert_eq!(VpnEvent::reconnecting(0, 0).event_type(), "reconnecting");
    }

    #[test]
    fn test_serialization() {
        let event = VpnEvent::connected("Profile", "server.com");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("Connected"));
        assert!(json.contains("Profile"));
        assert!(json.contains("server.com"));
    }
}
