//! VPN Manager - Lifecycle, Health Monitoring, and Auto-Reconnect
//!
//! This module provides the VpnManager struct which coordinates all VPN-related
//! functionality including:
//! - VPN connection lifecycle management
//! - Auto-reconnection with exponential backoff
//! - Health monitoring via periodic ping checks
//! - Graceful shutdown with proper cleanup

// Allow unused code for infrastructure that may be used in future features
#![allow(dead_code)]

//! ## Auto-Reconnect
//!
//! When enabled, the VPN manager will automatically attempt to reconnect if
//! the connection drops unexpectedly. It uses exponential backoff:
//! - Initial delay: 1 second
//! - Multiplier: 2x
//! - Maximum delay: 30 seconds
//! - Maximum retries: 5
//!
//! ## Health Monitoring
//!
//! The manager can periodically check if the sing-box process is still running
//! and optionally perform ping checks to verify connectivity.
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use vpn::manager::{VpnManager, ReconnectConfig};
//! use std::sync::Arc;
//!
//! // Create manager with auto-reconnect enabled
//! let manager = Arc::new(VpnManager::with_reconnect_config(
//!     ReconnectConfig::with_enabled(true)
//! ));
//!
//! // Use the retry helper for reconnection
//! let result = manager.retry_connection(|| async {
//!     // Your connection logic here
//!     Ok(())
//! }).await;
//! ```

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};

use super::VlessConfig;

/// Default initial delay for reconnection (in milliseconds)
const DEFAULT_INITIAL_DELAY_MS: u64 = 1000;

/// Default maximum delay for reconnection (in milliseconds)
const DEFAULT_MAX_DELAY_MS: u64 = 30000;

/// Default backoff multiplier
const DEFAULT_BACKOFF_MULTIPLIER: f64 = 2.0;

/// Default maximum number of reconnect attempts
const DEFAULT_MAX_RETRIES: u32 = 5;

/// Default health check interval (in milliseconds)
const DEFAULT_HEALTH_CHECK_INTERVAL_MS: u64 = 10000;

/// VPN connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected and not attempting to connect
    Disconnected,
    /// Currently attempting to connect
    Connecting,
    /// Successfully connected
    Connected,
    /// Disconnected unexpectedly, attempting to reconnect
    Reconnecting,
    /// Disconnecting (graceful shutdown in progress)
    Disconnecting,
    /// Failed to connect after all retries exhausted
    Failed,
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Disconnected
    }
}

impl ConnectionState {
    /// Get a human-readable string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionState::Disconnected => "disconnected",
            ConnectionState::Connecting => "connecting",
            ConnectionState::Connected => "connected",
            ConnectionState::Reconnecting => "reconnecting",
            ConnectionState::Disconnecting => "disconnecting",
            ConnectionState::Failed => "failed",
        }
    }
}

/// Configuration for auto-reconnect behavior
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Whether auto-reconnect is enabled
    pub enabled: bool,
    /// Initial delay before first reconnect attempt (in milliseconds)
    pub initial_delay_ms: u64,
    /// Maximum delay between reconnect attempts (in milliseconds)
    pub max_delay_ms: u64,
    /// Backoff multiplier (delay = delay * multiplier after each attempt)
    pub backoff_multiplier: f64,
    /// Maximum number of reconnect attempts before giving up
    pub max_retries: u32,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            initial_delay_ms: DEFAULT_INITIAL_DELAY_MS,
            max_delay_ms: DEFAULT_MAX_DELAY_MS,
            backoff_multiplier: DEFAULT_BACKOFF_MULTIPLIER,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }
}

impl ReconnectConfig {
    /// Create a new reconnect config with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a reconnect config with auto-reconnect enabled
    pub fn with_enabled(enabled: bool) -> Self {
        Self {
            enabled,
            ..Default::default()
        }
    }

    /// Builder method to set initial delay
    pub fn initial_delay(mut self, delay_ms: u64) -> Self {
        self.initial_delay_ms = delay_ms;
        self
    }

    /// Builder method to set max delay
    pub fn max_delay(mut self, delay_ms: u64) -> Self {
        self.max_delay_ms = delay_ms;
        self
    }

    /// Builder method to set backoff multiplier
    pub fn multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Builder method to set max retries
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Calculate the delay for a given retry attempt (0-indexed)
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::from_millis(self.initial_delay_ms);
        }

        let delay_ms = self.initial_delay_ms as f64
            * self.backoff_multiplier.powi(attempt as i32);
        let capped_delay_ms = delay_ms.min(self.max_delay_ms as f64) as u64;

        Duration::from_millis(capped_delay_ms)
    }

    /// Create a backon ExponentialBuilder from this configuration
    ///
    /// This creates a backoff strategy compatible with the backon library's
    /// retry mechanism. The builder is configured with:
    /// - Initial delay from `initial_delay_ms`
    /// - Maximum delay from `max_delay_ms`
    /// - Backoff factor from `backoff_multiplier`
    /// - Maximum retries from `max_retries`
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use backon::Retryable;
    ///
    /// let config = ReconnectConfig::with_enabled(true);
    /// let backoff = config.to_backoff_builder();
    ///
    /// // Use with backon's retry mechanism
    /// let result = my_async_fn.retry(backoff).await;
    /// ```
    pub fn to_backoff_builder(&self) -> ExponentialBuilder {
        ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(self.initial_delay_ms))
            .with_max_delay(Duration::from_millis(self.max_delay_ms))
            .with_factor(self.backoff_multiplier as f32)
            .with_max_times(self.max_retries as usize)
    }
}

/// Configuration for health monitoring
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Whether health checks are enabled
    pub enabled: bool,
    /// Interval between health checks (in milliseconds)
    pub interval_ms: u64,
    /// Whether to perform ping checks (in addition to process checks)
    pub ping_check: bool,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: DEFAULT_HEALTH_CHECK_INTERVAL_MS,
            ping_check: false,
        }
    }
}

impl HealthCheckConfig {
    /// Create a new health check config with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder method to enable/disable health checks
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Builder method to set check interval
    pub fn interval(mut self, interval_ms: u64) -> Self {
        self.interval_ms = interval_ms;
        self
    }

    /// Builder method to enable/disable ping checks
    pub fn with_ping_check(mut self, enabled: bool) -> Self {
        self.ping_check = enabled;
        self
    }
}

/// Internal state for reconnection attempts
#[derive(Debug, Default)]
struct ReconnectState {
    /// Current number of reconnect attempts
    attempt_count: AtomicU32,
    /// Whether a reconnection is currently in progress
    in_progress: AtomicBool,
}

impl ReconnectState {
    fn new() -> Self {
        Self::default()
    }

    /// Get the current attempt count
    fn attempts(&self) -> u32 {
        self.attempt_count.load(Ordering::SeqCst)
    }

    /// Increment the attempt count and return the new value
    fn increment_attempts(&self) -> u32 {
        self.attempt_count.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Reset the attempt count to zero
    fn reset_attempts(&self) {
        self.attempt_count.store(0, Ordering::SeqCst);
    }

    /// Check if a reconnection is in progress
    fn is_in_progress(&self) -> bool {
        self.in_progress.load(Ordering::SeqCst)
    }

    /// Set the reconnection in progress state
    fn set_in_progress(&self, in_progress: bool) {
        self.in_progress.store(in_progress, Ordering::SeqCst);
    }
}

/// VPN Manager - Central coordinator for VPN lifecycle
///
/// The VpnManager is responsible for:
/// - Managing VPN connection state
/// - Storing the current VPN configuration
/// - Handling auto-reconnection with exponential backoff
/// - Health monitoring of the sing-box process
/// - Graceful shutdown coordination
///
/// # Example
///
/// ```ignore
/// use vpn::manager::VpnManager;
///
/// // Create a new manager with default settings
/// let manager = VpnManager::new();
///
/// // Enable auto-reconnect
/// manager.set_auto_reconnect(true);
///
/// // Connect to VPN (config handling done elsewhere)
/// manager.set_state(ConnectionState::Connecting);
/// ```
pub struct VpnManager {
    /// Current connection state
    state: RwLock<ConnectionState>,

    /// Current VPN configuration (if any)
    config: RwLock<Option<VlessConfig>>,

    /// Auto-reconnect configuration
    reconnect_config: RwLock<ReconnectConfig>,

    /// Health check configuration
    health_config: RwLock<HealthCheckConfig>,

    /// Internal reconnection state
    reconnect_state: ReconnectState,

    /// Whether kill switch should be enabled on connect
    kill_switch_enabled: AtomicBool,

    /// Flag to signal shutdown
    shutdown_requested: AtomicBool,
}

impl Default for VpnManager {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnManager {
    /// Create a new VPN manager with default settings
    pub fn new() -> Self {
        Self {
            state: RwLock::new(ConnectionState::Disconnected),
            config: RwLock::new(None),
            reconnect_config: RwLock::new(ReconnectConfig::default()),
            health_config: RwLock::new(HealthCheckConfig::default()),
            reconnect_state: ReconnectState::new(),
            kill_switch_enabled: AtomicBool::new(false),
            shutdown_requested: AtomicBool::new(false),
        }
    }

    /// Create a new VPN manager with custom reconnect configuration
    pub fn with_reconnect_config(reconnect_config: ReconnectConfig) -> Self {
        Self {
            state: RwLock::new(ConnectionState::Disconnected),
            config: RwLock::new(None),
            reconnect_config: RwLock::new(reconnect_config),
            health_config: RwLock::new(HealthCheckConfig::default()),
            reconnect_state: ReconnectState::new(),
            kill_switch_enabled: AtomicBool::new(false),
            shutdown_requested: AtomicBool::new(false),
        }
    }

    // ==================== State Management ====================

    /// Get the current connection state
    pub fn state(&self) -> ConnectionState {
        *self.state.read().unwrap()
    }

    /// Set the connection state
    pub fn set_state(&self, new_state: ConnectionState) {
        let mut state = self.state.write().unwrap();
        *state = new_state;

        // Reset reconnect attempts on successful connection
        if new_state == ConnectionState::Connected {
            self.reconnect_state.reset_attempts();
            self.reconnect_state.set_in_progress(false);
        }
    }

    /// Check if currently connected
    pub fn is_connected(&self) -> bool {
        self.state() == ConnectionState::Connected
    }

    /// Check if currently connecting (including reconnecting)
    pub fn is_connecting(&self) -> bool {
        matches!(
            self.state(),
            ConnectionState::Connecting | ConnectionState::Reconnecting
        )
    }

    // ==================== Configuration Management ====================

    /// Get the current VPN configuration
    pub fn config(&self) -> Option<VlessConfig> {
        self.config.read().unwrap().clone()
    }

    /// Set the current VPN configuration
    pub fn set_config(&self, config: Option<VlessConfig>) {
        let mut cfg = self.config.write().unwrap();
        *cfg = config;
    }

    /// Store a new configuration for future connections
    pub fn store_config(&self, config: VlessConfig) {
        self.set_config(Some(config));
    }

    /// Clear the stored configuration
    pub fn clear_config(&self) {
        self.set_config(None);
    }

    // ==================== Reconnect Management ====================

    /// Get the current reconnect configuration
    pub fn reconnect_config(&self) -> ReconnectConfig {
        self.reconnect_config.read().unwrap().clone()
    }

    /// Set the reconnect configuration
    pub fn set_reconnect_config(&self, config: ReconnectConfig) {
        let mut cfg = self.reconnect_config.write().unwrap();
        *cfg = config;
    }

    /// Enable or disable auto-reconnect
    pub fn set_auto_reconnect(&self, enabled: bool) {
        let mut cfg = self.reconnect_config.write().unwrap();
        cfg.enabled = enabled;
    }

    /// Check if auto-reconnect is enabled
    pub fn is_auto_reconnect_enabled(&self) -> bool {
        self.reconnect_config.read().unwrap().enabled
    }

    /// Get the current reconnect attempt count
    pub fn reconnect_attempts(&self) -> u32 {
        self.reconnect_state.attempts()
    }

    /// Check if a reconnection is currently in progress
    pub fn is_reconnecting(&self) -> bool {
        self.reconnect_state.is_in_progress()
    }

    /// Prepare for a reconnection attempt
    ///
    /// Returns the delay to wait before the attempt, or None if max retries exceeded.
    pub fn prepare_reconnect(&self) -> Option<Duration> {
        let config = self.reconnect_config.read().unwrap();

        if !config.enabled {
            return None;
        }

        let current_attempt = self.reconnect_state.attempts();
        if current_attempt >= config.max_retries {
            return None;
        }

        self.reconnect_state.set_in_progress(true);
        let attempt = self.reconnect_state.increment_attempts();

        // Use attempt - 1 for delay calculation (0-indexed)
        Some(config.delay_for_attempt(attempt - 1))
    }

    /// Mark reconnection as complete (success or failure)
    pub fn finish_reconnect(&self, success: bool) {
        self.reconnect_state.set_in_progress(false);

        if success {
            self.reconnect_state.reset_attempts();
            self.set_state(ConnectionState::Connected);
        } else {
            let config = self.reconnect_config.read().unwrap();
            if self.reconnect_state.attempts() >= config.max_retries {
                self.set_state(ConnectionState::Failed);
            }
        }
    }

    /// Reset all reconnection state
    pub fn reset_reconnect(&self) {
        self.reconnect_state.reset_attempts();
        self.reconnect_state.set_in_progress(false);
    }

    // ==================== Auto-Reconnect with Backon ====================

    /// Get a backon ExponentialBuilder configured with current reconnect settings
    ///
    /// This creates a backoff strategy that can be used with backon's retry mechanism.
    /// The builder uses the exponential backoff settings from ReconnectConfig:
    /// - Initial delay: 1 second (default)
    /// - Maximum delay: 30 seconds (default)
    /// - Factor: 2x (default)
    /// - Max retries: 5 (default)
    pub fn get_backoff_builder(&self) -> ExponentialBuilder {
        self.reconnect_config.read().unwrap().to_backoff_builder()
    }

    /// Execute an async operation with automatic retry using exponential backoff
    ///
    /// This method wraps an async operation with backon's retry mechanism,
    /// using the configured exponential backoff settings. It automatically
    /// tracks reconnection attempts and updates the connection state.
    ///
    /// # Arguments
    ///
    /// * `operation` - An async closure that returns `Result<T, E>`
    ///
    /// # Returns
    ///
    /// Returns `Ok(T)` if the operation succeeds within the retry limit,
    /// or `Err(E)` with the last error if all retries are exhausted.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let manager = Arc::new(VpnManager::with_reconnect_config(
    ///     ReconnectConfig::with_enabled(true)
    /// ));
    ///
    /// let result = manager.retry_async(|| async {
    ///     // Your async connection logic
    ///     connect_to_vpn().await
    /// }).await;
    /// ```
    pub async fn retry_async<F, Fut, T, E>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        if !self.is_auto_reconnect_enabled() {
            return operation().await;
        }

        self.set_state(ConnectionState::Reconnecting);
        self.reconnect_state.set_in_progress(true);

        let backoff = self.get_backoff_builder();
        let max_retries = self.reconnect_config.read().unwrap().max_retries;
        let reconnect_state = &self.reconnect_state;

        let result = operation
            .retry(backoff)
            .notify(|_err: &E, _dur: Duration| {
                // Track the attempt
                reconnect_state.increment_attempts();
            })
            .await;

        self.reconnect_state.set_in_progress(false);

        match &result {
            Ok(_) => {
                self.reconnect_state.reset_attempts();
                self.set_state(ConnectionState::Connected);
            }
            Err(_) => {
                if self.reconnect_state.attempts() >= max_retries {
                    self.set_state(ConnectionState::Failed);
                }
            }
        }

        result
    }

    /// Execute an async operation with retry and a notification callback
    ///
    /// Similar to `retry_async`, but allows providing a custom notification callback
    /// that is called before each retry attempt. This is useful for emitting events
    /// to the frontend or logging retry progress.
    ///
    /// # Arguments
    ///
    /// * `operation` - An async closure that returns `Result<T, E>`
    /// * `on_retry` - A callback called before each retry with (attempt, max_attempts, duration)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use crate::notifications::{emit_vpn_event, VpnEvent};
    ///
    /// manager.retry_with_notify(
    ///     || async { connect_to_vpn().await },
    ///     |attempt, max, dur| {
    ///         emit_vpn_event(&app_handle, VpnEvent::reconnecting(attempt, max));
    ///     }
    /// ).await;
    /// ```
    pub async fn retry_with_notify<F, Fut, T, E, N>(
        &self,
        mut operation: F,
        mut on_retry: N,
    ) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        N: FnMut(u32, u32, Duration),
    {
        if !self.is_auto_reconnect_enabled() {
            return operation().await;
        }

        self.set_state(ConnectionState::Reconnecting);
        self.reconnect_state.set_in_progress(true);

        let backoff = self.get_backoff_builder();
        let max_retries = self.reconnect_config.read().unwrap().max_retries;
        let reconnect_state = &self.reconnect_state;

        let result = operation
            .retry(backoff)
            .notify(|_err: &E, dur: Duration| {
                // Track the attempt and notify
                let attempt = reconnect_state.increment_attempts();
                on_retry(attempt, max_retries, dur);
            })
            .await;

        self.reconnect_state.set_in_progress(false);

        match &result {
            Ok(_) => {
                self.reconnect_state.reset_attempts();
                self.set_state(ConnectionState::Connected);
            }
            Err(_) => {
                if self.reconnect_state.attempts() >= max_retries {
                    self.set_state(ConnectionState::Failed);
                }
            }
        }

        result
    }

    /// Check if reconnection should be attempted based on current state
    ///
    /// Returns true if:
    /// - Auto-reconnect is enabled
    /// - Not currently reconnecting
    /// - Maximum retries not yet exceeded
    /// - Not in a shutdown state
    pub fn should_attempt_reconnect(&self) -> bool {
        if !self.is_auto_reconnect_enabled() {
            return false;
        }

        if self.is_shutdown_requested() {
            return false;
        }

        if self.is_reconnecting() {
            return false;
        }

        let config = self.reconnect_config.read().unwrap();
        self.reconnect_state.attempts() < config.max_retries
    }

    /// Get remaining reconnect attempts
    ///
    /// Returns the number of reconnect attempts remaining before giving up.
    pub fn remaining_attempts(&self) -> u32 {
        let config = self.reconnect_config.read().unwrap();
        config.max_retries.saturating_sub(self.reconnect_state.attempts())
    }

    /// Get the delay for the next reconnect attempt
    ///
    /// Returns the duration to wait before the next reconnect attempt,
    /// or None if auto-reconnect is disabled or max retries exceeded.
    pub fn next_retry_delay(&self) -> Option<Duration> {
        if !self.is_auto_reconnect_enabled() {
            return None;
        }

        let config = self.reconnect_config.read().unwrap();
        let current_attempt = self.reconnect_state.attempts();

        if current_attempt >= config.max_retries {
            return None;
        }

        Some(config.delay_for_attempt(current_attempt))
    }

    // ==================== Health Check Management ====================

    /// Get the current health check configuration
    pub fn health_config(&self) -> HealthCheckConfig {
        self.health_config.read().unwrap().clone()
    }

    /// Set the health check configuration
    pub fn set_health_config(&self, config: HealthCheckConfig) {
        let mut cfg = self.health_config.write().unwrap();
        *cfg = config;
    }

    /// Enable or disable health checks
    pub fn set_health_check(&self, enabled: bool) {
        let mut cfg = self.health_config.write().unwrap();
        cfg.enabled = enabled;
    }

    /// Check if health checks are enabled
    pub fn is_health_check_enabled(&self) -> bool {
        self.health_config.read().unwrap().enabled
    }

    // ==================== Kill Switch Management ====================

    /// Check if kill switch should be enabled when connecting
    pub fn is_kill_switch_enabled(&self) -> bool {
        self.kill_switch_enabled.load(Ordering::SeqCst)
    }

    /// Enable or disable kill switch on connect
    pub fn set_kill_switch(&self, enabled: bool) {
        self.kill_switch_enabled.store(enabled, Ordering::SeqCst);
    }

    // ==================== Shutdown Management ====================

    /// Request a graceful shutdown
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
    }

    /// Check if shutdown has been requested
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Clear the shutdown request (e.g., after completing shutdown)
    pub fn clear_shutdown_request(&self) {
        self.shutdown_requested.store(false, Ordering::SeqCst);
    }

    /// Prepare for disconnection
    ///
    /// This method should be called before starting the disconnect process.
    /// It sets the state to Disconnecting and clears any pending reconnect.
    pub fn prepare_disconnect(&self) {
        self.set_state(ConnectionState::Disconnecting);
        self.reset_reconnect();
    }

    /// Complete the disconnection process
    ///
    /// This method should be called after the sing-box process has been stopped.
    /// It optionally clears the stored config.
    pub fn complete_disconnect(&self, clear_config: bool) {
        self.set_state(ConnectionState::Disconnected);
        self.reset_reconnect();

        if clear_config {
            self.clear_config();
        }

        self.clear_shutdown_request();
    }
}

// Ensure VpnManager is thread-safe
unsafe impl Send for VpnManager {}
unsafe impl Sync for VpnManager {}

/// Create a thread-safe reference to a VpnManager
///
/// This is a convenience function for creating an Arc-wrapped VpnManager
/// that can be shared across threads and used with Tauri's state management.
pub fn create_vpn_manager() -> Arc<VpnManager> {
    Arc::new(VpnManager::new())
}

// ==================== Health Monitoring ====================

/// Result of a health check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthCheckResult {
    /// VPN is healthy - process running and (optionally) ping successful
    Healthy {
        /// Latency in milliseconds if ping check was performed
        latency_ms: Option<u64>,
    },
    /// Process is not running (exited or crashed)
    ProcessNotRunning {
        /// Exit code if available
        exit_code: Option<i32>,
    },
    /// Process is running but ping check failed
    PingFailed {
        /// Error message from ping check
        error: String,
    },
    /// Error checking health
    Error {
        /// Error message
        message: String,
    },
}

impl HealthCheckResult {
    /// Check if the VPN is healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthCheckResult::Healthy { .. })
    }

    /// Check if the process has exited unexpectedly
    pub fn is_process_dead(&self) -> bool {
        matches!(self, HealthCheckResult::ProcessNotRunning { .. })
    }

    /// Create a healthy result with optional latency
    pub fn healthy(latency_ms: Option<u64>) -> Self {
        HealthCheckResult::Healthy { latency_ms }
    }

    /// Create a process not running result
    pub fn process_not_running(exit_code: Option<i32>) -> Self {
        HealthCheckResult::ProcessNotRunning { exit_code }
    }

    /// Create a ping failed result
    pub fn ping_failed(error: impl Into<String>) -> Self {
        HealthCheckResult::PingFailed { error: error.into() }
    }

    /// Create an error result
    pub fn error(message: impl Into<String>) -> Self {
        HealthCheckResult::Error { message: message.into() }
    }
}

/// Callback type for health check results
///
/// This callback is invoked after each health check with the result.
/// It can be used to:
/// - Log health check results
/// - Emit events to the frontend
/// - Trigger auto-reconnection on process death
pub type HealthCheckCallback = Box<dyn Fn(HealthCheckResult) + Send + Sync + 'static>;

/// Handle for controlling a running health monitor
///
/// Dropping this handle will stop the health monitor.
pub struct HealthMonitorHandle {
    /// Abort handle for the monitoring task
    abort_handle: tokio::task::AbortHandle,
}

impl HealthMonitorHandle {
    /// Stop the health monitor
    pub fn stop(self) {
        self.abort_handle.abort();
    }

    /// Check if the monitor is still running
    pub fn is_running(&self) -> bool {
        !self.abort_handle.is_finished()
    }
}

impl Drop for HealthMonitorHandle {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

/// Health monitor for periodic VPN health checks
///
/// The health monitor periodically checks if the sing-box process is running
/// and optionally performs ping checks to verify connectivity.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use vpn::manager::{HealthMonitor, HealthCheckConfig};
/// use vpn::process::AppState;
///
/// let state = Arc::new(AppState::default());
/// let config = HealthCheckConfig::new()
///     .interval(5000)
///     .with_ping_check(true);
///
/// let handle = HealthMonitor::spawn(
///     state,
///     config,
///     |result| {
///         if result.is_process_dead() {
///             println!("VPN process died! Triggering reconnect...");
///         }
///     }
/// );
///
/// // Later, to stop monitoring:
/// handle.stop();
/// ```
pub struct HealthMonitor;

impl HealthMonitor {
    /// Spawn a health monitoring task
    ///
    /// This spawns a background task that periodically checks the health of
    /// the VPN connection and calls the callback with the result.
    ///
    /// # Arguments
    ///
    /// * `state` - The application state containing the sing-box process handle
    /// * `config` - Health check configuration
    /// * `callback` - Callback function invoked with each health check result
    ///
    /// # Returns
    ///
    /// A handle that can be used to stop the health monitor. The monitor will
    /// automatically stop when the handle is dropped.
    pub fn spawn<F>(
        state: Arc<super::process::AppState>,
        config: HealthCheckConfig,
        callback: F,
    ) -> HealthMonitorHandle
    where
        F: Fn(HealthCheckResult) + Send + Sync + 'static,
    {
        let callback = Arc::new(callback);
        let interval = Duration::from_millis(config.interval_ms);
        let ping_check = config.ping_check;

        let task = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                interval_timer.tick().await;

                // Check process health
                let process_health = super::process::check_process_health(&state);

                let result = match process_health {
                    super::process::ProcessHealthStatus::Running => {
                        // Process is running, optionally perform ping check
                        if ping_check {
                            match super::process::perform_ping_check(None, None).await {
                                Ok(latency) => HealthCheckResult::healthy(Some(latency)),
                                Err(e) => HealthCheckResult::ping_failed(e),
                            }
                        } else {
                            HealthCheckResult::healthy(None)
                        }
                    }
                    super::process::ProcessHealthStatus::Exited(code) => {
                        HealthCheckResult::process_not_running(code)
                    }
                    super::process::ProcessHealthStatus::NotRunning => {
                        HealthCheckResult::process_not_running(None)
                    }
                    super::process::ProcessHealthStatus::Restarting => {
                        // Wrapper is handling restart, treat as healthy (temporary gap)
                        HealthCheckResult::healthy(None)
                    }
                    super::process::ProcessHealthStatus::Error(e) => {
                        HealthCheckResult::error(e)
                    }
                };

                callback(result);
            }
        });

        HealthMonitorHandle {
            abort_handle: task.abort_handle(),
        }
    }

    /// Spawn a health monitor with a channel-based result delivery
    ///
    /// Instead of a callback, this returns a receiver that yields health
    /// check results. This is useful for integrating with async workflows.
    ///
    /// # Arguments
    ///
    /// * `state` - The application state containing the sing-box process handle
    /// * `config` - Health check configuration
    ///
    /// # Returns
    ///
    /// A tuple of (handle, receiver) where the handle controls the monitor
    /// and the receiver yields health check results.
    pub fn spawn_with_channel(
        state: Arc<super::process::AppState>,
        config: HealthCheckConfig,
    ) -> (HealthMonitorHandle, tokio::sync::mpsc::UnboundedReceiver<HealthCheckResult>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let handle = Self::spawn(state, config, move |result| {
            // Ignore send errors (receiver dropped)
            let _ = tx.send(result);
        });

        (handle, rx)
    }

    /// Perform a single health check
    ///
    /// This is useful for on-demand health checks outside of the periodic
    /// monitoring loop.
    ///
    /// # Arguments
    ///
    /// * `state` - The application state containing the sing-box process handle
    /// * `ping_check` - Whether to perform a ping check
    ///
    /// # Returns
    ///
    /// The result of the health check
    pub async fn check_once(
        state: &super::process::AppState,
        ping_check: bool,
    ) -> HealthCheckResult {
        let process_health = super::process::check_process_health(state);

        match process_health {
            super::process::ProcessHealthStatus::Running => {
                if ping_check {
                    match super::process::perform_ping_check(None, None).await {
                        Ok(latency) => HealthCheckResult::healthy(Some(latency)),
                        Err(e) => HealthCheckResult::ping_failed(e),
                    }
                } else {
                    HealthCheckResult::healthy(None)
                }
            }
            super::process::ProcessHealthStatus::Exited(code) => {
                HealthCheckResult::process_not_running(code)
            }
            super::process::ProcessHealthStatus::NotRunning => {
                HealthCheckResult::process_not_running(None)
            }
            super::process::ProcessHealthStatus::Restarting => {
                HealthCheckResult::healthy(None)
            }
            super::process::ProcessHealthStatus::Error(e) => {
                HealthCheckResult::error(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_default() {
        let state = ConnectionState::default();
        assert_eq!(state, ConnectionState::Disconnected);
    }

    #[test]
    fn test_connection_state_as_str() {
        assert_eq!(ConnectionState::Disconnected.as_str(), "disconnected");
        assert_eq!(ConnectionState::Connecting.as_str(), "connecting");
        assert_eq!(ConnectionState::Connected.as_str(), "connected");
        assert_eq!(ConnectionState::Reconnecting.as_str(), "reconnecting");
        assert_eq!(ConnectionState::Disconnecting.as_str(), "disconnecting");
        assert_eq!(ConnectionState::Failed.as_str(), "failed");
    }

    #[test]
    fn test_reconnect_config_default() {
        let config = ReconnectConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.initial_delay_ms, 1000);
        assert_eq!(config.max_delay_ms, 30000);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_reconnect_config_builder() {
        let config = ReconnectConfig::with_enabled(true)
            .initial_delay(500)
            .max_delay(60000)
            .multiplier(3.0)
            .max_retries(10);

        assert!(config.enabled);
        assert_eq!(config.initial_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 60000);
        assert_eq!(config.backoff_multiplier, 3.0);
        assert_eq!(config.max_retries, 10);
    }

    #[test]
    fn test_reconnect_config_delay_calculation() {
        let config = ReconnectConfig::default();

        // Attempt 0: 1000ms
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(1000));

        // Attempt 1: 1000 * 2 = 2000ms
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(2000));

        // Attempt 2: 1000 * 4 = 4000ms
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(4000));

        // Attempt 3: 1000 * 8 = 8000ms
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(8000));

        // Attempt 4: 1000 * 16 = 16000ms
        assert_eq!(config.delay_for_attempt(4), Duration::from_millis(16000));

        // Attempt 5: 1000 * 32 = 32000ms, but capped at 30000ms
        assert_eq!(config.delay_for_attempt(5), Duration::from_millis(30000));
    }

    #[test]
    fn test_health_check_config_default() {
        let config = HealthCheckConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval_ms, 10000);
        assert!(!config.ping_check);
    }

    #[test]
    fn test_health_check_config_builder() {
        let config = HealthCheckConfig::new()
            .enabled(false)
            .interval(5000)
            .with_ping_check(true);

        assert!(!config.enabled);
        assert_eq!(config.interval_ms, 5000);
        assert!(config.ping_check);
    }

    #[test]
    fn test_vpn_manager_new() {
        let manager = VpnManager::new();
        assert_eq!(manager.state(), ConnectionState::Disconnected);
        assert!(manager.config().is_none());
        assert!(!manager.is_auto_reconnect_enabled());
        assert!(manager.is_health_check_enabled());
        assert!(!manager.is_kill_switch_enabled());
        assert!(!manager.is_shutdown_requested());
    }

    #[test]
    fn test_vpn_manager_state_management() {
        let manager = VpnManager::new();

        manager.set_state(ConnectionState::Connecting);
        assert_eq!(manager.state(), ConnectionState::Connecting);
        assert!(manager.is_connecting());
        assert!(!manager.is_connected());

        manager.set_state(ConnectionState::Connected);
        assert_eq!(manager.state(), ConnectionState::Connected);
        assert!(manager.is_connected());
        assert!(!manager.is_connecting());
    }

    #[test]
    fn test_vpn_manager_config_management() {
        let manager = VpnManager::new();

        assert!(manager.config().is_none());

        let config = VlessConfig {
            uuid: "test-uuid".to_string(),
            address: "test.example.com".to_string(),
            port: 443,
            security: "tls".to_string(),
            transport_type: "ws".to_string(),
            path: "/path".to_string(),
            host: "test.example.com".to_string(),
            name: "Test Server".to_string(),
            routing_mode: None,
            target_country: None,
            protocol: None,
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            obfs_password: None,
            diag_mtu: None,
            diag_sniff: None,
            diag_stack: None,
            diag_plain_dns: None,
            diag_udp_timeout: None,
            diag_no_killswitch: None,
            diag_endpoint_independent_nat: None,
        };

        manager.store_config(config.clone());
        let stored = manager.config();
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().uuid, "test-uuid");

        manager.clear_config();
        assert!(manager.config().is_none());
    }

    #[test]
    fn test_vpn_manager_reconnect_management() {
        let manager = VpnManager::new();

        // Auto-reconnect should be disabled by default
        assert!(!manager.is_auto_reconnect_enabled());
        assert_eq!(manager.reconnect_attempts(), 0);

        // Enable auto-reconnect
        manager.set_auto_reconnect(true);
        assert!(manager.is_auto_reconnect_enabled());

        // Prepare first reconnect attempt
        let delay = manager.prepare_reconnect();
        assert!(delay.is_some());
        assert_eq!(delay.unwrap(), Duration::from_millis(1000));
        assert_eq!(manager.reconnect_attempts(), 1);
        assert!(manager.is_reconnecting());

        // Finish failed attempt
        manager.finish_reconnect(false);
        assert!(!manager.is_reconnecting());
        assert_eq!(manager.reconnect_attempts(), 1);

        // Prepare second attempt
        let delay = manager.prepare_reconnect();
        assert!(delay.is_some());
        assert_eq!(delay.unwrap(), Duration::from_millis(2000));
        assert_eq!(manager.reconnect_attempts(), 2);
    }

    #[test]
    fn test_vpn_manager_reconnect_max_retries() {
        let manager = VpnManager::with_reconnect_config(
            ReconnectConfig::with_enabled(true).max_retries(2)
        );

        // First attempt
        assert!(manager.prepare_reconnect().is_some());
        manager.finish_reconnect(false);

        // Second attempt
        assert!(manager.prepare_reconnect().is_some());
        manager.finish_reconnect(false);

        // Third attempt should fail (max retries reached)
        assert!(manager.prepare_reconnect().is_none());
        assert_eq!(manager.state(), ConnectionState::Failed);
    }

    #[test]
    fn test_vpn_manager_successful_reconnect_resets() {
        let manager = VpnManager::with_reconnect_config(
            ReconnectConfig::with_enabled(true)
        );

        // Make some failed attempts
        manager.prepare_reconnect();
        manager.finish_reconnect(false);
        manager.prepare_reconnect();
        assert_eq!(manager.reconnect_attempts(), 2);

        // Successful reconnect should reset
        manager.finish_reconnect(true);
        assert_eq!(manager.reconnect_attempts(), 0);
        assert_eq!(manager.state(), ConnectionState::Connected);
    }

    #[test]
    fn test_vpn_manager_connected_state_resets_reconnect() {
        let manager = VpnManager::with_reconnect_config(
            ReconnectConfig::with_enabled(true)
        );

        // Make some reconnect attempts
        manager.prepare_reconnect();
        manager.prepare_reconnect();
        assert_eq!(manager.reconnect_attempts(), 2);

        // Setting connected state should reset reconnect attempts
        manager.set_state(ConnectionState::Connected);
        assert_eq!(manager.reconnect_attempts(), 0);
        assert!(!manager.is_reconnecting());
    }

    #[test]
    fn test_vpn_manager_kill_switch() {
        let manager = VpnManager::new();

        assert!(!manager.is_kill_switch_enabled());

        manager.set_kill_switch(true);
        assert!(manager.is_kill_switch_enabled());

        manager.set_kill_switch(false);
        assert!(!manager.is_kill_switch_enabled());
    }

    #[test]
    fn test_vpn_manager_shutdown() {
        let manager = VpnManager::new();

        assert!(!manager.is_shutdown_requested());

        manager.request_shutdown();
        assert!(manager.is_shutdown_requested());

        manager.clear_shutdown_request();
        assert!(!manager.is_shutdown_requested());
    }

    #[test]
    fn test_vpn_manager_disconnect_flow() {
        let manager = VpnManager::new();

        // Set up connected state
        manager.set_state(ConnectionState::Connected);
        manager.store_config(VlessConfig {
            uuid: "test".to_string(),
            address: "test.com".to_string(),
            port: 443,
            security: "tls".to_string(),
            transport_type: "ws".to_string(),
            path: "/".to_string(),
            host: "test.com".to_string(),
            name: "Test".to_string(),
            routing_mode: None,
            target_country: None,
            protocol: None,
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            obfs_password: None,
            diag_mtu: None,
            diag_sniff: None,
            diag_stack: None,
            diag_plain_dns: None,
            diag_udp_timeout: None,
            diag_no_killswitch: None,
            diag_endpoint_independent_nat: None,
        });

        // Prepare disconnect
        manager.prepare_disconnect();
        assert_eq!(manager.state(), ConnectionState::Disconnecting);

        // Complete disconnect (keeping config)
        manager.complete_disconnect(false);
        assert_eq!(manager.state(), ConnectionState::Disconnected);
        assert!(manager.config().is_some());

        // Complete disconnect (clearing config)
        manager.set_state(ConnectionState::Connected);
        manager.complete_disconnect(true);
        assert_eq!(manager.state(), ConnectionState::Disconnected);
        assert!(manager.config().is_none());
    }

    #[test]
    fn test_create_vpn_manager() {
        let manager = create_vpn_manager();
        assert_eq!(manager.state(), ConnectionState::Disconnected);
    }

    #[test]
    fn test_reconnect_state() {
        let state = ReconnectState::new();

        assert_eq!(state.attempts(), 0);
        assert!(!state.is_in_progress());

        assert_eq!(state.increment_attempts(), 1);
        assert_eq!(state.increment_attempts(), 2);
        assert_eq!(state.attempts(), 2);

        state.set_in_progress(true);
        assert!(state.is_in_progress());

        state.reset_attempts();
        assert_eq!(state.attempts(), 0);
    }

    // ==================== Backon Integration Tests ====================

    #[test]
    fn test_reconnect_config_to_backoff_builder() {
        let config = ReconnectConfig::with_enabled(true)
            .initial_delay(500)
            .max_delay(10000)
            .multiplier(1.5)
            .max_retries(3);

        // The builder should be created without error
        let _builder = config.to_backoff_builder();

        // Verify the config values used to create it
        assert_eq!(config.initial_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 10000);
        assert_eq!(config.backoff_multiplier, 1.5);
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_vpn_manager_get_backoff_builder() {
        let manager = VpnManager::with_reconnect_config(
            ReconnectConfig::with_enabled(true)
                .initial_delay(2000)
                .max_delay(60000)
        );

        // Should create a backoff builder without error
        let _builder = manager.get_backoff_builder();
    }

    #[test]
    fn test_vpn_manager_should_attempt_reconnect() {
        let manager = VpnManager::new();

        // Should be false when auto-reconnect is disabled
        assert!(!manager.should_attempt_reconnect());

        // Enable auto-reconnect
        manager.set_auto_reconnect(true);
        assert!(manager.should_attempt_reconnect());

        // Should be false during shutdown
        manager.request_shutdown();
        assert!(!manager.should_attempt_reconnect());
        manager.clear_shutdown_request();

        // Should be false when already reconnecting
        manager.reconnect_state.set_in_progress(true);
        assert!(!manager.should_attempt_reconnect());
        manager.reconnect_state.set_in_progress(false);

        // Should be true again
        assert!(manager.should_attempt_reconnect());
    }

    #[test]
    fn test_vpn_manager_should_attempt_reconnect_max_retries() {
        let manager = VpnManager::with_reconnect_config(
            ReconnectConfig::with_enabled(true).max_retries(2)
        );

        assert!(manager.should_attempt_reconnect());

        // Simulate 2 attempts
        manager.reconnect_state.increment_attempts();
        manager.reconnect_state.increment_attempts();

        // Should be false when max retries reached
        assert!(!manager.should_attempt_reconnect());
    }

    #[test]
    fn test_vpn_manager_remaining_attempts() {
        let manager = VpnManager::with_reconnect_config(
            ReconnectConfig::with_enabled(true).max_retries(5)
        );

        assert_eq!(manager.remaining_attempts(), 5);

        manager.reconnect_state.increment_attempts();
        assert_eq!(manager.remaining_attempts(), 4);

        manager.reconnect_state.increment_attempts();
        manager.reconnect_state.increment_attempts();
        assert_eq!(manager.remaining_attempts(), 2);

        // Simulate exhausting all retries
        manager.reconnect_state.increment_attempts();
        manager.reconnect_state.increment_attempts();
        assert_eq!(manager.remaining_attempts(), 0);

        // Should not underflow
        manager.reconnect_state.increment_attempts();
        assert_eq!(manager.remaining_attempts(), 0);
    }

    #[test]
    fn test_vpn_manager_next_retry_delay() {
        let manager = VpnManager::with_reconnect_config(
            ReconnectConfig::with_enabled(true)
                .initial_delay(1000)
                .max_retries(3)
        );

        // First delay should be 1000ms (attempt 0)
        assert_eq!(manager.next_retry_delay(), Some(Duration::from_millis(1000)));

        // After first attempt, delay should be 2000ms (attempt 1)
        manager.reconnect_state.increment_attempts();
        assert_eq!(manager.next_retry_delay(), Some(Duration::from_millis(2000)));

        // After second attempt, delay should be 4000ms (attempt 2)
        manager.reconnect_state.increment_attempts();
        assert_eq!(manager.next_retry_delay(), Some(Duration::from_millis(4000)));

        // After third attempt (max reached), should return None
        manager.reconnect_state.increment_attempts();
        assert_eq!(manager.next_retry_delay(), None);
    }

    #[test]
    fn test_vpn_manager_next_retry_delay_disabled() {
        let manager = VpnManager::new();

        // Should return None when auto-reconnect is disabled
        assert_eq!(manager.next_retry_delay(), None);
    }

    #[test]
    fn test_reconnect_config_default_backoff_values() {
        // Verify default values match the spec: 1s, 2s, 4s, 8s, max 30s, 5 retries
        let config = ReconnectConfig::default();

        assert_eq!(config.initial_delay_ms, 1000);  // 1 second
        assert_eq!(config.max_delay_ms, 30000);     // 30 seconds
        assert_eq!(config.backoff_multiplier, 2.0); // 2x multiplier
        assert_eq!(config.max_retries, 5);          // 5 retries

        // Verify exponential sequence: 1s, 2s, 4s, 8s, 16s (capped at 30s)
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(1000));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(2000));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(4000));
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(8000));
        assert_eq!(config.delay_for_attempt(4), Duration::from_millis(16000));
        assert_eq!(config.delay_for_attempt(5), Duration::from_millis(30000)); // Capped
        assert_eq!(config.delay_for_attempt(6), Duration::from_millis(30000)); // Still capped
    }

    #[tokio::test]
    async fn test_retry_async_disabled() {
        let manager = VpnManager::new();
        // Auto-reconnect is disabled by default

        let mut call_count = 0;
        let result = manager.retry_async(|| {
            call_count += 1;
            async { Ok::<_, String>(42) }
        }).await;

        assert_eq!(result, Ok(42));
        assert_eq!(call_count, 1); // Only called once since retry is disabled
    }

    #[tokio::test]
    async fn test_retry_async_success_first_try() {
        let manager = VpnManager::with_reconnect_config(
            ReconnectConfig::with_enabled(true)
        );

        let mut call_count = 0;
        let result = manager.retry_async(|| {
            call_count += 1;
            async { Ok::<_, String>("success") }
        }).await;

        assert_eq!(result, Ok("success"));
        assert_eq!(call_count, 1);
        assert_eq!(manager.state(), ConnectionState::Connected);
        assert_eq!(manager.reconnect_attempts(), 0);
    }

    // ==================== Health Monitoring Tests ====================

    #[test]
    fn test_health_check_result_is_healthy() {
        assert!(HealthCheckResult::healthy(None).is_healthy());
        assert!(HealthCheckResult::healthy(Some(100)).is_healthy());
        assert!(!HealthCheckResult::process_not_running(None).is_healthy());
        assert!(!HealthCheckResult::ping_failed("timeout").is_healthy());
        assert!(!HealthCheckResult::error("error").is_healthy());
    }

    #[test]
    fn test_health_check_result_is_process_dead() {
        assert!(!HealthCheckResult::healthy(None).is_process_dead());
        assert!(HealthCheckResult::process_not_running(None).is_process_dead());
        assert!(HealthCheckResult::process_not_running(Some(1)).is_process_dead());
        assert!(!HealthCheckResult::ping_failed("timeout").is_process_dead());
        assert!(!HealthCheckResult::error("error").is_process_dead());
    }

    #[test]
    fn test_health_check_result_factory_methods() {
        // Test healthy with latency
        let healthy = HealthCheckResult::healthy(Some(50));
        assert!(matches!(healthy, HealthCheckResult::Healthy { latency_ms: Some(50) }));

        // Test healthy without latency
        let healthy_no_latency = HealthCheckResult::healthy(None);
        assert!(matches!(healthy_no_latency, HealthCheckResult::Healthy { latency_ms: None }));

        // Test process not running
        let dead = HealthCheckResult::process_not_running(Some(1));
        assert!(matches!(dead, HealthCheckResult::ProcessNotRunning { exit_code: Some(1) }));

        // Test ping failed
        let ping_err = HealthCheckResult::ping_failed("network error");
        if let HealthCheckResult::PingFailed { error } = ping_err {
            assert_eq!(error, "network error");
        } else {
            panic!("Expected PingFailed variant");
        }

        // Test error
        let err = HealthCheckResult::error("some error");
        if let HealthCheckResult::Error { message } = err {
            assert_eq!(message, "some error");
        } else {
            panic!("Expected Error variant");
        }
    }

    #[test]
    fn test_health_check_result_debug() {
        // Ensure Debug trait is derived correctly
        let healthy = HealthCheckResult::healthy(Some(100));
        let debug_str = format!("{:?}", healthy);
        assert!(debug_str.contains("Healthy"));
        assert!(debug_str.contains("100"));
    }

    #[test]
    fn test_health_check_result_clone() {
        let original = HealthCheckResult::healthy(Some(50));
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_health_check_result_eq() {
        assert_eq!(HealthCheckResult::healthy(Some(50)), HealthCheckResult::healthy(Some(50)));
        assert_ne!(HealthCheckResult::healthy(Some(50)), HealthCheckResult::healthy(Some(100)));
        assert_ne!(HealthCheckResult::healthy(Some(50)), HealthCheckResult::healthy(None));

        assert_eq!(
            HealthCheckResult::process_not_running(Some(0)),
            HealthCheckResult::process_not_running(Some(0))
        );
        assert_ne!(
            HealthCheckResult::process_not_running(Some(0)),
            HealthCheckResult::process_not_running(Some(1))
        );

        assert_eq!(
            HealthCheckResult::ping_failed("a"),
            HealthCheckResult::ping_failed("a")
        );
        assert_ne!(
            HealthCheckResult::ping_failed("a"),
            HealthCheckResult::ping_failed("b")
        );

        assert_eq!(
            HealthCheckResult::error("err"),
            HealthCheckResult::error("err")
        );
    }
}
