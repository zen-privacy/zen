/**
 * VPN Notification Service
 *
 * Listens to Tauri VPN events and displays toast notifications
 * for connection state changes.
 */

import { toast } from 'sonner'

// VPN event types matching the backend VpnEvent enum
interface VpnConnectedEvent {
  type: 'Connected'
  data: {
    profile_name: string
    server: string
  }
}

interface VpnDisconnectedEvent {
  type: 'Disconnected'
  data: {
    reason: string | null
  }
}

interface VpnErrorEvent {
  type: 'Error'
  data: {
    message: string
    code: string | null
  }
}

interface VpnReconnectingEvent {
  type: 'Reconnecting'
  data: {
    attempt: number
    max_attempts: number
  }
}

interface VpnKillSwitchChangedEvent {
  type: 'KillSwitchChanged'
  data: {
    enabled: boolean
  }
}

type VpnEvent =
  | VpnConnectedEvent
  | VpnDisconnectedEvent
  | VpnErrorEvent
  | VpnReconnectingEvent
  | VpnKillSwitchChangedEvent

// Event name used by the backend
const VPN_EVENT_NAME = 'vpn-event'

// Store the unlisten function for cleanup
let unlistenFn: (() => void) | null = null

// Callback for kill switch state changes (subscribed by Settings component)
type KillSwitchCallback = (enabled: boolean) => void
const killSwitchCallbacks: Set<KillSwitchCallback> = new Set()

/**
 * Subscribe to kill switch state changes.
 * Returns an unsubscribe function.
 */
export function onKillSwitchChanged(callback: KillSwitchCallback): () => void {
  killSwitchCallbacks.add(callback)
  return () => killSwitchCallbacks.delete(callback)
}

/**
 * Handle incoming VPN events and display appropriate toast notifications
 */
function handleVpnEvent(event: VpnEvent): void {
  switch (event.type) {
    case 'Connected':
      toast.success('VPN Connected', {
        description: `Connected to ${event.data.profile_name}`,
        duration: 4000,
      })
      break

    case 'Disconnected':
      toast.info('VPN Disconnected', {
        description: event.data.reason || 'Connection closed',
        duration: 4000,
      })
      break

    case 'Error':
      toast.error('VPN Error', {
        description: event.data.message,
        duration: 6000,
      })
      break

    case 'Reconnecting':
      toast.loading('Reconnecting...', {
        description: `Attempt ${event.data.attempt} of ${event.data.max_attempts}`,
        duration: 3000,
        id: 'vpn-reconnecting', // Use stable ID to update existing toast
      })
      break

    case 'KillSwitchChanged':
      if (event.data.enabled) {
        toast.info('Kill Switch', {
          description: 'Auto-enabled to prevent IP leaks',
          duration: 3000,
        })
      }
      // Notify subscribers (Settings component)
      killSwitchCallbacks.forEach((cb) => cb(event.data.enabled))
      break
  }
}

/**
 * Initialize VPN event listeners
 *
 * Sets up listeners for all VPN-related events from the Tauri backend.
 * Call this once when the app starts.
 *
 * @returns Promise that resolves when listeners are set up
 */
export async function initializeNotifications(): Promise<void> {
  // Check if Tauri is available
  if (!window.__TAURI__) {
    return
  }

  try {
    // Dynamically import Tauri event module
    const { listen } = await import('@tauri-apps/api/event')

    // Set up the event listener
    unlistenFn = await listen<VpnEvent>(VPN_EVENT_NAME, (event) => {
      handleVpnEvent(event.payload)
    })
  } catch {
    // Tauri event API not available, skip notification setup
  }
}

/**
 * Clean up VPN event listeners
 *
 * Call this when the app is unmounting to prevent memory leaks.
 */
export function cleanupNotifications(): void {
  if (unlistenFn) {
    unlistenFn()
    unlistenFn = null
  }
}

/**
 * Manually trigger a VPN connected notification
 */
export function notifyConnected(profileName: string, server: string): void {
  handleVpnEvent({
    type: 'Connected',
    data: { profile_name: profileName, server },
  })
}

/**
 * Manually trigger a VPN disconnected notification
 */
export function notifyDisconnected(reason?: string): void {
  handleVpnEvent({
    type: 'Disconnected',
    data: { reason: reason || null },
  })
}

/**
 * Manually trigger a VPN error notification
 */
export function notifyError(message: string, code?: string): void {
  handleVpnEvent({
    type: 'Error',
    data: { message, code: code || null },
  })
}

/**
 * Manually trigger a VPN reconnecting notification
 */
export function notifyReconnecting(attempt: number, maxAttempts: number): void {
  handleVpnEvent({
    type: 'Reconnecting',
    data: { attempt, max_attempts: maxAttempts },
  })
}
