import { useState, useEffect, useCallback } from 'react'
import { toast } from 'sonner'
import { LogViewer } from './LogViewer'
import { onKillSwitchChanged } from '../services/notifications'

interface KillSwitchStatus {
  enabled: boolean
  available: boolean
  backend: string
  message: string
}

interface RuleSetInfo {
  id: string
  name: string
}

interface RoutingConfig {
  routing_mode?: string
  target_country?: string
}

interface SettingsProps {
  /** Whether the settings panel is open */
  isOpen: boolean
  /** Callback when the panel should close */
  onClose: () => void
  /** Current VPN server IP (needed for kill switch) */
  serverIp?: string
  /** Whether VPN is currently connected */
  isConnected: boolean
  /** Available rule sets (countries) */
  ruleSets: RuleSetInfo[]
  /** Current profile routing config */
  currentConfig?: RoutingConfig
  /** Handler to update config */
  onUpdateConfig: (key: 'routing_mode' | 'target_country', value: string) => Promise<void> | void
}

export function Settings({
  isOpen,
  onClose,
  serverIp,
  isConnected,
  ruleSets,
  currentConfig,
  onUpdateConfig,
}: SettingsProps) {
  const [killSwitchEnabled, setKillSwitchEnabled] = useState(false)
  const [killSwitchAvailable, setKillSwitchAvailable] = useState(false)
  const [killSwitchBackend, setKillSwitchBackend] = useState('')
  const [killSwitchLoading, setKillSwitchLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<'general' | 'logs'>('general')

  const invoke = window.__TAURI__?.core?.invoke

  const fetchKillSwitchStatus = useCallback(async () => {
    if (!invoke) return

    try {
      const status = await invoke<KillSwitchStatus>('get_killswitch_status')
      setKillSwitchEnabled(status.enabled)
      setKillSwitchAvailable(status.available)
      setKillSwitchBackend(status.backend)
    } catch {
      // Silently fail - kill switch might not be available on this platform
      setKillSwitchAvailable(false)
    }
  }, [invoke])

  // Fetch kill switch status on mount, when modal opens, and when connection state changes
  useEffect(() => {
    fetchKillSwitchStatus()
  }, [isOpen, isConnected, fetchKillSwitchStatus])

  // Subscribe to kill switch state changes from backend events
  useEffect(() => {
    const unsubscribe = onKillSwitchChanged((enabled) => {
      setKillSwitchEnabled(enabled)
      // Also refresh full status to get backend/availability info
      fetchKillSwitchStatus()
    })
    return unsubscribe
  }, [fetchKillSwitchStatus])

  const handleKillSwitchToggle = async () => {
    if (!invoke) return
    if (!killSwitchAvailable) {
      toast.error('Kill switch not available', {
        description: 'Your system does not support the kill switch feature',
      })
      return
    }

    setKillSwitchLoading(true)

    try {
      if (killSwitchEnabled) {
        // Disable kill switch
        await invoke('disable_killswitch')
        setKillSwitchEnabled(false)
        toast.success('Kill switch disabled', {
          description: 'Traffic is no longer being blocked when VPN disconnects',
        })
      } else {
        // Enable kill switch
        if (!serverIp) {
          toast.error('Cannot enable kill switch', {
            description: 'Connect to a VPN server first',
          })
          setKillSwitchLoading(false)
          return
        }
        await invoke('enable_killswitch', { serverIp })
        setKillSwitchEnabled(true)
        toast.success('Kill switch enabled', {
          description: 'All traffic will be blocked if VPN disconnects',
        })
      }
    } catch (e) {
      toast.error('Kill switch error', {
        description: String(e),
      })
      // Refresh status to get actual state
      await fetchKillSwitchStatus()
    } finally {
      setKillSwitchLoading(false)
    }
  }

  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose()
    }
  }

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose()
    }
  }, [onClose])

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown)
      return () => document.removeEventListener('keydown', handleKeyDown)
    }
  }, [isOpen, handleKeyDown])

  if (!isOpen) return null

  return (
    <div className="modal-overlay" onClick={handleBackdropClick}>
      <div className="modal-container">
        <div className="modal-header">
          <h2>Settings</h2>
          <button className="modal-close" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="modal-tabs">
          <button
            className={`modal-tab ${activeTab === 'general' ? 'active' : ''}`}
            onClick={() => setActiveTab('general')}
          >
            General
          </button>
          <button
            className={`modal-tab ${activeTab === 'logs' ? 'active' : ''}`}
            onClick={() => setActiveTab('logs')}
          >
            Logs
          </button>
        </div>

        <div className="modal-content">
          {activeTab === 'general' && (
            <div className="modal-section">
              <h3 className="modal-section-title">Security</h3>

              <div className="modal-item">
                <div className="modal-item-info">
                  <div className="modal-item-label">Kill Switch</div>
                  <div className="modal-item-desc">
                    Block all internet traffic if VPN connection drops. Enabled automatically on connect.
                    {!killSwitchAvailable && (
                      <span className="text-warning"> Not available.</span>
                    )}
                    {killSwitchAvailable && killSwitchBackend && (
                      <span className="text-muted"> Using {killSwitchBackend}.</span>
                    )}
                  </div>
                </div>
                <div className="modal-item-control">
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={killSwitchEnabled}
                      onChange={handleKillSwitchToggle}
                      disabled={!killSwitchAvailable || killSwitchLoading}
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>
              </div>

              {killSwitchEnabled && (
                <div className="modal-notice">
                  ⚠️ Kill switch active. Traffic blocked when VPN disconnects.
                  {!isConnected && ' Connect to restore access.'}
                </div>
              )}

              <h3 className="modal-section-title">Routing</h3>

              <div className="modal-item">
                <div className="modal-item-info">
                  <div className="modal-item-label">Mode</div>
                  <div className="modal-item-desc">
                    Choose how traffic is routed. Smart bypasses local (country) traffic.
                  </div>
                </div>
                <div className="modal-item-control">
                  <select
                    className="settings-select"
                    value={currentConfig?.routing_mode || 'global'}
                    onChange={(e) => onUpdateConfig('routing_mode', e.target.value)}
                    disabled={isConnected}
                  >
                    <option value="global">Global (All via VPN)</option>
                    <option value="smart">Smart (Bypass local)</option>
                  </select>
                </div>
              </div>

              {currentConfig?.routing_mode === 'smart' && (
                <div className="modal-item">
                  <div className="modal-item-info">
                    <div className="modal-item-label">Country Rules</div>
                    <div className="modal-item-desc">
                      Traffic to this country goes direct; others via VPN.
                    </div>
                  </div>
                  <div className="modal-item-control">
                    <select
                      className="settings-select"
                      value={currentConfig?.target_country || 'ru'}
                      onChange={(e) => onUpdateConfig('target_country', e.target.value)}
                      disabled={isConnected}
                    >
                      {((ruleSets && ruleSets.length > 0) ? ruleSets : [{ id: 'ru', name: 'RU' }]).map((r) => (
                        <option key={r.id} value={r.id}>{r.name}</option>
                      ))}
                    </select>
                  </div>
                </div>
              )}

              <h3 className="modal-section-title">Connection</h3>

              <div className="modal-item">
                <div className="modal-item-info">
                  <div className="modal-item-label">Auto-Reconnect</div>
                  <div className="modal-item-desc">
                    Automatically reconnect when connection drops.
                  </div>
                </div>
                <div className="modal-item-control">
                  <span className="modal-badge">Always On</span>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="modal-section modal-logs">
              <LogViewer
                maxDisplayCount={200}
                pollInterval={5000}
                autoScroll={true}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
