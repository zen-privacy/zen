import { useState, useEffect, useCallback } from 'react'
import { toast } from 'sonner'
import { LogViewer } from './LogViewer'

interface KillSwitchStatus {
  enabled: boolean
  available: boolean
  backend: string
  message: string
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
}

export function Settings({
  isOpen,
  onClose,
  serverIp,
  isConnected,
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

  useEffect(() => {
    if (isOpen) {
      fetchKillSwitchStatus()
    }
  }, [isOpen, fetchKillSwitchStatus])

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
                    Block all internet traffic if VPN connection drops.
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
