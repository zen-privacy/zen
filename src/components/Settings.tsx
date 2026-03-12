import { useState, useEffect, useCallback } from 'react'
import { LogViewer } from './LogViewer'

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
  isConnected,
  ruleSets,
  currentConfig,
  onUpdateConfig,
}: SettingsProps) {
  const [activeTab, setActiveTab] = useState<'general' | 'logs'>('general')

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
                    Always active. All traffic is routed through the VPN tunnel — nothing can bypass it.
                  </div>
                </div>
                <div className="modal-item-control">
                  <span className="modal-badge">Always On</span>
                </div>
              </div>

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
