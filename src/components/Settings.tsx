import { useState, useEffect, useCallback } from 'react'
import { LogViewer } from './LogViewer'

interface RuleSetInfo {
  id: string
  name: string
}

interface RoutingConfig {
  routing_mode?: string
  target_country?: string
  diag_mtu?: number
  diag_sniff?: boolean
  diag_stack?: string
  diag_plain_dns?: boolean
  diag_udp_timeout?: number
  diag_no_killswitch?: boolean
  diag_endpoint_independent_nat?: boolean
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
  onUpdateConfig: (key: string, value: any) => Promise<void> | void
}

export function Settings({
  isOpen,
  onClose,
  isConnected,
  ruleSets,
  currentConfig,
  onUpdateConfig,
}: SettingsProps) {
  const [activeTab, setActiveTab] = useState<'general' | 'diagnostics' | 'logs'>('general')

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
            className={`modal-tab ${activeTab === 'diagnostics' ? 'active' : ''}`}
            onClick={() => setActiveTab('diagnostics')}
          >
            Diagnostics
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

          {activeTab === 'diagnostics' && (
            <div className="modal-section">
              <h3 className="modal-section-title">Bisect: Real-time UDP</h3>
              <p className="modal-item-desc" style={{ marginBottom: 12 }}>
                Toggle one flag at a time, reconnect, test a Telegram call.
              </p>

              <div className="modal-item">
                <div className="modal-item-info">
                  <div className="modal-item-label">Endpoint-Independent NAT</div>
                  <div className="modal-item-desc">
                    Required for ICE/STUN (Telegram, WhatsApp calls). Off by default in sing-box.
                  </div>
                </div>
                <div className="modal-item-control">
                  <select
                    className="settings-select"
                    value={currentConfig?.diag_endpoint_independent_nat ? 'on' : 'off'}
                    onChange={(e) => onUpdateConfig('diag_endpoint_independent_nat', e.target.value === 'on' ? true : undefined)}
                    disabled={isConnected}
                  >
                    <option value="off">Off (default)</option>
                    <option value="on">On</option>
                  </select>
                </div>
              </div>

              <div className="modal-item">
                <div className="modal-item-info">
                  <div className="modal-item-label">Protocol Sniffing</div>
                  <div className="modal-item-desc">
                    Detect protocols on TUN. Can break DTLS/SRTP.
                  </div>
                </div>
                <div className="modal-item-control">
                  <select
                    className="settings-select"
                    value={currentConfig?.diag_sniff === false ? 'off' : 'on'}
                    onChange={(e) => onUpdateConfig('diag_sniff', e.target.value === 'on' ? undefined : false)}
                    disabled={isConnected}
                  >
                    <option value="on">On (default)</option>
                    <option value="off">Off</option>
                  </select>
                </div>
              </div>

              <div className="modal-item">
                <div className="modal-item-info">
                  <div className="modal-item-label">MTU</div>
                  <div className="modal-item-desc">
                    TUN interface MTU. Lower = less fragmentation.
                  </div>
                </div>
                <div className="modal-item-control">
                  <select
                    className="settings-select"
                    value={currentConfig?.diag_mtu || 1400}
                    onChange={(e) => {
                      const v = parseInt(e.target.value)
                      onUpdateConfig('diag_mtu', v === 1400 ? undefined : v)
                    }}
                    disabled={isConnected}
                  >
                    <option value={1400}>1400 (default)</option>
                    <option value={1280}>1280</option>
                    <option value={1200}>1200</option>
                  </select>
                </div>
              </div>

              <div className="modal-item">
                <div className="modal-item-info">
                  <div className="modal-item-label">DNS Mode</div>
                  <div className="modal-item-desc">
                    DNS-over-TLS adds latency. Plain UDP is faster.
                  </div>
                </div>
                <div className="modal-item-control">
                  <select
                    className="settings-select"
                    value={currentConfig?.diag_plain_dns ? 'plain' : 'tls'}
                    onChange={(e) => onUpdateConfig('diag_plain_dns', e.target.value === 'plain' ? true : undefined)}
                    disabled={isConnected}
                  >
                    <option value="tls">DNS-over-TLS (default)</option>
                    <option value="plain">Plain UDP</option>
                  </select>
                </div>
              </div>

              <div className="modal-item">
                <div className="modal-item-info">
                  <div className="modal-item-label">TUN Stack</div>
                  <div className="modal-item-desc">
                    Packet processing stack. Affects UDP handling.
                  </div>
                </div>
                <div className="modal-item-control">
                  <select
                    className="settings-select"
                    value={currentConfig?.diag_stack || 'system'}
                    onChange={(e) => onUpdateConfig('diag_stack', e.target.value === 'system' ? undefined : e.target.value)}
                    disabled={isConnected}
                  >
                    <option value="system">system (default)</option>
                    <option value="gvisor">gvisor</option>
                    <option value="mixed">mixed</option>
                  </select>
                </div>
              </div>

              <div className="modal-item">
                <div className="modal-item-info">
                  <div className="modal-item-label">UDP Timeout</div>
                  <div className="modal-item-desc">
                    How long idle UDP sessions stay open. If call drops at this time — it's the cause.
                  </div>
                </div>
                <div className="modal-item-control">
                  <select
                    className="settings-select"
                    value={currentConfig?.diag_udp_timeout || 300}
                    onChange={(e) => {
                      const v = parseInt(e.target.value)
                      onUpdateConfig('diag_udp_timeout', v === 300 ? undefined : v)
                    }}
                    disabled={isConnected}
                  >
                    <option value={10}>10s (fast test)</option>
                    <option value={30}>30s</option>
                    <option value={60}>60s</option>
                    <option value={300}>300s (default)</option>
                    <option value={600}>600s</option>
                  </select>
                </div>
              </div>

              <div className="modal-item">
                <div className="modal-item-info">
                  <div className="modal-item-label">Kill Switch</div>
                  <div className="modal-item-desc">
                    Disable pf firewall rules to test if they block something.
                  </div>
                </div>
                <div className="modal-item-control">
                  <select
                    className="settings-select"
                    value={currentConfig?.diag_no_killswitch ? 'off' : 'on'}
                    onChange={(e) => onUpdateConfig('diag_no_killswitch', e.target.value === 'off' ? true : undefined)}
                    disabled={isConnected}
                  >
                    <option value="on">On (default)</option>
                    <option value="off">Disabled</option>
                  </select>
                </div>
              </div>

              <div className="modal-item">
                <div className="modal-item-info">
                  <div className="modal-item-label">Reset All</div>
                  <div className="modal-item-desc">
                    Restore all diagnostic flags to defaults.
                  </div>
                </div>
                <div className="modal-item-control">
                  <button
                    className="modal-badge"
                    style={{ cursor: isConnected ? 'not-allowed' : 'pointer' }}
                    disabled={isConnected}
                    onClick={() => {
                      onUpdateConfig('diag_mtu', undefined)
                      onUpdateConfig('diag_sniff', undefined)
                      onUpdateConfig('diag_stack', undefined)
                      onUpdateConfig('diag_plain_dns', undefined)
                      onUpdateConfig('diag_udp_timeout', undefined)
                      onUpdateConfig('diag_no_killswitch', undefined)
                      onUpdateConfig('diag_endpoint_independent_nat', undefined)
                    }}
                  >
                    Reset
                  </button>
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
