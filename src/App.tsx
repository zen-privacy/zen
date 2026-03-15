import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import { Toaster } from './components/Toaster'
import { Settings } from './components/Settings'

declare global {
  interface Window {
    __TAURI__: {
      core: {
        invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>
      }
    }
  }
}

interface VlessConfig {
  uuid: string
  address: string
  port: number
  security: string
  transport_type: string
  path: string
  host: string
  name: string
  routing_mode?: string
  target_country?: string
  protocol?: string
  up_mbps?: number
  down_mbps?: number
  obfs?: string
  obfs_password?: string
  // Diagnostic flags for bisecting real-time UDP issues (e.g. Telegram calls)
  diag_mtu?: number
  diag_sniff?: boolean
  diag_stack?: string
  diag_plain_dns?: boolean
  diag_udp_timeout?: number
  diag_no_killswitch?: boolean
  diag_endpoint_independent_nat?: boolean
}

interface RuleSetInfo {
  id: string
  name: string
}

interface Profile {
  id: string
  name: string
  config: VlessConfig
}

interface AppStatus {
  singbox_installed: boolean
  singbox_path: string
  downloading: boolean
  needs_update: boolean
  current_version: string
  required_version: string
}

interface TrafficStats {
  rx_bytes: number
  tx_bytes: number
}

interface UpdateInfo {
  available: boolean
  current_version: string
  latest_version: string
  notes?: string | null
  asset_url?: string | null
  sha256?: string | null
  platform: string
  downloaded_path?: string | null
}

function App() {
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [isConnecting, setIsConnecting] = useState(false)
  const [isDisconnecting, setIsDisconnecting] = useState(false)
  const [isDownloading, setIsDownloading] = useState(false)
  const [singboxInstalled, setSingboxInstalled] = useState(true)
  const [singboxNeedsUpdate, setSingboxNeedsUpdate] = useState(false)
  const [singboxVersionInfo, setSingboxVersionInfo] = useState({ current: '', required: '' })
  const [error, setError] = useState<string | null>(null)
  const [traffic, setTraffic] = useState<TrafficStats | null>(null)
  const [isVisible, setIsVisible] = useState(() => !document.hidden)
  const [lastStatusError, setLastStatusError] = useState<string | null>(null)
  const currentProfile = selectedId ? profiles.find(p => p.id === selectedId) : null
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null)
  const [checkingUpdate, setCheckingUpdate] = useState(false)
  const [installingUpdate, setInstallingUpdate] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [ruleSets, setRuleSets] = useState<RuleSetInfo[]>([])
  const [subUrl, setSubUrl] = useState('')
  const [isFetchingSub, setIsFetchingSub] = useState(false)
  const [showSudoDialog, setShowSudoDialog] = useState(false)
  const [sudoPassword, setSudoPassword] = useState('')
  const [sudoSaving, setSudoSaving] = useState(false)
  const [sudoError, setSudoError] = useState<string | null>(null)
  const [pendingConnect, setPendingConnect] = useState(false)

  const invoke = window.__TAURI__?.core?.invoke

  useEffect(() => {
    checkSetup()
    loadProfiles()
    loadRuleSets()
    loadSavedSubscription()
    handleCheckUpdate()

    const handleVisibility = () => setIsVisible(!document.hidden)
    document.addEventListener('visibilitychange', handleVisibility)
    return () => document.removeEventListener('visibilitychange', handleVisibility)
  }, [])

  // Poll traffic when connected
  useEffect(() => {
    if (!isConnected || !isVisible) {
      setTraffic(null)
      return
    }

    const pollTraffic = async () => {
      if (!invoke || document.hidden) return
      try {
        const stats = await invoke<TrafficStats>('get_traffic_stats')
        setTraffic(stats)
      } catch {
        // Interface might not be ready yet
      }
    }

    pollTraffic()
    const interval = setInterval(pollTraffic, 3000) // Reduced frequency: every 3 seconds
    return () => clearInterval(interval)
  }, [isConnected, isVisible])

  const checkSetup = async () => {
    if (!invoke) return
    try {
      const status = await invoke<AppStatus>('check_singbox_installed')
      setSingboxInstalled(status.singbox_installed)
      setSingboxNeedsUpdate(status.needs_update)
      setSingboxVersionInfo({ current: status.current_version, required: status.required_version })
    } catch (e) {
      toast.error('Failed to check setup', { description: String(e) })
    }
  }

  const loadProfiles = async () => {
    if (!invoke) return
    try {
      const loaded = await invoke<Profile[]>('load_profiles')
      setProfiles(loaded)
    } catch (e) {
      toast.error('Failed to load profiles', { description: String(e) })
    }
  }

  const loadRuleSets = async () => {
    if (!invoke) return
    try {
      const sets = await invoke<RuleSetInfo[]>('get_available_rule_sets')
      setRuleSets(sets)
    } catch (e) {
      console.error('Failed to load rule sets:', e)
    }
  }

  const handleUpdateConfig = async (key: string, value: any) => {
    if (!invoke || !currentProfile) return
    const updatedConfig = { ...currentProfile.config, [key]: value }
    const updatedProfile = { ...currentProfile, config: updatedConfig }

    // Update local state immediately
    setProfiles(prev => prev.map(p => p.id === currentProfile.id ? updatedProfile : p))

    try {
      await invoke('save_profile', { profile: updatedProfile })
    } catch (e) {
      toast.error('Failed to save settings')
    }
  }

  const handleDownloadSingbox = async () => {
    if (!invoke) return
    setError(null)
    setIsDownloading(true)

    try {
      await invoke<string>('download_singbox')
      setSingboxInstalled(true)
      setSingboxNeedsUpdate(false)
    } catch (e) {
      setError(String(e))
    } finally {
      setIsDownloading(false)
    }
  }

  const loadSavedSubscription = async () => {
    if (!invoke) return
    try {
      const savedUrl = await invoke<string>('load_subscription_url')
      if (savedUrl) {
        setSubUrl(savedUrl)
        // Auto-refresh subscription on startup
        await refreshSubscription(savedUrl)
      }
    } catch {
      // No saved subscription, that's fine
    }
  }

  const refreshSubscription = async (url?: string) => {
    if (!invoke) return
    const subUrlToUse = url || subUrl.trim()
    if (!subUrlToUse) return

    try {
      const configs = await invoke<VlessConfig[]>('fetch_subscription', { url: subUrlToUse })
      const validConfigs = configs.filter(c => c.address && c.port && c.port > 0 && c.port <= 65535)

      if (validConfigs.length === 0) return

      // Delete all existing profiles and replace with subscription
      const existingProfiles = await invoke<Profile[]>('load_profiles')
      for (const p of existingProfiles) {
        await invoke('delete_profile', { id: p.id })
      }

      // Add new profiles from subscription
      let firstId: string | null = null
      for (const config of validConfigs) {
        const profile: Profile = {
          id: crypto.randomUUID(),
          name: config.name || `Server`,
          config,
        }
        await invoke('save_profile', { profile })
        if (!firstId) firstId = profile.id
      }

      await loadProfiles()
      if (firstId && !isConnected) {
        setSelectedId(firstId)
      }
    } catch {
      // Silent fail on auto-refresh
    }
  }

  const handleFetchSubscription = async () => {
    if (!invoke || !subUrl.trim()) return
    setError(null)
    setIsFetchingSub(true)

    try {
      // Save subscription URL for future auto-refresh
      await invoke('save_subscription_url', { url: subUrl.trim() })

      await refreshSubscription()
      toast.success('Subscription updated')
    } catch (e) {
      setError(String(e))
    } finally {
      setIsFetchingSub(false)
    }
  }

  const handleCheckUpdate = async () => {
    if (!invoke) return
    setCheckingUpdate(true)
    try {
      const info = await invoke<UpdateInfo>('check_for_update')
      setUpdateInfo(info)
      if (info.available) {
        toast.info(`Update ${info.latest_version} available`)
      }
    } catch {
      // Silently fail on startup check
    } finally {
      setCheckingUpdate(false)
    }
  }

  const handleInstallUpdate = async () => {
    if (!invoke) return
    setInstallingUpdate(true)
    try {
      const info = await invoke<UpdateInfo>('install_update')
      setUpdateInfo(info)
      if (info.downloaded_path) {
        toast.success('Update downloaded', {
          description: info.platform.startsWith('windows')
            ? 'Installer launched'
            : `Saved to: ${info.downloaded_path}`,
        })
      } else {
        toast.error('Download failed')
      }
    } catch (e) {
      toast.error('Failed to install update', { description: String(e) })
    } finally {
      setInstallingUpdate(false)
    }
  }

  const handleSudoSubmit = async () => {
    if (!invoke || !sudoPassword.trim()) return
    setSudoSaving(true)
    setSudoError(null)

    try {
      await invoke('sudo_set_password', { password: sudoPassword })
      setSudoPassword('')
      setShowSudoDialog(false)
      toast.success('Password saved')

      // Retry the pending connection
      if (pendingConnect) {
        setPendingConnect(false)
        setTimeout(() => handleConnect(), 100)
      }
    } catch (e) {
      const err = String(e)
      if (err.includes('SUDO_PASSWORD_INVALID')) {
        setSudoError('Wrong password')
      } else {
        setSudoError(err)
      }
    } finally {
      setSudoSaving(false)
    }
  }

  const connectWithSudoCheck = async (config: VlessConfig): Promise<void> => {
    if (!invoke) return
    try {
      await invoke('start_singbox', { config })
      setIsConnected(true)
      setLastStatusError(null)
    } catch (e) {
      const err = String(e)
      if (err.includes('SUDO_PASSWORD_REQUIRED')) {
        // Show password dialog, retry after
        setPendingConnect(true)
        setShowSudoDialog(true)
        setIsConnecting(false)
        return
      }
      throw e
    }
  }

  const handleConnect = async () => {
    if (!invoke) return
    if (isConnecting || isDisconnecting) return

    setError(null)

    try {
      if (isConnected) {
        setIsDisconnecting(true)
        await invoke('stop_singbox')
        setIsConnected(false)
        setLastStatusError(null)
      } else {
        setIsConnecting(true)
        if (!currentProfile) {
          setError('Select a profile first')
          setIsConnecting(false)
          return
        }
        await connectWithSudoCheck(currentProfile.config)
      }
    } catch (e) {
      setError(String(e))
      setLastStatusError(String(e))
      setIsConnected(false)
    } finally {
      setIsConnecting(false)
      setIsDisconnecting(false)
    }
  }

  const handleSwitchServer = async (profileId: string) => {
    if (!invoke) return
    if (isConnecting || isDisconnecting) return

    // If clicking the already connected server — do nothing
    if (profileId === selectedId && isConnected) return

    const targetProfile = profiles.find(p => p.id === profileId)
    if (!targetProfile) return

    setSelectedId(profileId)
    setError(null)

    // Disconnect current if connected
    if (isConnected) {
      setIsDisconnecting(true)
      try {
        await invoke('stop_singbox')
      } catch {
        // Ignore disconnect errors during switch
      }
      setIsConnected(false)
      setIsDisconnecting(false)
    }

    // Always connect to clicked server
    setIsConnecting(true)
    try {
      await connectWithSudoCheck(targetProfile.config)
    } catch (e) {
      setError(String(e))
      setLastStatusError(String(e))
      setIsConnected(false)
    } finally {
      setIsConnecting(false)
    }
  }

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }

  const getStatusClass = () => {
    if (isDisconnecting) return 'disconnecting'
    if (isConnecting) return 'connecting'
    if (isConnected) return 'connected'
    if (lastStatusError) return 'error'
    return 'idle'
  }

  const getStatusText = () => {
    if (isDisconnecting) return 'Disconnecting...'
    if (isConnecting) return 'Connecting...'
    if (isConnected) return 'Protected'
    if (lastStatusError) return 'Error'
    return 'Disconnected'
  }

  // Setup banner when sing-box not installed or needs update
  if (!singboxInstalled || singboxNeedsUpdate) {
    return (
      <div className="app">
        <div className="setup-banner">
          <h2>{singboxNeedsUpdate ? 'Update Required' : 'Welcome to Zen Privacy'}</h2>
          <p>
            {singboxNeedsUpdate
              ? `VPN engine v${singboxVersionInfo.current} is incompatible. Version ${singboxVersionInfo.required} required.`
              : 'Download the VPN engine to start your heist on censorship'}
          </p>
          <button
            className="btn-download"
            onClick={handleDownloadSingbox}
            disabled={isDownloading}
          >
            {isDownloading ? (
              <>
                <span className="spinner" />
                {singboxNeedsUpdate ? 'Updating...' : 'Downloading...'}
              </>
            ) : (
              singboxNeedsUpdate ? `Update to v${singboxVersionInfo.required}` : 'Download Engine'
            )}
          </button>
          {error && <div className="error-message">{error}</div>}
        </div>
      </div>
    )
  }

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <h1>
          <span>Z</span>en <span>P</span>rivacy
        </h1>
        <div className="header-controls">
          <button
            className="btn-icon"
            onClick={() => setSettingsOpen(true)}
            title="Settings"
          >
            ⚙️
          </button>
        </div>
      </header>

      {/* Main Content - 2 Columns */}
      <main className="main-content two-columns">
        {/* Left Panel - Servers */}
        <section className="servers-panel">
          <div className="panel-header">
            <h2 className="panel-title">Servers</h2>
            {isConnected && (
              <button
                className="btn-disconnect"
                onClick={handleConnect}
                disabled={isDisconnecting}
                title="Disconnect"
              >
                {isDisconnecting ? '...' : '⏻'}
              </button>
            )}
          </div>

          {(isConnecting || isDisconnecting) && (
            <div className={`connection-status-bar ${getStatusClass()}`}>
              {isDisconnecting ? 'Disconnecting...' : 'Connecting...'}
            </div>
          )}

          <div className="servers-list">
            {profiles.length === 0 ? (
              <div className="empty-state">
                <p>Add a subscription to get started</p>
              </div>
            ) : (
              profiles.map((profile: Profile) => (
                <div
                  key={profile.id}
                  className={`server-card ${selectedId === profile.id ? 'selected' : ''} ${selectedId === profile.id && isConnected ? 'active' : ''}`}
                  onClick={() => handleSwitchServer(profile.id)}
                >
                  <div className="server-info">
                    <div className="server-name">{profile.name}</div>
                    <div className="server-address">
                      {profile.config.address}:{profile.config.port}
                    </div>
                  </div>
                  {selectedId === profile.id && isConnected && (
                    <span className="server-active-dot" />
                  )}
                </div>
              ))
            )}
          </div>

          <div className="add-server sub-input">
            <input
              type="text"
              placeholder="Subscription URL"
              value={subUrl}
              onChange={(e) => setSubUrl(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleFetchSubscription()}
            />
            <button
              className="btn-add"
              onClick={handleFetchSubscription}
              disabled={isFetchingSub || !subUrl.trim()}
            >
              {isFetchingSub ? '...' : 'Sync'}
            </button>
          </div>
          {error && <div className="error-message">{error}</div>}
        </section>

        {/* Right Panel - Status */}
        <section className="settings-panel">
          <div className="settings-card">
            <h3 className="settings-title">Status</h3>

            <div className="settings-item">
              <span className="settings-item-label">Server</span>
              <span className="settings-item-value">
                {currentProfile?.name || 'None'}
              </span>
            </div>

            <div className="settings-item">
              <span className="settings-item-label">Connection</span>
              <span className={`settings-item-value status-${getStatusClass()}`}>
                {getStatusText()}
              </span>
            </div>

            {isConnected && traffic && (
              <>
                <div className="settings-item">
                  <span className="settings-item-label">↓ Download</span>
                  <span className="settings-item-value traffic-down">
                    {formatBytes(traffic.rx_bytes)}
                  </span>
                </div>
                <div className="settings-item">
                  <span className="settings-item-label">↑ Upload</span>
                  <span className="settings-item-value traffic-up">
                    {formatBytes(traffic.tx_bytes)}
                  </span>
                </div>
              </>
            )}
          </div>

          <div className="settings-card updates-section">
            <h3 className="settings-title">Updates</h3>

            <button
              className="btn-update"
              onClick={updateInfo?.available ? handleInstallUpdate : handleCheckUpdate}
              disabled={checkingUpdate || installingUpdate}
            >
              {checkingUpdate ? 'Checking...' :
                installingUpdate ? 'Installing...' :
                  updateInfo?.available ? `Install ${updateInfo.latest_version}` :
                    'Check Updates'}
            </button>

            <div className="version-info">
              v{updateInfo?.current_version || '0.1.6'}
              {updateInfo?.available && ` → ${updateInfo.latest_version}`}
            </div>
          </div>
        </section>
      </main>

      <Toaster theme="dark" />
      <Settings
        isOpen={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        isConnected={isConnected}
        ruleSets={ruleSets}
        currentConfig={currentProfile?.config}
        onUpdateConfig={handleUpdateConfig}
      />

      {/* Sudo password dialog */}
      {showSudoDialog && (
        <div className="modal-overlay" onClick={() => { setShowSudoDialog(false); setPendingConnect(false) }}>
          <div className="modal-content sudo-dialog" onClick={e => e.stopPropagation()}>
            <h3>System Password Required</h3>
            <p>VPN requires administrator privileges. Enter your system password to continue.</p>
            <input
              type="password"
              placeholder="System password"
              value={sudoPassword}
              onChange={e => setSudoPassword(e.target.value)}
              onKeyPress={e => e.key === 'Enter' && handleSudoSubmit()}
              autoFocus
            />
            {sudoError && <div className="error-message">{sudoError}</div>}
            <div className="sudo-dialog-buttons">
              <button
                className="btn-add"
                onClick={handleSudoSubmit}
                disabled={sudoSaving || !sudoPassword.trim()}
              >
                {sudoSaving ? '...' : 'Save & Connect'}
              </button>
              <button
                className="btn-cancel"
                onClick={() => { setShowSudoDialog(false); setPendingConnect(false); setSudoError(null) }}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}

export default App
