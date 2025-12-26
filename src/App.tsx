import React, { useState, useEffect } from 'react'
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
  const [linkInput, setLinkInput] = useState('')
  const [isConnected, setIsConnected] = useState(false)
  const [isConnecting, setIsConnecting] = useState(false)
  const [isDownloading, setIsDownloading] = useState(false)
  const [singboxInstalled, setSingboxInstalled] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [traffic, setTraffic] = useState<TrafficStats | null>(null)
  const [isVisible, setIsVisible] = useState(() => !document.hidden)
  const [lastStatusError, setLastStatusError] = useState<string | null>(null)
  const currentProfile = selectedId ? profiles.find(p => p.id === selectedId) : null
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null)
  const [checkingUpdate, setCheckingUpdate] = useState(false)
  const [installingUpdate, setInstallingUpdate] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)

  const invoke = window.__TAURI__?.core?.invoke

  useEffect(() => {
    checkSetup()
    loadProfiles()
    // Auto-check for updates on startup
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
    const interval = setInterval(pollTraffic, 1000)
    return () => clearInterval(interval)
  }, [isConnected, isVisible])

  const checkSetup = async () => {
    if (!invoke) return
    try {
      const status = await invoke<AppStatus>('check_singbox_installed')
      setSingboxInstalled(status.singbox_installed)
    } catch (e) {
      toast.error('Failed to check setup', { description: String(e) })
    }
  }

  const loadProfiles = async () => {
    if (!invoke) return
    try {
      const loaded = await invoke<Profile[]>('load_profiles')
      setProfiles(loaded)
      if (loaded.length > 0 && !selectedId) {
        setSelectedId(loaded[0].id)
      }
    } catch (e) {
      toast.error('Failed to load profiles', { description: String(e) })
    }
  }

  const handleDownloadSingbox = async () => {
    if (!invoke) return
    setError(null)
    setIsDownloading(true)

    try {
      await invoke<string>('download_singbox')
      setSingboxInstalled(true)
    } catch (e) {
      setError(String(e))
    } finally {
      setIsDownloading(false)
    }
  }

  const handleAddProfile = async () => {
    if (!invoke || !linkInput.trim()) return
    setError(null)

    try {
      const config = await invoke<VlessConfig>('parse_vless_link', { link: linkInput })
      if (!config.address || !config.uuid || !config.port || config.port < 1 || config.port > 65535) {
        setError('Invalid profile data (address/port/uuid)')
        return
      }
      const profile: Profile = {
        id: crypto.randomUUID(),
        name: config.name,
        config,
      }
      await invoke('save_profile', { profile })
      setLinkInput('')
      await loadProfiles()
      setSelectedId(profile.id)
    } catch (e) {
      setError(String(e))
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

  const handleDeleteProfile = async (id: string, e: React.MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation()
    if (!invoke) return

    try {
      await invoke('delete_profile', { id })
      if (selectedId === id) {
        setSelectedId(null)
      }
      await loadProfiles()
    } catch (e) {
      setError(String(e))
    }
  }

  const handleConnect = async () => {
    if (!invoke) return
    setError(null)
    setIsConnecting(true)

    try {
      if (isConnected) {
        await invoke('stop_singbox')
        setIsConnected(false)
        setLastStatusError(null)
      } else {
        if (!currentProfile) {
          setError('Select a profile first')
          setIsConnecting(false)
          return
        }
        await invoke('start_singbox', { config: currentProfile.config })
        setIsConnected(true)
        setLastStatusError(null)
      }
    } catch (e) {
      setError(String(e))
      setLastStatusError(String(e))
      setIsConnected(false)
    } finally {
      setIsConnecting(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleAddProfile()
    }
  }

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }

  const getStatusClass = () => {
    if (isConnecting) return 'connecting'
    if (isConnected) return 'connected'
    if (lastStatusError) return 'error'
    return 'idle'
  }

  const getStatusText = () => {
    if (isConnecting) return 'Connecting...'
    if (isConnected) return 'Protected'
    if (lastStatusError) return 'Error'
    return 'Disconnected'
  }

  // Setup banner when sing-box not installed
  if (!singboxInstalled) {
    return (
      <div className="app">
        <div className="setup-banner">
          <h2>Welcome to Zen VPN</h2>
          <p>Download the VPN engine to start your heist on censorship</p>
          <button
            className="btn-download"
            onClick={handleDownloadSingbox}
            disabled={isDownloading}
          >
            {isDownloading ? (
              <>
                <span className="spinner" />
                Downloading...
              </>
            ) : (
              'Download Engine'
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
          <span>Z</span>en <span>V</span>PN
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

      {/* Main Content - 3 Columns */}
      <main className="main-content">
        {/* Left Panel - Servers */}
        <section className="servers-panel">
          <h2 className="panel-title">Servers</h2>
          
          <div className="servers-list">
            {profiles.length === 0 ? (
              <div className="empty-state">
                <div className="empty-state-icon">🔐</div>
                <p>Add a server to start</p>
              </div>
            ) : (
              profiles.map((profile: Profile) => (
                <div
                  key={profile.id}
                  className={`server-card ${selectedId === profile.id ? 'selected' : ''}`}
                  onClick={() => setSelectedId(profile.id)}
                >
                  <div className="server-name">{profile.name}</div>
                  <div className="server-address">
                    {profile.config.address}:{profile.config.port}
                  </div>
                  <button
                    className="server-delete"
                    onClick={(e) => handleDeleteProfile(profile.id, e)}
                  >
                    ✕
                  </button>
                </div>
              ))
            )}
          </div>

          <div className="add-server">
            <input
              type="text"
              placeholder="vless:// link"
              value={linkInput}
              onChange={(e) => setLinkInput(e.target.value)}
              onKeyPress={handleKeyPress}
            />
            <button className="btn-add" onClick={handleAddProfile}>
              Add
            </button>
          </div>
          {error && <div className="error-message">{error}</div>}
        </section>

        {/* Center Panel - Connect */}
        <section className="connect-panel">
          <div className="connect-poster">
            {/* Mask - clickable connect button */}
            <div 
              className={`mask-container ${getStatusClass()}`}
              onClick={handleConnect}
              title={isConnected ? 'Click to disconnect' : 'Click to connect'}
            >
              <img 
                src={isConnected ? '/images/mask-two.png' : '/images/mask.png'} 
                alt={isConnected ? 'Disconnect' : 'Connect'} 
                className="mask-image" 
              />
            </div>
          </div>
        </section>

        {/* Right Panel - Settings */}
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
        serverIp={currentProfile?.config.address}
        isConnected={isConnected}
      />
    </div>
  )
}

export default App
