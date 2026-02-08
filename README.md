<p align="center">
  <img src="public/images/mask.png" alt="Zen Privacy" width="120">
</p>

<h1 align="center">Zen Privacy</h1>

<p align="center">
  <strong>Privacy protection client for Windows and Linux</strong>
</p>

<p align="center">
  <a href="https://github.com/zen-privacy/zen/releases/latest">
    <img src="https://img.shields.io/github/v/release/zen-privacy/zen?style=flat-square" alt="Release">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-CC%20BY--NC%204.0-blue?style=flat-square" alt="License">
  </a>
</p>

---

## Features

- **VLESS Protocol** — VLESS with Reality, WebSocket+TLS transport
- **Hysteria2 Protocol** — QUIC-based protocol with optional obfuscation
- **TUN Mode** — Routes all system traffic through encrypted tunnel
- **Kill Switch** — Blocks traffic on VPN disconnect to prevent IP leaks
- **Auto-reconnect** — Automatic reconnection with exponential backoff
- **Smart Routing** — Country-based rule sets for selective proxying
- **Traffic Stats** — Real-time upload/download monitoring
- **Auto-updates** — Built-in update mechanism with one-click installation
- **Cross-platform** — Windows and Linux support
- **Auto-download Engine** — sing-box core downloaded automatically

## Installation

### Windows

Download `ZenPrivacy_x.x.x_x64-setup.exe` from [Releases](https://github.com/zen-privacy/zen/releases/latest) and run the installer.

### Linux

Download from [Releases](https://github.com/zen-privacy/zen/releases/latest):

```bash
# Debian / Ubuntu
sudo dpkg -i zen-privacy_*_amd64.deb

# Fedora / RHEL
sudo dnf install zen-privacy-*.x86_64.rpm
```

## Quick Start

1. **Launch** Zen Privacy from your applications menu
2. **Download Engine** — Click the button on first run (one-time setup)
3. **Add Server** — Paste a `vless://` or `hysteria2://` link, or import a sing-box JSON config
4. **Connect** — Click the mask to connect
5. **Enjoy** — Your traffic is now protected

## Auto-Updates

Zen Privacy checks for updates automatically. When a new version is available:

1. Go to **Settings** → **Check for Updates**
2. Click **Install Update**
3. The new version will be downloaded and installed automatically

## Building from Source

### Requirements

- Node.js 20+
- Rust 1.70+
- **Linux**: `libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev patchelf`

### Build

```bash
# Install dependencies
npm install

# Development mode
npm run tauri dev

# Production build
npm run tauri build
```

## Linux Notes

### GNOME Tray Support

GNOME hides tray icons by default. To enable:

1. Install `gnome-shell-extension-appindicator`
2. Enable "AppIndicator and KStatusNotifierItem Support" extension
3. Restart GNOME Shell

## License

This project is licensed under [Creative Commons Attribution-NonCommercial 4.0 International](LICENSE).

**You are free to:**
- Share — copy and redistribute the material
- Adapt — remix, transform, and build upon the material

**Under the following terms:**
- **Attribution** — You must give appropriate credit
- **NonCommercial** — You may not use the material for commercial purposes

---

<p align="center">
  Made with ❤️ for privacy
</p>
