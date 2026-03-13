# macOS: Архитектура привилегированных операций

## Проблема

VPN-клиент на macOS требует root-привилегии для:
- Создания TUN-интерфейса (`utun99`)
- Управления маршрутами (`route add/delete`)
- Управления файрволом (`pfctl`)
- Управления системным DNS (`networksetup`)

macOS не кэширует авторизацию `osascript do shell script with administrator privileges` — каждый вызов показывает диалог пароля. В отличие от Linux (pkexec кэширует через polkit) и Windows (UAC один раз на процесс).

### Что было до исправлений (v2.2.0-beta, коммит f369b74)

Каждая операция вызывала `osascript` отдельно:
- **Connect**: osascript (route + pfctl + sing-box) — OK, пользователь ожидает
- **Reconnect при крэше**: osascript заново — спам паролем каждые 5 сек
- **Disconnect**: osascript (killall + pfctl cleanup) — ещё один пароль
- **Любой крэш sing-box** → health monitor → `attempt_reconnection` → osascript → пароль

Также: `route add` без предварительного `route delete` падал с "File exists" при повторном подключении. Вывод route-команд попадал в stdout osascript и интерпретировался как ошибка.

## Решение: LaunchDaemon

Используем нативный механизм macOS — `launchd` (аналог systemd на Linux).

### Архитектура

```
┌─────────────────────────────────────────────────────┐
│  Tauri App (пользовательский процесс)               │
│                                                     │
│  Connect:                                           │
│    1. Генерирует sing-box config.json               │
│    2. Генерирует zen-vpn-launcher.sh                │
│    3. Генерирует com.zen.vpn.plist                  │
│    4. ONE osascript → launchctl bootstrap            │
│                                                     │
│  Disconnect:                                        │
│    1. ONE osascript → launchctl bootout + cleanup    │
│    2. restore_dns() из dns-backup.txt               │
│                                                     │
│  Health Monitor:                                    │
│    - pgrep -x sing-box (каждые 5 сек)              │
│    - Если sing-box мёртв но launchd job жив →       │
│      статус Restarting (launchd перезапускает)       │
│    - Если launchd job тоже мёртв → статус Failed    │
│    - НЕ вызывает reconnect на macOS                 │
└──────────────────────┬──────────────────────────────┘
                       │ osascript (1 раз)
                       ▼
┌─────────────────────────────────────────────────────┐
│  launchd (system domain, root)                      │
│                                                     │
│  /Library/LaunchDaemons/com.zen.vpn.plist           │
│    - RunAtLoad: true                                │
│    - KeepAlive.SuccessfulExit: false                │
│    - ThrottleInterval: 3 сек                        │
│                                                     │
│  При крэше sing-box:                                │
│    launchd автоматически перезапускает               │
│    zen-vpn-launcher.sh → exec sing-box              │
│    Без пароля. Без участия Tauri.                   │
└──────────────────────┬──────────────────────────────┘
                       │ exec
                       ▼
┌─────────────────────────────────────────────────────┐
│  zen-vpn-launcher.sh (запускается launchd, root)    │
│                                                     │
│  При каждом запуске/перезапуске:                     │
│    1. route delete + route add (серверный маршрут)   │
│    2. pfctl -a com.zen.vpn -f ... (kill switch)     │
│    3. Бэкап системного DNS → dns-backup.txt         │
│    4. networksetup -setdnsservers → 223.5.5.5       │
│    5. exec sing-box run -c config.json              │
│                                                     │
│  exec заменяет bash на sing-box —                   │
│  launchd отслеживает реальный PID sing-box          │
└─────────────────────────────────────────────────────┘
```

### Файлы (все в ~/Library/Application Support/zen-vpn/)

| Файл | Назначение |
|------|-----------|
| `config.json` | Конфигурация sing-box |
| `zen-vpn-launcher.sh` | Скрипт запуска (routes, pfctl, DNS, exec sing-box) |
| `com.zen.vpn.plist` | Staging-копия plist (копируется в /Library/LaunchDaemons/) |
| `pf-killswitch.conf` | Правила pfctl для kill switch |
| `dns-backup.txt` | Бэкап оригинальных DNS всех интерфейсов |
| `singbox.log` | Лог sing-box (stdout/stderr через plist) |

### Сценарии

**Connect (1 пароль):**
```
osascript → launchctl bootout (cleanup старого)
          → cp plist /Library/LaunchDaemons/
          → chmod +x launcher.sh
          → launchctl bootstrap system plist
```

**Крэш sing-box (0 паролей):**
```
launchd обнаруживает exit → ждёт ThrottleInterval (3 сек) → запускает launcher.sh заново
launcher.sh: route + pfctl + DNS + exec sing-box
```

**Disconnect (1 пароль):**
```
osascript → launchctl bootout (останавливает sing-box)
          → pfctl -a com.zen.vpn -F all
          → route delete
          → rm plist
restore_dns() → читает dns-backup.txt → networksetup -setdnsservers empty
```

## DNS Leak Prevention

### Проблема
На macOS `strict_route: false` (нельзя `true` — routing loop). Системный DNS-резолвер обходит TUN и идёт напрямую к провайдеру. whoer.net показывает IP провайдера.

### Решение
Launcher-скрипт (root) при каждом старте sing-box:
1. Сохраняет текущий DNS каждого сетевого интерфейса в `dns-backup.txt`
2. `networksetup -setdnsservers "$svc" 223.5.5.5 1.1.1.1` — перенаправляет системный DNS
3. Эти запросы идут через TUN → sing-box → proxy

При отключении `restore_dns()` восстанавливает оригинальные DNS из бэкапа.

## ProcessHealthStatus::Restarting

Новый статус в health monitor. На macOS, когда sing-box не найден через `pgrep`, но `launchctl print system/com.zen.vpn` успешен — значит launchd перезапускает процесс. Health monitor воспринимает это как healthy (временный gap) и не пытается реконнектить.

## endpoint_independent_nat: true

По умолчанию включен для всех платформ. Критично для VoIP (Telegram звонки, WebRTC). Без этого sing-box привязывает UDP-сессию к конкретному destination port; серверы VoIP часто меняют порты (STUN/ICE), что обрывает звонок.

## Платформенные различия

| | macOS | Linux | Windows |
|---|---|---|---|
| Привилегии | LaunchDaemon (osascript 1 раз) | pkexec (кэширует) | UAC (1 раз на процесс) |
| Авто-рестарт | launchd KeepAlive | Health monitor + reconnect | Health monitor + reconnect |
| Kill switch | pfctl anchor | nftables/iptables | netsh |
| DNS leak fix | networksetup | systemd-resolved | Adapter DNS |
| TUN stack | system | gvisor | gvisor |
| strict_route | false (routing loop) | true | true |
