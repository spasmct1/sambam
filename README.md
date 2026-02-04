# sambam

**The fastest way to share files with Windows and macOS.** No setup. No passwords. No patience required.

You know the drill: Your colleague needs a file. They're on Windows. You're on Linux. You could email it (if it's under 25MB). You could upload it to some cloud service (and wait). You could set up Samba (LOL, see you next week). Or...

```bash
sudo sambam /path/to/folder
```

Done. They open `\\your-ip\share` in Explorer. Files are flowing. You're a hero.
**sambam** is like `python -m http.server` but for Windows network shares. One command, instant SMB file sharing.

![Demo](demo.gif)

## Why sambam?

| The Old Way | The sambam Way |
|-------------|----------------|
| Install Samba | `sudo sambam .` |
| Edit smb.conf | That's it. |
| Configure users | Seriously. |
| Restart services | You're done. |
| Debug permissions | Go grab coffee. |
| Google error messages | |
| Cry softly | |

## Features

- **Zero configuration** - No config files, no setup wizards, no existential dread
- **Anonymous access** - No passwords by default (or add authentication if needed)
- **Optional authentication** - Require username/password when you need it
- **Multiple shares** - Share multiple directories with different names
- **Auto-expire** - Automatically stop sharing after a set time
- **Config file** - Save your settings in `~/.sambamrc`
- **Cross-platform clients** - Works with Windows 10/11 and macOS
- **Single binary** - Runs on any Linux distribution (Debian, Ubuntu, OpenWrt, etc.)
- **Daemon mode** - Run in background, stop when done

## Installation

Download the latest binary from the [Releases](https://github.com/darkpenguin23/sambam/releases) page, then: 

```bash
chmod +x sambam-linux-amd64
sudo mv sambam-linux-amd64 /usr/local/bin/sambam
```

Or build from source:

```bash
go build -o sambam .
```

## Usage

```bash
# Share current directory
sudo sambam

# Share a specific folder
sudo sambam /path/to/folder

# Custom share name
sudo sambam -n photos ~/Pictures

# Multiple shares
sudo sambam -n docs:/home/user/documents -n pics:/home/user/photos

# Read-only (they can look, but not touch)
sudo sambam -r /data

# Require authentication (generates random password)
sudo sambam --username admin /data

# Require authentication with specific password
sudo sambam --username admin --password secret123 /data

# Auto-expire after 30 minutes
sudo sambam --expire 30m /data

# Run as daemon (background)
sudo sambam -d /data

# Stop the daemon
sudo sambam stop

# Debug mode (see connections and file activity)
sudo sambam --debug /data

# Hide dotfiles (files starting with '.')
sudo sambam --hide-dotfiles /data

# Daemon with logging and authentication
sudo sambam -d --debug --username admin -L /var/log/sambam.log /data
```




## Options

```
-n, --name       Share name or name:path (repeatable for multiple shares)
-l, --listen     Listen address (default: "0.0.0.0:445")
-r, --readonly   Read-only mode
--username       Require authentication with this username
--password       Password for authentication (random if not set)
--expire         Auto-shutdown after duration (e.g., 30m, 1h, 2h30m)
--debug          Show connections and file activity
--hide-dotfiles  Hide files starting with '.' (visible by default)
-d, --daemon     Run as background daemon
-p, --pidfile    PID file location (default: "/tmp/sambam.pid")
-L, --logfile    Log file for daemon mode
-v, --version    Show version
-h, --help       Show help
```

## Configuration File

You can save your settings in `~/.sambamrc` (TOML format):

```toml
# Listen address
listen = "0.0.0.0:445"

# Read-only mode
readonly = false

# Debug mode
debug = true

# Authentication
username = "admin"
password = "secret123"

# Auto-expire
expire = "1h"

# Multiple shares
[shares]
docs = "/home/user/documents"
pics = "/home/user/photos"
```

CLI flags override config file settings. See `sambamrc.example` for a full example.

## Connecting from Windows

Once sambam is running, it shows you the exact path to use:

```
  🔗 sambam v1.2.0

  Sharing      /home/user/documents
  Share        share
  Listen       0.0.0.0:445
  Mode         read-write
  Auth         anonymous

  Connect from Windows:
    \\192.168.1.100\share

  Press Ctrl+C to stop
```

With authentication enabled:

```
  🔗 sambam v1.2.0

  Sharing      /home/user/documents
  Share        share
  Listen       0.0.0.0:445
  Mode         read-write
  Auth         admin:xK9mQ2pL5n

  Connect from Windows:
    \\192.168.1.100\share

  Press Ctrl+C to stop
```

From Windows:
1. Open **File Explorer**
2. Type the path in the address bar: `\\192.168.1.100\share`
3. Press Enter
4. If authentication is required, enter the username and password

Or mount as a drive with credentials:
```cmd
net use Z: \\192.168.1.100\share /user:admin
```

## Windows Credential Troubleshooting

Windows caches SMB credentials. If you're having authentication issues:

```cmd
# List active connections
net use

# Disconnect a specific share
net use \\192.168.1.100\share /delete

# Or disconnect all shares
net use * /delete
```

After clearing cached connections, reconnect and Windows will prompt for new credentials.

## Debug Output

With `--debug` flag, see what's happening in real-time:

```
  15:04:05 connect 192.168.1.100:54321
  15:04:10 create file documents/report.docx
  15:04:12 create dir  backup
  15:04:15 delete temp/old-file.txt
```

## Requirements

- **Root privileges** - Port 445 requires root (or use `-l :8445` for non-standard port)
- **Linux server** - Works on any distribution (Debian, Ubuntu, OpenWrt, Alpine, etc.)
- **Clients** - Windows 10/11 or macOS (any version with SMB support)

## Security Notice

By default, sambam uses anonymous/guest authentication. This means:

- **No passwords** - Anyone on your network can access the share
- **Use on trusted networks only** - Don't run this on public WiFi
- **Not for production** - This is for quick file transfers, not Fort Knox

For sensitive shares, use `--username` to require authentication, and `-r` for read-only mode.

## License

AGPL-3.0

---
*Idea and design by a human, programming by an AI*
*Made for those moments when you just need to share a damn file.*
