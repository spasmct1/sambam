# sambam

**The fastest way to share files with Windows.** No setup. No passwords. No patience required.

You know the drill: Your colleague needs a file. They're on Windows. You're on Linux. You could email it (if it's under 25MB). You could upload it to some cloud service (and wait). You could set up Samba (LOL, see you next week). Or...

```bash
sudo sambam /path/to/folder
```

Done. They open `\\your-ip\share` in Explorer. Files are flowing. You're a hero.

**sambam** is like `python -m http.server` but for Windows network shares. One command, instant SMB file sharing.

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
- **Anonymous access** - No passwords to forget (or share via sticky note)
- **Windows 11 compatible** - Full SMB2/3 protocol support
- **Single binary** - Copy it anywhere, run it everywhere
- **Daemon mode** - Run in background, stop when done
- **Pretty output** - Because life's too short for ugly terminals
- **Debug logging** - See who's connecting and what they're doing

## Installation

Download the latest release for your platform:

```bash
# Linux AMD64
curl -LO https://github.com/user/sambam/releases/latest/download/sambam-linux-amd64
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

# Read-only (they can look, but not touch)
sudo sambam -r /data

# Run as daemon (background)
sudo sambam -d /data

# Stop the daemon
sudo sambam stop

# Debug mode (see connections and file activity)
sudo sambam -D /data

# Daemon with logging
sudo sambam -d -D -L /var/log/sambam.log /data
```

## Options

```
-n, --name      Share name (default: "share")
-l, --listen    Listen address (default: "0.0.0.0:445")
-r, --readonly  Read-only mode
-D, --debug     Show connections and file activity
-d, --daemon    Run as background daemon
-p, --pidfile   PID file location (default: "/tmp/sambam.pid")
-L, --logfile   Log file for daemon mode
-v, --version   Show version
-h, --help      Show help
```

## Connecting from Windows

Once sambam is running, it shows you the exact path to use:

```
  🔗 sambam v1.1.0

  Sharing      /home/user/documents
  Share        share
  Listen       0.0.0.0:445
  Mode         read-write

  Connect from Windows:
    \\192.168.1.100\share
    \\10.0.0.5\share

  Press Ctrl+C to stop
```

From Windows:
1. Open **File Explorer**
2. Type the path in the address bar: `\\192.168.1.100\share`
3. Press Enter
4. Profit

Or mount as a drive:
```cmd
net use Z: \\192.168.1.100\share
```

## Debug Output

With `-D` flag, see what's happening in real-time:

```
  15:04:05 connect 192.168.1.100:54321
  15:04:10 create file documents/report.docx
  15:04:12 create dir  backup
  15:04:15 delete temp/old-file.txt
```

## Requirements

- **Root privileges** - Port 445 requires root (or use `-l :8445` for non-standard port)
- **Linux** - Tested on Debian 12, Ubuntu 22.04
- **Windows client** - Windows 10/11 with SMB2/3

## Security Notice

sambam uses anonymous/guest authentication. This means:

- **No passwords** - Anyone on your network can access the share
- **Use on trusted networks only** - Don't run this on public WiFi
- **Not for production** - This is for quick file transfers, not Fort Knox

When in doubt, use `-r` for read-only mode.

## License

AGPL-3.0

---

*Made for those moments when you just need to share a damn file.*
