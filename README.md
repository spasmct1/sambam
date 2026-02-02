# sambam

Instant SMB/CIFS file sharing for Windows clients. Like `python -m http.server` but for Windows network shares.

## Features

- **Zero configuration** - Just run and share
- **Anonymous access** - No username/password required
- **Windows 11 compatible** - SMB2/3 protocol support
- **Single binary** - No dependencies, easy deployment
- **Read-only mode** - Optional protection against modifications

## Usage

```bash
# Share current directory (requires root for port 445)
sudo ./sambam

# Share a specific directory
sudo ./sambam /path/to/folder

# Custom share name
sudo ./sambam -n myfiles /path/to/folder

# Read-only share
sudo ./sambam -r /data

# Use non-standard port (doesn't require root)
sudo ./sambam -l 0.0.0.0:4455 .
```

## Options

```
-n, --name string     Name of the SMB share (default "share")
-l, --listen string   Address to listen on (default "0.0.0.0:445")
-r, --readonly        Make share read-only
-v, --version         Show version
-h, --help            Show help
```

## Connecting from Windows

After starting sambam, connect from Windows:

1. Open File Explorer
2. Type in the address bar: `\\<server-ip>\share`
3. Press Enter

Or from Command Prompt:
```cmd
net use Z: \\<server-ip>\share
```

## Building

```bash
# Standard build
go build -o sambam .

# Static optimized build
CGO_ENABLED=0 go build -ldflags="-s -w" -o sambam .
```

## Requirements

- Port 445 requires root/administrator privileges
- Linux (tested on Debian 12)
- Windows 11 client support (SMB2/3)

## Notes

- This tool uses anonymous/guest authentication - suitable for quick file transfers on trusted networks
- Not recommended for production use or sensitive data
- Based on SMB2/3 protocol implementation

## License

AGPL-3.0 (based on macos-fuse-t/go-smb2)
