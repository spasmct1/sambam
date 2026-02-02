package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	smb2 "github.com/sambam/sambam/smb/server"
	"github.com/sambam/sambam/smb/vfs"

	"github.com/spf13/pflag"
)

var (
	version = "1.0.0"
)

func main() {
	// CLI flags
	shareName := pflag.StringP("name", "n", "share", "Name of the SMB share")
	listenAddr := pflag.StringP("listen", "l", "0.0.0.0:445", "Address to listen on")
	readOnly := pflag.BoolP("readonly", "r", false, "Make share read-only")
	showVersion := pflag.BoolP("version", "v", false, "Show version")
	showHelp := pflag.BoolP("help", "h", false, "Show help")

	pflag.Parse()

	if *showHelp {
		printUsage()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("sambam %s\n", version)
		os.Exit(0)
	}

	// Determine directory to share
	shareDir := "."
	args := pflag.Args()
	if len(args) > 0 {
		shareDir = args[0]
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(shareDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(1)
	}

	// Verify directory exists
	info, err := os.Stat(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: %s is not a directory\n", absPath)
		os.Exit(1)
	}

	// Check if running as root (required for port 445)
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Warning: Not running as root. Port 445 typically requires root privileges.")
		fmt.Fprintln(os.Stderr, "         Consider using: sudo sambam")
	}

	// Create filesystem
	fs := NewPassthroughFS(absPath, *readOnly)

	// Get hostname for NTLM
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SAMBAM"
	}

	// Create server with anonymous/guest authentication
	srv := smb2.NewServer(
		&smb2.ServerConfig{
			AllowGuest: true,
		},
		&smb2.NTLMAuthenticator{
			TargetSPN:    "",
			NbDomain:     hostname,
			NbName:       hostname,
			DnsName:      hostname + ".local",
			DnsDomain:    ".local",
			UserPassword: map[string]string{}, // No users = guest only
			AllowGuest:   true,
		},
		map[string]vfs.VFSFileSystem{*shareName: fs},
	)

	// Get local IPs for display
	localIPs := getLocalIPs()

	fmt.Println("sambam - Instant SMB/CIFS file sharing")
	fmt.Println("-------------------------------------------")
	fmt.Printf("Sharing: %s\n", absPath)
	fmt.Printf("Share name: %s\n", *shareName)
	fmt.Printf("Read-only: %v\n", *readOnly)
	fmt.Printf("Listening on: %s\n", *listenAddr)
	fmt.Println()
	fmt.Println("Connect from Windows:")
	for _, ip := range localIPs {
		fmt.Printf("  \\\\%s\\%s\n", ip, *shareName)
	}
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Start server in goroutine
	go func() {
		if err := srv.Serve(*listenAddr); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
	srv.Shutdown()
}

func printUsage() {
	fmt.Println("sambam - Instant SMB/CIFS file sharing for Windows clients")
	fmt.Println()
	fmt.Println("Usage: sambam [options] [directory]")
	fmt.Println()
	fmt.Println("Options:")
	pflag.PrintDefaults()
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  sambam                    # Share current directory")
	fmt.Println("  sambam /path/to/folder    # Share specific directory")
	fmt.Println("  sambam -n myfiles .       # Share with custom name")
	fmt.Println("  sambam -r /data           # Read-only share")
}

func getLocalIPs() []string {
	var ips []string

	// Get actual network interface IPs
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			// Skip loopback and down interfaces
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				// Only IPv4 for simplicity
				if ip != nil && ip.To4() != nil {
					ips = append(ips, ip.String())
				}
			}
		}
	}

	if len(ips) == 0 {
		ips = append(ips, "<your-ip>")
	}

	return ips
}
