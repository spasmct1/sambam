package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/sevlyar/go-daemon"
	"github.com/spf13/pflag"

	smb2 "github.com/sambam/sambam/smb/server"
	"github.com/sambam/sambam/smb/vfs"
)

var (
	version = "1.1.0"
)

func main() {
	// Check for stop subcommand before flag parsing
	if len(os.Args) > 1 && os.Args[1] == "stop" {
		stopDaemon()
		return
	}

	// CLI flags
	shareName := pflag.StringP("name", "n", "share", "Name of the SMB share")
	listenAddr := pflag.StringP("listen", "l", "0.0.0.0:445", "Address to listen on")
	readOnly := pflag.BoolP("readonly", "r", false, "Make share read-only")
	showVersion := pflag.BoolP("version", "v", false, "Show version")
	showHelp := pflag.BoolP("help", "h", false, "Show help")

	// Daemon mode flags
	daemonMode := pflag.BoolP("daemon", "d", false, "Run as background daemon")
	pidFile := pflag.StringP("pidfile", "p", "/tmp/sambam.pid", "PID file location (daemon mode)")
	logFile := pflag.StringP("logfile", "L", "", "Log file path (daemon mode)")

	// Debug flag
	debugMode := pflag.BoolP("debug", "D", false, "Show client connections")

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

	// Handle daemon mode
	if *daemonMode {
		// Set log output to file if specified
		logFileName := *logFile
		if logFileName == "" {
			logFileName = "/dev/null"
		}

		// Get current working directory to preserve it in daemon
		cwd, _ := os.Getwd()

		ctx := &daemon.Context{
			PidFileName: *pidFile,
			PidFilePerm: 0644,
			LogFileName: logFileName,
			LogFilePerm: 0640,
			WorkDir:     cwd,
			Umask:       027,
		}

		child, err := ctx.Reborn()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to start daemon: %v\n", err)
			os.Exit(1)
		}

		if child != nil {
			// Parent process
			fmt.Printf("Daemon started with PID %d\n", child.Pid)
			fmt.Printf("PID file: %s\n", *pidFile)
			if *logFile != "" {
				fmt.Printf("Log file: %s\n", *logFile)
			}
			fmt.Println("Use 'sambam stop' to stop the daemon")
			os.Exit(0)
		}

		// Child process continues
		defer ctx.Release()

		// Disable colors in daemon mode (no terminal)
		DisableColors()

		// Setup logging
		if *logFile != "" {
			log.Printf("sambam daemon started, sharing %s as %s", absPath, *shareName)
		}
	}

	// Create filesystem
	fs := NewPassthroughFS(absPath, *readOnly)

	// Setup filesystem callbacks for debug mode
	if *debugMode {
		fs.OnCreate = func(path string, isDir bool) {
			timestamp := time.Now().Format("15:04:05")
			typeStr := "file"
			if isDir {
				typeStr = "dir"
			}
			if *daemonMode {
				log.Printf("Created %s: %s", typeStr, path)
			} else {
				fmt.Printf("  %s %s %s %s\n", Dim(timestamp), Green("create"), Dim(typeStr), path)
			}
		}
		fs.OnDelete = func(path string) {
			timestamp := time.Now().Format("15:04:05")
			if *daemonMode {
				log.Printf("Deleted: %s", path)
			} else {
				fmt.Printf("  %s %s %s\n", Dim(timestamp), Red("delete"), path)
			}
		}
	}

	// Get hostname for NTLM
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SAMBAM"
	}

	// Setup connection callback for debug mode
	var onConnect func(string)
	if *debugMode {
		onConnect = func(remoteAddr string) {
			timestamp := time.Now().Format("15:04:05")
			if *daemonMode {
				log.Printf("Connection from %s", remoteAddr)
			} else {
				fmt.Printf("  %s %s %s\n", Dim(timestamp), Green("connect"), remoteAddr)
			}
		}
	}

	// Create server with anonymous/guest authentication
	srv := smb2.NewServer(
		&smb2.ServerConfig{
			AllowGuest: true,
			OnConnect:  onConnect,
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

	// Parse listen address and add default port if needed
	listenHost, listenPort := parseHostPort(*listenAddr)
	if listenPort == "" {
		listenPort = "445"
	}
	fullListenAddr := net.JoinHostPort(listenHost, listenPort)

	// Get IPs for display
	var displayIPs []string
	if listenHost == "0.0.0.0" || listenHost == "" {
		displayIPs = getLocalIPs()
	} else {
		displayIPs = []string{listenHost}
	}

	// Format connection string with port if non-standard
	portSuffix := ""
	if listenPort != "445" {
		portSuffix = ":" + listenPort
	}

	// Print banner (skipped in daemon mode without logfile)
	if !*daemonMode {
		printBanner(absPath, *shareName, *readOnly, fullListenAddr, displayIPs, portSuffix)
	}

	// Start server in goroutine
	go func() {
		if err := srv.Serve(fullListenAddr); err != nil {
			if *daemonMode && *logFile != "" {
				log.Printf("Server error: %v", err)
			} else if !*daemonMode {
				fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			}
			os.Exit(1)
		}
	}()

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	if *daemonMode && *logFile != "" {
		log.Println("Shutting down...")
	} else if !*daemonMode {
		fmt.Println("\nShutting down...")
	}
	srv.Shutdown()
}

func printBanner(absPath, shareName string, readOnly bool, listenAddr string, displayIPs []string, portSuffix string) {
	fmt.Println()
	fmt.Printf("  %s\n", CyanBold("🔗 sambam v"+version))
	fmt.Println()
	fmt.Printf("  %-12s %s\n", "Sharing", Green(absPath))
	fmt.Printf("  %-12s %s\n", "Share", Yellow(shareName))
	fmt.Printf("  %-12s %s\n", "Listen", listenAddr)

	modeStr := "read-write"
	if readOnly {
		modeStr = Red("read-only")
	} else {
		modeStr = Green("read-write")
	}
	fmt.Printf("  %-12s %s\n", "Mode", modeStr)
	fmt.Println()
	fmt.Println("  Connect from Windows:")
	for _, ip := range displayIPs {
		fmt.Printf("    %s\n", Cyan(fmt.Sprintf("\\\\%s%s\\%s", ip, portSuffix, shareName)))
	}
	fmt.Println()
	fmt.Printf("  %s\n", Dim("Press Ctrl+C to stop"))
	fmt.Println()
}

func printUsage() {
	fmt.Println()
	fmt.Printf("  %s\n", CyanBold("🔗 sambam v"+version))
	fmt.Println()
	fmt.Println(Dim("  Instant SMB/CIFS file sharing for Windows clients"))
	fmt.Println()
	fmt.Println(Bold("  Usage:"))
	fmt.Printf("    %s [options] [directory]\n", Cyan("sambam"))
	fmt.Printf("    %s\n", Cyan("sambam stop"))
	fmt.Println()
	fmt.Println(Bold("  Options:"))
	fmt.Printf("    %s, %s    Name of the SMB share %s\n", Green("-n"), Green("--name"), Dim("(default: share)"))
	fmt.Printf("    %s, %s  Address to listen on %s\n", Green("-l"), Green("--listen"), Dim("(default: 0.0.0.0:445)"))
	fmt.Printf("    %s, %s  Make share read-only\n", Green("-r"), Green("--readonly"))
	fmt.Printf("    %s, %s   Show client connections\n", Green("-D"), Green("--debug"))
	fmt.Printf("    %s, %s  Run as background daemon\n", Green("-d"), Green("--daemon"))
	fmt.Printf("    %s, %s  PID file location %s\n", Green("-p"), Green("--pidfile"), Dim("(default: /tmp/sambam.pid)"))
	fmt.Printf("    %s, %s  Log file path (daemon mode)\n", Green("-L"), Green("--logfile"))
	fmt.Printf("    %s, %s  Show version\n", Green("-v"), Green("--version"))
	fmt.Printf("    %s, %s    Show help\n", Green("-h"), Green("--help"))
	fmt.Println()
	fmt.Println(Bold("  Examples:"))
	fmt.Printf("    %s                    %s\n", Cyan("sambam"), Dim("# Share current directory"))
	fmt.Printf("    %s    %s\n", Cyan("sambam /path/to/folder"), Dim("# Share specific directory"))
	fmt.Printf("    %s       %s\n", Cyan("sambam -n myfiles ."), Dim("# Share with custom name"))
	fmt.Printf("    %s           %s\n", Cyan("sambam -r /data"), Dim("# Read-only share"))
	fmt.Printf("    %s           %s\n", Cyan("sambam -d /data"), Dim("# Run as daemon"))
	fmt.Printf("    %s               %s\n", Cyan("sambam stop"), Dim("# Stop running daemon"))
	fmt.Println()
}

func parseHostPort(addr string) (host, port string) {
	// Try to split as host:port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// No port specified, treat entire string as host
		return addr, ""
	}
	return host, port
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

func stopDaemon() {
	// Allow custom PID file via -p flag after "stop"
	pidFilePath := "/tmp/sambam.pid"
	if len(os.Args) > 2 {
		// Check for -p or --pidfile flag
		for i := 2; i < len(os.Args); i++ {
			if os.Args[i] == "-p" || os.Args[i] == "--pidfile" {
				if i+1 < len(os.Args) {
					pidFilePath = os.Args[i+1]
				}
				break
			}
		}
	}

	// Read PID file
	data, err := os.ReadFile(pidFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "No daemon running (PID file not found: %s)\n", pidFilePath)
		} else {
			fmt.Fprintf(os.Stderr, "Error reading PID file: %v\n", err)
		}
		os.Exit(1)
	}

	// Parse PID
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid PID in file: %v\n", err)
		os.Exit(1)
	}

	// Find the process
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Process not found: %v\n", err)
		os.Exit(1)
	}

	// Send SIGTERM
	fmt.Printf("Stopping sambam daemon (PID %d)...\n", pid)
	err = process.Signal(syscall.SIGTERM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending signal: %v\n", err)
		os.Exit(1)
	}

	// Wait for process to exit (with timeout)
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		// Check if process is still running
		err = process.Signal(syscall.Signal(0))
		if err != nil {
			// Process is gone
			fmt.Println("Daemon stopped")
			// Clean up PID file if it still exists
			os.Remove(pidFilePath)
			return
		}
	}

	fmt.Fprintln(os.Stderr, "Warning: Daemon may not have stopped cleanly")
}
