package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/sevlyar/go-daemon"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	smb2 "github.com/sambam/sambam/smb/server"
	"github.com/sambam/sambam/smb/vfs"
)

// Share represents a named share with its path
type Share struct {
	Name string
	Path string
}

// Config represents the ~/.sambamrc configuration file
type Config struct {
	Listen       string            `toml:"listen"`
	Readonly     bool              `toml:"readonly"`
	Verbose      bool              `toml:"verbose"`
	VerboseLevel int               `toml:"verbose_level"`
	Debug        bool              `toml:"debug"` // backward compatibility: maps to verbose_level=3
	Trace        bool              `toml:"trace"`
	HideDotfiles bool              `toml:"hide_dotfiles"`
	Username     string            `toml:"username"`
	Password     string            `toml:"password"`
	Expire       string            `toml:"expire"`
	PidFile      string            `toml:"pidfile"`
	LogFile      string            `toml:"logfile"`
	Shares       map[string]string `toml:"shares"`
}

// loadConfig loads configuration from ~/.sambamrc if it exists
func loadConfig() *Config {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	configPath := filepath.Join(home, ".sambamrc")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil
	}

	var config Config
	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Error reading %s: %v\n", configPath, err)
		return nil
	}

	return &config
}

// logFormatter formats logrus entries to match sambam output style:
//
//	16:47:19 authenticated: guest
type logFormatter struct {
	showLevel bool
}

func (f *logFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	ts := Dim(entry.Time.Format("15:04:05"))
	if !f.showLevel {
		return []byte(fmt.Sprintf("  %s %s\n", ts, entry.Message)), nil
	}

	level := strings.ToUpper(entry.Level.String())
	levelTag := "[" + level + "]"
	switch entry.Level {
	case logrus.TraceLevel:
		levelTag = Dim("[TRC]")
	case logrus.DebugLevel:
		levelTag = Cyan("[DBG]")
	case logrus.InfoLevel:
		levelTag = Green("[INF]")
	case logrus.WarnLevel:
		levelTag = Yellow("[WRN]")
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		levelTag = Red("[ERR]")
	}

	return []byte(fmt.Sprintf("  %s %s %s\n", ts, levelTag, entry.Message)), nil
}

// generatePassword creates a random alphanumeric password
func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

var (
	version = "1.4.9"
)

func main() {
	// Check for stop subcommand before flag parsing
	if len(os.Args) > 1 && os.Args[1] == "stop" {
		stopDaemon()
		return
	}

	// Load config file
	config := loadConfig()

	// CLI flags
	shareSpecs := pflag.StringArrayP("name", "n", []string{}, "Share specification (name:path or just name)")
	listenAddr := pflag.StringP("listen", "l", "0.0.0.0:445", "Address to listen on")
	readOnly := pflag.BoolP("readonly", "r", false, "Make share read-only")
	showVersion := pflag.BoolP("version", "V", false, "Show version")
	showHelp := pflag.BoolP("help", "h", false, "Show help")

	// Daemon mode flags
	daemonMode := pflag.BoolP("daemon", "d", false, "Run as background daemon")
	pidFile := pflag.StringP("pidfile", "p", "/tmp/sambam.pid", "PID file location (daemon mode)")
	logFile := pflag.StringP("logfile", "L", "", "Log file path (daemon mode)")

	// Verbosity flags
	verbose := pflag.CountP("verbose", "v", "Show connections and file activity (-vv extended, -vvv full trace)")
	traceMode := pflag.Bool("trace", false, "Show full protocol trace (very verbose)")

	// Hidden files flag
	hideDotfiles := pflag.Bool("hide-dotfiles", false, "Hide files starting with '.'")

	// Authentication flags
	username := pflag.String("username", "", "Require authentication with this username")
	password := pflag.String("password", "", "Password for authentication (random if not specified)")

	// Auto-expire flag
	expireStr := pflag.String("expire", "", "Auto-shutdown after duration (e.g., 30m, 1h, 2h30m)")

	pflag.Parse()

	// Apply config file values where CLI flags weren't explicitly set
	if config != nil {
		if !pflag.CommandLine.Changed("listen") && config.Listen != "" {
			*listenAddr = config.Listen
		}
		if !pflag.CommandLine.Changed("readonly") && config.Readonly {
			*readOnly = true
		}
		if !pflag.CommandLine.Changed("verbose") {
			if config.VerboseLevel > 0 {
				*verbose = config.VerboseLevel
			} else if config.Verbose {
				*verbose = 1
			} else if config.Debug {
				*verbose = 3
			}
		}
		if !pflag.CommandLine.Changed("trace") && config.Trace {
			*traceMode = true
		}
		if !pflag.CommandLine.Changed("username") && config.Username != "" {
			*username = config.Username
		}
		if !pflag.CommandLine.Changed("password") && config.Password != "" {
			*password = config.Password
		}
		if !pflag.CommandLine.Changed("expire") && config.Expire != "" {
			*expireStr = config.Expire
		}
		if !pflag.CommandLine.Changed("hide-dotfiles") && config.HideDotfiles {
			*hideDotfiles = true
		}
		if !pflag.CommandLine.Changed("pidfile") && config.PidFile != "" {
			*pidFile = config.PidFile
		}
		if !pflag.CommandLine.Changed("logfile") && config.LogFile != "" {
			*logFile = config.LogFile
		}
	}

	// Set log level and formatter
	if *traceMode {
		logrus.SetLevel(logrus.TraceLevel)
		logrus.SetFormatter(&logFormatter{showLevel: true})
	} else if *verbose >= 3 {
		logrus.SetLevel(logrus.TraceLevel)
		logrus.SetFormatter(&logFormatter{showLevel: true})
	} else if *verbose >= 2 {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.SetFormatter(&logFormatter{showLevel: true})
	} else if *verbose > 0 {
		logrus.SetLevel(logrus.InfoLevel)
		logrus.SetFormatter(&logFormatter{showLevel: true})
	} else {
		logrus.SetLevel(logrus.ErrorLevel)
	}

	extraVerbose := *verbose >= 2
	fullVerbose := *verbose >= 3

	if *showHelp {
		printUsage()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("sambam %s (built with AI assistance)\n", version)
		os.Exit(0)
	}

	// Parse shares
	var shares []Share
	args := pflag.Args()

	if len(*shareSpecs) == 0 && len(args) == 0 {
		// No -n flags and no positional arg: use config shares or current dir
		if config != nil && len(config.Shares) > 0 {
			for name, path := range config.Shares {
				absPath, err := filepath.Abs(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error resolving path for '%s': %v\n", name, err)
					os.Exit(1)
				}
				shares = append(shares, Share{Name: name, Path: absPath})
			}
		} else {
			// Default: share current directory using folder name
			absPath, err := filepath.Abs(".")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
				os.Exit(1)
			}
			shares = append(shares, Share{Name: shareName(absPath), Path: absPath})
		}
	} else if len(*shareSpecs) == 0 {
		// No -n flags but have positional arg: use folder name
		absPath, err := filepath.Abs(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
			os.Exit(1)
		}
		shares = append(shares, Share{Name: shareName(absPath), Path: absPath})
	} else {
		// Parse each -n flag
		for _, spec := range *shareSpecs {
			var name, path string
			if strings.Contains(spec, ":") {
				parts := strings.SplitN(spec, ":", 2)
				name = parts[0]
				path = parts[1]
			} else {
				// Just a name, use positional arg or current dir
				name = spec
				if len(args) > 0 {
					path = args[0]
				} else {
					path = "."
				}
			}
			absPath, err := filepath.Abs(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving path for '%s': %v\n", name, err)
				os.Exit(1)
			}
			shares = append(shares, Share{Name: name, Path: absPath})
		}
	}

	// Verify all share directories exist
	for _, share := range shares {
		info, err := os.Stat(share.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if !info.IsDir() {
			fmt.Fprintf(os.Stderr, "Error: %s is not a directory\n", share.Path)
			os.Exit(1)
		}
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
			var shareNames []string
			for _, s := range shares {
				shareNames = append(shareNames, s.Name)
			}
			log.Printf("sambam daemon started, sharing: %s", strings.Join(shareNames, ", "))
		}
	}

	// Create filesystems for all shares
	vfsShares := make(map[string]vfs.VFSFileSystem)
	for _, share := range shares {
		fs := NewPassthroughFS(share.Path, *readOnly)

		// Setup filesystem callbacks for verbose mode
		if *verbose > 0 {
			fs.OnCreate = func(path string, isDir bool) {
				typeStr := "file"
				if isDir {
					typeStr = "dir"
				}
				logrus.Infof("create: %s %s", typeStr, path)
			}
			fs.OnOverwrite = func(path string) {
				logrus.Infof("replace: %s", path)
			}
			fs.OnDelete = func(path string) {
				logrus.Infof("delete: %s", path)
			}
		}
		if extraVerbose {
			fs.OnOpen = func(path string, mode string) {
				path = normalizeLogPath(path)
				logrus.Infof("open: %s (%s)", path, mode)
			}
			fs.OnDirRead = func(path string) {
				path = normalizeLogPath(path)
				logrus.Infof("dir read: %s", path)
			}
			fs.OnRead = func(path string) {
				path = normalizeLogPath(path)
				logrus.Infof("read: %s", path)
			}
			fs.OnClose = func(path string, mode string, readBytes uint64, writeBytes uint64) {
				path = normalizeLogPath(path)
				summary := fmt.Sprintf("r=%s w=%s", formatBytes(readBytes), formatBytes(writeBytes))
				logrus.Infof("close: %s (%s) %s", path, mode, summary)
			}
			fs.OnSlowOp = func(op string, path string, duration time.Duration, size int) {
				path = normalizeLogPath(path)
				logrus.Warnf("slow: %s %s took %s size=%d", op, path, duration.Round(time.Millisecond), size)
			}
		}
		if fullVerbose {
			fs.OnDirOpen = func(path string) {
				path = normalizeLogPath(path)
				logrus.Infof("dir open: %s", path)
			}
		}

		vfsShares[share.Name] = fs
	}

	// Get hostname for NTLM
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SAMBAM"
	}

	// Setup verbose/debug callbacks
	var onConnect func(string)
	var onRename func(string, string)
	var onDetect func(string, string)
	var onAuthFail func(string, string)
	if *verbose > 0 {
		onConnect = func(remoteAddr string) {
			logrus.Infof("connect: %s", remoteAddr)
		}
		onRename = func(from, to string) {
			logrus.Infof("rename: %s -> %s", from, to)
		}
		onDetect = func(action, path string) {
			logrus.Infof("detected: %s %s", action, path)
		}
	}
	if extraVerbose {
		onAuthFail = func(remoteAddr, username string) {
			if username == "" {
				username = "<unknown>"
			}
			logrus.Warnf("auth fail: %s user=%s", remoteAddr, username)
		}
	}

	// Setup authentication
	userPassword := map[string]string{}
	allowGuest := true
	actualPassword := *password

	if *username != "" {
		allowGuest = false
		if actualPassword == "" {
			actualPassword = generatePassword(10)
		}
		userPassword[*username] = actualPassword
	}

	// Create server
	srv := smb2.NewServer(
		&smb2.ServerConfig{
			AllowGuest:   allowGuest,
			Xatrrs:       true,
			HideDotfiles: *hideDotfiles,
			OnConnect:    onConnect,
			OnRename:     onRename,
			OnDetect:     onDetect,
			OnAuthFail:   onAuthFail,
		},
		&smb2.NTLMAuthenticator{
			TargetSPN:    "",
			NbDomain:     hostname,
			NbName:       hostname,
			DnsName:      hostname + ".local",
			DnsDomain:    ".local",
			UserPassword: userPassword,
			AllowGuest:   allowGuest,
		},
		vfsShares,
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
		printBanner(shares, *readOnly, fullListenAddr, displayIPs, portSuffix, *username, actualPassword, *expireStr)
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

	// Wait for interrupt or expiry
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Setup expiry timer if specified
	var expireTimer *time.Timer
	var expireTime time.Time
	if *expireStr != "" {
		duration, err := time.ParseDuration(*expireStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid expire duration: %v\n", err)
			os.Exit(1)
		}
		expireTime = time.Now().Add(duration)
		expireTimer = time.NewTimer(duration)

		// Start countdown display goroutine (only in foreground mode)
		if !*daemonMode {
			go func() {
				ticker := time.NewTicker(1 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						remaining := time.Until(expireTime)
						if remaining > 0 {
							// Move cursor up and clear line, then print countdown
							fmt.Printf("\r  %s %s   ", Dim("Expires in"), Yellow(formatDuration(remaining)))
						}
					case <-sigChan:
						return
					}
				}
			}()
		}
	}

	// Wait for signal or expiry
	if expireTimer != nil {
		select {
		case <-sigChan:
		case <-expireTimer.C:
			if *daemonMode && *logFile != "" {
				log.Println("Expire time reached, shutting down...")
			} else if !*daemonMode {
				fmt.Println("\n\n  Time expired!")
			}
		}
	} else {
		<-sigChan
	}

	if *daemonMode && *logFile != "" {
		log.Println("Shutting down...")
	} else if !*daemonMode {
		fmt.Println("\nShutting down...")
	}
	srv.Shutdown()
}

// formatDuration formats a duration as a human-readable string
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	} else if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func normalizeLogPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func printBanner(shares []Share, readOnly bool, listenAddr string, displayIPs []string, portSuffix string, username string, password string, expireStr string) {
	fmt.Println()
	fmt.Printf("  %s\n", CyanBold("sambam v"+version))
	fmt.Println()

	// Show shares
	if len(shares) == 1 {
		fmt.Printf("  %-12s %s\n", "Sharing", Green(shares[0].Path))
		fmt.Printf("  %-12s %s\n", "Share", Yellow(shares[0].Name))
	} else {
		// Find longest share name for alignment
		maxLen := 0
		for _, share := range shares {
			if len(share.Name) > maxLen {
				maxLen = len(share.Name)
			}
		}
		if maxLen < 12 {
			maxLen = 12
		}
		fmt.Printf("  %s\n", "Shares:")
		for _, share := range shares {
			padding := strings.Repeat(" ", maxLen-len(share.Name))
			fmt.Printf("    %s%s %s %s\n", Yellow(share.Name), padding, Dim("→"), Green(share.Path))
		}
	}

	fmt.Printf("  %-12s %s\n", "Listen", listenAddr)

	modeStr := "read-write"
	if readOnly {
		modeStr = Green("read-only")
	} else {
		modeStr = Red("read-write")
	}
	fmt.Printf("  %-12s %s\n", "Mode", modeStr)

	if username != "" {
		fmt.Printf("  %-12s %s\n", "Auth", Yellow(username)+Dim(":")+Yellow(password))
	} else {
		fmt.Printf("  %-12s %s\n", "Auth", Dim("anonymous"))
	}

	// Extract port number from portSuffix (":8888" -> "8888")
	nonStdPort := portSuffix != ""
	portNum := ""
	if nonStdPort {
		portNum = portSuffix[1:] // strip leading ":"
	}

	fmt.Println()
	if nonStdPort {
		fmt.Println("  Connect from Windows " + Dim("(requires SSH tunnel)") + ":")
		for _, ip := range displayIPs {
			fmt.Printf("    %s\n", Cyan(fmt.Sprintf("ssh -L 445:%s:%s user@%s", ip, portNum, ip)))
		}
		fmt.Printf("    %s\n", Dim("then connect to:")+" "+Cyan("\\\\localhost\\"+shares[0].Name))
	} else {
		fmt.Println("  Connect from Windows:")
		for _, share := range shares {
			for _, ip := range displayIPs {
				fmt.Printf("    %s\n", Cyan(fmt.Sprintf("\\\\%s\\%s", ip, share.Name)))
			}
		}
	}
	fmt.Println()
	if nonStdPort {
		fmt.Println("  Connect from macOS " + Dim("(requires SSH tunnel)") + ":")
		for _, ip := range displayIPs {
			fmt.Printf("    %s\n", Cyan(fmt.Sprintf("ssh -L 445:%s:%s user@%s", ip, portNum, ip)))
		}
		fmt.Printf("    %s\n", Dim("then connect to:")+" "+Cyan("smb://localhost/"+shares[0].Name))
	} else {
		fmt.Println("  Connect from macOS:")
		for _, share := range shares {
			for _, ip := range displayIPs {
				fmt.Printf("    %s\n", Cyan(fmt.Sprintf("smb://%s/%s", ip, share.Name)))
			}
		}
	}
	fmt.Println()
	fmt.Println("  Connect from Linux:")
	authOpt := "guest"
	if username != "" {
		authOpt = "username=" + username + ",password=" + password
	}
	portOpt := ""
	if nonStdPort {
		portOpt = ",port=" + portNum
	}
	for _, share := range shares {
		for _, ip := range displayIPs {
			fmt.Printf("    %s\n", Cyan(fmt.Sprintf("sudo mount -t cifs //%s/%s /mnt -o %s%s", ip, share.Name, authOpt, portOpt)))
		}
	}
	for _, share := range shares {
		for _, ip := range displayIPs {
			fmt.Printf("    %s %s\n", Cyan(fmt.Sprintf("sudo mount -t cifs //%s/%s /mnt -o %s%s,vers=3.1.1,posix,cifsacl", ip, share.Name, authOpt, portOpt)), Dim("# POSIX"))
		}
	}
	fmt.Println()
	fmt.Printf("  %s\n", Dim("Built with AI assistance"))
	fmt.Println()
	if expireStr != "" {
		fmt.Printf("  %s\n", Dim("Press Ctrl+C to stop, or wait for expiry"))
		fmt.Println()
		// Initial expires line - no newline so countdown can overwrite
		fmt.Printf("  %s %s   ", Dim("Expires in"), Yellow(expireStr))
	} else {
		fmt.Printf("  %s\n", Dim("Press Ctrl+C to stop"))
	}
}

func printUsage() {
	fmt.Println()
	fmt.Printf("  %s %s\n", CyanBold("sambam v"+version), Dim("(built with AI assistance)"))
	fmt.Println()
	fmt.Println(Dim("  Instant SMB/CIFS file sharing for Windows clients"))
	fmt.Println()
	fmt.Println(Bold("  Usage:"))
	fmt.Printf("    %s [options] [directory]\n", Cyan("sambam"))
	fmt.Printf("    %s\n", Cyan("sambam stop"))
	fmt.Println()
	fmt.Println(Bold("  Options:"))
	fmt.Printf("    %s, %s      %s\n", Green("-n"), Green("--name"), "Share name or name:path "+Dim("(repeatable)"))
	fmt.Printf("    %s, %s    %s\n", Green("-l"), Green("--listen"), "Address to listen on "+Dim("(default: 0.0.0.0:445)"))
	fmt.Printf("    %s, %s  %s\n", Green("-r"), Green("--readonly"), "Make share read-only")
	fmt.Printf("        %s  %s\n", Green("--username"), "Require authentication")
	fmt.Printf("        %s  %s\n", Green("--password"), "Password "+Dim("(random if not set)"))
	fmt.Printf("        %s    %s\n", Green("--expire"), "Auto-shutdown after duration "+Dim("(e.g., 30m, 1h)"))
	fmt.Printf("    %s, %s   %s\n", Green("-v"), Green("--verbose"), "Show connections and file activity "+Dim("(-vv extended, -vvv full trace)"))
	fmt.Printf("        %s     %s\n", Green("--trace"), "Full protocol trace (very verbose)")
	fmt.Printf("        %s\n", Green("--hide-dotfiles")+"  Hide files starting with '.'")
	fmt.Printf("    %s, %s    %s\n", Green("-d"), Green("--daemon"), "Run as background daemon")
	fmt.Printf("    %s, %s   %s\n", Green("-p"), Green("--pidfile"), "PID file location "+Dim("(default: /tmp/sambam.pid)"))
	fmt.Printf("    %s, %s   %s\n", Green("-L"), Green("--logfile"), "Log file path (daemon mode)")
	fmt.Printf("    %s, %s   %s\n", Green("-V"), Green("--version"), "Show version")
	fmt.Printf("    %s, %s      %s\n", Green("-h"), Green("--help"), "Show help")
	fmt.Println()
	fmt.Println(Bold("  Examples:"))
	fmt.Printf("    %s  %s\n", Cyan("sambam")+"                              ", Dim("# Share current directory as 'share'"))
	fmt.Printf("    %s  %s\n", Cyan("sambam /path/to/folder")+"              ", Dim("# Share specific directory"))
	fmt.Printf("    %s  %s\n", Cyan("sambam -n myfiles .")+"                 ", Dim("# Share current dir as 'myfiles'"))
	fmt.Printf("    %s  %s\n", Cyan("sambam -n docs:/docs -n pics:/photos"), Dim("# Multiple shares"))
	fmt.Printf("    %s  %s\n", Cyan("sambam -r /data")+"                     ", Dim("# Read-only share"))
	fmt.Printf("    %s  %s\n", Cyan("sambam -d /data")+"                     ", Dim("# Run as daemon"))
	fmt.Printf("    %s  %s\n", Cyan("sambam stop")+"                         ", Dim("# Stop running daemon"))
	fmt.Println()
}

// shareName returns a valid share name for the given path.
// filepath.Base("/") returns "/" which is not a valid share name,
// so we fall back to "root" for the filesystem root.
func shareName(path string) string {
	name := filepath.Base(path)
	if name == "/" || name == "." {
		return "root"
	}
	return name
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
