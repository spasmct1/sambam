# sambam fish completion

# Helper: true when no subcommand has been entered yet.
function __fish_sambam_no_subcommand
    not __fish_seen_subcommand_from stop
end

# Subcommand (first positional argument)
complete -c sambam -n "__fish_use_subcommand" -a stop -d "Stop running daemon"

# Main-mode flags
complete -c sambam -n "__fish_sambam_no_subcommand" -s n -l name -r -d "Share name or name:path (repeatable)"
complete -c sambam -n "__fish_sambam_no_subcommand" -s l -l listen -r -d "Address to listen on"
complete -c sambam -n "__fish_sambam_no_subcommand" -s r -l readonly -d "Make share read-only"
complete -c sambam -n "__fish_sambam_no_subcommand" -s d -l daemon -d "Run as background daemon"
complete -c sambam -n "__fish_sambam_no_subcommand" -s p -l pidfile -r -f -a "(__fish_complete_path)" -d "PID file location"
complete -c sambam -n "__fish_sambam_no_subcommand" -s L -l logfile -r -f -a "(__fish_complete_path)" -d "Log file path"
complete -c sambam -n "__fish_sambam_no_subcommand" -s v -l verbose -d "Show connections and file activity"
complete -c sambam -n "__fish_sambam_no_subcommand" -l trace -d "Show full protocol trace"
complete -c sambam -n "__fish_sambam_no_subcommand" -l hide-dotfiles -d "Hide files starting with '.'"
complete -c sambam -n "__fish_sambam_no_subcommand" -l username -r -d "Require authentication with this username"
complete -c sambam -n "__fish_sambam_no_subcommand" -l password -r -d "Password for authentication"
complete -c sambam -n "__fish_sambam_no_subcommand" -l expire -r -d "Auto-shutdown after duration"
complete -c sambam -n "__fish_sambam_no_subcommand" -s V -l version -d "Show version"
complete -c sambam -n "__fish_sambam_no_subcommand" -s h -l help -d "Show help"

# Positional directory argument in main mode
complete -c sambam -n "__fish_sambam_no_subcommand" -f -a "(__fish_complete_directories)" -d "Directory to share"

# stop subcommand flags
complete -c sambam -n "__fish_seen_subcommand_from stop" -s p -l pidfile -r -f -a "(__fish_complete_path)" -d "PID file location"
complete -c sambam -n "__fish_seen_subcommand_from stop" -s h -l help -d "Show help"
