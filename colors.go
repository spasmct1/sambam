package main

import (
	"os"
)

// ANSI escape codes for terminal colors
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	cyan    = "\033[36m"
)

// colorEnabled indicates whether color output should be used
var colorEnabled = isTerminal()

// isTerminal checks if stdout is a terminal
func isTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// DisableColors disables colored output (useful for daemon mode)
func DisableColors() {
	colorEnabled = false
}

// Color helper functions

func Cyan(s string) string {
	if !colorEnabled {
		return s
	}
	return cyan + s + reset
}

func CyanBold(s string) string {
	if !colorEnabled {
		return s
	}
	return cyan + bold + s + reset
}

func Green(s string) string {
	if !colorEnabled {
		return s
	}
	return green + s + reset
}

func Yellow(s string) string {
	if !colorEnabled {
		return s
	}
	return yellow + s + reset
}

func Red(s string) string {
	if !colorEnabled {
		return s
	}
	return red + s + reset
}

func Bold(s string) string {
	if !colorEnabled {
		return s
	}
	return bold + s + reset
}

func Dim(s string) string {
	if !colorEnabled {
		return s
	}
	return dim + s + reset
}
