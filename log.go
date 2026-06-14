package main

import (
	"fmt"
	"os"
)

// ANSI colors for log-level prefixes, used only when stderr is a terminal.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
)

var stderrIsTTY = isTerminal(os.Stderr)

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// logf writes "<prefix>: <message>" to stderr, coloring the prefix on a TTY.
func logf(color, prefix, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if stderrIsTTY {
		fmt.Fprintf(os.Stderr, "%s%s:%s %s\n", color, prefix, colorReset, msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s: %s\n", prefix, msg)
	}
}

func infof(format string, args ...any)  { logf(colorGreen, "info", format, args...) }
func warnf(format string, args ...any)  { logf(colorYellow, "warning", format, args...) }
func errorf(format string, args ...any) { logf(colorRed, "error", format, args...) }
