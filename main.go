package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
)

// version is overridable at build time: go build -ldflags "-X main.version=v1.2.3"
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "version", "-v", "--version":
		runVersion()
		return
	case "login", "serve":
		// handled below
	default:
		usage()
		os.Exit(2)
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", "config.json", "path to config file")
	sessionPath := fs.String("session", "session.json", "path to session file")
	force := fs.Bool("force", false, "login: re-run the browser flow even if the saved session is still valid")
	var dbg levelFlag
	fs.Var(&dbg, "d", "HTTP debug level 1-4 (-d=1 URL+status, -d=2 +request bodies, -d=3 +response bodies, -d=4 +streaming bodies; bare -d is 1)")
	fs.Parse(os.Args[2:])

	debugLevel = int(dbg)
	if debugLevel >= 2 {
		warnf("-d level ≥2 prints request/response bodies, including tokens, in cleartext")
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}

	switch cmd {
	case "login":
		if err := runLogin(cfg, *sessionPath, *force); err != nil {
			fatal(err)
		}
	case "serve":
		if err := runServe(cfg, *sessionPath); err != nil {
			fatal(err)
		}
	}
}

// runVersion prints the build version. The Makefile injects it via ldflags
// (git describe). For a plain `go build`/`go install` without ldflags it falls
// back to the VCS revision recorded in the build info.
func runVersion() {
	v := version
	if v == "dev" {
		if rev := vcsRevision(); rev != "" {
			v = rev
		}
	}
	fmt.Printf("mcp-oauth-proxy %s\n", v)
}

func vcsRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return ""
	}
	return rev[:min(len(rev), 12)] + dirty
}

func usage() {
	fmt.Fprint(os.Stderr, `mcp-oauth-proxy — bridge a static bearer token to an OAuth-protected MCP server

Usage:
  mcp-oauth-proxy login  [--config config.json] [--session session.json] [--force] [-d[=N]]
  mcp-oauth-proxy serve  [--config config.json] [--session session.json] [-d[=N]]
  mcp-oauth-proxy version

  login    run the browser OAuth flow and save tokens (skips if the saved token still works)
  serve    run the proxy, injecting and refreshing the upstream access token
  version  print the build version

  -d[=N]   trace HTTP requests at level N (1-4); bare -d is 1
`)
}

func fatal(err error) {
	errorf("%v", err)
	os.Exit(1)
}
