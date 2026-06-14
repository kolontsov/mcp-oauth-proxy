package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
)

// Config holds the static, user-provided settings. Secrets that change at
// runtime (the OAuth tokens) live in the session file instead.
type Config struct {
	ClientID     string `json:"client_id"`     // OAuth client (consumer) ID
	AuthorizeURL string `json:"authorize_url"` // authorization endpoint (optional; discovered from mcp_url if blank)
	TokenURL     string `json:"token_url"`     // token endpoint (optional; discovered from mcp_url if blank)
	MCPURL       string `json:"mcp_url"`       // upstream MCP endpoint to proxy to
	Scopes       string `json:"scopes"`        // space-separated OAuth scopes (optional; discovered if blank)
	Resource     string `json:"resource"`      // RFC 8707 resource indicator (optional; discovered if blank)
	RedirectPort int    `json:"redirect_port"` // fixed port for the login callback; must match the registered redirect URI
	RedirectPath string `json:"redirect_path"` // path of the registered redirect URI
	ListenAddr   string `json:"listen_addr"`   // where the proxy listens, e.g. 127.0.0.1:9000
	InboundToken string `json:"inbound_token"` // static bearer token clients must present to the proxy

	Quirks []string `json:"quirks"` // opt-in workarounds for non-standard upstream servers; see quirk* constants
}

// Known quirk names. Quirks work around spec violations in a specific
// client/server pair; they are off by default.
const (
	// quirkInjectInitialized makes the proxy send notifications/initialized to
	// upstream after a successful initialize, on the client's behalf. The MCP
	// spec requires the client to send it; some clients (e.g. TypingMind) skip
	// it, and servers that gate on it (e.g. Salesforce) then answer tools/list
	// with an empty 200 the client can't parse.
	quirkInjectInitialized = "inject_initialized"
)

// knownQuirks is the set of recognised quirk names, used to reject typos.
var knownQuirks = map[string]bool{
	quirkInjectInitialized: true,
}

// hasQuirk reports whether the named quirk is enabled in the config.
func (c *Config) hasQuirk(name string) bool {
	for _, q := range c.Quirks {
		if q == name {
			return true
		}
	}
	return false
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Defaults.
	if c.RedirectPath == "" {
		c.RedirectPath = "/callback"
	}
	if c.RedirectPort == 0 {
		c.RedirectPort = 8585
	}
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:9000"
	}

	for k, v := range map[string]string{
		"client_id":     c.ClientID,
		"mcp_url":       c.MCPURL,
		"inbound_token": c.InboundToken,
	} {
		if v == "" {
			return nil, fmt.Errorf("config: %s is required", k)
		}
	}
	for _, q := range c.Quirks {
		if !knownQuirks[q] {
			return nil, fmt.Errorf("config: unknown quirk %q", q)
		}
	}
	// Endpoints are discovered from mcp_url when omitted, but must be given as a
	// pair if at all — a lone endpoint is a configuration mistake.
	if (c.AuthorizeURL == "") != (c.TokenURL == "") {
		return nil, fmt.Errorf("config: set both authorize_url and token_url, or neither (to discover)")
	}
	// URLs must be absolute http(s); otherwise serve starts and only fails on the
	// first proxied request.
	for k, v := range map[string]string{
		"mcp_url":       c.MCPURL,
		"authorize_url": c.AuthorizeURL,
		"token_url":     c.TokenURL,
	} {
		if v == "" {
			continue // optional endpoints are discovered from mcp_url
		}
		if err := validateAbsoluteURL(v); err != nil {
			return nil, fmt.Errorf("config: %s %w", k, err)
		}
	}
	return &c, nil
}

func validateAbsoluteURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("is not a valid URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("must be an absolute http(s) URL, got %q", s)
	}
	return nil
}

func (c *Config) redirectURI() string {
	return fmt.Sprintf("http://localhost:%d%s", c.RedirectPort, c.RedirectPath)
}
