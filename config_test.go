package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigRequiresInboundToken(t *testing.T) {
	p := writeConfig(t, `{"client_id":"c","mcp_url":"https://x/mcp"}`)
	if _, err := loadConfig(p); err == nil {
		t.Fatal("expected error when inbound_token is missing")
	}
}

func TestConfigLoadsValid(t *testing.T) {
	p := writeConfig(t, `{"client_id":"c","mcp_url":"https://x/mcp","inbound_token":"tok"}`)
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InboundToken != "tok" || cfg.RedirectPort != 8585 {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestConfigRejectsUnknownQuirk(t *testing.T) {
	p := writeConfig(t, `{"client_id":"c","mcp_url":"https://x/mcp","inbound_token":"t","quirks":["nope"]}`)
	if _, err := loadConfig(p); err == nil {
		t.Fatal("expected error for unknown quirk")
	}
}

func TestConfigAcceptsKnownQuirk(t *testing.T) {
	p := writeConfig(t, `{"client_id":"c","mcp_url":"https://x/mcp","inbound_token":"t","quirks":["inject_initialized"]}`)
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.hasQuirk(quirkInjectInitialized) {
		t.Error("inject_initialized quirk should be enabled")
	}
}

func TestConfigRejectsLoneEndpoint(t *testing.T) {
	p := writeConfig(t, `{"client_id":"c","mcp_url":"https://x/mcp","inbound_token":"t","authorize_url":"https://a/authorize"}`)
	if _, err := loadConfig(p); err == nil {
		t.Fatal("expected error when only authorize_url is set")
	}
}
