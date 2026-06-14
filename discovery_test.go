package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// newDiscoveryServer mocks an MCP server that publishes RFC 9728 protected
// resource metadata plus RFC 8414 authorization server metadata. When
// withChallenge is true the MCP endpoint advertises the metadata URL via a 401
// WWW-Authenticate header; otherwise discovery must fall back to well-known.
func newDiscoveryServer(t *testing.T, withChallenge bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		if withChallenge {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp"`)
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		io.WriteString(w, `{"resource":"`+base+`/mcp","authorization_servers":["`+base+`"],"scopes_supported":["read","offline"]}`)
	})

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		io.WriteString(w, `{"authorization_endpoint":"`+base+`/authorize","token_endpoint":"`+base+`/token"}`)
	})

	return httptest.NewServer(mux)
}

func TestDiscoverViaChallenge(t *testing.T) {
	ts := newDiscoveryServer(t, true)
	defer ts.Close()

	ep, err := discover(context.Background(), http.DefaultClient, ts.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if ep.authorize != ts.URL+"/authorize" || ep.token != ts.URL+"/token" {
		t.Errorf("endpoints = %q / %q", ep.authorize, ep.token)
	}
	if ep.resource != ts.URL+"/mcp" {
		t.Errorf("resource = %q", ep.resource)
	}
	if len(ep.scopes) != 2 || ep.scopes[0] != "read" {
		t.Errorf("scopes = %v", ep.scopes)
	}
}

func TestDiscoverViaWellKnownFallback(t *testing.T) {
	ts := newDiscoveryServer(t, false) // no challenge header -> must use well-known
	defer ts.Close()

	ep, err := discover(context.Background(), http.DefaultClient, ts.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if ep.authorize != ts.URL+"/authorize" || ep.token != ts.URL+"/token" {
		t.Errorf("endpoints = %q / %q", ep.authorize, ep.token)
	}
}

func TestEnsureEndpointsFillsConfig(t *testing.T) {
	ts := newDiscoveryServer(t, true)
	defer ts.Close()

	cfg := &Config{MCPURL: ts.URL + "/mcp"}
	if err := ensureEndpoints(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.AuthorizeURL != ts.URL+"/authorize" || cfg.TokenURL != ts.URL+"/token" {
		t.Errorf("config endpoints = %q / %q", cfg.AuthorizeURL, cfg.TokenURL)
	}
	if cfg.Scopes != "read offline" {
		t.Errorf("scopes = %q, want discovered default", cfg.Scopes)
	}
	if cfg.Resource != ts.URL+"/mcp" {
		t.Errorf("resource = %q", cfg.Resource)
	}
}

func TestEnsureEndpointsKeepsExplicitScopes(t *testing.T) {
	ts := newDiscoveryServer(t, true)
	defer ts.Close()

	// Endpoints are discovered, but a user-set scope must survive.
	cfg := &Config{MCPURL: ts.URL + "/mcp", Scopes: "mcp_api refresh_token"}
	if err := ensureEndpoints(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.AuthorizeURL != ts.URL+"/authorize" {
		t.Errorf("endpoints not discovered: %q", cfg.AuthorizeURL)
	}
	if cfg.Scopes != "mcp_api refresh_token" {
		t.Errorf("scopes = %q, want the explicit value preserved", cfg.Scopes)
	}
}

func TestEnsureEndpointsSkipsWhenExplicit(t *testing.T) {
	// A bogus mcp_url proves no network call happens when endpoints are set.
	cfg := &Config{MCPURL: "http://127.0.0.1:0/mcp", AuthorizeURL: "https://a/authorize", TokenURL: "https://a/token"}
	if err := ensureEndpoints(context.Background(), cfg); err != nil {
		t.Fatalf("explicit endpoints should skip discovery: %v", err)
	}
	if cfg.AuthorizeURL != "https://a/authorize" {
		t.Error("explicit endpoint was overwritten")
	}
}

func TestAuthorizeURLIncludesResource(t *testing.T) {
	cfg := testConfig("https://auth.example.com", "https://api.example.com/mcp")
	cfg.Resource = "https://api.example.com/mcp"
	u, err := url.Parse(buildAuthorizeURL(cfg, "chal", "st8"))
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("resource"); got != cfg.Resource {
		t.Errorf("resource param = %q, want %q", got, cfg.Resource)
	}
}
