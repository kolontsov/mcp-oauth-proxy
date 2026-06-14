package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

// newTokenServer mocks an OAuth token endpoint. The handler decides the
// response from the posted form, so each test scripts its own behaviour.
func newTokenServer(t *testing.T, handler func(form url.Values) (int, string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			t.Errorf("unexpected token path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		code, body := handler(r.Form)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		io.WriteString(w, body)
	}))
}

func testConfig(host, mcpURL string) *Config {
	return &Config{
		ClientID:     "client-123",
		AuthorizeURL: host + "/authorize",
		TokenURL:     host + "/token",
		MCPURL:       mcpURL,
		Scopes:       "read offline",
		RedirectPort: 8585,
		RedirectPath: "/callback",
		InboundToken: "secret-inbound",
	}
}

func TestS256Challenge(t *testing.T) {
	verifier := "the-quick-brown-fox-pkce-verifier"
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := s256Challenge(verifier); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
}

func TestBuildAuthorizeURL(t *testing.T) {
	cfg := testConfig("https://auth.example.com", "https://api.example.com/mcp")
	u, err := url.Parse(buildAuthorizeURL(cfg, "chal", "st8"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	checks := map[string]string{
		"response_type":         "code",
		"client_id":             "client-123",
		"redirect_uri":          "http://localhost:8585/callback",
		"scope":                 "read offline",
		"code_challenge":        "chal",
		"code_challenge_method": "S256",
		"state":                 "st8",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("query %s = %q, want %q", k, got, want)
		}
	}
	if u.Path != "/authorize" {
		t.Errorf("path = %q", u.Path)
	}
}

func TestBuildAuthorizeURLPreservesExistingQuery(t *testing.T) {
	cfg := testConfig("https://auth.example.com", "https://api.example.com/mcp")
	cfg.AuthorizeURL = "https://auth.example.com/authorize?audience=https%3A%2F%2Fapi"
	u, err := url.Parse(buildAuthorizeURL(cfg, "chal", "st8"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("audience") != "https://api" {
		t.Errorf("pre-existing query param dropped: audience=%q", q.Get("audience"))
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge") != "chal" {
		t.Errorf("OAuth params missing — URL was concatenated, not merged: %s", u)
	}
}

func TestRequestTokenSuccess(t *testing.T) {
	ts := newTokenServer(t, func(form url.Values) (int, string) {
		if form.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q", form.Get("grant_type"))
		}
		if form.Get("code_verifier") != "verif" {
			t.Errorf("code_verifier = %q", form.Get("code_verifier"))
		}
		return 200, `{"access_token":"at1","refresh_token":"rt1","scope":"read offline"}`
	})
	defer ts.Close()
	cfg := testConfig(ts.URL, "https://api.example.com/mcp")

	form := url.Values{"grant_type": {"authorization_code"}, "code_verifier": {"verif"}}
	tr, err := requestToken(context.Background(), http.DefaultClient, cfg.TokenURL, form)
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != "at1" || tr.RefreshToken != "rt1" {
		t.Fatalf("unexpected token response: %+v", tr)
	}
}

func TestRequestTokenError(t *testing.T) {
	ts := newTokenServer(t, func(form url.Values) (int, string) {
		return 400, `{"error":"invalid_grant","error_description":"expired authorization code"}`
	})
	defer ts.Close()
	cfg := testConfig(ts.URL, "https://api.example.com/mcp")

	_, err := requestToken(context.Background(), http.DefaultClient, cfg.TokenURL, url.Values{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestRefreshToken(t *testing.T) {
	ts := newTokenServer(t, func(form url.Values) (int, string) {
		if form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q", form.Get("grant_type"))
		}
		if form.Get("refresh_token") != "rt-old" {
			t.Errorf("refresh_token = %q", form.Get("refresh_token"))
		}
		// No new refresh_token returned: the old one must be preserved.
		return 200, `{"access_token":"at-new"}`
	})
	defer ts.Close()
	cfg := testConfig(ts.URL, "https://api.example.com/mcp")

	got, err := refreshToken(context.Background(), http.DefaultClient, cfg.TokenURL, cfg.ClientID, cfg.Resource, Session{AccessToken: "at-old", RefreshToken: "rt-old"})
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "at-new" {
		t.Errorf("access token = %q, want at-new", got.AccessToken)
	}
	if got.RefreshToken != "rt-old" {
		t.Errorf("refresh token = %q, want preserved rt-old", got.RefreshToken)
	}
}

func TestTryRefreshExisting(t *testing.T) {
	ts := newTokenServer(t, func(form url.Values) (int, string) {
		if form.Get("refresh_token") == "rt-valid" {
			return 200, `{"access_token":"at-fresh"}`
		}
		return 400, `{"error":"invalid_grant"}`
	})
	defer ts.Close()
	cfg := testConfig(ts.URL, "https://api.example.com/mcp")

	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.json")
	saveSession(valid, &Session{AccessToken: "at-old", RefreshToken: "rt-valid"})
	if updated, ok := tryRefreshExisting(cfg, valid); !ok || updated.AccessToken != "at-fresh" {
		t.Fatalf("valid session: ok=%v access=%q", ok, updated.AccessToken)
	}

	revoked := filepath.Join(dir, "revoked.json")
	saveSession(revoked, &Session{AccessToken: "at-old", RefreshToken: "rt-revoked"})
	if _, ok := tryRefreshExisting(cfg, revoked); ok {
		t.Fatal("revoked session should not be reported valid")
	}

	if _, ok := tryRefreshExisting(cfg, filepath.Join(dir, "missing.json")); ok {
		t.Fatal("missing session should not be reported valid")
	}
}
