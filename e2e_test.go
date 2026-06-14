package main

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// oauthMock is a stand-in OAuth provider that implements both endpoints and
// verifies PKCE across the round-trip: the challenge presented at /authorize
// must match the verifier presented at /token.
type oauthMock struct {
	challenge string
}

func newOAuthMock(t *testing.T) (*httptest.Server, *oauthMock) {
	t.Helper()
	m := &oauthMock{}
	mux := http.NewServeMux()

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "bad authorize request", http.StatusBadRequest)
			return
		}
		m.challenge = q.Get("code_challenge")
		// Simulate the user approving: redirect straight back with a code.
		loc := q.Get("redirect_uri") + "?code=auth-code-xyz&state=" + url.QueryEscape(q.Get("state"))
		http.Redirect(w, r, loc, http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code") != "auth-code-xyz" {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != m.challenge {
				http.Error(w, `{"error":"invalid_grant","error_description":"PKCE mismatch"}`, http.StatusBadRequest)
				return
			}
			io.WriteString(w, `{"access_token":"at-1","refresh_token":"rt-1"}`)
		case "refresh_token":
			io.WriteString(w, `{"access_token":"at-2"}`)
		default:
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		}
	})

	return httptest.NewServer(mux), m
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestEndToEnd runs the whole chain against a single mock OAuth server:
// PKCE login (authorize -> callback -> code exchange) -> session file -> serve
// -> proxied upstream call -> refresh on 401.
func TestEndToEnd(t *testing.T) {
	oauth, _ := newOAuthMock(t)
	defer oauth.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer at-2":
			io.WriteString(w, "pong")
		default:
			w.WriteHeader(http.StatusUnauthorized) // at-1 is "expired" -> force a refresh
		}
	}))
	defer upstream.Close()

	cfg := testConfig(oauth.URL, upstream.URL)
	cfg.RedirectPort = freePort(t)

	// Act as the browser: fetch the authorize URL and follow the redirect into
	// our own callback server.
	prev := presentAuthURL
	presentAuthURL = func(authURL string, _ int) {
		go func() {
			resp, err := http.Get(authURL)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	defer func() { presentAuthURL = prev }()

	sessionPath := filepath.Join(t.TempDir(), "session.json")
	if err := runLogin(cfg, sessionPath, true); err != nil {
		t.Fatalf("login: %v", err)
	}

	sess, err := loadSession(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	if sess.AccessToken != "at-1" || sess.RefreshToken != "rt-1" {
		t.Fatalf("session after login = %+v", sess)
	}

	// Now serve, using the session login just produced.
	store, err := newStore(sessionPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0"}`))
	req.Header.Set("Authorization", "Bearer "+cfg.InboundToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || rr.Body.String() != "pong" {
		t.Fatalf("proxy response = %d %q, want 200 pong", rr.Code, rr.Body.String())
	}
}
