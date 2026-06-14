package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Session is the persisted OAuth state. It holds a long-lived refresh token,
// so the file is written with 0600 permissions.
type Session struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenURL     string `json:"token_url"` // where this refresh token is redeemed (stamped by login)
	Resource     string `json:"resource"`  // RFC 8707 resource indicator for refresh (stamped by login)
	Scope        string `json:"scope"`
	ObtainedAt   int64  `json:"obtained_at"` // unix seconds; informational only
}

// tokenResponse mirrors the JSON returned by an OAuth token endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func saveSession(path string, s *Session) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Write-then-rename so a concurrent reader (a running `serve`) never sees a
	// half-written file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadSession(path string) (*Session, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse session %s: %w", path, err)
	}
	return &s, nil
}

// Store guards the session and serialises token refreshes so that a burst of
// concurrent 401s triggers at most one refresh round-trip.
type Store struct {
	mu   sync.Mutex
	sess Session
	path string
	cfg  *Config
	hc   *http.Client
}

func newStore(path string, cfg *Config) (*Store, error) {
	s, err := loadSession(path)
	if err != nil {
		return nil, fmt.Errorf("load session (run `login` first): %w", err)
	}
	if s.RefreshToken == "" {
		return nil, fmt.Errorf("session has no refresh_token; re-run `login`")
	}
	if s.TokenURL == "" {
		return nil, fmt.Errorf("session has no token_url; re-run `login`")
	}
	return &Store{sess: *s, path: path, cfg: cfg, hc: httpClient(30 * time.Second)}, nil
}

func (s *Store) token() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sess.AccessToken
}

// refresh exchanges the refresh token for a new access token. The caller passes
// the access token that just failed. The on-disk session is reloaded first, so
// a token written out-of-band — by a concurrent refresh or a fresh `login` —
// is picked up without a redundant network round-trip.
func (s *Store) refresh(ctx context.Context, stale string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if disk, err := loadSession(s.path); err == nil {
		s.sess = *disk
	}
	if s.sess.AccessToken != stale {
		return s.sess.AccessToken, nil
	}

	// serve refreshes against the endpoint stamped into the session at login —
	// no discovery at serve time.
	updated, err := refreshToken(ctx, s.hc, s.sess.TokenURL, s.cfg.ClientID, s.sess.Resource, s.sess)
	if err != nil {
		return "", err
	}
	s.sess = updated
	if err := saveSession(s.path, &s.sess); err != nil {
		return "", fmt.Errorf("persist refreshed session: %w", err)
	}
	return s.sess.AccessToken, nil
}

// refreshToken exchanges sess.RefreshToken for a new access token and returns an
// updated session, honouring refresh-token rotation if the server sends one.
func refreshToken(ctx context.Context, hc *http.Client, tokenURL, clientID, resource string, sess Session) (Session, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {sess.RefreshToken},
		"client_id":     {clientID},
	}
	if resource != "" {
		form.Set("resource", resource)
	}
	tr, err := requestToken(ctx, hc, tokenURL, form)
	if err != nil {
		return sess, err
	}
	sess.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" { // Most providers keep the same refresh token, but honour rotation.
		sess.RefreshToken = tr.RefreshToken
	}
	if tr.Scope != "" {
		sess.Scope = tr.Scope
	}
	sess.ObtainedAt = time.Now().Unix()
	return sess, nil
}

// requestToken performs an OAuth token request and decodes the response,
// turning an OAuth error payload into a Go error.
func requestToken(ctx context.Context, hc *http.Client, tokenURL string, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("token endpoint returned non-JSON (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("token endpoint error: %s: %s", tr.Error, tr.ErrorDesc)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned no access_token (status %d)", resp.StatusCode)
	}
	return &tr, nil
}
