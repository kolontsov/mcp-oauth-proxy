package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// seedStore writes a session file and opens a Store on it.
func seedStore(t *testing.T, cfg *Config, sess Session) (*Store, string) {
	t.Helper()
	if sess.TokenURL == "" { // login stamps this; mirror it for seeded sessions
		sess.TokenURL = cfg.TokenURL
	}
	path := filepath.Join(t.TempDir(), "session.json")
	if err := saveSession(path, &sess); err != nil {
		t.Fatal(err)
	}
	store, err := newStore(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return store, path
}

func TestProxyRejectsBadInboundToken(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer upstream.Close()

	cfg := testConfig("https://auth.example.com", upstream.URL)
	store, _ := seedStore(t, cfg, Session{AccessToken: "at", RefreshToken: "rt"})
	h, err := newHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if hit {
		t.Error("upstream was reached despite bad inbound token")
	}
}

func TestProxyDeniesWhenNoInboundTokenConfigured(t *testing.T) {
	h := &handler{inboundToken: ""}
	req := httptest.NewRequest(http.MethodPost, "/", nil) // no Authorization header
	if h.authorized(req) {
		t.Fatal("empty inbound token must deny, not allow")
	}
}

func TestProxyForwardsUpstreamQuery(t *testing.T) {
	var gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
	}))
	defer upstream.Close()

	cfg := testConfig("https://auth.example.com", upstream.URL+"/mcp?workspace=abc")
	store, _ := seedStore(t, cfg, Session{AccessToken: "at", RefreshToken: "rt"})
	h, err := newHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/?trace=1", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+cfg.InboundToken)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !strings.Contains(gotQuery, "workspace=abc") {
		t.Errorf("upstream query = %q, want it to contain workspace=abc", gotQuery)
	}
	if !strings.Contains(gotQuery, "trace=1") {
		t.Errorf("upstream query = %q, want the request query merged in too", gotQuery)
	}
}

func TestServeRefreshesViaSessionTokenURL(t *testing.T) {
	tokenSrv := newTokenServer(t, func(form url.Values) (int, string) {
		return 200, `{"access_token":"at-new"}`
	})
	defer tokenSrv.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-new" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer upstream.Close()

	// cfg.TokenURL is deliberately bogus: serve must use the session's token_url
	// and never touch discovery or config endpoints.
	cfg := testConfig("https://auth.example.com", upstream.URL)
	cfg.TokenURL = "http://127.0.0.1:0/should-not-be-used"
	store, _ := seedStore(t, cfg, Session{AccessToken: "at-old", RefreshToken: "rt-old", TokenURL: tokenSrv.URL + "/token"})
	h, err := newHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+cfg.InboundToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (refresh via session token_url failed)", rr.Code)
	}
}

func TestProxySendsInitializedAfterInitialize(t *testing.T) {
	var methods []string
	var sessionIDs []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var msg struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &msg)
		methods = append(methods, msg.Method)
		sessionIDs = append(sessionIDs, r.Header.Get("Mcp-Session-Id"))
		if msg.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", "sess-123")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := testConfig("https://auth.example.com", upstream.URL)
	cfg.Quirks = []string{quirkInjectInitialized}
	store, _ := seedStore(t, cfg, Session{AccessToken: "at", RefreshToken: "rt"})
	h, err := newHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer "+cfg.InboundToken)
	h.ServeHTTP(httptest.NewRecorder(), req)

	want := []string{"initialize", "notifications/initialized"}
	if len(methods) != 2 || methods[0] != want[0] || methods[1] != want[1] {
		t.Fatalf("upstream saw methods %v, want %v", methods, want)
	}
	if sessionIDs[1] != "sess-123" {
		t.Errorf("notifications/initialized session id = %q, want sess-123 (from initialize response)", sessionIDs[1])
	}
}

func TestProxySkipsInitializedWhenNoSessionID(t *testing.T) {
	var methods []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var msg struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &msg)
		methods = append(methods, msg.Method)
		w.WriteHeader(http.StatusOK) // initialize reply, but no Mcp-Session-Id header
	}))
	defer upstream.Close()

	cfg := testConfig("https://auth.example.com", upstream.URL)
	cfg.Quirks = []string{quirkInjectInitialized}
	store, _ := seedStore(t, cfg, Session{AccessToken: "at", RefreshToken: "rt"})
	h, err := newHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer "+cfg.InboundToken)
	h.ServeHTTP(httptest.NewRecorder(), req)

	// Without a session id there's nothing to attach the notification to, so the
	// proxy must skip it rather than fire a session-less request.
	if len(methods) != 1 || methods[0] != "initialize" {
		t.Fatalf("upstream saw methods %v, want just [initialize] (no session id → skip)", methods)
	}
}

func TestProxyDoesNotInjectInitializedWithoutQuirk(t *testing.T) {
	var methods []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var msg struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &msg)
		methods = append(methods, msg.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Quirk is off by default: even an initialize must not trigger the follow-up.
	cfg := testConfig("https://auth.example.com", upstream.URL)
	store, _ := seedStore(t, cfg, Session{AccessToken: "at", RefreshToken: "rt"})
	h, err := newHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer "+cfg.InboundToken)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(methods) != 1 || methods[0] != "initialize" {
		t.Fatalf("upstream saw methods %v, want just [initialize] (no injection without the quirk)", methods)
	}
}

func TestRPCMethodLabel(t *testing.T) {
	tests := []struct {
		body                  string
		wantMethod, wantLabel string
	}{
		{`{"method":"tools/list"}`, "tools/list", "tools/list"},
		{`{"method":"tools/call","params":{"name":"soqlQuery"}}`, "tools/call", "tools/call(soqlQuery)"},
		{`{"method":"tools/call","params":{}}`, "tools/call", "tools/call"}, // no name → bare method
		{`not json`, "", ""},
	}
	for _, tc := range tests {
		method, label := rpcMethod([]byte(tc.body))
		if method != tc.wantMethod || label != tc.wantLabel {
			t.Errorf("rpcMethod(%q) = (%q, %q), want (%q, %q)", tc.body, method, label, tc.wantMethod, tc.wantLabel)
		}
	}
}

func TestProxyInjectsTokenAndRefreshesOn401(t *testing.T) {
	var seenAuth []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = append(seenAuth, r.Header.Get("Authorization"))
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"jsonrpc":"2.0"}` {
			t.Errorf("upstream body = %q", body)
		}
		if r.Header.Get("Authorization") == "Bearer at-new" {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "ok")
			return
		}
		w.WriteHeader(http.StatusUnauthorized) // stale token
	}))
	defer upstream.Close()

	tokenSrv := newTokenServer(t, func(form url.Values) (int, string) {
		if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "rt-old" {
			t.Errorf("unexpected refresh form: %v", form)
		}
		return 200, `{"access_token":"at-new"}`
	})
	defer tokenSrv.Close()

	cfg := testConfig(tokenSrv.URL, upstream.URL)
	store, sessionPath := seedStore(t, cfg, Session{AccessToken: "at-old", RefreshToken: "rt-old"})
	h, err := newHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0"}`))
	req.Header.Set("Authorization", "Bearer "+cfg.InboundToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || rr.Body.String() != "ok" {
		t.Fatalf("status=%d body=%q, want 200/ok", rr.Code, rr.Body.String())
	}
	wantAuth := []string{"Bearer at-old", "Bearer at-new"}
	if len(seenAuth) != 2 || seenAuth[0] != wantAuth[0] || seenAuth[1] != wantAuth[1] {
		t.Fatalf("upstream saw auth %v, want %v", seenAuth, wantAuth)
	}

	// The refreshed token must be persisted to disk.
	got, err := loadSession(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "at-new" {
		t.Errorf("persisted access token = %q, want at-new", got.AccessToken)
	}
}
