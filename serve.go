package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func runServe(cfg *Config, sessionPath string) error {
	// No discovery here: serve refreshes against the token_url/resource that
	// login stamped into the session, so startup makes no network calls.
	store, err := newStore(sessionPath, cfg)
	if err != nil {
		return err
	}
	h, err := newHandler(cfg, store)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{Addr: cfg.ListenAddr, Handler: h}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	infof("listening on %s, proxying to %s", cfg.ListenAddr, cfg.MCPURL)

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		infof("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// newHandler builds the reverse proxy that swaps the inbound static token for
// the upstream access token and refreshes it on demand.
func newHandler(cfg *Config, store *Store) (*handler, error) {
	target, err := url.Parse(cfg.MCPURL)
	if err != nil {
		return nil, fmt.Errorf("invalid mcp_url: %w", err)
	}
	transport := &authTransport{store: store, base: debugRoundTripper(http.DefaultTransport)}
	h := &handler{
		inboundToken:      cfg.InboundToken,
		target:            target,
		client:            &http.Client{Transport: transport, Timeout: 30 * time.Second},
		injectInitialized: cfg.hasQuirk(quirkInjectInitialized),
	}
	h.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = target.Path // single MCP endpoint
			req.URL.RawQuery = joinQuery(target.RawQuery, req.URL.RawQuery)
			req.Host = target.Host
			req.Header.Del("Authorization") // drop the inbound static token; transport adds the upstream token
		},
		Transport:     transport,
		FlushInterval: -1, // flush immediately so SSE streams aren't buffered
		// After a successful initialize, send notifications/initialized to
		// upstream before the initialize response reaches the client, so the
		// upstream session is "initialized" before the client's first request
		// (e.g. tools/list) arrives. Some MCP servers — notably Salesforce —
		// otherwise answer tools/list with an empty 200, which clients that skip
		// the notification (e.g. TypingMind) report as a JSON parse error.
		ModifyResponse: h.maybeInitialize,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			errorf("proxy error: %v", err)
			http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		},
	}
	return h, nil
}

// initRequestKey marks an inbound request as an MCP initialize call, so
// ModifyResponse knows to follow it with notifications/initialized.
type initRequestKey struct{}

// maybeInitialize fires notifications/initialized upstream after a successful
// initialize response, then lets that response flow on to the client unchanged.
func (h *handler) maybeInitialize(resp *http.Response) error {
	isInit, _ := resp.Request.Context().Value(initRequestKey{}).(bool)
	if !isInit || resp.StatusCode != http.StatusOK {
		return nil
	}
	h.sendInitialized(resp.Request.Context(), resp.Header.Get("Mcp-Session-Id"), resp.Request.Header.Get("Mcp-Protocol-Version"))
	return nil
}

// sendInitialized posts a notifications/initialized to upstream on the given
// session. It runs synchronously inside ModifyResponse so the upstream session
// is ready before the client sees the initialize result. Failures are logged
// but not propagated: the initialize response should still reach the client.
func (h *handler) sendInitialized(ctx context.Context, sessionID, protoVersion string) {
	if sessionID == "" {
		warnf("initialize response had no Mcp-Session-Id; skipping notifications/initialized")
		return
	}
	const body = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.target.String(), strings.NewReader(body))
	if err != nil {
		errorf("build notifications/initialized: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json,text/event-stream")
	req.Header.Set("Mcp-Session-Id", sessionID)
	if protoVersion != "" {
		req.Header.Set("Mcp-Protocol-Version", protoVersion)
	}
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(body)), nil }

	resp, err := h.client.Do(req)
	if err != nil {
		errorf("notifications/initialized failed: %v", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		warnf("notifications/initialized returned %s", resp.Status)
	}
}

// joinQuery combines the upstream endpoint's query with the request's, matching
// the behaviour of httputil.NewSingleHostReverseProxy.
func joinQuery(target, req string) string {
	switch {
	case target == "":
		return req
	case req == "":
		return target
	default:
		return target + "&" + req
	}
}

type handler struct {
	proxy             *httputil.ReverseProxy
	inboundToken      string
	target            *url.URL
	client            *http.Client
	injectInitialized bool // quirk: send notifications/initialized after initialize
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()

	// Buffer the body up front so we can both trace it and let the transport
	// replay it after a token refresh.
	var body []byte
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(rec, "read body: "+err.Error(), http.StatusBadRequest)
			h.accessLog(r, "", rec.status, start)
			return
		}
		body = b
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	method, label := rpcMethod(body)

	debugIncomingRequest(r, body)
	defer func() { h.accessLog(r, label, rec.status, start) }()

	if !h.authorized(r) {
		rec.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(rec, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Flag initialize calls so ModifyResponse can follow up with
	// notifications/initialized once upstream replies (inject_initialized quirk).
	if h.injectInitialized && method == "initialize" {
		r = r.WithContext(context.WithValue(r.Context(), initRequestKey{}, true))
	}
	h.proxy.ServeHTTP(rec, r)
}

// accessLog emits a one-line server access log for each request: remote addr,
// HTTP method, the JSON-RPC method (when present), response status, and elapsed
// time. At debug levels the →/← traces already cover this, so it's suppressed
// to avoid duplicate noise.
func (h *handler) accessLog(r *http.Request, label string, status int, start time.Time) {
	if debugLevel > 0 {
		return
	}
	elapsed := time.Since(start).Round(time.Millisecond)
	rpc := ""
	if label != "" {
		rpc = " " + label
	}
	infof("%s %s%s → %d (%s)", r.RemoteAddr, r.Method, rpc, status, elapsed)
}

// rpcMethod parses a JSON-RPC request body, returning the bare method and a
// display label for the access log. For tools/call the label includes the tool
// name, e.g. "tools/call(soqlQuery)". Both are "" if body isn't JSON-RPC.
func rpcMethod(body []byte) (method, label string) {
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &msg) != nil {
		return "", ""
	}
	label = msg.Method
	if msg.Method == "tools/call" && msg.Params.Name != "" {
		label = msg.Method + "(" + msg.Params.Name + ")"
	}
	return msg.Method, label
}

// statusRecorder wraps a ResponseWriter to remember the status code for the
// access log, while preserving Flush so streamed (SSE) responses still flush.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *handler) authorized(r *http.Request) bool {
	if h.inboundToken == "" {
		return false // config load requires a token; deny if somehow unset
	}
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return false // require an actual (case-insensitive) Bearer scheme
	}
	got := auth[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(got), []byte(h.inboundToken)) == 1
}

// authTransport injects the current upstream access token and, on a 401,
// refreshes it once and replays the request.
type authTransport struct {
	store *Store
	base  http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok := t.store.token()
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	resp.Body.Close()

	newTok, err := t.store.refresh(req.Context(), tok)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		req.Body = body
	}
	req.Header.Set("Authorization", "Bearer "+newTok)
	return t.base.RoundTrip(req)
}
