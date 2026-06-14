package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"
)

// debugLevel controls HTTP request/response tracing. It is set once from the
// repeated -d flag before any requests are made; 0 disables tracing.
var debugLevel int

// levelFlag is the debug verbosity. Bare -d means level 1; -d=N (0..4) sets it
// directly. IsBoolFlag lets -d stand alone without a value.
type levelFlag int

func (l *levelFlag) String() string   { return strconv.Itoa(int(*l)) }
func (l *levelFlag) IsBoolFlag() bool { return true }
func (l *levelFlag) Set(s string) error {
	if s == "true" { // bare -d
		*l = 1
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 4 {
		return fmt.Errorf("debug level must be 0-4")
	}
	*l = levelFlag(n)
	return nil
}

// httpClient builds an HTTP client whose transport traces requests when debug
// is enabled. At level 0 the transport is http.DefaultTransport unchanged.
func httpClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: debugRoundTripper(http.DefaultTransport)}
}

// debugRoundTripper wraps base with request/response tracing, or returns base
// untouched when debugging is off.
func debugRoundTripper(base http.RoundTripper) http.RoundTripper {
	if debugLevel == 0 {
		return base
	}
	return &debugTransport{level: debugLevel, base: base}
}

type debugTransport struct {
	level int
	base  http.RoundTripper
}

func (t *debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Fprintf(os.Stderr, "→ %s %s\n", req.Method, req.URL)
	if t.level >= 2 {
		if dump, err := httputil.DumpRequestOut(req, true); err == nil {
			writeIndented(dump)
		}
	}

	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	elapsed := time.Since(start).Round(time.Millisecond)
	if err != nil {
		fmt.Fprintf(os.Stderr, "← error after %s: %v\n", elapsed, err)
		return resp, err
	}
	fmt.Fprintf(os.Stderr, "← %s (%s)\n", resp.Status, elapsed)
	if t.level >= 3 {
		// Dump headers without touching the body (DumpResponse with body=true
		// buffers the whole stream, which would stall a live SSE response before
		// the proxy can forward it). The body is traced separately below.
		if dump, err := httputil.DumpResponse(resp, false); err == nil {
			writeIndented(dump)
		}
		stream := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")
		switch {
		case stream && t.level >= 4:
			// Tee the body to stderr as the proxy reads it, so we see each SSE
			// chunk as it arrives without buffering it away from the client.
			resp.Body = teeBody(resp.Body)
		case stream:
			fmt.Fprintln(os.Stderr, "    [streaming body omitted — use -d=4 to trace it]")
			fmt.Fprintln(os.Stderr)
		default:
			// Non-streaming body: tee it too, so the dump reflects exactly what
			// the client receives and never buffers ahead of the proxy.
			resp.Body = teeBody(resp.Body)
		}
	}
	return resp, err
}

// teeBody wraps an HTTP response body so every chunk read by the proxy is also
// written, indented, to stderr. It preserves streaming: bytes are forwarded the
// instant they are read, never buffered ahead of the client.
func teeBody(body io.ReadCloser) io.ReadCloser {
	return &tracedBody{ReadCloser: body, tee: io.TeeReader(body, indentWriter{})}
}

type tracedBody struct {
	io.ReadCloser
	tee io.Reader
}

func (b *tracedBody) Read(p []byte) (int, error) { return b.tee.Read(p) }

// indentWriter writes each chunk to stderr with the same 4-space indent as the
// header dumps, so traced bodies line up under their response.
type indentWriter struct{}

func (indentWriter) Write(p []byte) (int, error) {
	fmt.Fprintf(os.Stderr, "    %s", strings.ReplaceAll(string(p), "\n", "\n    "))
	return len(p), nil
}

// debugIncomingRequest traces a request arriving from the client (proxy ←
// client), distinct from the upstream →/← pair. body is the already-buffered
// request body, or nil. It mirrors the level conventions: level 1 logs the
// method and path, level ≥2 dumps headers and body.
func debugIncomingRequest(r *http.Request, body []byte) {
	if debugLevel == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "⇐ %s %s (from %s)\n", r.Method, r.URL.RequestURI(), r.RemoteAddr)
	if debugLevel < 2 {
		return
	}
	clone := r.Clone(r.Context())
	clone.Body = io.NopCloser(bytes.NewReader(body))
	if dump, err := httputil.DumpRequest(clone, true); err == nil {
		writeIndented(dump)
	}
}

func writeIndented(b []byte) {
	for _, line := range strings.Split(strings.TrimRight(string(b), "\r\n"), "\n") {
		fmt.Fprintf(os.Stderr, "    %s\n", strings.TrimRight(line, "\r"))
	}
	fmt.Fprintln(os.Stderr)
}
