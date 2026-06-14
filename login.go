package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// callbackResult carries the outcome of the OAuth redirect back to the main
// goroutine.
type callbackResult struct {
	code string
	err  error
}

func runLogin(cfg *Config, sessionPath string, force bool) error {
	discCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := ensureEndpoints(discCtx, cfg)
	cancel()
	if err != nil {
		return err
	}

	if !force {
		if updated, ok := tryRefreshExisting(cfg, sessionPath); ok {
			if err := saveSession(sessionPath, &updated); err != nil {
				return err
			}
			fmt.Println("Already authorized — refresh token is valid. (use -force to re-login)")
			return nil
		}
	}

	verifier := randomURLSafe(32)
	challenge := s256Challenge(verifier)
	state := randomURLSafe(16)

	authURL := buildAuthorizeURL(cfg, challenge, state)

	resultCh := make(chan callbackResult, 1)
	srv, err := startCallbackServer(cfg, state, resultCh)
	if err != nil {
		return err
	}
	defer srv.Close()

	presentAuthURL(authURL, cfg.RedirectPort)
	fmt.Println("Waiting for the authorization redirect...")

	var res callbackResult
	select {
	case res = <-resultCh:
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("timed out waiting for authorization")
	}
	if res.err != nil {
		return res.err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {res.code},
		"redirect_uri":  {cfg.redirectURI()},
		"client_id":     {cfg.ClientID},
		"code_verifier": {verifier},
	}
	if cfg.Resource != "" {
		form.Set("resource", cfg.Resource)
	}
	tr, err := requestToken(ctx, httpClient(30*time.Second), cfg.TokenURL, form)
	if err != nil {
		return fmt.Errorf("code exchange failed: %w", err)
	}

	sess := &Session{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenURL:     cfg.TokenURL,
		Resource:     cfg.Resource,
		Scope:        tr.Scope,
		ObtainedAt:   time.Now().Unix(),
	}
	if sess.RefreshToken == "" {
		return fmt.Errorf("no refresh_token returned — ensure a refresh-token scope is granted")
	}
	if err := saveSession(sessionPath, sess); err != nil {
		return err
	}
	fmt.Printf("\nAuthorized. Session saved to %s\n", sessionPath)
	return nil
}

// tryRefreshExisting checks for a saved session and verifies it by attempting a
// refresh. A file merely existing isn't proof — the refresh token may have been
// revoked server-side — so this makes one real round-trip.
func tryRefreshExisting(cfg *Config, sessionPath string) (Session, bool) {
	sess, err := loadSession(sessionPath)
	if err != nil || sess.RefreshToken == "" {
		return Session{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	updated, err := refreshToken(ctx, httpClient(30*time.Second), cfg.TokenURL, cfg.ClientID, cfg.Resource, *sess)
	if err != nil {
		fmt.Printf("Existing session can't be refreshed (%v); starting browser login...\n\n", err)
		return Session{}, false
	}
	// Re-stamp the freshly resolved endpoint/resource so the session stays current.
	updated.TokenURL = cfg.TokenURL
	updated.Resource = cfg.Resource
	return updated, true
}

func buildAuthorizeURL(cfg *Config, challenge, state string) string {
	u, err := url.Parse(cfg.AuthorizeURL)
	if err != nil {
		return cfg.AuthorizeURL // malformed endpoint; let the request fail visibly
	}
	q := u.Query() // preserve any query params already on the endpoint
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.redirectURI())
	if cfg.Scopes != "" {
		q.Set("scope", cfg.Scopes)
	}
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	if cfg.Resource != "" {
		q.Set("resource", cfg.Resource)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// startCallbackServer binds the fixed redirect port and serves a single
// handler that validates state and captures the authorization code.
func startCallbackServer(cfg *Config, state string, resultCh chan<- callbackResult) (*http.Server, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.RedirectPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s for callback: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.RedirectPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			finish(w, resultCh, callbackResult{err: fmt.Errorf("authorization denied: %s: %s", e, q.Get("error_description"))})
			return
		}
		// Reject bad callbacks without aborting: a stray/forged request must not
		// stop us from accepting the legitimate browser redirect that follows.
		if q.Get("state") != state {
			http.Error(w, "state mismatch — ignoring callback", http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "callback missing authorization code", http.StatusBadRequest)
			return
		}
		finish(w, resultCh, callbackResult{code: code})
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	return srv, nil
}

// finish writes a browser-facing page and reports the result exactly once.
func finish(w http.ResponseWriter, resultCh chan<- callbackResult, res callbackResult) {
	if res.err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Authorization failed: %v\nYou can close this tab.", res.err)
	} else {
		fmt.Fprint(w, "Authorization complete. You can close this tab and return to the terminal.")
	}
	select {
	case resultCh <- res:
	default:
	}
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// presentAuthURL shows the authorization URL to the user, as an OSC 8 terminal
// hyperlink (clickable where supported, plain text elsewhere). No browser is
// launched, so this works over SSH / on headless hosts. It is a var so tests
// can drive the redirect instead of relying on a human.
var presentAuthURL = func(authURL string, redirectPort int) {
	fmt.Println("Open this URL in your browser to authorize:")
	fmt.Println()
	fmt.Println("  " + osc8(authURL, authURL))
	fmt.Println()
	fmt.Printf("If the proxy runs on a remote host, forward the callback port first\n(run on your local machine):\n\n  ssh -L %d:localhost:%d user@remote-host\n\n", redirectPort, redirectPort)
}

// osc8 wraps text in an OSC 8 hyperlink escape sequence.
func osc8(url, text string) string {
	return "\033]8;;" + url + "\033\\" + text + "\033]8;;\033\\"
}
