package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// endpoints is the result of discovering an MCP server's OAuth configuration.
type endpoints struct {
	authorize string
	token     string
	resource  string
	scopes    []string
}

// protectedResourceMetadata is the RFC 9728 document the MCP server publishes.
type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// authServerMetadata is the RFC 8414 / OpenID Connect discovery document.
type authServerMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// ensureEndpoints fills authorize/token (and, if unset, resource and scopes) by
// discovering them from the MCP server. Explicitly configured endpoints win and
// skip discovery entirely.
func ensureEndpoints(ctx context.Context, cfg *Config) error {
	if cfg.AuthorizeURL != "" && cfg.TokenURL != "" {
		return nil
	}
	hc := httpClient(30 * time.Second)
	ep, err := discover(ctx, hc, cfg.MCPURL)
	if err != nil {
		return fmt.Errorf("endpoint discovery failed (set authorize_url/token_url manually): %w", err)
	}
	cfg.AuthorizeURL, cfg.TokenURL = ep.authorize, ep.token
	if cfg.Resource == "" {
		cfg.Resource = ep.resource
	}
	if cfg.Scopes == "" {
		cfg.Scopes = strings.Join(ep.scopes, " ")
	}
	infof("discovered OAuth endpoints: authorize=%s token=%s", ep.authorize, ep.token)
	return nil
}

func discover(ctx context.Context, hc *http.Client, mcpURL string) (endpoints, error) {
	prm, err := fetchProtectedResource(ctx, hc, mcpURL)
	if err != nil {
		return endpoints{}, err
	}
	if len(prm.AuthorizationServers) == 0 {
		return endpoints{}, fmt.Errorf("protected resource metadata lists no authorization_servers")
	}
	asm, err := fetchAuthServer(ctx, hc, prm.AuthorizationServers[0])
	if err != nil {
		return endpoints{}, err
	}
	if asm.AuthorizationEndpoint == "" || asm.TokenEndpoint == "" {
		return endpoints{}, fmt.Errorf("authorization server metadata missing endpoints")
	}
	return endpoints{
		authorize: asm.AuthorizationEndpoint,
		token:     asm.TokenEndpoint,
		resource:  prm.Resource,
		scopes:    prm.ScopesSupported,
	}, nil
}

// fetchProtectedResource locates the RFC 9728 document, preferring the URL
// advertised in an unauthenticated 401 challenge and falling back to the
// well-known paths.
func fetchProtectedResource(ctx context.Context, hc *http.Client, mcpURL string) (*protectedResourceMetadata, error) {
	var candidates []string
	if u := challengeMetadataURL(ctx, hc, mcpURL); u != "" {
		candidates = append(candidates, u)
	}
	candidates = append(candidates, wellKnownResourceURLs(mcpURL)...)

	for _, u := range candidates {
		if prm, err := getJSON[protectedResourceMetadata](ctx, hc, u); err == nil && len(prm.AuthorizationServers) > 0 {
			return prm, nil
		}
	}
	return nil, fmt.Errorf("could not locate protected resource metadata for %s", mcpURL)
}

func fetchAuthServer(ctx context.Context, hc *http.Client, issuer string) (*authServerMetadata, error) {
	for _, u := range authServerMetadataURLs(issuer) {
		if asm, err := getJSON[authServerMetadata](ctx, hc, u); err == nil && asm.TokenEndpoint != "" {
			return asm, nil
		}
	}
	return nil, fmt.Errorf("could not locate authorization server metadata for %s", issuer)
}

var resourceMetadataRe = regexp.MustCompile(`resource_metadata="([^"]+)"`)

// challengeMetadataURL makes an unauthenticated request and reads the
// resource_metadata URL from a WWW-Authenticate challenge, if present.
func challengeMetadataURL(ctx context.Context, hc *http.Client, mcpURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mcpURL, nil)
	if err != nil {
		return ""
	}
	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	m := resourceMetadataRe.FindStringSubmatch(resp.Header.Get("WWW-Authenticate"))
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// wellKnownResourceURLs builds the RFC 9728 fallback locations (path-aware and
// root) for the protected resource metadata.
func wellKnownResourceURLs(mcpURL string) []string {
	u, err := url.Parse(mcpURL)
	if err != nil {
		return nil
	}
	base := u.Scheme + "://" + u.Host
	var out []string
	if p := strings.TrimRight(u.Path, "/"); p != "" {
		out = append(out, base+"/.well-known/oauth-protected-resource"+p)
	}
	return append(out, base+"/.well-known/oauth-protected-resource")
}

// authServerMetadataURLs builds RFC 8414 and OpenID Connect discovery locations
// for an issuer, honouring issuers that carry a path component.
func authServerMetadataURLs(issuer string) []string {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil
	}
	base := u.Scheme + "://" + u.Host
	out := []string{base + "/.well-known/oauth-authorization-server"}
	if p := strings.TrimRight(u.Path, "/"); p != "" {
		out = append([]string{
			base + "/.well-known/oauth-authorization-server" + p,
			base + "/.well-known/openid-configuration" + p,
		}, out...)
	}
	return append(out, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration")
}

func getJSON[T any](ctx context.Context, hc *http.Client, u string) (*T, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}
