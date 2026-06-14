# mcp-oauth-proxy

A small HTTP-to-HTTP proxy that lets a simple bearer-token client talk to an
OAuth-protected MCP server. You log in once in the browser (Authorization Code +
PKCE); the proxy then injects and auto-refreshes the OAuth access token, so
clients only ever send a single static token.

Works with any OAuth 2.0 / 2.1 provider (PKCE, refresh-token rotation, and the
RFC 8707 resource indicator are all supported, as required by the MCP
authorization spec). The OAuth endpoints are discovered from
`mcp_url` (MCP authorization spec: RFC 9728 protected-resource metadata → RFC
8414 authorization-server metadata), so config is usually just `client_id`,
`mcp_url`, and `inbound_token`. Set `authorize_url`/`token_url` explicitly to
skip discovery.

## Usage

```sh
cp config.example.json config.json   # fill in client_id, urls, inbound_token
make build
./mcp-oauth-proxy login               # browser OAuth, saves session.json
./mcp-oauth-proxy serve               # proxy on listen_addr
```

Point your MCP client at `listen_addr` with `Authorization: Bearer <inbound_token>`.

## Quirks

Workarounds for spec violations in a specific client/server pair. Opt in via the
`quirks` array in `config.json`:

- `inject_initialized` — after a successful `initialize`, send
  `notifications/initialized` to the upstream server on the client's behalf. The
  MCP spec requires the *client* to send this notification before any other
  request; some clients (e.g. TypingMind) skip it. Servers that strictly gate on
  it — notably Salesforce — then answer `tools/list` with an empty `200` (itself
  non-compliant: it should be a JSON-RPC error), which the client reports as a
  JSON parse error. This quirk sends the missing notification so such a client
  and server can interoperate.

```json
"quirks": ["inject_initialized"]
```

## Debugging

Pass `-d[=N]` to trace HTTP traffic (`serve` and `login`): `-d=1` logs request
URLs and statuses, `-d=2` adds request bodies, `-d=3` adds response bodies, and
`-d=4` also traces streaming (SSE) bodies. Without `-d`, `serve` prints a
one-line access log per request. Levels ≥2 print tokens in cleartext.

## License

Released under the [MIT License](LICENSE). Provided "as is", without warranty of
any kind and with no guarantee — use at your own risk.
