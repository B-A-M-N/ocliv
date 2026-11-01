// Command mcp-oauth-lab is a self-contained lab OAuth authorization server
// + MCP resource server for staging OAuth publication tests. It serves
// exactly the server-root paths below on loopback, behind HS256 JWT Bearer
// auth on /mcp, with one read-only tool ("ping").
//
//   - /mcp (JSON-RPC: initialize, notifications/initialized,
//     tools/list, tools/call ping; every POST requires Authorization)
//   - /.well-known/oauth-protected-resource/mcp (RFC 9728 metadata)
//   - /.well-known/oauth-authorization-server (RFC 8414 metadata)
//   - /oauth/register (minimal dynamic client registration)
//   - /oauth/authorize (GET consent page, POST approve/deny → 302)
//   - /oauth/token (authorization_code + refresh_token grants)
//   - /oauth/revoke (access jti / refresh invalidation)
//
// Contract:
//   - the public resource URL is https://<host>/r/<route-id>/mcp. The
//     expected URL arrives via MCP_RESOURCE_URL or MCP_RESOURCE_FILE
//     (the publisher-owned binding handoff); default is the local URL,
//     which fails strict discovery closed (correct: unbound lab must
//     not verify). The issuer is the resource URL with trailing /mcp
//     replaced by /oauth, derived per-request from the live binding.
//   - a relay rewrites public route-scoped shapes to these server-root
//     paths; this server never parses relay route prefixes.
//   - JWTs are HS256 with the secret from MCP_OAUTH_SECRET (min 32
//     chars, fail closed at startup if absent or short).
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

var supportedVersions = map[string]bool{
	"2024-11-05": true,
	"2025-06-18": true,
	"2026-07-28": true,
}

const (
	accessTTL  = 15 * time.Minute
	refreshTTL = 24 * time.Hour
	codeTTL    = 5 * time.Minute
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthErr(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": code, "error_description": desc,
	})
}

func result(id any, r any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": r}
}

func rpcErr(id any, code int, msg string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": msg}}
}

type clientRec struct {
	redirects []string
	issuedAt  int64
}

type txnRec struct {
	clientID    string
	redirectURI string
	challenge   string
	scope       string
	resource    string
	state       string
}

type codeRec struct {
	clientID    string
	redirectURI string
	challenge   string
	scope       string
	resource    string
	expiresAt   time.Time
}

type refreshRec struct {
	clientID  string
	scope     string
	expiresAt time.Time
}

type claims struct {
	Iss      string `json:"iss"`
	Aud      string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Jti      string `json:"jti"`
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`
}

type lab struct {
	mu           sync.Mutex
	secret       string
	resource     string
	resourceFile string
	clients      map[string]*clientRec
	txns         map[string]*txnRec
	codes        map[string]*codeRec
	refresh      map[string]*refreshRec
	revoked      map[string]bool
}

func newLab(secret, resource, resourceFile string) *lab {
	return &lab{
		secret: secret, resource: resource, resourceFile: resourceFile,
		clients: map[string]*clientRec{},
		txns:    map[string]*txnRec{},
		codes:   map[string]*codeRec{},
		refresh: map[string]*refreshRec{},
		revoked: map[string]bool{},
	}
}

// currentResource re-reads the publisher-owned binding file on every
// request, so the lab advertises the public route URL the moment the
// publisher writes it — no restart, no stale URL. A missing or
// unreadable file falls back to the startup value (local URL), which
// fails strict discovery closed.
func (l *lab) currentResource() string {
	if l.resourceFile == "" {
		return l.resource
	}
	raw, err := os.ReadFile(l.resourceFile)
	if err != nil {
		return l.resource
	}
	if u := strings.TrimSpace(string(raw)); u != "" {
		return u
	}
	return l.resource
}

// currentIssuer derives the issuer per-request from the live binding:
// the resource URL with trailing /mcp replaced by /oauth.
func (l *lab) currentIssuer() string {
	return issuerFor(l.currentResource())
}

func issuerFor(resource string) string {
	if strings.HasSuffix(resource, "/mcp") {
		return strings.TrimSuffix(resource, "/mcp") + "/oauth"
	}
	return resource + "/oauth"
}

func randHex(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func scopeHas(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// mintAccess signs an HS256 JWT valid for accessTTL. Callers needing
// nonstandard claims for tests use mintAccessCustom.
func (l *lab) mintAccess(clientID, scope string) (token, jti string, err error) {
	now := time.Now()
	return l.mintAccessCustom(clientID, scope,
		l.currentResource(), l.currentIssuer(), now.Add(accessTTL))
}

func (l *lab) mintAccessCustom(clientID, scope, aud, iss string, exp time.Time) (string, string, error) {
	jti, err := randHex(16)
	if err != nil {
		return "", "", err
	}
	now := time.Now().Unix()
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	pay, _ := json.Marshal(claims{
		Iss: iss, Aud: aud, Exp: exp.Unix(), Iat: now,
		Jti: jti, Scope: scope, ClientID: clientID,
	})
	hs := base64.RawURLEncoding.EncodeToString(hdr)
	ps := base64.RawURLEncoding.EncodeToString(pay)
	mac := hmac.New(sha256.New, []byte(l.secret))
	mac.Write([]byte(hs + "." + ps))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hs + "." + ps + "." + sig, jti, nil
}

func (l *lab) validateAccess(token string) (*claims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	mac := hmac.New(sha256.New, []byte(l.secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(want)) != 1 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var c claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, false
	}
	if c.Iss != l.currentIssuer() || c.Aud != l.currentResource() {
		return nil, false
	}
	if time.Now().Unix() >= c.Exp {
		return nil, false
	}
	if !scopeHas(c.Scope, "mcp:tools") {
		return nil, false
	}
	l.mu.Lock()
	revoked := l.revoked[c.Jti]
	l.mu.Unlock()
	if revoked {
		return nil, false
	}
	return &c, true
}

func (l *lab) challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate",
		`Bearer realm="mcp-oauth-lab", resource="`+l.currentResource()+
			`", error="invalid_token", error_description="valid Bearer JWT required"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (l *lab) authorized(r *http.Request) (*claims, bool) {
	h := r.Header.Get("Authorization")
	if h == "" || !strings.HasPrefix(h, "Bearer ") {
		return nil, false
	}
	return l.validateAccess(strings.TrimPrefix(h, "Bearer "))
}

func (l *lab) serveMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := l.authorized(r); !ok {
		l.challenge(w)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var in rpcReq
	if err := json.Unmarshal(body, &in); err != nil || in.JSONRPC != "2.0" {
		writeJSON(w, rpcErr(nil, -32700, "parse error"))
		return
	}
	if in.ID == nil {
		fmt.Printf("oauth-lab: notification %s accepted\n", in.Method)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	fmt.Printf("oauth-lab: method=%s id=%v\n", in.Method, in.ID)
	switch in.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(in.Params, &p)
		if !supportedVersions[p.ProtocolVersion] {
			writeJSON(w, rpcErr(in.ID, -32602,
				fmt.Sprintf("unsupported protocol version %q", p.ProtocolVersion)))
			return
		}
		writeJSON(w, result(in.ID, map[string]any{
			"protocolVersion": p.ProtocolVersion,
			"capabilities":    map[string]any{},
			"serverInfo":      map[string]any{"name": "ocliv-oauth-lab", "version": "1"},
		}))
	case "tools/list":
		writeJSON(w, result(in.ID, map[string]any{
			"tools": []any{map[string]any{
				"name":        "ping",
				"description": "authenticated read-only smoke probe",
				"annotations": map[string]any{"readOnlyHint": true},
				"inputSchema": map[string]any{
					"type":                 "object",
					"properties":           map[string]any{},
					"additionalProperties": false,
				},
			}},
		}))
	case "tools/call":
		var p rpcCallParams
		if err := json.Unmarshal(in.Params, &p); err != nil {
			writeJSON(w, rpcErr(in.ID, -32602, "invalid params"))
			return
		}
		if p.Name != "ping" {
			writeJSON(w, rpcErr(in.ID, -32602, fmt.Sprintf("unknown tool %q", p.Name)))
			return
		}
		if len(p.Arguments) != 0 {
			writeJSON(w, rpcErr(in.ID, -32602, "ping takes no arguments"))
			return
		}
		writeJSON(w, result(in.ID, map[string]any{
			"content": []any{map[string]any{
				"type": "text",
				"text": "pong:ocliv-oauth-lab-1",
			}},
		}))
	case "ping":
		writeJSON(w, result(in.ID, map[string]any{}))
	default:
		writeJSON(w, rpcErr(in.ID, -32601, "method not found"))
	}
}

func (l *lab) serveProtectedResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{
		"resource":                 l.currentResource(),
		"authorization_servers":    []string{l.currentIssuer()},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp:tools", "offline_access"},
	})
}

func (l *lab) serveAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	iss := l.currentIssuer()
	writeJSON(w, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"registration_endpoint":                 iss + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

func (l *lab) serveRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var in struct {
		RedirectURIs []string `json:"redirect_uris"`
		GrantTypes   []string `json:"grant_types"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_client_metadata", "malformed registration")
		return
	}
	if len(in.RedirectURIs) == 0 {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris required")
		return
	}
	for _, ru := range in.RedirectURIs {
		u, err := url.Parse(ru)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			writeOAuthErr(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must be https URLs")
			return
		}
	}
	allowed := map[string]bool{"authorization_code": true, "refresh_token": true}
	for _, g := range in.GrantTypes {
		if !allowed[g] {
			writeOAuthErr(w, http.StatusBadRequest, "invalid_client_metadata", fmt.Sprintf("unsupported grant_type %q", g))
			return
		}
	}
	id, err := randHex(20) // 160-bit client_id
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	grants := in.GrantTypes
	if grants == nil {
		grants = []string{"authorization_code", "refresh_token"}
	}
	l.mu.Lock()
	l.clients[id] = &clientRec{redirects: in.RedirectURIs, issuedAt: time.Now().Unix()}
	l.mu.Unlock()
	writeJSON(w, map[string]any{
		"client_id":                  id,
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              in.RedirectURIs,
		"grant_types":                grants,
		"token_endpoint_auth_method": "none",
	})
}

func (l *lab) clientRedirectOK(id, redirectURI string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.clients[id]
	if !ok {
		return false
	}
	for _, ru := range c.redirects {
		if ru == redirectURI {
			return true
		}
	}
	return false
}

func (l *lab) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		l.authorizeGet(w, r)
	case http.MethodPost:
		l.authorizePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (l *lab) authorizeGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	l.mu.Lock()
	_, known := l.clients[clientID]
	l.mu.Unlock()
	if clientID == "" || !known {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	if redirectURI == "" || !l.clientRedirectOK(clientID, redirectURI) {
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" {
		http.Error(w, "response_type must be code", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "code_challenge with S256 required", http.StatusBadRequest)
		return
	}
	if res := q.Get("resource"); res != "" && res != l.currentResource() {
		http.Error(w, "resource mismatch", http.StatusBadRequest)
		return
	}
	scope := q.Get("scope")
	if scope == "" {
		scope = "mcp:tools"
	}
	txn, err := randHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	l.mu.Lock()
	l.txns[txn] = &txnRec{
		clientID: clientID, redirectURI: redirectURI,
		challenge: q.Get("code_challenge"), scope: scope,
		resource: q.Get("resource"), state: q.Get("state"),
	}
	l.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><body><h1>Authorize %s?</h1>`+
		`<p>Scope: %s</p>`+
		`<form method="post" action="/oauth/authorize">`+
		`<input type="hidden" name="transaction_id" value="%s">`+
		`<button type="submit" name="decision" value="approve">Approve</button>`+
		`<button type="submit" name="decision" value="deny">Deny</button>`+
		`</form></body></html>`,
		html.EscapeString(clientID), html.EscapeString(scope), html.EscapeString(txn))
}

func redirectWith(w http.ResponseWriter, base string, kv map[string]string) {
	u, err := url.Parse(base)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	for k, v := range kv {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, &http.Request{}, u.String(), http.StatusFound)
}

func (l *lab) authorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	txnID := r.FormValue("transaction_id")
	l.mu.Lock()
	txn, ok := l.txns[txnID]
	if ok {
		delete(l.txns, txnID)
	}
	l.mu.Unlock()
	if !ok {
		http.Error(w, "unknown transaction", http.StatusBadRequest)
		return
	}
	if r.FormValue("decision") != "approve" {
		redirectWith(w, txn.redirectURI, map[string]string{
			"error": "access_denied", "state": txn.state,
		})
		return
	}
	code, err := randHex(16) // 128-bit code
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	l.mu.Lock()
	l.codes[code] = &codeRec{
		clientID: txn.clientID, redirectURI: txn.redirectURI,
		challenge: txn.challenge, scope: txn.scope,
		resource: txn.resource, expiresAt: time.Now().Add(codeTTL),
	}
	l.mu.Unlock()
	redirectWith(w, txn.redirectURI, map[string]string{
		"code": code, "state": txn.state,
	})
}

func (l *lab) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		l.grantCode(w, r)
	case "refresh_token":
		l.grantRefresh(w, r)
	default:
		writeOAuthErr(w, http.StatusBadRequest, "invalid_grant", "unsupported grant_type")
	}
}

func (l *lab) grantCode(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	l.mu.Lock()
	rec, ok := l.codes[code]
	if ok {
		delete(l.codes, code) // single-use: any presentation consumes it
	}
	l.mu.Unlock()
	if !ok {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_grant", "unknown or reused code")
		return
	}
	if time.Now().After(rec.expiresAt) {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_grant", "code expired")
		return
	}
	l.mu.Lock()
	_, known := l.clients[clientID]
	l.mu.Unlock()
	if !known || clientID != rec.clientID {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_client", "unknown client")
		return
	}
	if redirectURI == "" || redirectURI != rec.redirectURI {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if verifier == "" || s256Challenge(verifier) != rec.challenge {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	access, _, err := l.mintAccess(clientID, rec.scope)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := map[string]any{
		"access_token": access, "token_type": "Bearer",
		"expires_in": int(accessTTL.Seconds()), "scope": rec.scope,
	}
	if scopeHas(rec.scope, "offline_access") {
		rt, err := randHex(32)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		l.mu.Lock()
		l.refresh[rt] = &refreshRec{
			clientID: clientID, scope: rec.scope,
			expiresAt: time.Now().Add(refreshTTL),
		}
		l.mu.Unlock()
		out["refresh_token"] = rt
	}
	writeJSON(w, out)
}

func (l *lab) grantRefresh(w http.ResponseWriter, r *http.Request) {
	rt := r.FormValue("refresh_token")
	l.mu.Lock()
	rec, ok := l.refresh[rt]
	if ok {
		delete(l.refresh, rt) // rotate: old refresh is invalidated
	}
	l.mu.Unlock()
	if !ok {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_grant", "unknown or rotated refresh token")
		return
	}
	if time.Now().After(rec.expiresAt) {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	if cid := r.FormValue("client_id"); cid != "" && cid != rec.clientID {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_client", "client mismatch")
		return
	}
	access, _, err := l.mintAccess(rec.clientID, rec.scope)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	next, err := randHex(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	l.mu.Lock()
	l.refresh[next] = &refreshRec{
		clientID: rec.clientID, scope: rec.scope,
		expiresAt: time.Now().Add(refreshTTL),
	}
	l.mu.Unlock()
	writeJSON(w, map[string]any{
		"access_token": access, "token_type": "Bearer",
		"expires_in": int(accessTTL.Seconds()), "scope": rec.scope,
		"refresh_token": next,
	})
}

func (l *lab) serveRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	token := r.FormValue("token")
	if token == "" {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_request", "token required")
		return
	}
	l.mu.Lock()
	if _, ok := l.refresh[token]; ok {
		delete(l.refresh, token)
	}
	l.mu.Unlock()
	if parts := strings.Split(token, "."); len(parts) == 3 {
		mac := hmac.New(sha256.New, []byte(l.secret))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(want)) == 1 {
			if raw, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var c claims
				if json.Unmarshal(raw, &c) == nil && c.Jti != "" {
					l.mu.Lock()
					l.revoked[c.Jti] = true
					l.mu.Unlock()
				}
			}
		}
	}
	w.WriteHeader(http.StatusOK)
}

func newMux(l *lab) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", l.serveMCP)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", l.serveProtectedResource)
	mux.HandleFunc("/.well-known/oauth-authorization-server", l.serveAuthServerMetadata)
	mux.HandleFunc("/oauth/register", l.serveRegister)
	mux.HandleFunc("/oauth/authorize", l.serveAuthorize)
	mux.HandleFunc("/oauth/token", l.serveToken)
	mux.HandleFunc("/oauth/revoke", l.serveRevoke)
	return mux
}

func resolveResource(localAddr string) string {
	if u := strings.TrimSpace(os.Getenv("MCP_RESOURCE_URL")); u != "" {
		return u
	}
	if p := strings.TrimSpace(os.Getenv("MCP_RESOURCE_FILE")); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			if !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "oauth-lab: cannot read MCP_RESOURCE_FILE: %v\n", err)
				os.Exit(2)
			}
			// Missing binding file at startup is the normal boot
			// order: the publisher writes it after route registration
			// and currentResource() picks it up live. Warn loudly;
			// strict discovery still fails closed until bound.
			fmt.Fprintf(os.Stderr, "oauth-lab: MCP_RESOURCE_FILE %s not present yet; advertising local URL until bound\n", p)
		} else if u := strings.TrimSpace(string(raw)); u != "" {
			return u
		}
	}
	return "http://" + localAddr + "/mcp"
}

func main() {
	port := flag.String("port", "18767", "loopback port to listen on")
	flag.Parse()

	secret := os.Getenv("MCP_OAUTH_SECRET")
	if len(secret) < 32 {
		fmt.Fprintln(os.Stderr, "oauth-lab: MCP_OAUTH_SECRET must be set with at least 32 characters (fail closed, no anonymous mode)")
		os.Exit(2)
	}

	addr := "127.0.0.1:" + *port
	l := newLab(secret, "", strings.TrimSpace(os.Getenv("MCP_RESOURCE_FILE")))
	l.resource = resolveResource(addr)

	mux := newMux(l)
	fmt.Println("oauth-lab listening on " + addr + " resource=" + l.resource)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "oauth-lab: "+err.Error())
		os.Exit(1)
	}
}
