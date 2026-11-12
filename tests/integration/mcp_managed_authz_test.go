package integration

// Managed authorization end-to-end (relay-side AS). A route whose upstream
// has no native OAuth is fronted by the relay acting as the Authorization
// Server. This file proves, through the REAL relay → agent → upstream path:
//
//   - a client that registers but is not operator-approved gets no tool access
//   - no token is minted before approval (publication-level boundary)
//   - the external bearer is NEVER forwarded upstream; the relay injects a
//     relay-minted upstream identity instead
//   - a valid token executes exactly once
//   - missing / tampered / revoked / rotated-key tokens execute zero tools
//
// The oracle is the upstream execution counter plus the headers it observes,
// not status codes alone.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"ocliv/internal/authz"
	"ocliv/internal/config"
	"ocliv/internal/mcp"
)

// managedUpstream is a plain local MCP server with no OAuth of its own. It
// counts executions and records the identity headers the relay injects.
type managedUpstream struct {
	execs     atomic.Int64
	seenAuth  atomic.Value // last Authorization header (must always be empty)
	seenSub   atomic.Value // last X-Ocliv-Upstream-Sub
	seenRoute atomic.Value // last X-Ocliv-Route
	srv       *httptest.Server
}

func startManagedUpstream(t *testing.T) *managedUpstream {
	t.Helper()
	up := &managedUpstream{}
	up.seenAuth.Store("<unset>")
	up.seenSub.Store("<unset>")
	up.seenRoute.Store("<unset>")
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		up.seenAuth.Store(r.Header.Get("Authorization"))
		up.seenSub.Store(r.Header.Get("X-Ocliv-Upstream-Sub"))
		up.seenRoute.Store(r.Header.Get("X-Ocliv-Route"))
		up.execs.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":["demo"]}}`))
	})
	up.srv = httptest.NewServer(mux)
	t.Cleanup(up.srv.Close)
	return up
}

// publicationTenant reads the owning tenant of a route's publication.
func publicationTenant(t *testing.T, h *harness, rid string) string {
	t.Helper()
	var tenant string
	if err := h.db.SQL().QueryRow(
		`SELECT tenant_id FROM mcp_publications WHERE route_id=? AND revoked_at IS NULL`, rid).Scan(&tenant); err != nil {
		t.Fatalf("publication tenant: %v", err)
	}
	return tenant
}

// managedHarness attaches an agent and registers a managed-oauth route.
func managedHarness(t *testing.T) (*harness, *managedUpstream, string, string) {
	t.Helper()
	up := startManagedUpstream(t)
	h := newHarnessNS(t, "tenant-mgd.example.test", "relay.example.test", "public.example.org")
	t.Cleanup(func() { h.db.Close() })
	t.Cleanup(h.relaySrv.Close)
	h.startAgentOpts(t, portOfUpstream(t, up.srv.URL), config.Agent{AccessMode: "mcp_managed_oauth"})
	code, rid, url, _ := mgmtRouteCreate(t, h, "managed-oauth")
	if code != http.StatusOK {
		t.Fatalf("managed route create status=%d", code)
	}
	return h, up, rid, url
}

// managedCall posts a tools/list to the route with an optional bearer.
func managedCall(t *testing.T, h *harness, rid, bearer string) (int, string) {
	t.Helper()
	headers := map[string]string{"Content-Type": "application/json"}
	if bearer != "" {
		headers["Authorization"] = "Bearer " + bearer
	}
	resp := routeReq(t, h, "public.example.org", "/r/"+rid+"/mcp", headers)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	return resp.StatusCode, string(body)
}

// managedDCR registers a client for the route.
func managedDCR(t *testing.T, h *harness, rid string) string {
	t.Helper()
	body := `{"client_name":"managed-test","redirect_uris":["http://127.0.0.1:59999/cb"],"token_endpoint_auth_method":"none"}`
	resp := routeReqBody(t, h, "public.example.org", "/r/"+rid+"/oauth/register", body)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("DCR status=%d body=%s", resp.StatusCode, raw)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.ClientID == "" {
		t.Fatalf("DCR reply unparseable: %v (%q)", err, raw)
	}
	return out.ClientID
}

func routeReqBody(t *testing.T, h *harness, host, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.relaySrv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	resp, err := visitorClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// managedAuthorize runs the authorization step and returns the code from the
// redirect Location, or "" when no code was issued.
func managedAuthorize(t *testing.T, h *harness, rid, clientID, verifier string) string {
	t.Helper()
	challenge := base64.RawURLEncoding.EncodeToString(func() []byte {
		sum := sha256.Sum256([]byte(verifier))
		return sum[:]
	}())
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "http://127.0.0.1:59999/cb")
	q.Set("response_type", "code")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", "xyz")
	req, err := http.NewRequest(http.MethodGet, h.relaySrv.URL+"/r/"+rid+"/oauth/authorize?"+q.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "public.example.org"
	resp, err := visitorClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusFound {
		return ""
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("bad redirect: %v", err)
	}
	return loc.Query().Get("code")
}

// managedToken exchanges a code for an access token.
func managedToken(t *testing.T, h *harness, rid, clientID, code, verifier string) (int, string) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "http://127.0.0.1:59999/cb")
	form.Set("code_verifier", verifier)
	req, err := http.NewRequest(http.MethodPost, h.relaySrv.URL+"/r/"+rid+"/oauth/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "public.example.org"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := visitorClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, string(raw)
}

// TestManagedAuthzPublicationLevelBoundary: a registered-but-unapproved
// client receives no token and no tool access.
func TestManagedAuthzPublicationLevelBoundary(t *testing.T) {
	h, up, rid, _ := managedHarness(t)
	clientID := managedDCR(t, h, rid)

	// No bearer: denied, zero executions.
	before := up.execs.Load()
	if code, _ := managedCall(t, h, rid, ""); code != http.StatusUnauthorized {
		t.Fatalf("no bearer status=%d, want 401", code)
	}
	if got := up.execs.Load() - before; got != 0 {
		t.Fatalf("no bearer executed %d tools, want 0", got)
	}

	// Authorization before approval: no code is issued.
	if code := managedAuthorize(t, h, rid, clientID, "verifier-1"); code != "" {
		t.Fatalf("authorization issued code %q before approval, want none", code)
	}

	// A forged token must not work.
	before = up.execs.Load()
	if code, _ := managedCall(t, h, rid, "forged-token"); code != http.StatusUnauthorized {
		t.Fatalf("forged bearer status=%d, want 401", code)
	}
	if got := up.execs.Load() - before; got != 0 {
		t.Fatalf("forged bearer executed %d tools, want 0", got)
	}
}

// TestManagedAuthzApprovedClientExecutesOnce: after operator approval the
// client completes the flow, executes exactly once, and the upstream sees
// the relay-minted identity — never the external bearer.
func TestManagedAuthzApprovedClientExecutesOnce(t *testing.T) {
	h, up, rid, _ := managedHarness(t)
	clientID := managedDCR(t, h, rid)

	// Operator approval (the publication-level boundary).
	st := authz.NewSQLStore(h.db.SQL())
	tenant := publicationTenant(t, h, rid)
	if err := st.ApproveGrant(clientID, tenant, rid); err != nil {
		t.Fatalf("approve: %v", err)
	}

	code := managedAuthorize(t, h, rid, clientID, "verifier-2")
	if code == "" {
		t.Fatal("approved client received no authorization code")
	}
	status, body := managedToken(t, h, rid, clientID, code, "verifier-2")
	if status != http.StatusOK {
		t.Fatalf("token status=%d body=%s", status, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token reply unparseable: %v (%q)", err, body)
	}

	before := up.execs.Load()
	code2, _ := managedCall(t, h, rid, tok.AccessToken)
	if code2 != http.StatusOK {
		t.Fatalf("approved call status=%d, want 200", code2)
	}
	if got := up.execs.Load() - before; got != 1 {
		t.Fatalf("approved call executed %d tools, want 1", got)
	}
	// The external bearer must never reach the upstream.
	if seen, _ := up.seenAuth.Load().(string); seen != "" {
		t.Fatalf("upstream saw Authorization %q, want none", seen)
	}
	if sub, _ := up.seenSub.Load().(string); sub != clientID {
		t.Fatalf("upstream identity = %q, want client %q", sub, clientID)
	}
	if route, _ := up.seenRoute.Load().(string); route != rid {
		t.Fatalf("upstream route = %q, want %q", route, rid)
	}
}

// TestManagedAuthzTokenBinding: a token is bound to its route, tenant,
// audience, and PKCE verifier. Every mismatch executes zero tools.
func TestManagedAuthzTokenBinding(t *testing.T) {
	h, up, rid, _ := managedHarness(t)
	clientID := managedDCR(t, h, rid)
	st := authz.NewSQLStore(h.db.SQL())
	tenant := publicationTenant(t, h, rid)
	if err := st.ApproveGrant(clientID, tenant, rid); err != nil {
		t.Fatalf("approve: %v", err)
	}
	code := managedAuthorize(t, h, rid, clientID, "verifier-3")
	if code == "" {
		t.Fatal("no code")
	}

	// A failed PKCE exchange burns the code (fail-closed: an intercepted
	// code cannot be brute-forced against the verifier).
	if status, body := managedToken(t, h, rid, clientID, code, "wrong-verifier"); status == http.StatusOK {
		t.Fatalf("wrong verifier minted a token: %s", body)
	}
	if status, _ := managedToken(t, h, rid, clientID, code, "verifier-3"); status != http.StatusBadRequest {
		t.Fatalf("replaying a burned code status=%d, want 400", status)
	}

	// A fresh code with the correct verifier works.
	code = managedAuthorize(t, h, rid, clientID, "verifier-3")
	if code == "" {
		t.Fatal("no fresh code")
	}
	status, body := managedToken(t, h, rid, clientID, code, "verifier-3")
	if status != http.StatusOK {
		t.Fatalf("correct verifier status=%d body=%s", status, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token reply unparseable: %v (%q)", err, body)
	}

	// Replay: the code is single-use.
	if status, _ := managedToken(t, h, rid, clientID, code, "verifier-3"); status == http.StatusOK {
		t.Fatal("authorization code replay minted a second token")
	}

	// A tampered bearer is denied with zero executions.
	before := up.execs.Load()
	if c, _ := managedCall(t, h, rid, tok.AccessToken+"x"); c != http.StatusUnauthorized {
		t.Fatalf("tampered bearer status=%d, want 401", c)
	}
	if got := up.execs.Load() - before; got != 0 {
		t.Fatalf("tampered bearer executed %d tools, want 0", got)
	}
}

// TestManagedAuthzRevocationIsImmediate: revoking the grant stops the token
// at the next request, with zero executions.
func TestManagedAuthzRevocationIsImmediate(t *testing.T) {
	h, up, rid, _ := managedHarness(t)
	clientID := managedDCR(t, h, rid)
	st := authz.NewSQLStore(h.db.SQL())
	tenant := publicationTenant(t, h, rid)
	if err := st.ApproveGrant(clientID, tenant, rid); err != nil {
		t.Fatalf("approve: %v", err)
	}
	code := managedAuthorize(t, h, rid, clientID, "verifier-4")
	if code == "" {
		t.Fatal("no code")
	}
	status, body := managedToken(t, h, rid, clientID, code, "verifier-4")
	if status != http.StatusOK {
		t.Fatalf("token status=%d body=%s", status, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token reply unparseable: %v (%q)", err, body)
	}
	if c, _ := managedCall(t, h, rid, tok.AccessToken); c != http.StatusOK {
		t.Fatalf("pre-revocation call status=%d, want 200", c)
	}

	if err := st.RevokeGrant(clientID, tenant, rid); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	before := up.execs.Load()
	if c, _ := managedCall(t, h, rid, tok.AccessToken); c != http.StatusUnauthorized {
		t.Fatalf("post-revocation call status=%d, want 401", c)
	}
	if got := up.execs.Load() - before; got != 0 {
		t.Fatalf("post-revocation executed %d tools, want 0", got)
	}
}

// TestManagedAuthzKeyRotation: rotating the issuer key invalidates every
// token signed by the retired key.
func TestManagedAuthzKeyRotation(t *testing.T) {
	h, up, rid, _ := managedHarness(t)
	clientID := managedDCR(t, h, rid)
	st := authz.NewSQLStore(h.db.SQL())
	tenant := publicationTenant(t, h, rid)
	if err := st.ApproveGrant(clientID, tenant, rid); err != nil {
		t.Fatalf("approve: %v", err)
	}
	code := managedAuthorize(t, h, rid, clientID, "verifier-5")
	if code == "" {
		t.Fatal("no code")
	}
	status, body := managedToken(t, h, rid, clientID, code, "verifier-5")
	if status != http.StatusOK {
		t.Fatalf("token status=%d body=%s", status, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token reply unparseable: %v (%q)", err, body)
	}

	if _, err := st.RotateIssuer(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	before := up.execs.Load()
	if c, _ := managedCall(t, h, rid, tok.AccessToken); c != http.StatusUnauthorized {
		t.Fatalf("post-rotation call status=%d, want 401", c)
	}
	if got := up.execs.Load() - before; got != 0 {
		t.Fatalf("post-rotation executed %d tools, want 0", got)
	}
}

// TestManagedAuthzRepublishPreservesApproval: a publisher restart rebinds
// the SAME route identity, so operator approvals survive it — the client's
// existing token keeps working with no re-approval. An incompatible
// authentication-mode change under the same stable name is refused.
func TestManagedAuthzRepublishPreservesApproval(t *testing.T) {
	h, up, rid, _ := managedHarness(t)
	clientID := managedDCR(t, h, rid)
	st := authz.NewSQLStore(h.db.SQL())
	tenant := publicationTenant(t, h, rid)
	if err := st.ApproveGrant(clientID, tenant, rid); err != nil {
		t.Fatalf("approve: %v", err)
	}
	authCode := managedAuthorize(t, h, rid, clientID, "verifier-repub")
	if authCode == "" {
		t.Fatal("no authorization code")
	}
	status, body := managedToken(t, h, rid, clientID, authCode, "verifier-repub")
	if status != http.StatusOK {
		t.Fatalf("token status=%d body=%s", status, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token reply unparseable: %v (%q)", err, body)
	}
	if c, _ := managedCall(t, h, rid, tok.AccessToken); c != http.StatusOK {
		t.Fatalf("pre-restart call status=%d, want 200", c)
	}

	// Publisher restart: republish under the same name/profile.
	code, rid2, _, _ := mgmtRouteCreate(t, h, "managed-oauth")
	if code != http.StatusOK {
		t.Fatalf("republish status=%d", code)
	}
	if rid2 != rid {
		t.Fatalf("republish minted %q, want stable %q", rid2, rid)
	}

	// Approval state is preserved: the same token still works, with no
	// re-approval and no new grant row.
	grants, err := st.ListGrants()
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	n := 0
	for _, g := range grants {
		if g.ClientID == clientID && g.Route == rid {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("approval rows for client/route = %d, want 1 (no duplicate, none lost)", n)
	}
	before := up.execs.Load()
	if c, _ := managedCall(t, h, rid, tok.AccessToken); c != http.StatusOK {
		t.Fatalf("post-restart call status=%d, want 200", c)
	}
	if got := up.execs.Load() - before; got != 1 {
		t.Fatalf("post-restart executed %d tools, want 1", got)
	}

	// An incompatible authentication-mode change under the same stable
	// name is refused, never silently applied.
	if code, _, _, _ := mgmtRouteCreate(t, h, "upstream-oauth"); code != http.StatusConflict {
		t.Fatalf("mode change status=%d, want 409", code)
	}
	// The route is unchanged and still serving.
	if c, _ := managedCall(t, h, rid, tok.AccessToken); c != http.StatusOK {
		t.Fatalf("post-mode-change call status=%d, want 200", c)
	}
}

// TestManagedAuthzDiscoveryIsRouteScoped: PRM names this route's resource and
// this route's AS; the AS metadata advertises exactly the route's endpoints.
func TestManagedAuthzDiscoveryIsRouteScoped(t *testing.T) {
	h, _, rid, routeURL := managedHarness(t)

	resp := routeReq(t, h, "public.example.org", "/.well-known/oauth-protected-resource/r/"+rid+"/mcp", nil)
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PRM status=%d", resp.StatusCode)
	}
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(raw, &prm); err != nil {
		t.Fatalf("PRM unparseable: %v (%q)", err, raw)
	}
	if prm.Resource != routeURL {
		t.Fatalf("PRM resource = %q, want %q", prm.Resource, routeURL)
	}
	if len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != strings.TrimSuffix(routeURL, "/mcp")+"/oauth" {
		t.Fatalf("PRM authorization_servers = %v, want the route AS", prm.AuthorizationServers)
	}

	resp2 := routeReq(t, h, "public.example.org", "/.well-known/oauth-authorization-server/r/"+rid+"/oauth", nil)
	raw2, _ := io.ReadAll(io.LimitReader(resp2.Body, 64*1024))
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("AS metadata status=%d", resp2.StatusCode)
	}
	var as struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		RegistrationEndpoint  string `json:"registration_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(raw2, &as); err != nil {
		t.Fatalf("AS metadata unparseable: %v (%q)", err, raw2)
	}
	wantIssuer := strings.TrimSuffix(routeURL, "/mcp") + "/oauth"
	if as.Issuer != wantIssuer {
		t.Fatalf("AS issuer = %q, want %q", as.Issuer, wantIssuer)
	}
	if as.AuthorizationEndpoint != wantIssuer+"/authorize" || as.TokenEndpoint != wantIssuer+"/token" ||
		as.RegistrationEndpoint != wantIssuer+"/register" || as.JWKSURI != wantIssuer+"/jwks" {
		t.Fatalf("AS endpoints not route-scoped: %+v", as)
	}
}

// TestManagedAuthzStdioAdapter: a relay-terminated route backed by the
// bounded stdio adapter. The external client completes OAuth against the
// relay, and the child sees only the forwarded JSON-RPC message — never
// the external bearer.
func TestManagedAuthzStdioAdapter(t *testing.T) {
	// cat echoes its stdin line back, so the child's reply is the request
	// body plus a newline: a deterministic protocol round trip.
	a, err := mcp.New(mcp.Options{Command: "cat"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, portStr, err := net.SplitHostPort(a.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	h := newHarnessNS(t, "tenant-stdio.example.test", "relay.example.test", "public.example.org")
	t.Cleanup(func() { h.db.Close() })
	t.Cleanup(h.relaySrv.Close)
	h.startAgentOpts(t, port, config.Agent{AccessMode: "mcp_managed_oauth"})
	code, rid, _, _ := mgmtRouteCreate(t, h, "managed-oauth")
	if code != http.StatusOK {
		t.Fatalf("managed route create status=%d", code)
	}

	clientID := managedDCR(t, h, rid)
	st := authz.NewSQLStore(h.db.SQL())
	tenant := publicationTenant(t, h, rid)
	if err := st.ApproveGrant(clientID, tenant, rid); err != nil {
		t.Fatalf("approve: %v", err)
	}
	authCode := managedAuthorize(t, h, rid, clientID, "verifier-stdio")
	if authCode == "" {
		t.Fatal("no authorization code")
	}
	status, body := managedToken(t, h, rid, clientID, authCode, "verifier-stdio")
	if status != http.StatusOK {
		t.Fatalf("token status=%d body=%s", status, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token reply unparseable: %v (%q)", err, body)
	}

	// No bearer: denied before the child is touched.
	if c, _ := managedCall(t, h, rid, ""); c != http.StatusUnauthorized {
		t.Fatalf("no bearer status=%d, want 401", c)
	}

	// Authorized: the child echoes the exact JSON-RPC message.
	const rpcBody = `{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}`
	req, err := http.NewRequest(http.MethodPost, h.relaySrv.URL+"/r/"+rid+"/mcp", strings.NewReader(rpcBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "public.example.org"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := visitorClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized stdio call status=%d, want 200", resp.StatusCode)
	}
	if string(raw) != rpcBody+"\n" {
		t.Fatalf("stdio child reply = %q, want the echoed request", raw)
	}
}

var _ = fmt.Sprintf
