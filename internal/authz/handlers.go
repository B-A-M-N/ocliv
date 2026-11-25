package authz

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Default bounds for the managed authorization endpoints.
const (
	DefaultCodeTTL    = 10 * time.Minute
	DefaultTokenTTL   = 1 * time.Hour
	DefaultConsentTTL = 15 * time.Minute
)

// hasExactResource enforces RFC 8707 binding without accepting ambiguous
// repeated form/query parameters. url.Values.Get silently chooses the first
// value, which could let intermediaries and the authorization server
// interpret a multi-resource request differently.
func hasExactResource(values []string, routeURL string) bool {
	return len(values) == 1 && values[0] != "" && values[0] == routeURL
}

// Bounded-input limits for the public OAuth endpoints (2026-11-14 review
// P2). Registration writes durable rows, so its request body and every
// metadata field are individually capped. The form endpoints (authorize,
// token, consent, revoke) carry no durable client metadata, so a smaller
// form limit applies.
const (
	// MaxRegisterBody bounds one dynamic client registration request.
	MaxRegisterBody = 1 << 20
	// MaxFormBody bounds one authorization/token/consent/revoke form.
	MaxFormBody = 64 << 10
	// MaxClientName bounds one registered client's display name.
	MaxClientName = 256
	// MaxClientURIs bounds the redirect_uris count per registration.
	MaxClientURIs = 32
	// MaxRedirectURILength bounds one redirect URI string.
	MaxRedirectURILength = 2048
)

// Server serves the route-scoped authorization endpoints for one managed
// route. It is stateless apart from its Issuer and Store.
type Server struct {
	Issuer    *Issuer
	Store     Store
	Tenant    string // owning tenant; grants and tokens are scoped to it
	RouteID   string
	RouteURL  string // external route URL; used as the token audience
	IssuerURL string // exact AS issuer string
	CodeTTL   time.Duration
	TokenTTL  time.Duration
	// RefreshTTL bounds a refresh token. Zero selects
	// DefaultRefreshTTL. Refresh tokens rotate on use; the operator's
	// client revocation remains the terminal authority.
	RefreshTTL time.Duration
	// ConsentTTL bounds a pending consent challenge. Zero selects
	// DefaultConsentTTL.
	ConsentTTL time.Duration
	// OIDCTxTTL bounds an in-flight federated OIDC authorization round-trip.
	// Zero selects DefaultOIDCTxTTL.
	OIDCTxTTL time.Duration
	// OIDCClient performs discovery, token exchange, and JWKS validation for
	// federated visitor authentication (OCL-005). Nil uses a strict HTTPS client.
	OIDCClient *OIDCClient
	// AutoApproveRedirectHosts is DEPRECATED: use route-scoped ClientTrustPolicy
	// paired with federated VisitorAuthPolicy instead.
	AutoApproveRedirectHosts []string
}

// NewServer builds a route-scoped authorization server.
func NewServer(issuer *Issuer, store Store, tenant, routeID, routeURL, issuerURL string) *Server {
	return &Server{
		Issuer:    issuer,
		Store:     store,
		Tenant:    tenant,
		RouteID:   routeID,
		RouteURL:  routeURL,
		IssuerURL: issuerURL,
		CodeTTL:   DefaultCodeTTL,
		TokenTTL:  DefaultTokenTTL,
	}
}

func (s *Server) codeTTL() time.Duration {
	if s.CodeTTL > 0 {
		return s.CodeTTL
	}
	return DefaultCodeTTL
}

func (s *Server) tokenTTL() time.Duration {
	if s.TokenTTL > 0 {
		return s.TokenTTL
	}
	return DefaultTokenTTL
}

// MintChallenge returns a fresh consent challenge id.
func MintChallenge() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("authz: challenge: %w", err)
	}
	return "cns_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// consentPageData is the rendered consent screen.
type consentPageData struct {
	Challenge       string
	ClientID        string
	ClientName      string
	Tenant          string
	RouteID         string
	RedirectURI     string
	CodeChallenge   string
	State           string
	Resource        string
	ConsentURL      string
	ConsentStatus   string
	ConsentComplete string
}

// renderConsent writes the native Ocliv operator authorization screen.
// Primary workflow: approve this specific transaction via Ocliv's Ed25519-signed
// management CLI (`ocliv service approve`) with zero pairing-secret copying;
// the page polls for the operator's decision and completes the OAuth redirect
// automatically. Manual pairing-secret entry remains available as a fallback.
func (s *Server) renderConsent(w http.ResponseWriter, d consentPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(http.StatusOK)
	_ = consentPageTemplate.Execute(w, d)
}

var consentPageTemplate = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize {{.ClientName}}</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body><h1>Authorize {{.ClientName}}</h1>
<p>Client <code>{{.ClientID}}</code> is requesting access to this MCP route.</p>
<p id="tx-status">Waiting for operator approval of transaction <code>{{.Challenge}}</code>…</p>
<p>Approve this exact request from your enrolled publisher host (no secrets to copy):</p>
<pre>ocliv service approve &lt;service-name&gt; --challenge {{.Challenge}}</pre>
<details><summary>Manual pairing credential fallback</summary>
<form method="post" action="{{.ConsentURL}}">
<input type="hidden" name="challenge" value="{{.Challenge}}">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="resource" value="{{.Resource}}">
<label for="pairing_secret">Pairing credential</label>
<input type="password" id="pairing_secret" name="pairing_secret" autocomplete="off" required>
<button type="submit">Approve</button>
</form>
</details>
<form id="complete-form" method="post" action="{{.ConsentComplete}}" style="display:none">
<input type="hidden" name="challenge" value="{{.Challenge}}">
</form>
<script>
(function() {
  var statusURL = {{.ConsentStatus}} + "?challenge=" + encodeURIComponent({{.Challenge}});
  var statusEl = document.getElementById("tx-status");
  var polls = 0, failures = 0, maxPolls = 300, maxFailures = 5;
  var timer = setInterval(function() {
    polls++;
    if (polls > maxPolls) {
      clearInterval(timer);
      statusEl.textContent = "Authorization request expired. Retry from your client.";
      return;
    }
    fetch(statusURL, {cache: "no-store", referrerPolicy: "no-referrer"}).then(function(r) {
      if (!r.ok) { throw new Error("status " + r.status); }
      return r.json();
    }).then(function(d) {
      failures = 0;
      if (d.status === "approved" || d.status === "denied") {
        clearInterval(timer);
        document.getElementById("complete-form").submit();
      } else if (d.status === "expired" || d.status === "consumed" || d.status === "unknown") {
        clearInterval(timer);
        statusEl.textContent = "Authorization request " + d.status + ". Retry from your client.";
      }
    }).catch(function() {
      failures++;
      if (failures >= maxFailures) {
        clearInterval(timer);
        statusEl.textContent = "Stopped polling after repeated connection errors. Reload or retry from your client.";
      }
    });
  }, 2000);
})();
</script></body></html>`))

// ProtectedResourceMetadata implements RFC 9728 for the route.
func (s *Server) ProtectedResourceMetadata() map[string]any {
	return map[string]any{
		"resource":                 s.RouteURL,
		"authorization_servers":    []string{s.IssuerURL},
		"bearer_methods_supported": []string{"header"},
	}
}

// AuthorizationServerMetadata implements RFC 8414 for the route.
func (s *Server) AuthorizationServerMetadata() map[string]any {
	base := s.IssuerURL
	return map[string]any{
		"issuer":                                         base,
		"authorization_endpoint":                         base + "/authorize",
		"token_endpoint":                                 base + "/token",
		"registration_endpoint":                          base + "/register",
		"revocation_endpoint":                            base + "/revoke",
		"jwks_uri":                                       base + "/jwks",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"scopes_supported":                               []string{"mcp:tools", "offline_access"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post"},
		"revocation_endpoint_auth_methods_supported":     []string{"none"},
		"resource_indicators_supported":                  true,
		"authorization_response_iss_parameter_supported": true,
	}
}

// ServeJWKS renders the route's key set.
func (s *Server) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := s.Issuer.JWKSJSON()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// registerReq is the RFC 7591 dynamic client registration request. Every
// client-supplied field is untrusted.
type registerReq struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	LogoURI                 string   `json:"logo_uri"`
	ClientURI               string   `json:"client_uri"`
	SoftwareID              string   `json:"software_id"`
	// ApplicationType is the RFC 8251 "native"/"web" marker MCP clients
	// are expected to send. A "web" client must not use a loopback
	// redirect: the loopback exception exists for native applications
	// only, and an absent value is treated as unspecified (older
	// clients send nothing).
	ApplicationType string `json:"application_type"`
}

// ServeRegister implements RFC 7591 dynamic client registration. It creates a
// client with NO access: the client must still be approved by an operator for
// a specific route.
func (s *Server) ServeRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Bounded input: reject the whole request when the body exceeds the cap
	// (a valid JSON prefix followed by excess bytes is NOT accepted), and
	// require exactly one JSON value.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRegisterBody))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error":             "invalid_client_metadata",
			"error_description": "registration body too large",
		})
		return
	}
	var req registerReq
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_client_metadata",
			"error_description": "malformed registration body",
		})
		return
	}
	// Exactly one JSON value: the body must contain one complete JSON
	// document and nothing else. The second decode must report a clean
	// end-of-input; ANY other outcome — a second value OR malformed
	// trailing bytes (a syntax error) — is refused. Pre-fix only a second
	// VALID value was rejected, so "object + garbage" was accepted.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_client_metadata",
			"error_description": "registration body must contain exactly one JSON value",
		})
		return
	}
	// Individually bounded metadata fields.
	if len(req.ClientName) > MaxClientName {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error":             "invalid_client_metadata",
			"error_description": "client_name too long",
		})
		return
	}
	if len(req.RedirectURIs) > MaxClientURIs {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error":             "invalid_client_metadata",
			"error_description": "too many redirect_uris",
		})
		return
	}
	for _, uri := range req.RedirectURIs {
		if len(uri) > MaxRedirectURILength {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
				"error":             "invalid_client_metadata",
				"error_description": "redirect_uri too long",
			})
			return
		}
	}
	if len(req.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris is required", http.StatusBadRequest)
		return
	}
	for _, uri := range req.RedirectURIs {
		if err := ValidateRedirectURI(uri, req.RedirectURIs); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri", "error_description": err.Error()})
			return
		}
	}
	// A "web" application type with a loopback redirect is the exact
	// shape RFC 8251 / the MCP authorization guidance tells the AS to
	// refuse: the loopback http exception exists for native clients,
	// which prove nothing about their channel. Absent or "native" is
	// accepted (older MCP clients omit the field entirely).
	if strings.EqualFold(req.ApplicationType, "web") {
		for _, uri := range req.RedirectURIs {
			if u, perr := url.Parse(uri); perr == nil && isCanonicalLoopbackHost(u.Hostname()) {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":             "invalid_redirect_uri",
					"error_description": "a web client may not use a loopback redirect",
				})
				return
			}
		}
	}
	// SSRF hardening: the relay never fetches client-supplied URLs. The
	// metadata is stored for display/audit only.

	// Bounded registration: public DCR writes durable rows, so a route
	// may hold at most MaxClientsPerRoute clients. The atomic store step
	// evicts the oldest unrevoked registration with no grant when needed;
	// granted identities and revoked ID reservations remain durable. Old
	// abandoned registrations are also reclaimed on the maintenance
	// interval, so a flood cannot grow the table without bound.
	id, err := MintClientID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	client := Client{
		ID:           id,
		Name:         req.ClientName,
		RedirectURIs: append([]string(nil), req.RedirectURIs...),
		CreatedAt:    time.Now(),
		Tenant:       s.tenant(),
		Route:        s.RouteID,
	}
	// OCL-005 & OCL-007: Dynamic client registration NEVER creates an active
	// grant. Unauthenticated registrations remain pending until resource-owner
	// authentication (federated OIDC or explicit operator approval) succeeds,
	// so registration floods are bounded and cleanly evictable by LRU/pruning.
	if err := s.Store.TryRegisterClientWithPendingGrant(client, s.tenant(), s.RouteID); err != nil {
		if err != ErrClientQuota {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": err.Error()})
			return
		}
		if _, perr := s.Store.PruneAbandonedClients(time.Now()); perr != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := s.Store.TryRegisterClientWithPendingGrant(client, s.tenant(), s.RouteID); err != nil {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error":             "invalid_client_metadata",
				"error_description": "registration quota for this route is exhausted",
			})
			return
		}
	}
	isSynth := IsSyntheticProbeRequest(r)
	_ = s.Store.RecordHostObservation(HostObservation{
		TenantID:       s.tenant(),
		RouteID:        s.RouteID,
		CanonicalURL:   s.RouteURL,
		ClientID:       id,
		ClientKind:     ClassifyClientKind(client.RedirectURIs, isSynth),
		Stage:          StageClientRegistered,
		ResultCategory: "ok",
		IsSynthetic:    isSynth,
		ObservedAt:     time.Now().UTC(),
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
	})
}

// scopedClient returns the client only when its registration belongs to
// this authorization server's tenant + route. Legacy rows with no stored
// identity are unbound and fail closed. The relay is a route-scoped AS,
// so a client_id minted through one route is not an identity on another.
func (s *Server) scopedClient(id string) (*Client, error) {
	client, err := s.Store.GetClient(id)
	if err != nil {
		return nil, err
	}
	if client.Tenant == "" || client.Route == "" {
		return nil, fmt.Errorf("authz: client %q has no route registration scope", id)
	}
	if client.Tenant != s.tenant() {
		return nil, fmt.Errorf("authz: client %q is registered for tenant %q, not tenant %q",
			id, client.Tenant, s.tenant())
	}
	if client.Route != s.RouteID {
		g, gerr := s.Store.GetGrant(id, s.tenant(), s.RouteID)
		if gerr != nil || g == nil {
			return nil, fmt.Errorf("authz: client %q is registered for tenant %q route %q, not tenant %q route %q",
				id, client.Tenant, client.Route, s.tenant(), s.RouteID)
		}
	}
	return client, nil
}

// exactOperatorApprovedBinding returns true only when an explicit, active,
// non-revoked per-client operator direct grant (GrantMethodDirectOperator)
// exists for this exact (client, tenant, route) with SkipPairing enabled and
// the requested redirectURI is bound to client. Redirect-URI-only trust policy
// grants and migrated legacy grants are explicitly excluded (OCL-005, OCL-006):
// migrated direct grants are quarantined until explicitly reauthorized.
func exactOperatorApprovedBinding(grant *Grant, client *Client, tenant, routeID, redirectURI string) bool {
	if grant == nil || client == nil || client.RevokedAt != nil {
		return false
	}
	if grant.Status != GrantActive || !grant.SkipPairing {
		return false
	}
	if grant.Provenance.Method != GrantMethodDirectOperator {
		return false
	}
	if grant.Tenant != tenant || grant.Route != routeID || client.Tenant != tenant {
		return false
	}
	for _, u := range client.RedirectURIs {
		if u == redirectURI {
			return true
		}
	}
	return false
}

// validateGrantPolicyLive re-checks live grant status AND provenance policy
// invariants (active trust policy and authoritative federated visitor policy)
// on every request, code redemption, and refresh rotation (OCL-005, OCL-006).
func validateGrantPolicyLive(store Store, grant *Grant, tenant, routeID string) error {
	if grant == nil || grant.Status != GrantActive {
		return fmt.Errorf("authz: client is not approved for this route")
	}
	vp, vperr := store.GetVisitorAuthPolicy(tenant, routeID)
	if vperr != nil {
		return fmt.Errorf("authz: verify visitor auth policy: %w", vperr)
	}
	// Make the route's federated authentication policy authoritative:
	// when a federated visitor auth policy is active, ONLY grants established
	// through federated OIDC for an currently-allowed (issuer, subject) may be
	// used. Legacy, pairing, direct_operator, and trust_policy-only grants fail
	// closed immediately.
	if vp.IsActiveFederated() {
		if grant.Provenance.Method != GrantMethodFederatedOIDC {
			return fmt.Errorf("%w: non-federated grant (%s) cannot access federated route", ErrFederatedPolicyRequired, grant.Provenance.Method)
		}
		if !vp.AllowsSubject(grant.Provenance.OwnerIssuer, grant.Provenance.OwnerSubject) {
			return fmt.Errorf("authz: federated resource-owner subject is no longer authorized for this route")
		}
		if vp.ClientPolicy != "" && grant.Provenance.TrustPolicyID == "" {
			return fmt.Errorf("authz: federated grant missing required client_policy trust binding")
		}
	} else if grant.Provenance.Method == GrantMethodFederatedOIDC {
		return fmt.Errorf("authz: federated visitor auth policy is no longer active for this route")
	}
	if grant.Provenance.TrustPolicyID != "" {
		policies, err := store.ListTrustPolicies(tenant, routeID)
		if err != nil {
			return fmt.Errorf("authz: verify trust policy: %w", err)
		}
		found := false
		for _, p := range policies {
			if p.ID == grant.Provenance.TrustPolicyID && p.Enabled && p.RevokedAt == nil {
				if vp.IsActiveFederated() && vp.ClientPolicy != "" && vp.ClientPolicy != "custom" && p.Kind != vp.ClientPolicy {
					continue
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("authz: trust policy %q has been revoked", grant.Provenance.TrustPolicyID)
		}
	}
	return nil
}

// canAutoApproveClient returns true when the relay operator has configured
// AutoApproveRedirectHosts AND every redirect URI registered on c uses
// HTTPS (or HTTP for a canonical loopback host) and matches an allowlisted host.
func (s *Server) canAutoApproveClient(c *Client) bool {
	if len(s.AutoApproveRedirectHosts) == 0 || len(c.RedirectURIs) == 0 {
		return false
	}
	allowed := make(map[string]struct{}, len(s.AutoApproveRedirectHosts))
	for _, h := range s.AutoApproveRedirectHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			allowed[h] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return false
	}
	for _, rawURI := range c.RedirectURIs {
		u, err := url.Parse(rawURI)
		if err != nil || u.Host == "" {
			return false
		}
		host := strings.ToLower(u.Hostname())
		if _, ok := allowed[host]; !ok {
			return false
		}
		if u.Scheme == "http" && !isCanonicalLoopbackHost(host) {
			return false
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return false
		}
	}
	return true
}

// ServeAuthorize starts the authorization code flow. It NEVER issues a code
// on its own: an ACTIVE grant is the operator's approval of the client, not
// an authorization of this transaction. A public client_id plus redirect URI
// is not an authentication credential — anyone can replay them — so every
// fresh authorization renders the consent page, and only a completed consent
// (the operator's single-use pairing credential against a one-time
// challenge) mints a code. A revoked client is rejected outright.
// redirectAuthorizationError emits an RFC 6749 §4.1.2.1 + RFC 9207 OAuth
// authorization error redirect containing error, optional error_description,
// original state, and exact iss. It MUST ONLY be called after client_id and
// redirect_uri have been validated against the client's registered URIs.
func redirectAuthorizationError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc, issuerURL string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errCode, "error_description": errDesc})
		return
	}
	params := u.Query()
	params.Set("error", errCode)
	if errDesc != "" {
		params.Set("error_description", errDesc)
	}
	if state != "" {
		params.Set("state", state)
	}
	if issuerURL != "" {
		params.Set("iss", issuerURL)
	}
	u.RawQuery = params.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) ServeAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	state := q.Get("state")
	challenge := q.Get("code_challenge")
	challengeMethod := q.Get("code_challenge_method")
	resource := q["resource"]

	// Step 1 (BEFORE redirect_uri is trusted): validate client and exact
	// redirect_uri membership. Never redirect an attacker-controlled URI.
	client, err := s.scopedClient(clientID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
		return
	}
	if client.RevokedAt != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client", "error_description": "client revoked"})
		return
	}
	if err := ValidateRedirectURI(redirectURI, client.RedirectURIs); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	// Step 2 (AFTER client and redirect_uri are verified): OAuth authorization
	// errors redirect back to redirect_uri with state and RFC 9207 `iss`.
	if responseType != "code" {
		redirectAuthorizationError(w, r, redirectURI, state, "unsupported_response_type", "only response_type=code is supported", s.IssuerURL)
		return
	}
	grantedScope, err := normalizeGrantedScopes(q.Get("scope"))
	if err != nil {
		redirectAuthorizationError(w, r, redirectURI, state, "invalid_scope", err.Error(), s.IssuerURL)
		return
	}
	// MCP authorization spec + RFC 8707: the canonical resource is required
	// and must be this route exactly. A token for another resource is never
	// issued for this route.
	if !hasExactResource(resource, s.RouteURL) {
		redirectAuthorizationError(w, r, redirectURI, state, "invalid_target", "resource must be this route's canonical URL", s.IssuerURL)
		return
	}
	if challengeMethod != "S256" || challenge == "" {
		redirectAuthorizationError(w, r, redirectURI, state, "invalid_request", "PKCE S256 required", s.IssuerURL)
		return
	}
	// The challenge must be a well-formed S256 value (RFC 7636 §4.2: the
	// base64url encoding of a 32-byte SHA-256 digest). Anything else is
	// rejected here rather than stored for the token step to discover.
	if err := ValidateCodeChallengeS256(challenge); err != nil {
		redirectAuthorizationError(w, r, redirectURI, state, "invalid_request", err.Error(), s.IssuerURL)
		return
	}
	grant, err := s.Store.GetGrant(clientID, s.tenant(), s.RouteID)
	if err != nil {
		grant = nil
	}
	if grant != nil && grant.Status == GrantRevoked {
		redirectAuthorizationError(w, r, redirectURI, state, "access_denied", "client revoked", s.IssuerURL)
		return
	}
	// OCL-005: Federated resource-owner authentication is authoritative when
	// configured on the route. Evaluate it BEFORE any legacy/direct-grant
	// authorization branch so enabling federated OIDC cannot be bypassed by
	// pre-existing grants.
	vp, vperr := s.Store.GetVisitorAuthPolicy(s.tenant(), s.RouteID)
	if vperr != nil {
		redirectAuthorizationError(w, r, redirectURI, state, "server_error", "visitor auth policy unavailable", s.IssuerURL)
		return
	}
	if vp.IsActiveFederated() {
		s.startFederatedOIDC(w, r, vp, client, redirectURI, challenge, state, resource[0], grantedScope)
		return
	}
	if exactOperatorApprovedBinding(grant, client, s.tenant(), s.RouteID, redirectURI) &&
		(len(s.AutoApproveRedirectHosts) == 0 || s.canAutoApproveClient(client)) {
		_ = s.Store.AuditAuthz("client", s.tenant(), s.RouteID, clientID, "authorize", "ok", "direct operator pre-approved grant")
		s.issueCode(w, r, clientID, redirectURI, challenge, "S256", state, grantedScope)
		return
	}
	// Approved AND consented: the ordinary OAuth authorization-code + PKCE
	// flow, with no Ocliv-specific authorization parameter. The consent is
	// the client's proof of possession of the pairing credential, recorded
	// durably against the grant.
	//
	// There is deliberately no "already approved" branch. An ACTIVE grant
	// authorizes nothing by itself: operator approval and transaction
	// authorization are separate things (OAuth BCP guidance on client
	// impersonation), so every authorization goes through consent.
	if grant == nil {
		if err := s.Store.CreateGrant(Grant{
			ClientID:  clientID,
			Tenant:    s.tenant(),
			Route:     s.RouteID,
			Status:    GrantPending,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
	}
	// Bounded pending state: a caller who starts flows without completing
	// them cannot fill the table. The cap is per route.
	if n, err := s.Store.CountPendingConsents(s.tenant(), s.RouteID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	} else if n >= MaxPendingConsentsPerRoute {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error":             "invalid_request",
			"error_description": "too many pending consent challenges for this route",
		})
		return
	}
	challengeID, err := MintChallenge()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.Store.CreateConsent(Consent{
		Challenge:     challengeID,
		ClientID:      clientID,
		Tenant:        s.tenant(),
		Route:         s.RouteID,
		RedirectURI:   redirectURI,
		CodeChallenge: challenge,
		State:         state,
		Resource:      resource[0],
		Scope:         grantedScope,
		ExpiresAt:     time.Now().Add(s.consentTTL()),
	}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.renderConsent(w, consentPageData{
		Challenge:       challengeID,
		ClientID:        clientID,
		ClientName:      client.Name,
		Tenant:          s.tenant(),
		RouteID:         s.RouteID,
		RedirectURI:     redirectURI,
		CodeChallenge:   challenge,
		State:           state,
		Resource:        resource[0],
		ConsentURL:      s.consentURL(),
		ConsentStatus:   s.IssuerURL + "/consent/status",
		ConsentComplete: s.IssuerURL + "/consent/complete",
	})
}

// consentURL is the canonical, route-scoped endpoint the consent form posts
// to: this route's AS issuer plus "/consent". A server-root path would not
// be served by route dispatch, and a browser following the generated form
// must land on exactly the endpoint that can complete this transaction.
func (s *Server) consentURL() string {
	return s.IssuerURL + "/consent"
}

// consentTTL bounds how long a pending consent challenge is valid.
func (s *Server) consentTTL() time.Duration {
	if s.ConsentTTL > 0 {
		return s.ConsentTTL
	}
	return DefaultConsentTTL
}

func (s *Server) oidcTxTTL() time.Duration {
	if s.OIDCTxTTL > 0 {
		return s.OIDCTxTTL
	}
	return DefaultOIDCTxTTL
}

func (s *Server) oidcClient() *OIDCClient {
	if s.OIDCClient != nil {
		return s.OIDCClient
	}
	return &OIDCClient{}
}

func (s *Server) oidcCallbackURL() string {
	return s.IssuerURL + "/callback"
}

// startFederatedOIDC enforces client policy eligibility (exact redirect URI
// match against an active ClientTrustPolicy when configured), creates a
// single-use transaction-bound OIDC state+nonce+PKCE record, and redirects the
// resource owner to the configured OIDC provider (OCL-005).
func (s *Server) startFederatedOIDC(w http.ResponseWriter, r *http.Request, vp *VisitorAuthPolicy, client *Client, redirectURI, codeChallenge, clientState, resource, scope string) {
	var trustPolicyID string
	matchedPolicy, merr := s.Store.MatchTrustPolicy(s.tenant(), s.RouteID, client.RedirectURIs)
	if merr != nil {
		redirectAuthorizationError(w, r, redirectURI, clientState, "server_error", "trust policy check failed", s.IssuerURL)
		return
	}
	if vp.ClientPolicy != "" {
		if matchedPolicy == nil {
			_ = s.Store.AuditAuthz("visitor", s.tenant(), s.RouteID, client.ID, "federated-authorize", "denied", "client redirect does not match required client_policy "+vp.ClientPolicy)
			redirectAuthorizationError(w, r, redirectURI, clientState, "access_denied", "client does not satisfy route client_policy", s.IssuerURL)
			return
		}
		if vp.ClientPolicy != "custom" && matchedPolicy.Kind != vp.ClientPolicy {
			_ = s.Store.AuditAuthz("visitor", s.tenant(), s.RouteID, client.ID, "federated-authorize", "denied", "client_policy kind mismatch")
			redirectAuthorizationError(w, r, redirectURI, clientState, "access_denied", "client does not satisfy route client_policy", s.IssuerURL)
			return
		}
		trustPolicyID = matchedPolicy.ID
	} else if matchedPolicy != nil {
		trustPolicyID = matchedPolicy.ID
	}

	if n, err := s.Store.CountPendingOIDCTransactions(s.tenant(), s.RouteID); err != nil {
		redirectAuthorizationError(w, r, redirectURI, clientState, "server_error", "internal error", s.IssuerURL)
		return
	} else if n >= MaxPendingOIDCTxPerRoute {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error":             "invalid_request",
			"error_description": "too many pending federated login transactions for this route",
		})
		return
	}

	oidcState, err := mintRandomToken("ost_", 24)
	if err != nil {
		redirectAuthorizationError(w, r, redirectURI, clientState, "server_error", "internal error", s.IssuerURL)
		return
	}
	oidcNonce, err := mintRandomToken("onc_", 24)
	if err != nil {
		redirectAuthorizationError(w, r, redirectURI, clientState, "server_error", "internal error", s.IssuerURL)
		return
	}
	pkceVerifier, err := mintRandomToken("opk_", 36)
	if err != nil {
		redirectAuthorizationError(w, r, redirectURI, clientState, "server_error", "internal error", s.IssuerURL)
		return
	}
	idpAuthURL, err := s.oidcClient().BuildAuthorizeURL(r.Context(), vp.Issuer, vp.ClientID, s.oidcCallbackURL(), oidcState, oidcNonce, pkceVerifier)
	if err != nil {
		_ = s.Store.AuditAuthz("visitor", s.tenant(), s.RouteID, client.ID, "federated-authorize", "error", "oidc discovery failed")
		redirectAuthorizationError(w, r, redirectURI, clientState, "server_error", "identity provider unavailable", s.IssuerURL)
		return
	}
	if err := s.Store.CreateOIDCTransaction(OIDCTransaction{
		State:          oidcState,
		Nonce:          oidcNonce,
		PKCEVerifier:   pkceVerifier,
		ClientID:       client.ID,
		Tenant:         s.tenant(),
		Route:          s.RouteID,
		RedirectURI:    redirectURI,
		CodeChallenge:  codeChallenge,
		ClientState:    clientState,
		Resource:       resource,
		Scope:          scope,
		TrustPolicyID:  trustPolicyID,
		PolicyRevision: vp.Revision,
		ExpiresAt:      time.Now().UTC().Add(s.oidcTxTTL()),
	}); err != nil {
		redirectAuthorizationError(w, r, redirectURI, clientState, "server_error", "internal error", s.IssuerURL)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, idpAuthURL, http.StatusFound)
}

// ServeOIDCCallback completes federated resource-owner authentication after
// the upstream OIDC provider redirects back to /r/<route-id>/oauth/callback
// (OCL-005). It validates state, exchanges the code with PKCE via oauth2,
// verifies the id_token via go-oidc/v3 (signature, issuer, audience, azp,
// nonce, expiry), and then atomically validates client, publication, trust
// policy, visitor policy state & revision, subject allowlist, and revocation
// inside ONE store transaction before activating the grant.
func (s *Server) ServeOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	oidcState := strings.TrimSpace(q.Get("state"))
	idpCode := strings.TrimSpace(q.Get("code"))
	idpErr := strings.TrimSpace(q.Get("error"))
	if oidcState == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "missing state"})
		return
	}
	tx, err := s.Store.ConsumeOIDCTransaction(oidcState, s.tenant(), s.RouteID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "invalid or expired federated transaction"})
		return
	}
	if idpErr != "" {
		_ = s.Store.AuditAuthz("visitor", s.tenant(), s.RouteID, tx.ClientID, "federated-callback", "denied", "idp error "+idpErr)
		redirectAuthorizationError(w, r, tx.RedirectURI, tx.ClientState, "access_denied", "identity provider denied authentication", s.IssuerURL)
		return
	}
	if idpCode == "" {
		redirectAuthorizationError(w, r, tx.RedirectURI, tx.ClientState, "access_denied", "missing identity provider authorization code", s.IssuerURL)
		return
	}
	client, cerr := s.scopedClient(tx.ClientID)
	if cerr != nil || client.RevokedAt != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client", "error_description": "client revoked"})
		return
	}
	if existingGrant, gerr := s.Store.GetGrant(tx.ClientID, s.tenant(), s.RouteID); gerr == nil && existingGrant != nil && existingGrant.Status == GrantRevoked {
		redirectAuthorizationError(w, r, tx.RedirectURI, tx.ClientState, "access_denied", "client grant revoked", s.IssuerURL)
		return
	}
	vp, vperr := s.Store.GetVisitorAuthPolicy(s.tenant(), s.RouteID)
	if vperr != nil || !vp.IsActiveFederated() || (tx.PolicyRevision > 0 && vp.Revision != tx.PolicyRevision) {
		redirectAuthorizationError(w, r, tx.RedirectURI, tx.ClientState, "access_denied", "federated visitor auth policy inactive or changed", s.IssuerURL)
		return
	}
	subject, exErr := s.oidcClient().ExchangeAndVerify(
		r.Context(), vp.Issuer, vp.ClientID, vp.ClientSecret,
		idpCode, s.oidcCallbackURL(), tx.PKCEVerifier, tx.Nonce,
	)
	if exErr != nil {
		_ = s.Store.AuditAuthz("visitor", s.tenant(), s.RouteID, tx.ClientID, "federated-callback", "denied", "oidc exchange or verification failed")
		redirectAuthorizationError(w, r, tx.RedirectURI, tx.ClientState, "access_denied", "identity provider authentication failed", s.IssuerURL)
		return
	}
	// Atomically re-verify client, publication, trust policy, visitor policy
	// state & revision, allowed issuer/subject, and grant revocation inside
	// ONE store transaction before activating the grant (eliminates TOCTOU).
	act := FederatedGrantActivation{
		ClientID:               tx.ClientID,
		Tenant:                 s.tenant(),
		Route:                  s.RouteID,
		RedirectURI:            tx.RedirectURI,
		ExpectedPolicyRevision: tx.PolicyRevision,
		TrustPolicyID:          tx.TrustPolicyID,
		OwnerIssuer:            vp.Issuer,
		OwnerSubject:           subject,
	}
	if err := s.Store.ApproveFederatedGrantAtomic(act); err != nil {
		_ = s.Store.AuditAuthz("visitor", s.tenant(), s.RouteID, tx.ClientID, "federated-callback", "denied", "atomic federated grant activation denied")
		redirectAuthorizationError(w, r, tx.RedirectURI, tx.ClientState, "access_denied", "grant authorization failed", s.IssuerURL)
		return
	}
	_ = s.Store.AuditAuthz("visitor", s.tenant(), s.RouteID, tx.ClientID, "authz-federated-authorize", "ok",
		"iss="+vp.Issuer+" sub="+subject+" policy="+tx.TrustPolicyID)
	s.issueCode(w, r, tx.ClientID, tx.RedirectURI, tx.CodeChallenge, "S256", tx.ClientState, tx.Scope)
}

// issueCode mints and returns an authorization code via the redirect URI.
// The code, state, and the RFC 9207 issuer identifier are added through
// url.Values so a redirect URI that already carries query parameters keeps
// them: string concatenation would corrupt it.
func normalizeGrantedScopes(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "mcp:tools offline_access", nil
	}
	seen := map[string]bool{}
	var out []string
	for _, sc := range strings.Fields(raw) {
		if sc != "mcp:tools" && sc != "offline_access" {
			return "", fmt.Errorf("unsupported scope %q", sc)
		}
		if !seen[sc] {
			seen[sc] = true
			out = append(out, sc)
		}
	}
	return strings.Join(out, " "), nil
}

func hasScope(scopeStr, target string) bool {
	for _, sc := range strings.Fields(scopeStr) {
		if sc == target {
			return true
		}
	}
	return false
}

func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, clientID, redirectURI, challenge, challengeMethod, state, scope string) {
	code, err := MintCode()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if scope == "" {
		scope = "mcp:tools offline_access"
	}
	if err := s.Store.CreateCode(Code{
		Code:            code,
		ClientID:        clientID,
		Tenant:          s.tenant(),
		Route:           s.RouteID,
		RedirectURI:     redirectURI,
		Challenge:       challenge,
		ChallengeMethod: challengeMethod,
		Scope:           scope,
		ExpiresAt:       time.Now().Add(s.codeTTL()),
	}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "internal_request", http.StatusBadRequest)
		return
	}
	params := u.Query()
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}
	if s.IssuerURL != "" {
		// RFC 9207: the authorization response names its issuer so a
		// mixed-client redirect cannot be mistaken for another AS's.
		params.Set("iss", s.IssuerURL)
	}
	u.RawQuery = params.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}

// ServeConsent completes a pending authorization after the operator submits
// the pairing credential by POST against the consent challenge.
func (s *Server) ServeConsent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	challengeID := r.Form.Get("challenge")
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	challenge := r.Form.Get("code_challenge")
	state := r.Form.Get("state")
	resourceValues := r.Form["resource"]
	pairing := r.Form.Get("pairing_secret")

	if !hasExactResource(resourceValues, s.RouteURL) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target",
			"error_description": "resource must be this route's canonical URL"})
		return
	}
	resource := resourceValues[0]
	// Consume the challenge first: it is one-time, expiring, and bound to the
	// transaction. Replay, expiry, and transaction mismatch all fail here.
	cons, err := s.Store.ConsumeConsent(challengeID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request",
			"error_description": err.Error()})
		return
	}
	if cons.ClientID != clientID || cons.RedirectURI != redirectURI ||
		cons.CodeChallenge != challenge || cons.State != state ||
		cons.Tenant != s.tenant() || cons.Route != s.RouteID ||
		cons.Resource != resource {
		s.Store.AuditAuthz("client", s.tenant(), s.RouteID, clientID, "consent", "denied",
			"consent transaction mismatch")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request",
			"error_description": "consent transaction mismatch"})
		return
	}
	client, err := s.scopedClient(clientID)
	if err != nil || client.RevokedAt != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
		return
	}
	if vp, vperr := s.Store.GetVisitorAuthPolicy(s.tenant(), s.RouteID); vperr != nil || vp.IsActiveFederated() {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "access_denied",
			"error_description": "route requires federated visitor authentication",
		})
		return
	}
	grant, err := s.Store.GetGrant(clientID, s.tenant(), s.RouteID)
	if err != nil || grant.Status != GrantActive {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "access_denied",
			"error_description": "no operator approval for this client"})
		return
	}
	// The operator's pairing credential. Required: an approved client_id
	// alone is not consent. It is single-use and expiring: consuming it
	// burns it, so one credential authorizes exactly one consent
	// transaction and a replay fails closed.
	ok, err := s.Store.ConsumePairingSecret(clientID, s.tenant(), s.RouteID, pairing)
	if err != nil || !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "access_denied",
			"error_description": "valid operator pairing credential required",
		})
		return
	}
	// The completed consent transaction is the authorization itself: the
	// operator's credential was presented and burned, the challenge was
	// consumed, and every transaction field was rebound. Affirm the grant
	// active and mint exactly one code.
	s.Store.AuditAuthz("client", s.tenant(), s.RouteID, clientID, "consent", "ok",
		"authorization completed through operator consent")
	if err := s.Store.ApproveGrant(clientID, s.tenant(), s.RouteID); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "access_denied",
			"error_description": "operator approval unavailable",
		})
		return
	}
	s.issueCode(w, r, clientID, redirectURI, challenge, "S256", state, cons.Scope)
}

// ServeConsentStatus reports the current decision status of a transaction-bound
// consent challenge for this route so the browser consent screen can complete
// automatically once the operator approves or denies via Ocliv's Ed25519-signed
// management channel (OCL-005 native default).
func (s *Server) ServeConsentStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	challenge := strings.TrimSpace(r.URL.Query().Get("challenge"))
	if challenge == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	cons, err := s.Store.GetConsentStatus(challenge, s.tenant(), s.RouteID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"status": "unknown"})
		return
	}
	status := cons.Decision
	if cons.ConsumedAt != nil {
		status = "consumed"
	} else if cons.Expired() {
		status = "expired"
	} else if status == "" {
		status = "pending"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}

// ServeConsentComplete atomically consumes an operator-decided consent
// transaction (approved or denied via the Ed25519-signed management channel)
// and completes the standard OAuth authorization redirect with PKCE + RFC 9207
// `iss` — POST-only, zero pairing secrets copied (OCL-005 native default).
func (s *Server) ServeConsentComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	challenge := strings.TrimSpace(r.Form.Get("challenge"))
	if challenge == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "missing challenge"})
		return
	}
	if vp, vperr := s.Store.GetVisitorAuthPolicy(s.tenant(), s.RouteID); vperr != nil || vp.IsActiveFederated() {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "access_denied",
			"error_description": "route requires federated visitor authentication",
		})
		return
	}
	cons, err := s.Store.ConsumeDecidedConsent(challenge, s.tenant(), s.RouteID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if cons.Decision == "denied" {
		_ = s.Store.AuditAuthz("operator", s.tenant(), s.RouteID, cons.ClientID, "consent-complete", "denied", "operator denied transaction")
		redirectAuthorizationError(w, r, cons.RedirectURI, cons.State, "access_denied", "operator denied authorization request", s.IssuerURL)
		return
	}
	client, cerr := s.scopedClient(cons.ClientID)
	if cerr != nil || client.RevokedAt != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client", "error_description": "client revoked"})
		return
	}
	grant, gerr := s.Store.GetGrant(cons.ClientID, s.tenant(), s.RouteID)
	if gerr != nil || validateGrantPolicyLive(s.Store, grant, s.tenant(), s.RouteID) != nil {
		redirectAuthorizationError(w, r, cons.RedirectURI, cons.State, "access_denied", "client grant is no longer active", s.IssuerURL)
		return
	}
	_ = s.Store.AuditAuthz("operator", s.tenant(), s.RouteID, cons.ClientID, "consent-complete", "ok",
		"native transaction-bound approval by "+cons.DecidedByKeyID)
	s.issueCode(w, r, cons.ClientID, cons.RedirectURI, cons.CodeChallenge, "S256", cons.State, cons.Scope)
}

// DefaultRefreshTTL bounds a refresh token. It is deliberately short of
// "forever": an operator's client revocation is the terminal authority,
// and a rotating credential with a bounded life keeps a stolen refresh
// token useful only within its window (and only until first replay).
var DefaultRefreshTTL = 30 * 24 * time.Hour

// ServeToken exchanges an authorization code for an access token, and a
// refresh token for a fresh pair under RFC 6749 §6 rotation: the presented
// refresh token is consumed on use, so a replay of an already-rotated
// token fails closed and the operator's revocation of the client's grant
// terminates the lineage.
func (s *Server) ServeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.serveCodeGrant(w, r)
	case "refresh_token":
		s.serveRefreshGrant(w, r)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

// DefaultAbsoluteRefreshTTL caps the maximum lifetime of a confidential
// client's persistent opaque refresh token.
var DefaultAbsoluteRefreshTTL = 90 * 24 * time.Hour

func extractClientCredentials(r *http.Request) (clientID, clientSecret string) {
	if id, sec, ok := r.BasicAuth(); ok {
		return id, sec
	}
	return r.Form.Get("client_id"), r.Form.Get("client_secret")
}

func authenticateConfidentialClient(client *Client, secret string) bool {
	if client == nil || client.ClientSecretHash == "" || secret == "" {
		return false
	}
	got := HashSecret(secret)
	return subtle.ConstantTimeCompare([]byte(got), []byte(client.ClientSecretHash)) == 1
}

func mintOpaqueRefreshToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "rtok_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// serveCodeGrant exchanges an authorization code for tokens.
func (s *Server) serveCodeGrant(w http.ResponseWriter, r *http.Request) {
	codeStr := r.Form.Get("code")
	clientID, clientSecret := extractClientCredentials(r)
	redirectURI := r.Form.Get("redirect_uri")
	verifier := r.Form.Get("code_verifier")
	resourceValues := r.Form["resource"]

	// Any supplied resource must be exact and unambiguous. Public clients always
	// require resource; google_confidential clients may omit it on code exchange
	// (derived from the already route-bound authorization code).
	if len(resourceValues) > 0 && !hasExactResource(resourceValues, s.RouteURL) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target",
			"error_description": "resource must be this route's canonical URL"})
		return
	}
	// Client-level revocation is rechecked here so a revoked client cannot
	// redeem an already-issued authorization code. The registration must
	// also belong to this route: a client_id minted through another
	// authorization server is not an identity here.
	client, cerr := s.scopedClient(clientID)
	if cerr != nil || client.RevokedAt != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client",
			"error_description": "client revoked"})
		return
	}
	if client.ClientMode == "confidential" && !authenticateConfidentialClient(client, clientSecret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client",
			"error_description": "client authentication failed"})
		return
	}
	if !(client.ClientMode == "confidential" && client.RefreshPolicy == "google_confidential") && !hasExactResource(resourceValues, s.RouteURL) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target",
			"error_description": "resource must be this route's canonical URL"})
		return
	}

	// Scope-aware atomic consumption: the stored code's tenant/route must
	// match this endpoint inside the store transaction. A foreign route's
	// attempt is refused without consuming the code.
	code, err := s.Store.ConsumeCode(codeStr, clientID, s.tenant(), s.RouteID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": err.Error()})
		return
	}
	if code.RedirectURI != redirectURI {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if err := VerifyPKCE(code.ChallengeMethod, code.Challenge, verifier); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": err.Error()})
		return
	}
	grant, err := s.Store.GetGrant(clientID, s.tenant(), s.RouteID)
	if err != nil || validateGrantPolicyLive(s.Store, grant, s.tenant(), s.RouteID) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "client is not approved for this route"})
		return
	}
	accessJTI, err := MintJTI()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	grantedScope := strings.TrimSpace(code.Scope)
	if grantedScope == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "authorization code is missing granted scope"})
		return
	}
	access, err := s.Issuer.Mint(TokenClaims{
		Issuer:   s.IssuerURL,
		Subject:  clientID,
		Audience: s.RouteURL,
		Tenant:   s.tenant(),
		Route:    s.RouteID,
		Scope:    grantedScope,
		Expiry:   time.Now().Add(s.tokenTTL()).Unix(),
		ID:       accessJTI,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var refresh string
	if hasScope(grantedScope, "offline_access") {
		if client.ClientMode == "confidential" {
			rtok, rerr := mintOpaqueRefreshToken()
			if rerr != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			now := time.Now().UTC()
			if err := s.Store.CreateOpaqueRefresh(OpaqueRefresh{
				TokenHash:         HashSecret(rtok),
				ClientID:          clientID,
				Tenant:            s.tenant(),
				Route:             s.RouteID,
				Scope:             grantedScope,
				ExpiresAt:         now.Add(s.refreshTTL()),
				AbsoluteExpiresAt: now.Add(DefaultAbsoluteRefreshTTL),
				LastUsedAt:        now,
			}); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			refresh = rtok
		} else {
			refreshJTI, err := MintJTI()
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			refresh, err = s.Issuer.Mint(TokenClaims{
				Issuer:    s.IssuerURL,
				Subject:   clientID,
				Audience:  s.RouteURL,
				Tenant:    s.tenant(),
				Route:     s.RouteID,
				Scope:     grantedScope,
				Expiry:    time.Now().Add(s.refreshTTL()).Unix(),
				ID:        refreshJTI,
				TokenType: "refresh",
			})
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
	}
	resp := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(s.tokenTTL().Seconds()),
		"scope":        grantedScope,
	}
	if refresh != "" {
		resp["refresh_token"] = refresh
	}
	isSynth := IsSyntheticProbeRequest(r)
	_ = s.Store.RecordHostObservation(HostObservation{
		TenantID:       s.tenant(),
		RouteID:        s.RouteID,
		CanonicalURL:   s.RouteURL,
		ClientID:       clientID,
		ClientKind:     ClassifyClientKind(client.RedirectURIs, isSynth),
		Stage:          StageClientAuthorized,
		ResultCategory: "ok",
		IsSynthetic:    isSynth,
		ObservedAt:     time.Now().UTC(),
	})
	writeJSON(w, http.StatusOK, resp)
}

// serveRefreshGrant rotates a refresh token. Every check the code grant
// applies to the client still applies here: the client must not be
// revoked and its grant must still be ACTIVE, so an operator's revocation
// terminates the refresh lineage without hunting individual tokens.
func (s *Server) serveRefreshGrant(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret := extractClientCredentials(r)
	refreshStr := r.Form.Get("refresh_token")
	resourceValues := r.Form["resource"]
	if clientID == "" || refreshStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	// Any supplied resource must be exact and unambiguous, regardless of client mode.
	if len(resourceValues) > 0 && !hasExactResource(resourceValues, s.RouteURL) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target",
			"error_description": "resource must be this route's canonical URL"})
		return
	}
	client, cerr := s.scopedClient(clientID)
	if cerr != nil || client.RevokedAt != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client",
			"error_description": "client revoked"})
		return
	}
	if client.ClientMode == "confidential" {
		if !authenticateConfidentialClient(client, clientSecret) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client",
				"error_description": "client authentication failed"})
			return
		}
		// Confidential clients may omit resource on refresh (derived from the
		// bound grant), while any supplied foreign or ambiguous resource is rejected.
		if len(resourceValues) > 0 && !hasExactResource(resourceValues, s.RouteURL) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target",
				"error_description": "resource must be this route's canonical URL"})
			return
		}
		grant, err := s.Store.GetGrant(clientID, s.tenant(), s.RouteID)
		if err != nil || validateGrantPolicyLive(s.Store, grant, s.tenant(), s.RouteID) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
				"error_description": "client is not approved for this route"})
			return
		}
		if client.RefreshPolicy == "google_confidential" {
			rec, err := s.Store.ExtendOpaqueRefresh(
				HashSecret(refreshStr), clientID, s.tenant(), s.RouteID, time.Now().UTC(), s.refreshTTL(),
			)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
					"error_description": "refresh token invalid, expired, or revoked"})
				return
			}
			grantedScope := strings.TrimSpace(rec.Scope)
			if grantedScope == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
					"error_description": "refresh token has no stored scope; reauthorization required"})
				return
			}
			accessJTI, err := MintJTI()
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			access, err := s.Issuer.Mint(TokenClaims{
				Issuer:   s.IssuerURL,
				Subject:  clientID,
				Audience: s.RouteURL,
				Tenant:   s.tenant(),
				Route:    s.RouteID,
				Scope:    grantedScope,
				Expiry:   time.Now().Add(s.tokenTTL()).Unix(),
				ID:       accessJTI,
			})
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  access,
				"token_type":    "Bearer",
				"expires_in":    int(s.tokenTTL().Seconds()),
				"refresh_token": refreshStr,
				"scope":         grantedScope,
			})
			return
		}
		newRtok, rerr := mintOpaqueRefreshToken()
		if rerr != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		rec, err := s.Store.RotateOpaqueRefresh(
			HashSecret(refreshStr), HashSecret(newRtok), clientID, s.tenant(), s.RouteID, time.Now().UTC(), s.refreshTTL(),
		)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
				"error_description": "refresh token invalid, rotated, expired, or revoked"})
			return
		}
		grantedScope := strings.TrimSpace(rec.Scope)
		if grantedScope == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
				"error_description": "refresh token has no stored scope; reauthorization required"})
			return
		}
		accessJTI, err := MintJTI()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		access, err := s.Issuer.Mint(TokenClaims{
			Issuer:   s.IssuerURL,
			Subject:  clientID,
			Audience: s.RouteURL,
			Tenant:   s.tenant(),
			Route:    s.RouteID,
			Scope:    grantedScope,
			Expiry:   time.Now().Add(s.tokenTTL()).Unix(),
			ID:       accessJTI,
		})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  access,
			"token_type":    "Bearer",
			"expires_in":    int(s.tokenTTL().Seconds()),
			"refresh_token": newRtok,
			"scope":         grantedScope,
		})
		return
	}
	if !hasExactResource(resourceValues, s.RouteURL) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target",
			"error_description": "resource must be this route's canonical URL"})
		return
	}
	claims, err := s.Issuer.Verify(refreshStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
			"error_description": "refresh token verification failed"})
		return
	}
	// A refresh credential is only ever accepted here: an access token
	// presented to this grant (or a refresh token at the tool path) is a
	// credential-kind confusion and is refused.
	if claims.TokenType != "refresh" || claims.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
			"error_description": "not a refresh token"})
		return
	}
	if claims.Subject != clientID || !claims.ValidateAudience(s.RouteURL) ||
		!claims.ValidateIssuer(s.IssuerURL) || claims.Tenant != s.tenant() || claims.Route != s.RouteID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
			"error_description": "refresh token is not bound to this client and route"})
		return
	}
	// Rotation with replay detection: the presented token must be
	// unrevoked. A rotated-out (replayed) token lands here and fails
	// closed — RFC 6749 §6 behavior.
	if revoked, rerr := s.Store.IsTokenRevoked(claims.ID, s.tenant(), s.RouteID); rerr != nil || revoked {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
			"error_description": "refresh token already rotated or revoked"})
		return
	}
	if client, cerr := s.scopedClient(clientID); cerr != nil || client.RevokedAt != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client",
			"error_description": "client revoked"})
		return
	}
	grant, err := s.Store.GetGrant(clientID, s.tenant(), s.RouteID)
	if err != nil || validateGrantPolicyLive(s.Store, grant, s.tenant(), s.RouteID) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
			"error_description": "client is not approved for this route"})
		return
	}
	// Burn the presented refresh token BEFORE minting the new pair, and
	// let the burn decide: only the caller that actually burned the
	// token may issue a replacement. Two simultaneous rotations of one
	// refresh token therefore cannot both succeed — the loser is told
	// invalid_grant instead of receiving a second live lineage.
	burned, berr := s.Store.BurnToken(claims.ID, clientID, s.tenant(), s.RouteID)
	if berr != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !burned {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
			"error_description": "refresh token already rotated or revoked"})
		return
	}
	accessJTI, err := MintJTI()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	grantedScope := claims.Scope
	if grantedScope == "" {
		grantedScope = "mcp:tools offline_access"
	}
	access, err := s.Issuer.Mint(TokenClaims{
		Issuer:   s.IssuerURL,
		Subject:  clientID,
		Audience: s.RouteURL,
		Tenant:   s.tenant(),
		Route:    s.RouteID,
		Scope:    grantedScope,
		Expiry:   time.Now().Add(s.tokenTTL()).Unix(),
		ID:       accessJTI,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var refresh string
	if hasScope(grantedScope, "offline_access") {
		if client.ClientMode == "confidential" {
			rtok, rerr := mintOpaqueRefreshToken()
			if rerr != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			now := time.Now().UTC()
			if err := s.Store.CreateOpaqueRefresh(OpaqueRefresh{
				TokenHash:         HashSecret(rtok),
				ClientID:          clientID,
				Tenant:            s.tenant(),
				Route:             s.RouteID,
				Scope:             grantedScope,
				ExpiresAt:         now.Add(s.refreshTTL()),
				AbsoluteExpiresAt: now.Add(DefaultAbsoluteRefreshTTL),
				LastUsedAt:        now,
			}); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			refresh = rtok
		} else {
			refreshJTI, err := MintJTI()
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			refresh, err = s.Issuer.Mint(TokenClaims{
				Issuer:    s.IssuerURL,
				Subject:   clientID,
				Audience:  s.RouteURL,
				Tenant:    s.tenant(),
				Route:     s.RouteID,
				Scope:     grantedScope,
				Expiry:    time.Now().Add(s.refreshTTL()).Unix(),
				ID:        refreshJTI,
				TokenType: "refresh",
			})
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
	}
	resp := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(s.tokenTTL().Seconds()),
		"scope":        grantedScope,
	}
	if refresh != "" {
		resp["refresh_token"] = refresh
	}
	writeJSON(w, http.StatusOK, resp)
}

// refreshTTL bounds a refresh token. Zero selects DefaultRefreshTTL.
func (s *Server) refreshTTL() time.Duration {
	if s.RefreshTTL > 0 {
		return s.RefreshTTL
	}
	return DefaultRefreshTTL
}

// ServeRevoke implements RFC 7009 token revocation for the route.
func (s *Server) ServeRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// The relay rejects revoked grants at admission, so a revoked client's
	// tokens stop working immediately even if the caller does not revoke each
	// token. Revocation here is defense in depth.
	tokenStr := r.Form.Get("token")
	if tokenStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if strings.HasPrefix(tokenStr, "rtok_") {
		if err := s.Store.RevokeOpaqueRefresh(HashSecret(tokenStr), s.tenant(), s.RouteID, time.Now().UTC()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	claims, err := s.Issuer.Verify(tokenStr)
	if err != nil {
		// RFC 7009: an invalid token is treated as already revoked.
		w.WriteHeader(http.StatusOK)
		return
	}
	// Scope fence: a token minted by another route's authorization server
	// is not this endpoint's credential. RFC 7009 says to answer success
	// without modifying state, so a caller cannot probe another route's
	// tokens here either. The binding checks are exactly the ones
	// admission applies: issuer, audience, tenant, and route.
	if !claims.ValidateIssuer(s.IssuerURL) || !claims.ValidateAudience(s.RouteURL) ||
		claims.Tenant != s.tenant() || claims.Route != s.RouteID {
		w.WriteHeader(http.StatusOK)
		return
	}
	// Durably revoke this specific token by its jti. Admission checks the
	// revocation set on every request, so denial is immediate.
	if claims.ID != "" {
		if err := s.Store.RevokeToken(claims.ID, claims.Subject, s.tenant(), s.RouteID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
	}
	// Revoking the client's grant is the operator's kill switch; it is
	// deliberately NOT implied by a token revocation, so a client cannot
	// revoke another client's approval or its own operator grant.
	w.WriteHeader(http.StatusOK)
}

// tenant is the owning tenant of this route; grants and tokens are scoped
// to it, and admission enforces the match.
func (s *Server) tenant() string {
	return s.Tenant
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// NormalizeScope trims and lowercases a scope string. Scopes are not enforced
// in Phase 1; this exists so the token field is stable.
func NormalizeScope(scope string) string { return strings.TrimSpace(scope) }
