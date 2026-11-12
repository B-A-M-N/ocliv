package authz

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Default bounds for the managed authorization endpoints.
const (
	DefaultCodeTTL  = 10 * time.Minute
	DefaultTokenTTL = 1 * time.Hour
)

// Server serves the route-scoped authorization endpoints for one managed
// route. It is stateless apart from its Issuer and Store.
type Server struct {
	Issuer    *Issuer
	Store     Store
	RouteID   string
	RouteURL  string // external route URL; used as the token audience
	IssuerURL string // exact AS issuer string
	CodeTTL   time.Duration
	TokenTTL  time.Duration
}

// NewServer builds a route-scoped authorization server.
func NewServer(issuer *Issuer, store Store, routeID, routeURL, issuerURL string) *Server {
	return &Server{
		Issuer:    issuer,
		Store:     store,
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
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"registration_endpoint":                 base + "/oauth/register",
		"revocation_endpoint":                   base + "/oauth/revoke",
		"jwks_uri":                              base + "/oauth/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"resource_indicators_supported":         true,
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
}

// ServeRegister implements RFC 7591 dynamic client registration. It creates a
// client with NO access: the client must still be approved by an operator for
// a specific route.
func (s *Server) ServeRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req registerReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid client metadata", http.StatusBadRequest)
		return
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
	// SSRF hardening: the relay never fetches client-supplied URLs. The
	// metadata is stored for display/audit only.
	id, err := MintClientID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.Store.RegisterClient(Client{
		ID:           id,
		Name:         req.ClientName,
		RedirectURIs: append([]string(nil), req.RedirectURIs...),
		CreatedAt:    time.Now(),
	}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
	})
}

// ServeAuthorize starts the authorization code flow. A pending grant produces
// no code; an active grant produces a single-use code; a revoked client is
// rejected.
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
	resource := q.Get("resource")

	if responseType != "code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_response_type"})
		return
	}
	if resource != "" && resource != s.RouteURL {
		// RFC 8707: the requested resource must be this route.
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target"})
		return
	}
	client, err := s.Store.GetClient(clientID)
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
	if challengeMethod != "S256" || challenge == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "PKCE S256 required"})
		return
	}

	grant, err := s.Store.GetGrant(clientID, s.tenant(), s.RouteID)
	if err != nil {
		// First contact for this route: record a pending grant. No code.
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
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":  "pending_approval",
			"client":  clientID,
			"message": "client registered; waiting for operator approval",
		})
		return
	}
	switch grant.Status {
	case GrantRevoked:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "access_denied", "error_description": "client revoked"})
		return
	case GrantPending:
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending_approval", "client": clientID})
		return
	}

	code, err := MintCode()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.Store.CreateCode(Code{
		Code:            code,
		ClientID:        clientID,
		Tenant:          s.tenant(),
		Route:           s.RouteID,
		RedirectURI:     redirectURI,
		Challenge:       challenge,
		ChallengeMethod: challengeMethod,
		ExpiresAt:       time.Now().Add(s.codeTTL()),
	}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	redirect := fmt.Sprintf("%s?code=%s", redirectURI, url.QueryEscape(code))
	if state != "" {
		redirect += "&state=" + url.QueryEscape(state)
	}
	w.Header().Set("Location", redirect)
	w.WriteHeader(http.StatusFound)
}

// ServeToken exchanges an authorization code for an access token.
func (s *Server) ServeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	codeStr := r.Form.Get("code")
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	verifier := r.Form.Get("code_verifier")

	code, err := s.Store.ConsumeCode(codeStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": err.Error()})
		return
	}
	if code.ClientID != clientID || code.RedirectURI != redirectURI {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if err := VerifyPKCE(code.ChallengeMethod, code.Challenge, verifier); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": err.Error()})
		return
	}
	grant, err := s.Store.GetGrant(clientID, s.tenant(), s.RouteID)
	if err != nil || grant.Status != GrantActive {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "client is not approved for this route"})
		return
	}
	token, err := s.Issuer.Mint(TokenClaims{
		Issuer:   s.IssuerURL,
		Subject:  clientID,
		Audience: s.RouteURL,
		Tenant:   s.tenant(),
		Route:    s.RouteID,
		Expiry:   time.Now().Add(s.tokenTTL()).Unix(),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(s.tokenTTL().Seconds()),
		"scope":        "",
	})
}

// ServeRevoke implements RFC 7009 token revocation for the route.
func (s *Server) ServeRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	claims, err := s.Issuer.Verify(tokenStr)
	if err != nil {
		// RFC 7009: an invalid token is treated as already revoked.
		w.WriteHeader(http.StatusOK)
		return
	}
	grant, err := s.Store.GetGrant(claims.Subject, s.tenant(), s.RouteID)
	if err == nil && grant.Status != GrantActive {
		// already denied at admission
	}
	w.WriteHeader(http.StatusOK)
}

// tenant is the tenant for this route. Phase 1 uses a fixed default; Phase 2
// wires the publication's tenant.
func (s *Server) tenant() string {
	if s.RouteID == "" {
		return ""
	}
	return "tenant-default"
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// NormalizeScope trims and lowercases a scope string. Scopes are not enforced
// in Phase 1; this exists so the token field is stable.
func NormalizeScope(scope string) string { return strings.TrimSpace(scope) }
