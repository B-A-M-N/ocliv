package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"ocliv/internal/authz"
	"ocliv/internal/store"
)

// authzManager owns the relay's managed-authorization state: the issuer key
// and the durable client/grant/code store (schemaV8). It is configured once
// per relay and shared by every managed route.
type authzManager struct {
	mu     sync.Mutex
	db     *store.DB
	store  *authz.SQLStore
	issuer *authz.Issuer
}

// newAuthzManager loads (or creates) the relay's issuer key. It fails closed:
// a relay that cannot load its issuer cannot serve managed routes.
func newAuthzManager(db *store.DB) (*authzManager, error) {
	st := authz.NewSQLStore(db.SQL())
	issuer, err := st.LoadIssuer()
	if err != nil {
		return nil, fmt.Errorf("relay: load authz issuer: %w", err)
	}
	return &authzManager{db: db, store: st, issuer: issuer}, nil
}

// issuerNow returns the current issuer, reloading it from the store so an
// operator key rotation (a store write) takes effect on the next request
// rather than after a relay restart. Rotation is an explicit security
// control, so it must not be delayed by an in-memory cache.
func (m *authzManager) issuerNow() (*authz.Issuer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	issuer, err := m.store.LoadIssuer()
	if err != nil {
		return nil, err
	}
	m.issuer = issuer
	return issuer, nil
}

// serverFor returns a route-scoped authorization server. routeURL is the
// external route URL used as the token audience; issuerURL is the exact AS
// issuer string.
func (m *authzManager) serverFor(tenant, routeID, routeURL, issuerURL string) (*authz.Server, error) {
	issuer, err := m.issuerNow()
	if err != nil {
		return nil, err
	}
	return authz.NewServer(issuer, m.store, tenant, routeID, routeURL, issuerURL), nil
}

// authorizer returns the admission authorizer over the current issuer.
func (m *authzManager) authorizer() (*authz.Authorizer, error) {
	issuer, err := m.issuerNow()
	if err != nil {
		return nil, err
	}
	return authz.NewAuthorizer(issuer, m.store), nil
}

// store returns the durable store.
func (m *authzManager) Store() *authz.SQLStore { return m.store }

// RotateKey rotates the relay's issuer key. Tokens signed by the retired key
// fail closed at admission.
func (m *authzManager) RotateKey() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	issuer, err := m.store.RotateIssuer()
	if err != nil {
		return fmt.Errorf("relay: rotate authz key: %w", err)
	}
	m.issuer = issuer
	return nil
}

// routeURLFor builds the external route URL used as the token audience.
func routeURLFor(host string, port int, routeID string) string {
	if port == 0 || port == 443 {
		return fmt.Sprintf("https://%s/r/%s/mcp", host, routeID)
	}
	return fmt.Sprintf("https://%s:%d/r/%s/mcp", host, port, routeID)
}

// issuerURLFor builds the exact AS issuer string for a route. It is
// route-scoped so the advertised endpoints match the route's real paths
// (RFC 8414 path-inserted well-known form).
func issuerURLFor(host string, port int, routeID string) string {
	if port == 0 || port == 443 {
		return fmt.Sprintf("https://%s/r/%s/oauth", host, routeID)
	}
	return fmt.Sprintf("https://%s:%d/r/%s/oauth", host, port, routeID)
}

// isManagedAuthzPath reports whether the request path is one the relay serves
// itself for a managed route (OAuth protocol or discovery metadata), as
// opposed to the tool path that is forwarded upstream.
func isManagedAuthzPath(escapedPath string) bool {
	if escapedPath == mcpWellKnownUpstreamPath || escapedPath == mcpASWellKnownUpstreamPath {
		return true
	}
	return mcpOAuthEndpoints[escapedPath]
}

// serveManagedAuthz serves a managed route's OAuth/metadata request locally.
// It never forwards these paths to the upstream.
func (s *Server) serveManagedAuthz(w http.ResponseWriter, r *http.Request, t *routeTarget, routeID string) {
	if s.authz == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	routeURL := routeURLFor(s.mcpHost, s.mcpPort, routeID)
	issuerURL := issuerURLFor(s.mcpHost, s.mcpPort, routeID)
	srv, err := s.authz.serverFor(t.TenantID, t.RouteID, routeURL, issuerURL)
	if err != nil {
		s.db.Audit("visitor", t.TenantID, t.LeaseID, "mcp_path", "denied", "authz issuer unavailable")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.EscapedPath() == mcpWellKnownUpstreamPath:
		writeManagedJSON(w, srv.ProtectedResourceMetadata())
	case r.URL.EscapedPath() == mcpASWellKnownUpstreamPath:
		writeManagedJSON(w, srv.AuthorizationServerMetadata())
	case strings.HasSuffix(r.URL.EscapedPath(), "/oauth/jwks"):
		srv.ServeJWKS(w, r)
	case strings.HasSuffix(r.URL.EscapedPath(), "/oauth/authorize"):
		srv.ServeAuthorize(w, r)
	case strings.HasSuffix(r.URL.EscapedPath(), "/oauth/token"):
		srv.ServeToken(w, r)
	case strings.HasSuffix(r.URL.EscapedPath(), "/oauth/register"):
		srv.ServeRegister(w, r)
	case strings.HasSuffix(r.URL.EscapedPath(), "/oauth/revoke"):
		srv.ServeRevoke(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// authorizeManaged checks the presented bearer for a managed route's tool
// path. It returns the client subject on success.
func (s *Server) authorizeManaged(r *http.Request, tenant, routeID string) (string, error) {
	if s.authz == nil {
		return "", fmt.Errorf("relay: no authz manager")
	}
	routeURL := routeURLFor(s.mcpHost, s.mcpPort, routeID)
	issuerURL := issuerURLFor(s.mcpHost, s.mcpPort, routeID)
	authorizer, err := s.authz.authorizer()
	if err != nil {
		return "", err
	}
	claims, err := authorizer.AuthorizeClaims(r, routeURL, issuerURL, tenant, routeID)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

func writeManagedJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}
