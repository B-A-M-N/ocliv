package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/B-A-M-N/ocliv/internal/authz"
	"github.com/B-A-M-N/ocliv/internal/store"
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
func newAuthzManager(db *store.DB, serverKey ...[]byte) (*authzManager, error) {
	st := authz.NewSQLStore(db.SQL())
	if len(serverKey) > 0 && len(serverKey[0]) > 0 {
		st.SetSecretKey(authz.DeriveVisitorSecretKey(serverKey[0]))
	}
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

// managedAuthzKind names the public endpoint a request targeted, for rate
// limiting. Discovery and jwks are not limited: they carry no write path.
func managedAuthzKind(escapedPath string) (string, bool) {
	for _, ep := range []string{"/oauth/register", "/oauth/authorize", "/oauth/callback", "/oauth/consent/complete", "/oauth/consent/status", "/oauth/consent", "/oauth/token", "/oauth/revoke"} {
		if strings.HasSuffix(escapedPath, ep) {
			return strings.TrimPrefix(ep, "/oauth/"), true
		}
	}
	return "", false
}

// authzMaintenanceInterval bounds how often expired authorization state
// is reclaimed while the relay runs. Pruning already runs at startup
// (reconcileBoot); this covers a long-lived relay. It is a variable so
// tests can drive the same loop on a short cadence.
var authzMaintenanceInterval = 10 * time.Minute

// RunAuthzMaintenance periodically reclaims expired authorization state
// for as long as the relay lives: consumed/expired codes and consent
// challenges, revocations past their retention window, and client
// registrations that never obtained approval past the pending lifetime.
// It rides the relay's own lifecycle context (no second service), is
// cancellable, performs only bounded indexed deletes, and can never
// resurrect access: authority lives in grants and clients, which pruning
// never touches. A failure is audited and the loop continues: a missed
// cycle costs space, not safety.
func (s *Server) RunAuthzMaintenance(ctx context.Context) {
	if s.authz == nil {
		return
	}
	t := time.NewTicker(authzMaintenanceInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			if err := s.authz.Store().PruneAuthzExpired(now); err != nil {
				s.db.Audit("system", "", "", "authz-prune", "error",
					"pruning authorization state failed: "+errShort(err))
			}
			if _, err := s.authz.Store().PruneAbandonedClients(now); err != nil {
				s.db.Audit("system", "", "", "authz-prune", "error",
					"reclaiming abandoned registrations failed: "+errShort(err))
			}
			if _, _, err := s.db.PrunePairingRequests(now, 24*time.Hour); err != nil {
				s.log.Error("authz maintenance: pruning pairing requests failed", "err", errShort(err))
				s.db.Audit("system", "", "", "authz-prune", "error",
					"pruning pairing requests failed: "+errShort(err))
			}
			if _, err := s.db.PruneTerminalLeaseEphemera(now, store.TerminalLeaseEphemeraRetention); err != nil {
				s.log.Error("authz maintenance: pruning terminal lease ephemera failed", "err", errShort(err))
				s.db.Audit("system", "", "", "authz-prune", "error",
					"pruning terminal lease ephemera failed: "+errShort(err))
			}
		}
	}
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
	srv.AutoApproveRedirectHosts = s.autoApproveRedirectHosts
	// Public endpoints are UNAUTHENTICATED by protocol (DCR, authorize,
	// consent, token, revoke), so each one is rate limited per tenant +
	// endpoint KIND + ROUTE and per source IP. The route is part of the key: a flood
	// against one route's public endpoint is an attack on that route,
	// and must not deny legitimate callers on an unrelated route in the
	// same tenant (the durable client quota is already per route). A
	// caller cannot drive unbounded durable writes (registrations,
	// consent challenges, token attempts) against one route's state.
	if kind, ok := managedAuthzKind(r.URL.EscapedPath()); ok {
		globalKey := "authz:" + kind + ":" + t.TenantID + ":" + t.RouteID
		ipKey := "authz-ip:" + kind + ":" + clientIP(r)
		if !s.throttle.Allow(globalKey) || !s.preAuth.Allow(ipKey) {
			s.db.Audit("visitor", t.TenantID, t.LeaseID, "mcp_path", "denied", "authz rate limited: "+kind)
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
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
	case strings.HasSuffix(r.URL.EscapedPath(), "/oauth/callback"):
		srv.ServeOIDCCallback(w, r)
	case strings.HasSuffix(r.URL.EscapedPath(), "/oauth/consent/status"):
		srv.ServeConsentStatus(w, r)
	case strings.HasSuffix(r.URL.EscapedPath(), "/oauth/consent/complete"):
		srv.ServeConsentComplete(w, r)
	case strings.HasSuffix(r.URL.EscapedPath(), "/oauth/consent"):
		srv.ServeConsent(w, r)
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
