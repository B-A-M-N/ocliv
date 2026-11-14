package authz

import (
	"fmt"
	"net/http"
	"strings"
)

// Authorizer validates a presented bearer token against one route.
type Authorizer struct {
	issuer *Issuer
	store  Store
}

// NewAuthorizer builds an authorizer over the relay's issuer and store.
func NewAuthorizer(issuer *Issuer, store Store) *Authorizer {
	return &Authorizer{issuer: issuer, store: store}
}

// Authorize checks a presented bearer token for a request to the given route.
//
// It enforces, in order: token present, signature valid, issuer exact match,
// audience exact match (RFC 8707), tenant match, route match, grant active.
// Any failure returns an error; the caller must deny the request.
func (a *Authorizer) Authorize(r *http.Request, routeURL, issuerURL, tenant, routeID string) error {
	_, err := a.AuthorizeClaims(r, routeURL, issuerURL, tenant, routeID)
	return err
}

// AuthorizeClaims is Authorize and additionally returns the verified claims,
// so the caller can attribute the request to a client.
func (a *Authorizer) AuthorizeClaims(r *http.Request, routeURL, issuerURL, tenant, routeID string) (*Claims, error) {
	token, err := BearerFromRequest(r)
	if err != nil {
		return nil, err
	}
	claims, err := a.issuer.Verify(token)
	if err != nil {
		return nil, fmt.Errorf("authz: %w", err)
	}
	if !claims.ValidateIssuer(issuerURL) {
		return nil, fmt.Errorf("authz: issuer mismatch: got %q want %q", claims.Issuer, issuerURL)
	}
	// Credential-kind separation: a refresh token is only ever valid at
	// the token endpoint's refresh grant. Presenting one at the tool
	// path would trade a long-lived renewal credential for route access,
	// so it is refused here. An access token (unset typ, including
	// legacy tokens minted before the field existed) is unaffected.
	if claims.TokenType != "" && claims.TokenType != "access" {
		return nil, fmt.Errorf("authz: %s tokens are not valid for route access", claims.TokenType)
	}
	if !claims.ValidateAudience(routeURL) {
		return nil, fmt.Errorf("authz: audience mismatch for route %q", routeURL)
	}
	if tenant != "" && claims.Tenant != tenant {
		return nil, fmt.Errorf("authz: tenant mismatch: got %q want %q", claims.Tenant, tenant)
	}
	if routeID != "" && claims.Route != routeID {
		return nil, fmt.Errorf("authz: route mismatch: got %q want %q", claims.Route, routeID)
	}
	// Publication-level boundary: the client must hold an ACTIVE grant for
	// this tenant + route. Revocation is checked here, on every request.
	grant, err := a.store.GetGrant(claims.Subject, tenant, routeID)
	if err != nil {
		return nil, fmt.Errorf("authz: no grant for client %q: %w", claims.Subject, err)
	}
	if grant.Status != GrantActive {
		return nil, fmt.Errorf("authz: client %q is not approved (status %q)", claims.Subject, grant.Status)
	}
	// Client-level revocation: a revoked client's existing tokens stop at
	// admission, not just at the next token exchange. The registration
	// must also belong to this route: a client_id minted through another
	// authorization server is not an identity here. Legacy rows with no
	// stored identity are unbound and fail closed.
	client, cerr := a.store.GetClient(claims.Subject)
	if cerr != nil || client.RevokedAt != nil {
		return nil, fmt.Errorf("authz: client %q is revoked", claims.Subject)
	}
	if client.Tenant == "" || client.Route == "" {
		return nil, fmt.Errorf("authz: client %q has no route registration scope", claims.Subject)
	}
	if client.Tenant != tenant || client.Route != routeID {
		return nil, fmt.Errorf("authz: client %q is registered for tenant %q route %q, not tenant %q route %q",
			claims.Subject, client.Tenant, client.Route, tenant, routeID)
	}
	// Every managed token must carry a jti. A token without one cannot be
	// individually revoked, so it is refused rather than admitted.
	if claims.ID == "" {
		return nil, fmt.Errorf("authz: token has no jti; refusing unmanaged token")
	}
	// Token-specific revocation (RFC 7009), scoped to this tenant + route.
	// Checked on every request so a revoked token is denied immediately.
	revoked, err := a.store.IsTokenRevoked(claims.ID, tenant, routeID)
	if err != nil {
		return nil, fmt.Errorf("authz: revocation check: %w", err)
	}
	if revoked {
		return nil, fmt.Errorf("authz: token %q is revoked", claims.ID)
	}
	return claims, nil
}

// BearerFromRequest extracts the bearer token from the Authorization header.
// It deliberately does not accept a cookie or a query parameter: a bearer in
// the query string leaks into logs and Referer headers.
func BearerFromRequest(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", fmt.Errorf("authz: missing bearer token")
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("authz: malformed Authorization header")
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", fmt.Errorf("authz: empty bearer token")
	}
	return token, nil
}
