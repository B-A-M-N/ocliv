package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Grant authorization provenance methods (OCL-006).
const (
	GrantMethodLegacy         = "legacy"
	GrantMethodPairing        = "pairing"
	GrantMethodDirectOperator = "direct_operator"
	GrantMethodTrustPolicy    = "trust_policy"
	GrantMethodFederatedOIDC  = "federated_oidc"
)

// Visitor authentication policy modes (OCL-005).
const (
	VisitorAuthModeFederated = "federated"
	VisitorAuthModePairing   = "pairing"
)

// DefaultOIDCTxTTL bounds an in-flight federated OIDC authorization round-trip.
const (
	DefaultOIDCTxTTL         = 10 * time.Minute
	MaxPendingOIDCTxPerRoute = 100
)

// GrantProvenance records exactly how an authorization grant was established so
// trust-policy or federated-policy revocation can atomically revoke dependent
// grants while leaving separately authorized grants intact (OCL-006).
type GrantProvenance struct {
	Method        string `json:"method,omitempty"`
	TrustPolicyID string `json:"trust_policy_id,omitempty"`
	OwnerIssuer   string `json:"owner_issuer,omitempty"`
	OwnerSubject  string `json:"owner_subject,omitempty"`
}

// VisitorAuthPolicy configures route-scoped federated resource-owner
// authentication (OCL-005). Ocliv remains the OAuth authorization server
// exposed to MCP clients while delegating human sign-in to a configured OIDC
// identity provider (e.g. Auth0).
type VisitorAuthPolicy struct {
	TenantID        string     `json:"tenant_id"`
	RouteID         string     `json:"route_id"`
	Mode            string     `json:"mode"` // "federated" | "pairing"
	Issuer          string     `json:"issuer"`
	ClientID        string     `json:"client_id"`
	ClientSecret    string     `json:"client_secret,omitempty"`
	AllowedSubjects []string   `json:"allowed_subjects"`
	ClientPolicy    string     `json:"client_policy,omitempty"` // e.g. "chatgpt" or ""
	Enabled         bool       `json:"enabled"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

// Redacted returns a safe view of the policy without client_secret.
func (p VisitorAuthPolicy) Redacted() VisitorAuthPolicy {
	cp := p
	cp.ClientSecret = ""
	cp.AllowedSubjects = append([]string(nil), p.AllowedSubjects...)
	return cp
}

// AllowsSubject reports whether (issuer, subject) matches this active policy.
func (p *VisitorAuthPolicy) AllowsSubject(issuer, subject string) bool {
	if p == nil || !p.Enabled || p.RevokedAt != nil || p.Mode != VisitorAuthModeFederated {
		return false
	}
	if issuer == "" || subject == "" || p.Issuer != issuer {
		return false
	}
	for _, s := range p.AllowedSubjects {
		if subtle.ConstantTimeCompare([]byte(s), []byte(subject)) == 1 {
			return true
		}
	}
	return false
}

// ValidateVisitorAuthPolicy validates a federated or pairing visitor auth policy.
func ValidateVisitorAuthPolicy(p VisitorAuthPolicy) (VisitorAuthPolicy, error) {
	if p.TenantID == "" || p.RouteID == "" {
		return VisitorAuthPolicy{}, fmt.Errorf("authz: visitor auth policy requires tenant_id and route_id")
	}
	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" {
		mode = VisitorAuthModeFederated
	}
	p.Mode = mode
	switch mode {
	case VisitorAuthModePairing:
		p.Issuer = ""
		p.ClientID = ""
		p.ClientSecret = ""
		p.AllowedSubjects = nil
		return p, nil
	case VisitorAuthModeFederated:
	default:
		return VisitorAuthPolicy{}, fmt.Errorf("authz: unsupported visitor_auth mode %q (want federated|pairing)", p.Mode)
	}
	issuer := strings.TrimSpace(p.Issuer)
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return VisitorAuthPolicy{}, fmt.Errorf("authz: federated issuer %q must be a clean https URL", p.Issuer)
	}
	p.Issuer = issuer
	p.ClientID = strings.TrimSpace(p.ClientID)
	if p.ClientID == "" {
		return VisitorAuthPolicy{}, fmt.Errorf("authz: federated visitor_auth requires client_id")
	}
	if len(p.AllowedSubjects) == 0 {
		return VisitorAuthPolicy{}, fmt.Errorf("authz: federated visitor_auth requires at least one allowed_subject")
	}
	seen := make(map[string]struct{}, len(p.AllowedSubjects))
	cleanSubs := make([]string, 0, len(p.AllowedSubjects))
	for _, raw := range p.AllowedSubjects {
		s := strings.TrimSpace(raw)
		if s == "" || s == "*" || strings.ContainsAny(s, "\r\n") {
			return VisitorAuthPolicy{}, fmt.Errorf("authz: invalid allowed_subject %q", raw)
		}
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			cleanSubs = append(cleanSubs, s)
		}
	}
	sort.Strings(cleanSubs)
	p.AllowedSubjects = cleanSubs
	p.ClientPolicy = strings.ToLower(strings.TrimSpace(p.ClientPolicy))
	if p.ClientPolicy != "" && p.ClientPolicy != "custom" {
		if _, ok := LookupTrustPreset(p.ClientPolicy); !ok {
			return VisitorAuthPolicy{}, fmt.Errorf("authz: unknown client_policy %q", p.ClientPolicy)
		}
	}
	return p, nil
}

// OIDCTransaction binds one in-flight federated OIDC login to the originating
// MCP client authorization transaction (OCL-005).
type OIDCTransaction struct {
	State         string
	Nonce         string
	PKCEVerifier  string
	ClientID      string
	Tenant        string
	Route         string
	RedirectURI   string
	CodeChallenge string
	ClientState   string
	Resource      string
	Scope         string
	TrustPolicyID string
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
}

// Expired reports whether the transaction has passed its expiry.
func (t *OIDCTransaction) Expired() bool { return time.Now().After(t.ExpiresAt) }

func mintRandomToken(prefix string, nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// OIDCDiscovery holds the validated OpenID Provider discovery metadata.
type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// OIDCClient executes discovery, authorization-code exchange, and JWKS JWT
// verification against an upstream OIDC identity provider (OCL-005).
type OIDCClient struct {
	HTTPClient *http.Client
}

func (c *OIDCClient) httpClient() *http.Client {
	if c != nil && c.HTTPClient != nil {
		cp := *c.HTTPClient
		cp.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("authz: redirects blocked during OIDC provider exchange")
		}
		return &cp
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("authz: redirects blocked during OIDC provider exchange")
		},
	}
}

func validateStrictHTTPSURL(raw, field string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("authz: OIDC %s %q must be a valid https URL", field, raw)
	}
	return nil
}

// Discover fetches and validates <issuer>/.well-known/openid-configuration.
func (c *OIDCClient) Discover(ctx context.Context, issuer string) (*OIDCDiscovery, error) {
	if err := validateStrictHTTPSURL(issuer, "issuer"); err != nil {
		return nil, err
	}
	discURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("authz: OIDC discovery fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authz: OIDC discovery returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return nil, fmt.Errorf("authz: read OIDC discovery: %w", err)
	}
	var doc OIDCDiscovery
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("authz: decode OIDC discovery: %w", err)
	}
	if doc.Issuer != issuer {
		return nil, fmt.Errorf("authz: OIDC discovery issuer mismatch: got %q want %q", doc.Issuer, issuer)
	}
	if err := validateStrictHTTPSURL(doc.AuthorizationEndpoint, "authorization_endpoint"); err != nil {
		return nil, err
	}
	if err := validateStrictHTTPSURL(doc.TokenEndpoint, "token_endpoint"); err != nil {
		return nil, err
	}
	if err := validateStrictHTTPSURL(doc.JWKSURI, "jwks_uri"); err != nil {
		return nil, err
	}
	return &doc, nil
}

// ExchangeCode redeems the IdP authorization code with PKCE verifier and
// returns the raw OIDC id_token JWT.
func (c *OIDCClient) ExchangeCode(ctx context.Context, tokenEndpoint, clientID, clientSecret, code, callbackURL, pkceVerifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL},
		"client_id":     {clientID},
		"code_verifier": {pkceVerifier},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("authz: OIDC token exchange failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return "", fmt.Errorf("authz: read OIDC token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authz: OIDC token endpoint returned HTTP %d", resp.StatusCode)
	}
	var tokResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokResp); err != nil || strings.TrimSpace(tokResp.IDToken) == "" {
		return "", fmt.Errorf("authz: OIDC token response missing id_token")
	}
	return tokResp.IDToken, nil
}

type oidcIDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce string `json:"nonce"`
}

type rawJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseJWKPublicKey(k rawJWK) (any, error) {
	switch k.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		eInt := int(new(big.Int).SetBytes(eb).Int64())
		if eInt < 3 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: eInt}, nil
	case "EC":
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(xb) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 JWK")
		}
		return ed25519.PublicKey(xb), nil
	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", k.Kty)
	}
}

// VerifyIDToken validates the IdP id_token signature against jwksURI and
// enforces exact issuer, audience, nonce, expiration, and non-empty subject.
func (c *OIDCClient) VerifyIDToken(ctx context.Context, jwksURI, expectedIssuer, expectedAudience, expectedNonce, rawIDToken string) (string, error) {
	if expectedIssuer == "" || expectedAudience == "" || expectedNonce == "" {
		return "", fmt.Errorf("authz: OIDC verification requires issuer, audience, and nonce")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("authz: fetch OIDC JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authz: OIDC JWKS returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", fmt.Errorf("authz: read OIDC JWKS: %w", err)
	}
	var jwks struct {
		Keys []rawJWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil || len(jwks.Keys) == 0 {
		return "", fmt.Errorf("authz: invalid OIDC JWKS")
	}

	claims := &oidcIDTokenClaims{}
	_, err = jwt.ParseWithClaims(
		rawIDToken,
		claims,
		func(t *jwt.Token) (any, error) {
			kid, _ := t.Header["kid"].(string)
			for _, k := range jwks.Keys {
				if k.Use != "" && k.Use != "sig" {
					continue
				}
				if kid != "" && k.Kid != "" && k.Kid != kid {
					continue
				}
				if kid != "" && k.Kid == "" && len(jwks.Keys) > 1 {
					continue
				}
				pub, perr := parseJWKPublicKey(k)
				if perr != nil {
					continue
				}
				return pub, nil
			}
			return nil, fmt.Errorf("authz: no matching JWK for kid %q", kid)
		},
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}),
		jwt.WithIssuer(expectedIssuer),
		jwt.WithAudience(expectedAudience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return "", fmt.Errorf("authz: OIDC id_token verification failed: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 {
		return "", fmt.Errorf("authz: OIDC id_token nonce mismatch")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return "", fmt.Errorf("authz: OIDC id_token missing subject")
	}
	return claims.Subject, nil
}
