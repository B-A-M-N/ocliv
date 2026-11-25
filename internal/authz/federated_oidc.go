package authz

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Grant authorization provenance methods (OCL-005, OCL-006).
const (
	GrantMethodLegacy         = "legacy"
	GrantMethodPairing        = "pairing"
	GrantMethodOperatorTx     = "operator_tx"
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

// Sentinel errors for authoritative federated policy enforcement.
var (
	ErrFederatedPolicyRequired = errors.New("authz: route requires federated visitor authentication")
	ErrPolicyRevisionMismatch  = errors.New("authz: visitor auth policy changed or was revoked during login")
	ErrOIDCEgressBlocked       = errors.New("authz: OIDC provider endpoint blocked by egress policy")
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
	Revision        int64      `json:"revision"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

// IsActiveFederated reports whether this policy actively enforces federated OIDC.
func (p *VisitorAuthPolicy) IsActiveFederated() bool {
	return p != nil && p.Enabled && p.RevokedAt == nil && p.Mode == VisitorAuthModeFederated
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
	if !p.IsActiveFederated() {
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
// MCP client authorization transaction and exact visitor policy revision (OCL-005).
type OIDCTransaction struct {
	State          string
	Nonce          string
	PKCEVerifier   string
	ClientID       string
	Tenant         string
	Route          string
	RedirectURI    string
	CodeChallenge  string
	ClientState    string
	Resource       string
	Scope          string
	TrustPolicyID  string
	PolicyRevision int64
	ExpiresAt      time.Time
	ConsumedAt     *time.Time
}

// Expired reports whether the transaction has passed its expiry.
func (t *OIDCTransaction) Expired() bool { return time.Now().After(t.ExpiresAt) }

// FederatedGrantActivation carries every invariant that must be verified
// atomically inside a single store transaction before activating a federated
// OIDC grant.
type FederatedGrantActivation struct {
	ClientID               string
	Tenant                 string
	Route                  string
	RedirectURI            string
	ExpectedPolicyRevision int64
	TrustPolicyID          string
	OwnerIssuer            string
	OwnerSubject           string
}

func mintRandomToken(prefix string, nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// --- At-rest encryption for authz_visitor_policies.client_secret ---

const visitorSecretEncPrefix = "enc:v1:"

// DeriveVisitorSecretKey derives a domain-separated 32-byte AES-256-GCM key
// from the relay's durable 32-byte server key (which lives in 0600
// visitor-hmac.key outside the SQLite database).
func DeriveVisitorSecretKey(serverKey []byte) []byte {
	if len(serverKey) == 0 {
		return nil
	}
	h := sha256.New()
	h.Write([]byte("ocliv-visitor-oidc-secret-v1:"))
	h.Write(serverKey)
	return h.Sum(nil)
}

func visitorSecretAAD(tenant, route, issuer, clientID string) []byte {
	return []byte(tenant + "\x00" + route + "\x00" + issuer + "\x00" + clientID)
}

// SealVisitorSecret encrypts a non-empty OIDC client secret using AES-256-GCM
// bound to (tenant, route, issuer, clientID) via AAD.
func SealVisitorSecret(key []byte, tenant, route, issuer, clientID, plaintext string) (string, error) {
	if plaintext == "" || len(key) == 0 {
		return plaintext, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("authz: init visitor secret cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("authz: init visitor secret gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("authz: visitor secret nonce: %w", err)
	}
	aad := visitorSecretAAD(tenant, route, issuer, clientID)
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), aad)
	return visitorSecretEncPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// OpenVisitorSecret decrypts an AES-256-GCM sealed OIDC client secret.
// Plaintext values without the enc:v1: prefix are returned as-is for backward
// compatibility when no encryption key was previously configured; sealed values
// always fail closed if the key is missing or AAD/tag verification fails.
func OpenVisitorSecret(key []byte, tenant, route, issuer, clientID, stored string) (string, error) {
	if stored == "" || !strings.HasPrefix(stored, visitorSecretEncPrefix) {
		return stored, nil
	}
	if len(key) == 0 {
		return "", fmt.Errorf("authz: visitor policy client_secret is encrypted but no decryption key is configured")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, visitorSecretEncPrefix))
	if err != nil {
		return "", fmt.Errorf("authz: corrupt encrypted visitor policy client_secret")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("authz: init visitor secret cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("authz: init visitor secret gcm: %w", err)
	}
	if len(raw) < gcm.NonceSize()+gcm.Overhead() {
		return "", fmt.Errorf("authz: truncated encrypted visitor policy client_secret")
	}
	nonce := raw[:gcm.NonceSize()]
	ct := raw[gcm.NonceSize():]
	aad := visitorSecretAAD(tenant, route, issuer, clientID)
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return "", fmt.Errorf("authz: decrypt visitor policy client_secret failed (key rotated or DB tampered)")
	}
	return string(pt), nil
}

// --- Maintained OIDC Client (go-oidc/v3 + golang.org/x/oauth2) with strict egress policy ---

// OIDCClient executes discovery, authorization-code exchange, and ID token
// verification against an upstream OIDC identity provider using maintained
// go-oidc/v3 and golang.org/x/oauth2 libraries with strict HTTPS and
// private-network egress enforcement (OCL-005).
type OIDCClient struct {
	HTTPClient           *http.Client
	AllowLoopbackForTest bool // test-only opt-in for httptest.NewTLSServer; never set in production
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

func isBlockedOIDCEgressIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() ||
		cgnatPrefix.Contains(addr) {
		return true
	}
	return false
}

func safeOIDCDialContext(base *net.Dialer, allowLoopback bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid host:port %q", ErrOIDCEgressBlocked, addr)
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("%w: resolve %q: %v", ErrOIDCEgressBlocked, host, err)
		}
		for _, ip := range ips {
			if allowLoopback && ip.IsLoopback() {
				continue
			}
			if isBlockedOIDCEgressIP(ip) {
				return nil, fmt.Errorf("%w: destination %q resolved to non-public address", ErrOIDCEgressBlocked, host)
			}
		}
		// Connect directly to the first verified IP to prevent DNS rebinding TOCTOU.
		return base.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
}

func (c *OIDCClient) httpClient() *http.Client {
	allowLoopback := c != nil && c.AllowLoopbackForTest
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	if c != nil && c.HTTPClient != nil {
		cp := *c.HTTPClient
		cp.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("authz: redirects blocked during OIDC provider exchange")
		}
		if tr, ok := cp.Transport.(*http.Transport); ok && tr != nil {
			trCopy := tr.Clone()
			trCopy.DialContext = safeOIDCDialContext(dialer, allowLoopback)
			cp.Transport = trCopy
		} else if cp.Transport == nil {
			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.DialContext = safeOIDCDialContext(dialer, allowLoopback)
			cp.Transport = tr
		}
		return &cp
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = safeOIDCDialContext(dialer, allowLoopback)
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
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

// providerWithContext uses go-oidc/v3 to discover and validate the OIDC provider
// while enforcing strict HTTPS on all endpoints and our SSRF egress policy.
func (c *OIDCClient) providerWithContext(ctx context.Context, issuer string) (context.Context, *oidc.Provider, error) {
	if err := validateStrictHTTPSURL(issuer, "issuer"); err != nil {
		return ctx, nil, err
	}
	hc := c.httpClient()
	oidcCtx := oidc.ClientContext(ctx, hc)
	prov, err := oidc.NewProvider(oidcCtx, issuer)
	if err != nil {
		return oidcCtx, nil, fmt.Errorf("authz: OIDC discovery failed: %w", err)
	}
	ep := prov.Endpoint()
	if err := validateStrictHTTPSURL(ep.AuthURL, "authorization_endpoint"); err != nil {
		return oidcCtx, nil, err
	}
	if err := validateStrictHTTPSURL(ep.TokenURL, "token_endpoint"); err != nil {
		return oidcCtx, nil, err
	}
	var meta struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := prov.Claims(&meta); err != nil {
		return oidcCtx, nil, fmt.Errorf("authz: decode OIDC discovery claims: %w", err)
	}
	if meta.Issuer != issuer {
		return oidcCtx, nil, fmt.Errorf("authz: OIDC discovery issuer mismatch: got %q want %q", meta.Issuer, issuer)
	}
	if err := validateStrictHTTPSURL(meta.JWKSURI, "jwks_uri"); err != nil {
		return oidcCtx, nil, err
	}
	return oidcCtx, prov, nil
}

// BuildAuthorizeURL discovers the provider and constructs the PKCE + nonce +
// state authorization URL using golang.org/x/oauth2.
func (c *OIDCClient) BuildAuthorizeURL(ctx context.Context, issuer, clientID, callbackURL, state, nonce, pkceVerifier string) (string, error) {
	_, prov, err := c.providerWithContext(ctx, issuer)
	if err != nil {
		return "", err
	}
	cfg := oauth2.Config{
		ClientID:    clientID,
		Endpoint:    prov.Endpoint(),
		RedirectURL: callbackURL,
		Scopes:      []string{oidc.ScopeOpenID},
	}
	return cfg.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	), nil
}

// ExchangeAndVerify redeems the IdP authorization code with PKCE via
// golang.org/x/oauth2 and verifies the returned ID token using go-oidc/v3
// (signature, JWKS key selection, issuer, audience, expiration, nonce, and
// OIDC Core §3.1.3.7 authorized-party `azp` validation).
func (c *OIDCClient) ExchangeAndVerify(ctx context.Context, issuer, clientID, clientSecret, code, callbackURL, pkceVerifier, expectedNonce string) (string, error) {
	if issuer == "" || clientID == "" || expectedNonce == "" {
		return "", fmt.Errorf("authz: OIDC verification requires issuer, client_id, and nonce")
	}
	oidcCtx, prov, err := c.providerWithContext(ctx, issuer)
	if err != nil {
		return "", err
	}
	cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     prov.Endpoint(),
		RedirectURL:  callbackURL,
		Scopes:       []string{oidc.ScopeOpenID},
	}
	oauthTok, err := cfg.Exchange(oidcCtx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return "", fmt.Errorf("authz: OIDC token exchange failed: %w", err)
	}
	rawIDToken, ok := oauthTok.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		return "", fmt.Errorf("authz: OIDC token response missing id_token")
	}
	verifier := prov.Verifier(&oidc.Config{
		ClientID: clientID,
		SupportedSigningAlgs: []string{
			oidc.RS256, oidc.RS384, oidc.RS512,
			oidc.ES256, oidc.ES384, oidc.ES512,
			oidc.PS256, oidc.PS384, oidc.PS512,
			oidc.EdDSA,
		},
	})
	idToken, err := verifier.Verify(oidcCtx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("authz: OIDC id_token verification failed: %w", err)
	}
	if idToken.Issuer != issuer {
		return "", fmt.Errorf("authz: OIDC id_token issuer mismatch")
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(expectedNonce)) != 1 {
		return "", fmt.Errorf("authz: OIDC id_token nonce mismatch")
	}
	// OIDC Core §3.1.3.7 azp enforcement:
	// - If the ID Token contains multiple audiences, azp MUST be present and equal clientID.
	// - If azp is present (even with a single audience), azp MUST equal clientID.
	var azpClaims struct {
		AZP string `json:"azp"`
	}
	if err := idToken.Claims(&azpClaims); err != nil {
		return "", fmt.Errorf("authz: decode OIDC id_token claims: %w", err)
	}
	if len(idToken.Audience) > 1 {
		if subtle.ConstantTimeCompare([]byte(azpClaims.AZP), []byte(clientID)) != 1 {
			return "", fmt.Errorf("authz: OIDC id_token multi-audience token missing matching azp")
		}
	} else if azpClaims.AZP != "" && subtle.ConstantTimeCompare([]byte(azpClaims.AZP), []byte(clientID)) != 1 {
		return "", fmt.Errorf("authz: OIDC id_token azp mismatch")
	}
	if strings.TrimSpace(idToken.Subject) == "" {
		return "", fmt.Errorf("authz: OIDC id_token missing subject")
	}
	return idToken.Subject, nil
}
