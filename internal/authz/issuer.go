// Package authz implements Ocliv's relay-side authorization module for MCP
// services that have no native OAuth support.
//
// Security contract:
//   - The relay is the Authorization Server for managed routes. It signs
//     access tokens with a persistent Ed25519 key and publishes the matching
//     public key as a JWKS document.
//   - Token signing and verification use github.com/golang-jwt/jwt/v5; no
//     OAuth cryptography is hand-rolled here.
//   - A token is only accepted if its issuer, audience, tenant, route, and
//     client grant all match the route being accessed.
//   - Client registration (DCR) never grants access. An operator must
//     explicitly approve a client; unknown clients are denied.
//   - Revocation is checked on every request, so it takes effect immediately.
package authz

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenClaims are the inputs for minting an access token.
type TokenClaims struct {
	Issuer   string // expected AS issuer (route-scoped)
	Subject  string // client_id
	Audience string // route URL (RFC 8707 resource indicator)
	Tenant   string // tenant id
	Route    string // route id
	Scope    string // optional scope string
	Expiry   int64  // unix seconds
	ID       string // token id (jti)
}

// Claims are the verified contents of an access token.
type Claims struct {
	jwt.RegisteredClaims
	Tenant string `json:"tenant,omitempty"`
	Route  string `json:"route,omitempty"`
	Scope  string `json:"scope,omitempty"`
}

// Issuer signs and verifies the relay's access tokens. It is safe for
// concurrent use.
type Issuer struct {
	kid    string
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	method jwt.SigningMethod
}

// NewIssuer generates a fresh Ed25519 issuer key.
func NewIssuer() (*Issuer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("authz: generate issuer key: %w", err)
	}
	kid, err := randomKID()
	if err != nil {
		return nil, err
	}
	return &Issuer{kid: kid, priv: priv, pub: pub, method: jwt.SigningMethodEdDSA}, nil
}

// IssuerFromKey rebuilds an issuer from a persisted key. priv must be a full
// Ed25519 private key (ed25519.PrivateKey).
func IssuerFromKey(kid string, priv ed25519.PrivateKey) (*Issuer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("authz: issuer key has %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("authz: issuer key has no Ed25519 public half")
	}
	return &Issuer{kid: kid, priv: priv, pub: pub, method: jwt.SigningMethodEdDSA}, nil
}

// KID returns the key id used in the token header and JWKS.
func (i *Issuer) KID() string { return i.kid }

// PrivateKeyBytes returns a copy of the raw private key for persistence.
func (i *Issuer) PrivateKeyBytes() []byte {
	out := make([]byte, len(i.priv))
	copy(out, i.priv)
	return out
}

// Mint signs an access token. The caller is responsible for the claims being
// authorized; Mint only encodes and signs them.
func (i *Issuer) Mint(c TokenClaims) (string, error) {
	if c.Issuer == "" || c.Subject == "" || c.Audience == "" {
		return "", fmt.Errorf("authz: mint requires issuer, subject, and audience")
	}
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    c.Issuer,
			Subject:   c.Subject,
			Audience:  jwt.ClaimStrings{c.Audience},
			ExpiresAt: jwt.NewNumericDate(time.Unix(c.Expiry, 0)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        c.ID,
		},
		Tenant: c.Tenant,
		Route:  c.Route,
		Scope:  c.Scope,
	}
	tok := jwt.NewWithClaims(i.method, claims)
	tok.Header["kid"] = i.kid
	signed, err := tok.SignedString(i.priv)
	if err != nil {
		return "", fmt.Errorf("authz: sign: %w", err)
	}
	return signed, nil
}

// Verify parses and cryptographically verifies a token and returns its claims.
// It rejects a wrong signing method, an unknown key id, a bad signature, and
// an expired or not-yet-valid token.
func (i *Issuer) Verify(token string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if t.Method != i.method {
			return nil, fmt.Errorf("authz: unexpected signing method %q", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid != i.kid {
			return nil, fmt.Errorf("authz: unknown key id %q", kid)
		}
		return i.pub, nil
	}, jwt.WithValidMethods([]string{i.method.Alg()}))
	if err != nil {
		return nil, fmt.Errorf("authz: verify: %w", err)
	}
	return claims, nil
}

// JWK is a single JSON Web Key (RFC 7517) for the Ed25519 public key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS is the JSON Web Key Set served at the route's jwks_uri.
func (i *Issuer) JWKS() []JWK {
	x := base64.RawURLEncoding.EncodeToString(i.pub)
	return []JWK{{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   x,
		Kid: i.kid,
		Use: "sig",
		Alg: "EdDSA",
	}}
}

// JWKSJSON renders the key set as JSON.
func (i *Issuer) JWKSJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"keys": i.JWKS()})
}

// ValidateAudience reports whether the claims' audience contains the expected
// route URL. An empty audience never matches.
func (c *Claims) ValidateAudience(route string) bool {
	if route == "" {
		return false
	}
	for _, a := range c.Audience {
		if a == route {
			return true
		}
	}
	return false
}

// ValidateIssuer reports whether the claims' issuer matches exactly.
func (c *Claims) ValidateIssuer(issuer string) bool {
	return issuer != "" && c.Issuer == issuer
}

// CodeChallengeS256 computes the RFC 7636 S256 code challenge for a verifier.
// The verifier is used verbatim (no trimming or padding changes).
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE reports whether the stored challenge matches the presented
// verifier using the S256 method. A plain (unsalted) challenge is never
// accepted: only "S256" is supported.
func VerifyPKCE(method, challenge, verifier string) error {
	if method != "S256" {
		return fmt.Errorf("authz: unsupported code challenge method %q (only S256)", method)
	}
	if challenge == "" || verifier == "" {
		return fmt.Errorf("authz: missing code challenge or verifier")
	}
	if CodeChallengeS256(verifier) != challenge {
		return fmt.Errorf("authz: PKCE verification failed")
	}
	return nil
}

// ValidateRedirectURI checks a client-supplied redirect URI. It rejects
// non-HTTPS schemes (except loopback for native clients), private and
// link-local addresses, wildcard hosts, and mismatches with the registered
// allowlist. The relay never fetches the URI.
func ValidateRedirectURI(uri string, allowlist []string) error {
	if uri == "" {
		return fmt.Errorf("authz: empty redirect uri")
	}
	u := strings.ToLower(uri)
	// Scheme: https always; http only for an exact loopback host.
	if !strings.HasPrefix(u, "https://") {
		if !strings.HasPrefix(u, "http://") {
			return fmt.Errorf("authz: redirect uri must use https")
		}
		host := strings.TrimPrefix(u, "http://")
		host = strings.SplitN(host, "/", 2)[0]
		host = strings.SplitN(host, ":", 2)[0]
		if host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
			return fmt.Errorf("authz: plain http redirect uri is only allowed for loopback")
		}
	}
	// No userinfo, no fragment.
	if strings.Contains(uri, "@") || strings.Contains(uri, "#") {
		return fmt.Errorf("authz: redirect uri must not contain userinfo or a fragment")
	}
	// Host must be public: reject private/link-local/loopback literals even
	// when the caller supplied them in the allowlist (a client can register
	// its own allowlist, so the allowlist alone is not a trust boundary).
	// Exception: an http loopback redirect is allowed for native clients.
	host := strings.SplitN(strings.SplitN(u, "://", 2)[1], "/", 2)[0]
	host = strings.SplitN(host, ":", 2)[0]
	host = strings.Trim(host, "[]")
	if IsPrivateHost(host) {
		isLoopback := host == "127.0.0.1" || host == "localhost" || host == "::1"
		if !(isLoopback && strings.HasPrefix(u, "http://")) {
			return fmt.Errorf("authz: redirect uri host %q is private or loopback", host)
		}
	}
	// Exact allowlist match.
	for _, allowed := range allowlist {
		if uri == allowed {
			return nil
		}
	}
	return fmt.Errorf("authz: redirect uri %q is not in the client allowlist", uri)
}

// IsPrivateHost reports whether a host is a private, link-local, loopback, or
// otherwise non-public address literal. Used to reject SSRF-capable targets.
func IsPrivateHost(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	switch host {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", "::":
		return true
	}
	if strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") ||
		strings.HasPrefix(host, "169.254.") || strings.HasPrefix(host, "127.") {
		return true
	}
	if strings.HasPrefix(host, "172.") {
		var second int
		if _, err := fmt.Sscanf(host, "172.%d.", &second); err == nil && second >= 16 && second <= 31 {
			return true
		}
	}
	if strings.HasPrefix(host, "fc") || strings.HasPrefix(host, "fd") ||
		strings.HasPrefix(host, "fe80:") {
		return true
	}
	return false
}

// randomKID returns a 16-byte URL-safe key id.
func randomKID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("authz: key id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Mutex is a small helper used by the in-memory store; kept here so the
// package has a single lock primitive.
type Mutex = sync.Mutex
