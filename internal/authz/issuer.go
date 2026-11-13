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
	"net/netip"
	"net/url"
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
	// TokenType marks a refresh token ("refresh"); an access token
	// leaves it empty. A refresh token is never accepted at the tool
	// path, and an access token is never accepted at the refresh
	// grant, so the two credential kinds cannot substitute for each
	// other.
	TokenType string
}

// Claims are the verified contents of an access token.
type Claims struct {
	jwt.RegisteredClaims
	Tenant string `json:"tenant,omitempty"`
	Route  string `json:"route,omitempty"`
	Scope  string `json:"scope,omitempty"`
	// TokenType is "refresh" for a refresh token; an access token
	// leaves it unset. A legacy token minted before the field existed
	// is accepted as an access token for backward compatibility.
	TokenType string `json:"typ,omitempty"`
}

// Issuer signs and verifies the relay's access tokens. It is safe for
// concurrent use.
type Issuer struct {
	kid    string
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	method jwt.SigningMethod
}

// KeyID returns the issuer's key identifier (the JWT "kid").
func (i *Issuer) KeyID() string { return i.kid }

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
		Tenant:    c.Tenant,
		Route:     c.Route,
		Scope:     c.Scope,
		TokenType: c.TokenType,
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
// accepted: only "S256" is supported. Both values are validated against
// RFC 7636 syntax before comparison, so a truncated or malformed verifier
// fails here instead of passing a weakened check.
func VerifyPKCE(method, challenge, verifier string) error {
	if method != "S256" {
		return fmt.Errorf("authz: unsupported code challenge method %q (only S256)", method)
	}
	if err := ValidateCodeVerifier(verifier); err != nil {
		return err
	}
	if err := ValidateCodeChallengeS256(challenge); err != nil {
		return err
	}
	if CodeChallengeS256(verifier) != challenge {
		return fmt.Errorf("authz: PKCE verification failed")
	}
	return nil
}

// RFC 7636 §4.1 bounds: the verifier is 43-128 characters from the
// unreserved set.
const (
	pkceVerifierMinLen = 43
	pkceVerifierMaxLen = 128
)

// validPKCEUnreserved reports whether r is in the RFC 7636 unreserved set
// (ALPHA / DIGIT / "-" / "." / "_" / "~").
func validPKCEUnreserved(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
		r == '-' || r == '.' || r == '_' || r == '~'
}

// ValidateCodeVerifier enforces the RFC 7636 §4.1 verifier grammar. A
// one-character or otherwise non-conforming verifier is rejected rather
// than hashed into a weak comparison.
func ValidateCodeVerifier(verifier string) error {
	if len(verifier) < pkceVerifierMinLen || len(verifier) > pkceVerifierMaxLen {
		return fmt.Errorf("authz: code verifier must be %d-%d characters", pkceVerifierMinLen, pkceVerifierMaxLen)
	}
	for _, r := range verifier {
		if !validPKCEUnreserved(r) {
			return fmt.Errorf("authz: code verifier contains an invalid character")
		}
	}
	return nil
}

// ValidateCodeChallengeS256 enforces the RFC 7636 §4.2 challenge grammar:
// the unpadded base64url encoding of exactly 32 bytes (a SHA-256 digest).
func ValidateCodeChallengeS256(challenge string) error {
	if len(challenge) != 43 {
		return fmt.Errorf("authz: S256 code challenge must be 43 base64url characters")
	}
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		return fmt.Errorf("authz: S256 code challenge is not valid base64url")
	}
	if len(raw) != 32 {
		return fmt.Errorf("authz: S256 code challenge must encode a 32-byte digest")
	}
	return nil
}

// ValidateRedirectURI checks a client-supplied redirect URI.
//
// Parsing uses net/url (never string splitting, which cannot read a
// bracketed IPv6 authority) and host classification uses net/netip, so
// every literal form — IPv4, IPv6, IPv4-mapped-IPv6, ULA, link-local —
// is classified once, correctly. The rules:
//
//   - scheme is https, or http only when the host is a canonical
//     loopback (a native client callback);
//   - http's loopback exception covers 127.0.0.0/8, ::1, and
//     IPv4-mapped loopback (::ffff:127.0.0.0/104, unmapped before the
//     check) — every form that actually connects to the loopback
//     interface — plus the name "localhost";
//   - private, link-local, unique-local, and other non-public literals
//     are rejected even when the caller supplied them in its own
//     allowlist (DCR is public, so the allowlist is not a trust
//     boundary);
//   - userinfo, fragments, and opaque forms are rejected;
//   - the URI must appear EXACTLY in the registered allowlist.
//
// The relay never fetches the URI.
func ValidateRedirectURI(uri string, allowlist []string) error {
	if uri == "" {
		return fmt.Errorf("authz: empty redirect uri")
	}
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("authz: redirect uri is not a parseable URL: %w", err)
	}
	if u.Opaque != "" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("authz: redirect uri must not contain userinfo, a fragment, or an opaque form")
	}
	switch u.Scheme {
	case "https":
	case "http":
	default:
		return fmt.Errorf("authz: redirect uri must use https (http only for a loopback native client)")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("authz: redirect uri has no host")
	}
	isLoopback := isCanonicalLoopbackHost(host)
	if u.Scheme == "http" && !isLoopback {
		return fmt.Errorf("authz: plain http redirect uri is only allowed for loopback")
	}
	if isNonPublicHost(host) && !(isLoopback && u.Scheme == "http") {
		return fmt.Errorf("authz: redirect uri host %q is private or loopback", host)
	}
	// Exact allowlist match.
	for _, allowed := range allowlist {
		if uri == allowed {
			return nil
		}
	}
	return fmt.Errorf("authz: redirect uri %q is not in the client allowlist", uri)
}

// isCanonicalLoopbackHost reports whether the host names this machine's
// loopback interface in any literal form (IPv4, IPv6, IPv4-mapped-IPv6)
// or by the reserved name.
func isCanonicalLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.Unmap().IsLoopback()
}

// isNonPublicHost reports whether the host is a private, link-local,
// unique-local, multicast, unspecified, or otherwise non-public address
// literal. DNS names that are not "localhost" are treated as public:
// the exact allowlist still binds them, and the relay never fetches them.
func isNonPublicHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified()
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified()
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
