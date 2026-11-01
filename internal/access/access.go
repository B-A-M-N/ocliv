// Package access owns visitor authorization: scoped tokens stored as
// one-way verifiers, redeemable share links, host-only session cookies,
// and exact-Origin CSRF checks (invariants C01-C12). It never forwards
// credentials to the local application.
package access

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"ocliv/internal/apperr"
)

// Visitor credential contract (spec 1.3).
const (
	HeaderName       = "X-Ocliv-Authorization" // relay-owned; app Authorization untouched
	AuthRequiredFlag = "X-Ocliv-Auth-Required"
	CookieName       = "__Host-ocliv-visitor"
	UnlockPath       = "/_ocliv/unlock"
	RedeemPath       = "/_ocliv/redeem"
	TokenBytes       = 32 // 256-bit CSPRNG secrets (C06)
	CookieIdleTTL    = time.Hour
	CookieAbsTTL     = 12 * time.Hour
	ShareLinkTTL     = 15 * time.Minute
)

// Token is a scoped visitor credential; only the verifier is stored (C06).
type Token struct {
	Raw      string // Bearer [REDACTED] shown once only
	Verifier string
	Scope    string
}

// MintRowID creates a non-secret database row identifier for session
// rows whose bearer must never be stored (P0-4). RawURLEncoding keeps it
// cookie-safe, matching the existing session credential format.
func MintRowID() (string, error) {
	raw := make([]byte, TokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", apperr.E(apperr.CodeInternal, "CSPRNG failure minting session row ID", err)
	}
	return "ocliv-sid-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Mint creates a fresh token with a one-way verifier.
func Mint(scope string) (*Token, error) {
	raw := make([]byte, TokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, apperr.E(apperr.CodeInternal, "CSPRNG failure minting visitor token", err)
	}
	s := "ocliv-vst-" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(s))
	return &Token{Raw: s, Verifier: hex.EncodeToString(sum[:]), Scope: scope}, nil
}

// Verify checks a presented Bearer [REDACTED] against a stored verifier in constant time.
func Verify(presented, verifier string) bool {
	sum := sha256.Sum256([]byte(presented))
	got := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(verifier)) == 1 && verifier != ""
}

// ShareLink builds the fragment-carrying unlock URL. The token travels in
// the URI fragment so it never reaches the relay in the HTTP request (C05).
func ShareLink(origin, token string) string {
	return origin + UnlockPath + "#t=" + token
}

// ExtractHeader pulls the relay-owned Bearer [REDACTED] from a visitor request.
// Tunnel tokens in query params, logs, or the app Authorization header are
// never honored (C04).
func ExtractHeader(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get(HeaderName))
	if strings.HasPrefix(v, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
	}
	return ""
}

// ExtractCookie pulls the host-only visitor session cookie value.
func ExtractCookie(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// SetSessionCookie issues the host-only Secure HttpOnly SameSite=Lax cookie.
func SetSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((CookieAbsTTL).Seconds()),
	})
}

// ClearSessionCookie removes the visitor session cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1})
}

// SessionVerifier derives the stored verifier for a cookie session id using
// the relay's server-side secret (HMAC, C06).
func SessionVerifier(sessionID string, serverKey []byte) string {
	m := hmac.New(sha256.New, serverKey)
	m.Write([]byte("ocliv-visitor-session\n" + sessionID))
	return hex.EncodeToString(m.Sum(nil))
}

// MintSessionID creates a fresh opaque session id.
func MintSessionID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", apperr.E(apperr.CodeInternal, "CSPRNG failure minting session id", err)
	}
	return "sess-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

// CheckCSRF enforces exact same-origin evidence for cookie-authenticated
// unsafe methods and WS upgrades (C08, C09). Header-token callers are
// exempt because they already present a dedicated credential.
func CheckCSRF(r *http.Request, tunnelOrigin string, hasHeaderToken bool) error {
	if hasHeaderToken {
		return nil
	}
	if IsSafeMethod(r.Method) {
		return nil
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return apperr.E(apperr.CodeVisitorForbid, "cookie-authenticated unsafe request requires exact Origin", nil)
	}
	if origin != tunnelOrigin {
		return apperr.E(apperr.CodeVisitorForbid, "cookie-authenticated request Origin mismatch", nil)
	}
	return nil
}

// IsSafeMethod reports RFC safe methods.
func IsSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// CheckUpgradeOrigin enforces exact-origin on cookie-authenticated WS
// handshakes (C09). Returns nil when a header token is present.
func CheckUpgradeOrigin(r *http.Request, tunnelOrigin string, hasHeaderToken bool) error {
	if hasHeaderToken {
		return nil
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	// Browser upgrades MUST carry an exact matching Origin.
	if origin == "" || origin != tunnelOrigin {
		return apperr.E(apperr.CodeVisitorForbid, "websocket upgrade Origin mismatch", nil)
	}
	return nil
}
