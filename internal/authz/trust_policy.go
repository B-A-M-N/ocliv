package authz

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// TrustPreset defines a built-in client trust profile pinned to exact HTTPS
// callback endpoints. Persisted policies always store the concrete resolved
// RedirectURIs so policy meaning cannot silently drift across upgrades.
type TrustPreset struct {
	Kind         string   `json:"kind"`
	DisplayName  string   `json:"display_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

var builtinTrustPresets = []TrustPreset{
	{
		Kind:         "chatgpt",
		DisplayName:  "ChatGPT",
		RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"},
	},
}

// LookupTrustPreset resolves a built-in trust preset by kind (case-insensitive).
// The returned struct contains a fresh copy of RedirectURIs.
func LookupTrustPreset(kind string) (TrustPreset, bool) {
	norm := strings.ToLower(strings.TrimSpace(kind))
	for _, p := range builtinTrustPresets {
		if p.Kind == norm {
			cp := p
			cp.RedirectURIs = append([]string(nil), p.RedirectURIs...)
			return cp, true
		}
	}
	return TrustPreset{}, false
}

// ListTrustPresets returns copies of all built-in trust presets.
func ListTrustPresets() []TrustPreset {
	out := make([]TrustPreset, len(builtinTrustPresets))
	for i, p := range builtinTrustPresets {
		cp := p
		cp.RedirectURIs = append([]string(nil), p.RedirectURIs...)
		out[i] = cp
	}
	return out
}

// ClientTrustPolicy is a durable, route-scoped exact-redirect trust policy.
// A dynamically registered public OAuth client on (TenantID, RouteID) whose
// complete redirect_uris set exactly equals RedirectURIs receives an ACTIVE
// direct grant (SkipPairing=true) at registration time.
type ClientTrustPolicy struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	RouteID      string     `json:"route_id"`
	OwnerKeyID   string     `json:"owner_key_id"`
	Kind         string     `json:"kind"`
	RedirectURIs []string   `json:"redirect_uris"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// DisplayLabel returns a human-readable label for status/UI output.
func (p ClientTrustPolicy) DisplayLabel() string {
	if preset, ok := LookupTrustPreset(p.Kind); ok {
		return preset.DisplayName
	}
	if p.Kind != "" && p.Kind != "custom" {
		return p.Kind
	}
	if len(p.RedirectURIs) == 1 {
		return p.RedirectURIs[0]
	}
	return fmt.Sprintf("custom (%d URIs)", len(p.RedirectURIs))
}

// MintTrustPolicyID returns a fresh high-entropy trust policy identifier.
func MintTrustPolicyID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("authz: trust policy id: %w", err)
	}
	return "tp_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// ValidateTrustRedirectURIs validates and deduplicates redirect URIs for a
// trust policy. Trust policies strictly require HTTPS callbacks with a host,
// no userinfo, no fragment, and no surrounding whitespace.
func ValidateTrustRedirectURIs(uris []string) ([]string, error) {
	if len(uris) == 0 {
		return nil, fmt.Errorf("authz: trust policy requires at least one https redirect_uri")
	}
	if len(uris) > MaxClientURIs {
		return nil, fmt.Errorf("authz: too many redirect_uris (max %d)", MaxClientURIs)
	}
	seen := make(map[string]struct{}, len(uris))
	out := make([]string, 0, len(uris))
	for _, raw := range uris {
		if raw == "" || strings.TrimSpace(raw) != raw {
			return nil, fmt.Errorf("authz: redirect_uri must not be empty or contain surrounding whitespace")
		}
		if len(raw) > MaxRedirectURILength {
			return nil, fmt.Errorf("authz: redirect_uri exceeds maximum length")
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("authz: invalid redirect_uri %q: %w", raw, err)
		}
		if u.Scheme != "https" {
			return nil, fmt.Errorf("authz: trust policy redirect_uri %q must use https", raw)
		}
		if u.Host == "" || u.Hostname() == "" {
			return nil, fmt.Errorf("authz: trust policy redirect_uri %q requires a host", raw)
		}
		if u.User != nil {
			return nil, fmt.Errorf("authz: trust policy redirect_uri %q must not contain userinfo", raw)
		}
		if u.Fragment != "" {
			return nil, fmt.Errorf("authz: trust policy redirect_uri %q must not contain a fragment", raw)
		}
		if err := ValidateRedirectURI(raw, uris); err != nil {
			return nil, fmt.Errorf("authz: invalid redirect_uri %q: %w", raw, err)
		}
		if _, dup := seen[raw]; !dup {
			seen[raw] = struct{}{}
			out = append(out, raw)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ExactRedirectURISetEqual reports whether a and b represent the exact same
// non-empty set of HTTPS redirect URIs. Extra, missing, wrong, or non-HTTPS
// URIs fail closed (return false).
func ExactRedirectURISetEqual(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	setA := make(map[string]struct{}, len(a))
	for _, u := range a {
		if !isStrictHTTPSURI(u) {
			return false
		}
		setA[u] = struct{}{}
	}
	setB := make(map[string]struct{}, len(b))
	for _, u := range b {
		if !isStrictHTTPSURI(u) {
			return false
		}
		setB[u] = struct{}{}
	}
	if len(setA) != len(setB) {
		return false
	}
	for u := range setA {
		if _, ok := setB[u]; !ok {
			return false
		}
	}
	return true
}

func isStrictHTTPSURI(raw string) bool {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}
