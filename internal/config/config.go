// Package config defines Ocliv's sparse configuration schema, precedence,
// validation, and redaction. Precedence: flags > non-secret env > file >
// compiled defaults. Secrets never come from insecure implicit defaults.
package config

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ocliv/internal/apperr"
)

// Defaults for ordinary operation.
const (
	DefaultRelayURL    = "https://relay.example.com"
	DefaultAccessMode  = "protected"
	DefaultDataDir     = ".ocliv"
	AgentKeyFile       = "agent.key"
	ConfigFile         = "config.toml"
	LeaseFile          = "lease.json"
	DefaultHTTPTimeout = 30
)

// Agent holds validated agent-side configuration.
type Agent struct {
	RelayURL      string
	Port          int
	Public        bool
	AccessMode    string // explicit lease policy (e.g. mcp_upstream_oauth); "" = protected/public from Public. Set only by `mcp serve`/`mcp publish`, never by `ocliv PORT` flags.
	Name          string
	TTLSeconds    int64
	UpstreamHost  string
	IPv6          bool
	JSONOut       bool
	NoShareLink   bool
	ShareLinkFile string // optional 0600 file receiving the share URL
	KeyPath       string
	DataDir       string
	InsecureTest  bool // test-only: trust a named test CA; never set in prod builds
}

// Relay holds validated relay-side configuration.
type Relay struct {
	Domain      string // e.g. example.com; tunnel namespace t.<domain>
	Namespace   string // e.g. t.example.com (derived)
	ListenAddr  string
	DataDir     string
	TLSCertFile string
	TLSKeyFile  string
}

// ValidatePort accepts only a TCP port 1-65535 (A03).
func ValidatePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, apperr.E(apperr.CodeCLIValidation,
			fmt.Sprintf("invalid port %q: want 1-65535", s), nil)
	}
	return p, nil
}

// CheckRelayTLS rejects relay URLs that would send credentials over
// plaintext to the network. https is always allowed; http is allowed only
// for loopback destinations (local development and tests), never for
// remote hosts (B01, B02).
func CheckRelayTLS(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid relay URL %q", raw)
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(u.Scheme, "http") {
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("relay URL must use https (http is loopback-only): %q", raw)
}

// LoopbackTarget resolves the deterministic dial destination (D06).
// Only literal 127.0.0.1 or ::1 are permitted.
func LoopbackTarget(port int, ipv6 bool) string {
	if ipv6 {
		return fmt.Sprintf("[::1]:%d", port)
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// DataDir returns the agent data directory, creating it with 0700.
func DataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "ocliv")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// RedactedURL removes any userinfo from a URL for logs/diagnostics.
func RedactedURL(u string) string {
	if i := strings.Index(u, "@"); i >= 0 {
		if j := strings.LastIndex(u[:i], "/"); j >= 0 {
			return u[:j+1] + "***" + u[i:]
		}
		return "***" + u[i:]
	}
	return u
}

// LoadAgentFile reads sparse key=value config (TOML-subset: one key = "value"
// per line) for non-secret fields only. Unknown keys are rejected.
func LoadAgentFile(path string) (map[string]string, error) {
	out := map[string]string{}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	allowed := map[string]bool{
		"relay_url": true, "default_access_mode": true,
		"default_ttl": true, "upstream_host": true,
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			return nil, apperr.E(apperr.CodeCLIValidation, fmt.Sprintf("bad config line: %q", line), nil)
		}
		k := strings.TrimSpace(kv[0])
		v := strings.Trim(strings.TrimSpace(kv[1]), `"'`)
		if !allowed[k] {
			return nil, apperr.E(apperr.CodeCLIValidation, fmt.Sprintf("unknown config key %q", k), nil)
		}
		out[k] = v
	}
	return out, nil
}

// EnvRelay returns OCLIV_RELAY_URL when set (non-secret env override).
func EnvRelay() string { return strings.TrimSpace(os.Getenv("OCLIV_RELAY_URL")) }

// CACertPath returns OCLIV_CACERT when set: an extra PEM CA bundle the
// agent trusts alongside system roots for lab/private relay edges (e.g.
// a Caddy `tls internal` staging CA). Empty means system roots only. It
// only ADDS trust; no flag or value disables verification.
func CACertPath() string { return strings.TrimSpace(os.Getenv("OCLIV_CACERT")) }

// CertPool returns system roots plus the OCLIV_CACERT bundle when set,
// or (nil, nil) when unset so callers keep default verification.
// A set-but-unreadable bundle is an error, never a silent fallback.
func CertPool() (*x509.CertPool, error) {
	path := CACertPath()
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates parsed from %s", path)
	}
	return pool, nil
}
