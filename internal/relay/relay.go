// Package relay owns public ingress, agent session lifecycle, lease
// routing, and visitor authorization enforcement. One authoritative routing
// decision point: route() maps an exact Host to exactly one live lease
// generation (D01), and every proxied request re-checks generation (F13).
package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"ocliv/internal/access"
	"ocliv/internal/apperr"
	"ocliv/internal/installer"
	"ocliv/internal/limits"
	"ocliv/internal/store"
)

// Options configures the relay.
type Options struct {
	DB        *store.DB
	Namespace string // e.g. t.example.com
	RelayHost string // e.g. relay.example.com (agent endpoint origin check)
	// MCPExternalHost is the exact public hostname that serves
	// path-based MCP routes (/r/<route-id>/mcp) for single-host ingress
	// without wildcard DNS (P0-A). Empty disables path-route resolution
	// entirely; wildcard tunnel-host routing is unaffected.
	MCPExternalHost string
	// MCPExternalPort is the public HTTPS port minted into route URLs.
	// 0 means 443 (omitted from URLs). A non-443 edge (e.g. a lab Caddy
	// on 8444) must set it or minted URLs point at a closed port while
	// Host matching — which strips numeric ports — still works.
	MCPExternalPort int
	ServerKey       []byte // HMAC key for visitor sessions; random per relay
	Logger          Logger
	// AutoApproveRedirectHosts lists trusted redirect hostnames that may
	// auto-approve managed OAuth clients with skip_pairing=true.
	AutoApproveRedirectHosts []string
	// GoogleVerificationJSON is the operator-configured JSON payload served at
	// GET /.well-known/google-connected-apps on MCPExternalHost (HTTP 200, no redirect).
	GoogleVerificationJSON []byte
	// GlobalMaxHTTPStreams, GlobalMaxWSStreams, GlobalMaxSessions set aggregate
	// server-wide caps across all leases. Zero uses the package defaults.
	GlobalMaxHTTPStreams int64
	GlobalMaxWSStreams   int64
	GlobalMaxSessions    int64
	// ReleaseManifestJSON is the release-manifest.json payload served at
	// GET /.well-known/ocliv-release-manifest.json. If nil the endpoint
	// returns 404 — no manifest configured by the operator.
	ReleaseManifestJSON []byte
	// ReleaseManifestSig is the raw 64-byte Ed25519 signature of ReleaseManifestJSON,
	// served at GET /.well-known/ocliv-release-manifest.json.sig. When both fields
	// are set the relay verifies the signature against the production key at startup
	// and refuses to start if the signature is invalid.
	ReleaseManifestSig []byte
	// ReleaseArtifactDir is the filesystem directory serving release artifacts at
	// GET /.well-known/ocliv-artifacts/{name}. If empty the artifact endpoint
	// returns 404. Every artifact must be declared in ReleaseManifestJSON before
	// it can be served; undeclared files are never accessible.
	ReleaseArtifactDir string
	// AllowUnsignedRelease permits starting a relay with a release manifest and
	// artifact directory without ReleaseManifestSig (development/lab use only).
	// Production relays must provide the full tuple: manifest + signature + artifacts.
	AllowUnsignedRelease bool
	// ReleaseVerifyKeys overrides the trusted Ed25519 public keys used to verify
	// ReleaseManifestSig at startup. When empty, installer.ProductionPublicKeys()
	// is used. Intended for tests and custom release keychains.
	ReleaseVerifyKeys []ed25519.PublicKey
	// EdgeMode explicitly sets the ingress topology for capability advertisement
	// and configuration validation. Valid values: "tunnel", "wildcard",
	// "single-host". Empty means unknown — capabilities advertised conservatively.
	EdgeMode string
}

// Logger is a minimal structured logger to avoid import cycles.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// Session is one live authenticated agent connection (F02: exactly one
// active generation per lease; older generations accept no new requests).
type Session struct {
	LeaseID    string
	TenantID   string
	KeyID      string
	Hostname   string
	Generation uint64
	AccessMode string
	Yamux      *yamux.Session
	Budget     *limits.LeaseBudget
	LastSeen   time.Time
	closed     chan struct{}
	closeOnce  sync.Once
}

func (s *Session) close() {
	s.closeOnce.Do(func() { close(s.closed) })
}

// ReadyForSessions reports whether the relay process and store are healthy and
// able to serve control-plane traffic: SQLite writable (a BEGIN IMMEDIATE probe,
// rolled back, proves the write lock — Ping alone only proves the process is
// alive), routing initialized (post-New), and admission maps below the
// cardinality cap.
//
// Intentional visitor-stream backpressure (HTTP/WS saturation) does NOT mark
// /health/ready unhealthy, because the relay process and publisher control
// plane remain healthy; separate data-plane saturation and session-admission
// signals are exposed via StatusSnapshot() / /health/status.
//
// It deliberately excludes public DNS/TLS, route liveness, and MCP
// compatibility: those are external doctor checks, never relay readiness
// (P2-2). Never report HTTPS_VERIFIED from this signal.
func (s *Server) ReadyForSessions() bool {
	if s == nil || s.db == nil || s.mux == nil {
		return false
	}
	if s.throttle.Keys() >= limits.MaxThrottleKeys ||
		s.preAuth.Keys() >= limits.MaxThrottleKeys ||
		s.mcpAdmission.Keys() >= limits.MaxThrottleKeys {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := s.db.SQL().Conn(ctx)
	if err != nil {
		return false
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return false
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	var one int
	if err := conn.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		return false
	}
	return true
}

// RelayStatus separates process/store readiness, publisher-session admission
// availability, and visitor data-plane saturation so operators and orchestrators
// can distinguish healthy backpressure from process faults.
type RelayStatus struct {
	ProcessReady      bool   `json:"process_ready"`
	SessionsReady     bool   `json:"sessions_ready"`
	HTTPSaturated     bool   `json:"http_saturated"`
	WSSaturated       bool   `json:"ws_saturated"`
	SessionsSaturated bool   `json:"sessions_saturated"`
	ActiveHTTPStreams int64  `json:"active_http_streams"`
	ActiveWSStreams   int64  `json:"active_ws_streams"`
	ActiveSessions    int64  `json:"active_sessions"`
	MaxHTTPStreams    int64  `json:"max_http_streams"`
	MaxWSStreams      int64  `json:"max_ws_streams"`
	MaxSessions       int64  `json:"max_publisher_sessions"`
	ReleaseTrustMode  string `json:"release_trust_mode"`
	ReleaseKeyID      string `json:"release_signing_key_id,omitempty"`
}

// StatusSnapshot returns the separated readiness and capacity snapshot.
func (s *Server) StatusSnapshot() RelayStatus {
	ready := s.ReadyForSessions()
	st := RelayStatus{
		ProcessReady:     ready,
		SessionsReady:    ready,
		ReleaseTrustMode: s.releaseTrustMode,
		ReleaseKeyID:     s.releaseKeyID,
	}
	if st.ReleaseTrustMode == "" {
		st.ReleaseTrustMode = "DISABLED"
	}
	if s != nil && s.globalBudget != nil {
		st.ActiveHTTPStreams, st.ActiveWSStreams, st.ActiveSessions = s.globalBudget.Stats()
		st.MaxHTTPStreams, st.MaxWSStreams, st.MaxSessions = s.globalBudget.Limits()
		st.HTTPSaturated = s.globalBudget.HTTPSaturated()
		st.WSSaturated = s.globalBudget.WSSaturated()
		st.SessionsSaturated = s.globalBudget.SessionsSaturated()
		st.SessionsReady = ready && !st.SessionsSaturated
	}
	return st
}

// Server is the relay composition root and façade (audit: keep it a
// façade, formalize contracts, do not re-split the package). Ownership:
//   - durable lease status/owner/generation/expiration → lease-transition
//     code (relay_leases.go, relay_lease_service.go); SQLite is
//     authoritative, every mutation atomic, sessions evicted only after
//     commit;
//   - live sessions, generations, timers → sessionRegistry, mutated only
//     under its mutex with close-outside-lock (relay_sessions.go);
//   - visitor credentials/sessions → visitorAccess (relay_access.go),
//     validated atomically against revocation, never forwarded upstream;
//   - one request/response exchange → one httpExchange (relay_http.go);
//   - HTTP authority dispatch → relay_authority.go (exact host + strict
//     path split), request admission → admitRoutedLease (shared by both
//     ingress modes; no second routing authority exists).
type Server struct {
	db        *store.DB
	namespace string
	relayHost string
	// mcpHost is the exact canonical external hostname for path-based
	// MCP routes; empty means the feature is off (P0-A).
	mcpHost string
	// mcpPort is the normalized public HTTPS port (443 default), minted
	// into route URLs when non-443. Host authority matching strips ports
	// (canonicalHost), so this affects only advertised URLs, never admission.
	mcpPort                  int
	autoApproveRedirectHosts []string
	googleVerificationJSON   []byte
	releaseManifestJSON      []byte
	releaseManifestSig       []byte
	releaseArtifactDir       string
	releaseTrustMode         string
	releaseKeyID             string
	edgeMode                 string
	visitors                 visitorAccess // HMAC key + verifier for visitor sessions
	log                      Logger

	registry     sessionRegistry // live sessions + expiry timers (relay_sessions.go only)
	nonces       nonceCache      // challenge/handshake replay cache (relay_nonce.go only)
	throttle     *limits.Throttle
	preAuth      *limits.Throttle // G07: per-IP cap on pre-auth endpoints
	mcpAdmission *limits.Throttle // P1-10: per-(source,lease) cap on MCP-profile forwarding
	budgets      *limits.Registry
	globalBudget *limits.GlobalBudget
	mux          *http.ServeMux
	authz        *authzManager // managed-route authorization (relay_authz.go only)
	// dispatchHold is a test-only barrier run between the dispatch-time
	// session recheck and the request-head write (P2-1). It lets a test
	// deterministically land a replacement in that window to prove the
	// stale session cannot forward. Nil in production; like the agent's
	// HandshakeTransport hook, it changes no production path.
	dispatchHold func()
	// routeCreateHold is a test-only barrier between the route-create
	// ACTIVE pre-check and the conditional INSERT (audit P1). It lets
	// a test revoke the lease in that window to prove the atomic
	// EXISTS predicate denies the mint. Nil in production.
	routeCreateHold func()
	// leaseExpiryCASHook is a test barrier for deterministic renewal-vs-expiry
	// admission races. Nil in production.
	leaseExpiryCASHook func(string)
}

// New builds the relay server.
func New(o Options) (*Server, error) {
	if o.ServerKey == nil {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, apperr.E(apperr.CodeInternal, "CSPRNG failure for server key", err)
		}
		o.ServerKey = k
	}
	port := o.MCPExternalPort
	if port == 0 {
		port = 443
	}
	var autoApprove []string
	seenAuto := make(map[string]struct{}, len(o.AutoApproveRedirectHosts))
	for _, raw := range o.AutoApproveRedirectHosts {
		if h := strings.ToLower(strings.TrimSpace(raw)); h != "" {
			if _, ok := seenAuto[h]; !ok {
				seenAuto[h] = struct{}{}
				autoApprove = append(autoApprove, h)
			}
		}
	}
	s := &Server{
		db:                       o.DB,
		namespace:                strings.ToLower(o.Namespace),
		relayHost:                strings.ToLower(o.RelayHost),
		mcpHost:                  strings.ToLower(o.MCPExternalHost),
		mcpPort:                  port,
		autoApproveRedirectHosts: autoApprove,
		googleVerificationJSON:   append([]byte(nil), o.GoogleVerificationJSON...),
		releaseManifestJSON:      append([]byte(nil), o.ReleaseManifestJSON...),
		releaseManifestSig:       append([]byte(nil), o.ReleaseManifestSig...),
		releaseArtifactDir:       o.ReleaseArtifactDir,
		edgeMode:                 strings.ToLower(strings.TrimSpace(o.EdgeMode)),
		visitors:                 newVisitorAccess(o.ServerKey),
		log:                      o.Logger,
		registry:                 newSessionRegistry(),
		nonces:                   newNonceCache(),
		throttle:                 limits.NewThrottle(limits.MaxBurstReg, time.Minute),
		preAuth:                  limits.NewThrottle(limits.PreAuthBurst, time.Minute),
		mcpAdmission:             limits.NewThrottle(limits.MCPAdmissionBurst, time.Minute),
		budgets:                  limits.NewRegistry(),
		globalBudget: limits.NewGlobalBudget(
			defaultOrI64(o.GlobalMaxHTTPStreams, limits.DefaultGlobalMaxHTTPStreams),
			defaultOrI64(o.GlobalMaxWSStreams, limits.DefaultGlobalMaxWSStreams),
			defaultOrI64(o.GlobalMaxSessions, limits.DefaultGlobalMaxSessions),
		),
		mux: http.NewServeMux(),
	}
	if s.log == nil {
		s.log = noopLog{}
	}
	if o.DB != nil {
		m, err := newAuthzManager(o.DB)
		if err != nil {
			return nil, err
		}
		s.authz = m
	}
	s.mux.HandleFunc("/.well-known/ocliv-release-manifest.json", s.handleReleaseManifest)
	s.mux.HandleFunc("/.well-known/ocliv-release-manifest.json.sig", s.handleReleaseManifestSig)
	// Require coherent release configuration at startup: either none of the
	// release-serving fields are set (endpoints 404), or the complete tuple
	// (manifest + artifact dir + valid signature, unless AllowUnsignedRelease
	// is explicitly enabled for development) is configured and verified.
	hasManifest := len(o.ReleaseManifestJSON) > 0
	hasSig := len(o.ReleaseManifestSig) > 0
	hasArtifacts := o.ReleaseArtifactDir != ""
	s.releaseTrustMode = "DISABLED"
	if hasManifest || hasSig || hasArtifacts {
		if !hasManifest {
			return nil, fmt.Errorf("relay startup: partial release config: release manifest is required when artifacts or signature are configured")
		}
		if !hasArtifacts {
			return nil, fmt.Errorf("relay startup: partial release config: release artifact directory is required when release manifest is configured")
		}
		if !hasSig && !o.AllowUnsignedRelease {
			return nil, fmt.Errorf("relay startup: partial release config: release manifest signature is required (set --release-manifest-sig or explicit dev override)")
		}
		if !hasSig && o.AllowUnsignedRelease {
			// Constrain unsigned dev release mode strictly:
			// explicit flag AND OCLIV_ENV=development AND loopback authorities only.
			isDevEnv := strings.EqualFold(strings.TrimSpace(os.Getenv("OCLIV_ENV")), "development")
			isLoopbackAuth := isDevTopologyHost(o.RelayHost) && (o.MCPExternalHost == "" || isDevTopologyHost(o.MCPExternalHost))
			if !isDevEnv || !isLoopbackAuth {
				return nil, fmt.Errorf("relay startup: --allow-unsigned-dev-release refused (requires OCLIV_ENV=development AND loopback relay/mcp authorities; host=%q mcp=%q)", o.RelayHost, o.MCPExternalHost)
			}
			s.releaseTrustMode = "UNSIGNED_DEVELOPMENT"
			s.log.Warn("WARNING: relay serving UNSIGNED development release manifest (release_trust_mode=UNSIGNED_DEVELOPMENT)")
		}
		if hasSig {
			var meta struct {
				ManifestVersion int    `json:"manifest_version"`
				ReleaseSequence int64  `json:"release_sequence"`
				SigningKeyID    string `json:"signing_key_id"`
				NonProduction   bool   `json:"non_production"`
			}
			_ = json.Unmarshal(o.ReleaseManifestJSON, &meta)
			if !o.AllowUnsignedRelease {
				if meta.NonProduction {
					return nil, fmt.Errorf("relay startup: refusing non_production=true release manifest in production mode")
				}
				if meta.ManifestVersion != 1 {
					return nil, fmt.Errorf("relay startup: refusing release manifest with manifest_version=%d (want 1)", meta.ManifestVersion)
				}
				if meta.ReleaseSequence <= 0 {
					return nil, fmt.Errorf("relay startup: refusing release manifest with missing/non-positive release_sequence=%d", meta.ReleaseSequence)
				}
			}
			sigHex := hex.EncodeToString(o.ReleaseManifestSig)
			if len(o.ReleaseVerifyKeys) > 0 {
				if err := installer.VerifyManifestAny(o.ReleaseManifestJSON, sigHex, o.ReleaseVerifyKeys); err != nil {
					return nil, fmt.Errorf("relay startup: release manifest signature invalid: %w", err)
				}
				s.releaseTrustMode = "SIGNED_PRODUCTION"
				s.releaseKeyID = meta.SigningKeyID
			} else {
				keyID, err := installer.VerifyManifestWithTrust(o.ReleaseManifestJSON, sigHex, meta.SigningKeyID, installer.ProductionTrustRoot())
				if err != nil {
					return nil, fmt.Errorf("relay startup: release manifest signature invalid: %w", err)
				}
				s.releaseTrustMode = "SIGNED_PRODUCTION"
				s.releaseKeyID = keyID
				s.log.Info("release manifest authenticated", "signing_key_id", keyID)
			}
		}
		if err := validateArtifactDir(o.ReleaseManifestJSON, o.ReleaseArtifactDir); err != nil {
			return nil, fmt.Errorf("release artifacts validation: %w", err)
		}
		s.mux.HandleFunc("/.well-known/ocliv-artifacts/", s.handleReleaseArtifact)
	}
	s.mux.HandleFunc("/v1/agent/enroll", s.handleEnroll)
	s.mux.HandleFunc("/v1/agent/pair-request", s.handlePairRequest)
	s.mux.HandleFunc("/v1/agent/pair-status", s.handlePairStatus)
	s.mux.HandleFunc("/v1/agent/capabilities", s.handleCapabilities)
	s.mux.HandleFunc("/v1/agent/challenge", s.handleChallenge)
	s.mux.HandleFunc("/v1/agent/connect", s.handleConnect)
	s.mux.HandleFunc("/v1/agent/leases", s.handleAgentLeases)
	s.mux.HandleFunc("/v1/agent/lease/", s.handleAgentLease) // signed agent management
	s.mux.HandleFunc("/v1/agent/key/rotate", s.handleAgentKeyRotate)
	s.mux.HandleFunc("/v1/agent/key/revoke", s.handleAgentKeyRevoke)
	s.mux.HandleFunc("/v1/agent/mcp-routes", s.handleAgentPublications)
	s.mux.HandleFunc("/v1/agent/mcp-routes/", s.handleAgentPublications)
	s.mux.HandleFunc(askPath, s.handleAsk)
	s.mux.HandleFunc(access.UnlockPath, s.handleUnlockPage)
	s.mux.HandleFunc(access.RedeemPath, s.handleRedeem)
	s.mux.HandleFunc("/_ocliv/healthz", s.handleEdgeHealthz)
	s.mux.HandleFunc("/", s.handlePublic)
	// Crash recovery: reconcile durable rows before serving traffic (F11).
	// Reconciliation failures refuse startup: serving on unknown durable
	// state is worse than not serving (P1-05).
	if err := s.reconcileBoot(); err != nil {
		return nil, err
	}
	// Best-effort startup prune: mark expired pending pairing requests and
	// remove old resolved ones. Never blocks startup on error.
	if s.db != nil {
		_, _, _ = s.db.PrunePairingRequests(time.Now(), 24*time.Hour)
	}
	if len(o.ServerKey) == 32 && s.db != nil {
		s.db.Audit("relay", "", "", "visitor_hmac_fingerprint", "ok", VisitorKeyFingerprint(o.ServerKey))
	}
	return s, nil
}

type noopLog struct{}

func (noopLog) Info(string, ...any)  {}
func (noopLog) Warn(string, ...any)  {}
func (noopLog) Error(string, ...any) {}

// defaultOrI64 returns val when non-zero, otherwise returns def.
func defaultOrI64(val, def int64) int64 {
	if val > 0 {
		return val
	}
	return def
}

// isDevTopologyHost reports whether host is empty or a loopback address
// (localhost, 127.0.0.0/8, ::1), used to constrain --allow-unsigned-dev-release.
func isDevTopologyHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// validateArtifactDir checks that every artifact declared in manifest.artifacts
// exists in dir as a regular file (no symlinks) and matches its declared SHA256.
// If the manifest also declares a provenance SBOM file with a SHA256, that file
// is likewise verified via O_NOFOLLOW at startup (though never served via the
// binary artifact endpoint).
func validateArtifactDir(manifestJSON []byte, dir string) error {
	var m struct {
		Artifacts map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"artifacts"`
		SBOM *struct {
			Name   string `json:"name"`
			File   string `json:"file"`
			SHA256 string `json:"sha256"`
		} `json:"sbom"`
		Provenance *struct {
			SBOM *struct {
				Format string `json:"format"`
				File   string `json:"file"`
				SHA256 string `json:"sha256"`
			} `json:"sbom"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return fmt.Errorf("manifest parse: %w", err)
	}
	for name, entry := range m.Artifacts {
		if !isValidArtifactName(name) {
			return fmt.Errorf("invalid artifact name in manifest: %q (must match ocliv-{os}-{arch})", name)
		}
		if entry.SHA256 == "" {
			return fmt.Errorf("artifact %q has no sha256 in manifest", name)
		}
		if err := verifyFileDigestNoFollow(dir, name, entry.SHA256); err != nil {
			return err
		}
	}
	// Verify provenance SBOM digest when declared with a real filename + 64-hex SHA256.
	var sbomFile, sbomSHA string
	if m.Provenance != nil && m.Provenance.SBOM != nil {
		sbomFile = strings.TrimSpace(m.Provenance.SBOM.File)
		sbomSHA = strings.TrimSpace(m.Provenance.SBOM.SHA256)
	} else if m.SBOM != nil {
		sbomFile = strings.TrimSpace(m.SBOM.File)
		if sbomFile == "" {
			sbomFile = strings.TrimSpace(m.SBOM.Name)
		}
		sbomSHA = strings.TrimSpace(m.SBOM.SHA256)
	}
	if sbomFile != "" && len(sbomSHA) == 64 {
		if strings.ContainsAny(sbomFile, `/\`) || strings.Contains(sbomFile, "..") {
			return fmt.Errorf("invalid provenance sbom filename %q", sbomFile)
		}
		if err := verifyFileDigestNoFollow(dir, sbomFile, sbomSHA); err != nil {
			return fmt.Errorf("provenance sbom validation: %w", err)
		}
	}
	return nil
}

func verifyFileDigestNoFollow(dir, name, expectedSHA string) error {
	p := filepath.Join(dir, name)
	if !strings.HasPrefix(filepath.Clean(p), filepath.Clean(dir)+string(filepath.Separator)) {
		return fmt.Errorf("file name %q escapes artifact directory", name)
	}
	f, _, err := openArtifactSafe(p)
	if err != nil {
		return fmt.Errorf("artifact validation: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hashing %q: %w", name, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expectedSHA) {
		return fmt.Errorf("file %q SHA256 mismatch: manifest=%s actual=%s", name, expectedSHA, got)
	}
	return nil
}

// Handler serves both agent control and public ingress. In production Caddy
// terminates TLS and forwards here over loopback/Unix socket (B03).
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CONNECT is never tunneled (D11, AS-072). Reject it ahead of
		// the mux so path cleaning cannot turn it into a 301 (V6).
		if r.Method == http.MethodConnect {
			rejectConnect(w, r)
			return
		}
		if !s.authorizeHost(w, r) {
			return
		}
		s.mux.ServeHTTP(w, r)
	})
}
