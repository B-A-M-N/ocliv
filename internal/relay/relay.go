// Package relay owns public ingress, agent session lifecycle, lease
// routing, and visitor authorization enforcement. One authoritative routing
// decision point: route() maps an exact Host to exactly one live lease
// generation (D01), and every proxied request re-checks generation (F13).
package relay

import (
	"context"
	"crypto/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"ocliv/internal/access"
	"ocliv/internal/apperr"
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

// ReadyForSessions reports whether the relay can accept tunnel sessions:
// SQLite writable (a BEGIN IMMEDIATE probe, rolled back, proves the write
// lock — Ping alone only proves the process is alive), routing
// initialized (post-New), and admission maps below the cardinality cap.
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
	mcpPort  int
	visitors visitorAccess // HMAC key + verifier for visitor sessions
	log      Logger

	registry     sessionRegistry // live sessions + expiry timers (relay_sessions.go only)
	nonces       nonceCache      // challenge/handshake replay cache (relay_nonce.go only)
	throttle     *limits.Throttle
	preAuth      *limits.Throttle // G07: per-IP cap on pre-auth endpoints
	mcpAdmission *limits.Throttle // P1-10: per-(source,lease) cap on MCP-profile forwarding
	budgets      *limits.Registry
	mux          *http.ServeMux
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
	s := &Server{
		db:           o.DB,
		namespace:    strings.ToLower(o.Namespace),
		relayHost:    strings.ToLower(o.RelayHost),
		mcpHost:      strings.ToLower(o.MCPExternalHost),
		mcpPort:      port,
		visitors:     newVisitorAccess(o.ServerKey),
		log:          o.Logger,
		registry:     newSessionRegistry(),
		nonces:       newNonceCache(),
		throttle:     limits.NewThrottle(limits.MaxBurstReg, time.Minute),
		preAuth:      limits.NewThrottle(limits.PreAuthBurst, time.Minute),
		mcpAdmission: limits.NewThrottle(limits.MCPAdmissionBurst, time.Minute),
		budgets:      limits.NewRegistry(),
		mux:          http.NewServeMux(),
	}
	if s.log == nil {
		s.log = noopLog{}
	}
	s.mux.HandleFunc("/v1/agent/enroll", s.handleEnroll)
	s.mux.HandleFunc("/v1/agent/challenge", s.handleChallenge)
	s.mux.HandleFunc("/v1/agent/connect", s.handleConnect)
	s.mux.HandleFunc("/v1/agent/lease/", s.handleAgentLease) // signed agent management
	s.mux.HandleFunc("/v1/agent/mcp-routes", s.handleAgentPublications)
	s.mux.HandleFunc("/v1/agent/mcp-routes/", s.handleAgentPublications)
	s.mux.HandleFunc(askPath, s.handleAsk)
	s.mux.HandleFunc(access.UnlockPath, s.handleUnlockPage)
	s.mux.HandleFunc(access.RedeemPath, s.handleRedeem)
	s.mux.HandleFunc("/", s.handlePublic)
	// Crash recovery: reconcile durable rows before serving traffic (F11).
	// Reconciliation failures refuse startup: serving on unknown durable
	// state is worse than not serving (P1-05).
	if err := s.reconcileBoot(); err != nil {
		return nil, err
	}
	return s, nil
}

type noopLog struct{}

func (noopLog) Info(string, ...any)  {}
func (noopLog) Warn(string, ...any)  {}
func (noopLog) Error(string, ...any) {}

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
