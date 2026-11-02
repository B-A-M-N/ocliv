// Agent session handshake and lifecycle (relay side).
//
//  1. Agent fetches POST /v1/agent/challenge {key_id} -> {nonce, origin,
//     version, expires_at}. The nonce is stored one-time-use (B07).
//  2. Agent dials GET /v1/agent/connect (WSS) with X-Ocliv-Key, X-Ocliv-TS,
//     X-Ocliv-Intent (base64 canonical JSON), X-Ocliv-Sig. Relay verifies
//     the Ed25519 domain-separated signature (B06), allocates or resumes a
//     lease (F04/F05), fences the generation (F03), and replies with one
//     Text "attached" message before bridging to yamux.
package relay

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"ocliv/internal/apperr"
	"ocliv/internal/identity"
	"ocliv/internal/protocol"
	"ocliv/internal/transport"
)

// challengeReq asks for a one-time nonce for a key id.
type challengeReq struct {
	KeyID string `json:"key_id"`
}

type challengeResp struct {
	Nonce   string `json:"nonce"`
	Origin  string `json:"origin"`
	Version string `json:"version"`
	Expires string `json:"expires_at"`
}

// maxIntentTTLSeconds bounds requested lease lifetimes (10 years).
// Larger values cannot be represented as a time.Duration without
// overflow, and short-lived tunnels never need more (F06).
const maxIntentTTLSeconds = 10 * 365 * 24 * 60 * 60

// LeaseIntent is the canonical signed statement of what the agent wants.
// The signature binds identity to relay origin, version, and lease intent
// (B06); neither visitor nor agent can widen it after signing (D07).
type LeaseIntent struct {
	Port       int    `json:"port"`
	Name       string `json:"name,omitempty"`
	Public     bool   `json:"public"`
	AccessMode string `json:"access_mode,omitempty"` // explicit policy; "" = protected/public from Public
	Ready      bool   `json:"ready"`
	LeaseID    string `json:"lease_id,omitempty"`    // resume attempt
	TTLSeconds int64  `json:"ttl_seconds,omitempty"` // requested lease lifetime; 0 = until close
	Version    string `json:"version"`               // handshake protocol version, must match
}

// handleChallenge mints a one-time nonce for an enrolled key.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.checkPreAuth(w, r, "challenge") {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req challengeReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pub, tenant, status, err := s.lookupKey(req.KeyID)
	if err != nil || !s.identityAdmitted(tenant, status) {
		s.db.Audit("agent", tenant, "", "challenge", "denied", "unknown, revoked, or suspended key")
		http.Error(w, "unknown agent key", http.StatusUnauthorized)
		return
	}
	ch, err := identity.NewChallenge("https://"+s.relayHost, protocol.Version)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonceB64 := base64.StdEncoding.EncodeToString(ch.Nonce)
	if !s.nonces.reserve(nonceB64, ch.ExpiresAt) {
		s.db.Audit("agent", tenant, "", "challenge", "denied", "nonce table full")
		http.Error(w, "busy, try again", http.StatusTooManyRequests)
		return
	}
	_ = pub
	writeJSON(w, http.StatusOK, challengeResp{
		Nonce: nonceB64, Origin: "https://" + s.relayHost,
		Version: protocol.Version, Expires: ch.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

// lookupKey returns the public key, tenant, and status for a key id.
func (s *Server) lookupKey(keyID string) (ed25519.PublicKey, string, string, error) {
	var pub []byte
	var tenant, status string
	err := s.db.SQL().QueryRow(
		`SELECT ed25519_public, tenant_id, status FROM agent_keys WHERE id=?`, keyID,
	).Scan(&pub, &tenant, &status)
	if err != nil {
		return nil, "", "", apperr.E(apperr.CodeEnrollAuth, "unknown agent key", err)
	}
	return ed25519.PublicKey(pub), tenant, status, nil
}

// identityAdmitted is the single operator-identity gate (P0-A): the key
// must be active and its tenant must not be suspended. Every agent
// attach path (challenge, connect, management auth, allocate/resume)
// enforces it; storage failures fail closed.
func (s *Server) identityAdmitted(tenantID, keyStatus string) bool {
	if keyStatus != "active" || tenantID == "" {
		return false
	}
	var tst string
	err := s.db.SQL().QueryRow(`SELECT status FROM tenants WHERE id=?`, tenantID).Scan(&tst)
	if err != nil {
		return false
	}
	return tst != "suspended"
}

// attachedMsg confirms session establishment before yamux starts.
// ShareURL carries the initial single-redeem share link to the owning agent
// only; it is never logged or exposed elsewhere.
type attachedMsg struct {
	Type       string `json:"type"`
	SessionID  string `json:"session_id"`
	LeaseID    string `json:"lease_id"`
	Hostname   string `json:"hostname"`
	Generation uint64 `json:"generation"`
	AccessMode string `json:"access_mode"`
	URL        string `json:"url"`
	ShareURL   string `json:"share_url,omitempty"`
}

// handleConnect validates the handshake, attaches the lease, then bridges
// the connection to yamux. Browser-originated handshakes are rejected: no
// cookie auth is accepted for agents (spec 3.2).
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil && !isLoopback(r.RemoteAddr) {
		http.Error(w, "agent endpoint requires TLS", http.StatusForbidden)
		return
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Origin")), "http") {
		http.Error(w, "browser origin rejected on agent endpoint", http.StatusForbidden)
		return
	}
	keyID := strings.TrimSpace(r.Header.Get("X-Ocliv-Key"))
	tsRaw := strings.TrimSpace(r.Header.Get("X-Ocliv-TS"))
	intentB64 := strings.TrimSpace(r.Header.Get("X-Ocliv-Intent"))
	sigB64 := strings.TrimSpace(r.Header.Get("X-Ocliv-Sig"))
	nonceB64 := strings.TrimSpace(r.Header.Get("X-Ocliv-Nonce"))
	if keyID == "" || tsRaw == "" || intentB64 == "" || sigB64 == "" || nonceB64 == "" {
		http.Error(w, "missing agent handshake", http.StatusUnauthorized)
		return
	}
	ts, err := time.Parse(time.RFC3339Nano, tsRaw)
	if err != nil {
		http.Error(w, "bad handshake timestamp", http.StatusUnauthorized)
		return
	}
	intentRaw, err := base64.StdEncoding.DecodeString(intentB64)
	if err != nil || len(intentRaw) > 2048 {
		http.Error(w, "bad handshake intent", http.StatusUnauthorized)
		return
	}
	var intent LeaseIntent
	if err := json.Unmarshal(intentRaw, &intent); err != nil {
		http.Error(w, "bad handshake intent", http.StatusUnauthorized)
		return
	}
	if intent.Port < 1 || intent.Port > 65535 {
		http.Error(w, "bad port in intent", http.StatusUnauthorized)
		return
	}
	if intent.TTLSeconds < 0 || intent.TTLSeconds > maxIntentTTLSeconds {
		http.Error(w, "bad ttl in intent", http.StatusUnauthorized)
		return
	}
	// The handshake version is negotiated, not assumed: an agent speaking
	// a different protocol version cannot attach (B10).
	if intent.Version != protocol.Version {
		http.Error(w, "protocol version mismatch", http.StatusUnauthorized)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		http.Error(w, "bad handshake signature", http.StatusUnauthorized)
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil || len(nonce) != identity.NonceBytes {
		http.Error(w, "bad handshake nonce", http.StatusUnauthorized)
		return
	}
	// Consume the nonce exactly once (B07: replay rejected).
	exp, ok := s.nonces.consume(nonceB64)
	if !ok || time.Now().After(exp) {
		s.db.Audit("agent", "", "", "handshake", "denied", "stale or replayed nonce")
		http.Error(w, "stale or replayed handshake", http.StatusUnauthorized)
		return
	}
	pub, tenant, status, err := s.lookupKey(keyID)
	if err != nil || !s.identityAdmitted(tenant, status) {
		s.db.Audit("agent", tenant, "", "handshake", "denied", "unknown, revoked, or suspended key")
		http.Error(w, "unknown, revoked, or suspended agent key", http.StatusUnauthorized)
		return
	}
	origin := "https://" + s.relayHost
	leaseIntentStr := string(intentRaw)
	if err := identity.Verify(pub, nonce, shortKeyID(keyID), origin, protocol.Version, ts, leaseIntentStr, sig); err != nil {
		s.db.Audit("agent", tenant, "", "handshake", "denied", "bad signature")
		http.Error(w, "handshake signature invalid", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	ctx := r.Context()
	ls, attached, aerr := s.allocateOrResume(tenant, keyID, intent)
	if aerr != nil {
		// Distinct close codes so the agent can tell terminal denials
		// (stop, F09) from retryable conflicts (back off and retry) and
		// replacement-permitted expiry (drop the stale local record and
		// reconnect once for a fresh lease, P0-4): 4401 terminal, 4409
		// conflict, 4410 expired-replaceable, 4429 quota.
		closeCode := 4401
		denyCode := "denied"
		var ae *apperr.Error
		if asApperr(aerr, &ae) {
			denyCode = string(ae.Code)
			switch ae.Code {
			case apperr.CodeConflict:
				closeCode = 4409
			case apperr.CodeExpired:
				closeCode = 4410
			case apperr.CodeQuotaLease:
				closeCode = 4429
			}
		}
		conn.Close(websocket.StatusCode(closeCode), "lease denied")
		s.db.Audit("agent", tenant, "", "attach", "denied", denyCode)
		return
	}
	raw, _ := json.Marshal(attached)
	if err := transport.WriteControl(ctx, conn, raw); err != nil {
		if _, merr := s.markReconnecting(ls.ID, ls.Generation); merr != nil {
			s.db.Audit("system", "", ls.ID, "attach", "error", "reconnect transition failed: "+errShort(merr))
		}
		conn.Close(1011, "internal")
		return
	}
	s.registerSession(ctx, conn, ls, tenant, keyID, attached.AccessMode)
}

// shortKeyID derives the identity key id from the stored key row id.
func shortKeyID(keyRowID string) string {
	return strings.TrimPrefix(keyRowID, "key-")
}
