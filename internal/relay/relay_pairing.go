package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/identity"
	"ocliv/internal/store"
)

const (
	pairingTTL        = 10 * time.Minute
	pairingRateLimit  = 5                // max pending per IP per window
	pairingRateWindow = 10 * time.Minute // window for rate limiting
	pairingGlobalMax  = 1000             // max pending requests relay-wide
)

type pairRequestBody struct {
	PublicKey string `json:"public_key"` // base64 std ed25519 public key
}

type pairRequestResp struct {
	PairingCode      string `json:"pairing_code"`
	PollID           string `json:"poll_id"`
	PollSecret       string `json:"poll_secret"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

type pairStatusReq struct {
	PollID     string `json:"poll_id"`
	PollSecret string `json:"poll_secret"`
}

type pairStatusResp struct {
	Status   string `json:"status"`
	TenantID string `json:"tenant_id,omitempty"` // set when approved
	KeyID    string `json:"key_id,omitempty"`    // set when approved
}

// handlePairRequest handles POST /v1/agent/pair-request.
// Publisher submits its public key; relay stores a pending pairing request
// and returns a short human-readable display code (for the operator) and a
// high-entropy poll_id + poll_secret (for publisher status polling).
func (s *Server) handlePairRequest(w http.ResponseWriter, r *http.Request) {
	if !s.checkPreAuth(w, r, "pair-request") {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req pairRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rawPub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(rawPub) != ed25519.PublicKeySize {
		http.Error(w, "bad public key", http.StatusBadRequest)
		return
	}

	sourceIP := clientIP(r)

	// Global capacity: prevent distributed flooding beyond per-IP limits.
	// Distinguish database faults (503) from actual capacity saturation (429).
	total, err := s.db.CountPendingPairingRequests()
	if err != nil {
		s.log.Error("pair-request: capacity count failed", "err", errShort(err))
		http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if total >= pairingGlobalMax {
		s.db.Audit("agent", "", "", "pair-request", "denied", "global pairing capacity exceeded")
		http.Error(w, "relay pairing capacity exceeded; try again later", http.StatusTooManyRequests)
		return
	}

	// Rate limit: max pairingRateLimit pending requests per IP per window.
	n, err := s.db.CountRecentPairingRequestsByIP(sourceIP, time.Now().Add(-pairingRateWindow))
	if err != nil {
		s.log.Error("pair-request: rate-limit check failed", "err", errShort(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n >= pairingRateLimit {
		s.db.Audit("agent", "", "", "pair-request", "denied", "rate limit exceeded")
		http.Error(w, "too many pairing requests; try again later", http.StatusTooManyRequests)
		return
	}

	sum := sha256.Sum256(rawPub)
	keyID := "key-" + hex.EncodeToString(sum[:identity.KeyIDBytes])

	now := time.Now().UTC()
	id := fmt.Sprintf("pair-%d", now.UnixNano())

	// Retry on UNIQUE constraint collision (display_code and poll_id must be unique).
	// Supersede + insert runs atomically in one transaction so a publisher key
	// never holds two simultaneously valid pending display codes.
	var (
		displayCode  string
		pollID       string
		pollSecret   string
		pollVerifier []byte
		insertErr    error
	)
	for attempt := 0; attempt < 4; attempt++ {
		var err error
		displayCode, err = mintPairingCode()
		if err != nil {
			s.log.Error("pair-request: mint code failed", "err", errShort(err))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		pollID, pollSecret, pollVerifier, err = mintPollCredentials()
		if err != nil {
			s.log.Error("pair-request: mint poll credentials failed", "err", errShort(err))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		insertErr = s.db.CreatePairingRequestSuperseding(id, displayCode, pollID, pollVerifier, rawPub, keyID, sourceIP, now.Add(pairingTTL))
		if insertErr == nil {
			break
		}
		if isPairingUniqueConstraintError(insertErr) {
			s.log.Warn("pair-request: code collision, retrying", "attempt", attempt+1)
			continue
		}
		break // non-collision error; fall through to failure
	}
	if insertErr != nil {
		s.log.Error("pair-request: store failed", "err", errShort(insertErr))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.db.Audit("agent", "", "", "pair-request", "ok", "created key="+keyID)
	writeJSON(w, http.StatusOK, pairRequestResp{
		PairingCode:      displayCode,
		PollID:           pollID,
		PollSecret:       pollSecret,
		ExpiresInSeconds: int(pairingTTL.Seconds()),
	})
}

// handlePairStatus handles POST /v1/agent/pair-status.
// The publisher authenticates with its high-entropy poll_id + poll_secret.
// The human display code is never accepted here — it is operator-only.
func (s *Server) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	if !s.checkPreAuth(w, r, "pair-status") {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req pairStatusReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.PollID == "" || req.PollSecret == "" {
		http.Error(w, "missing poll_id or poll_secret", http.StatusBadRequest)
		return
	}

	pr, err := s.db.GetPairingRequestByPollID(req.PollID)
	if err != nil {
		// Distinguish store faults (503) from missing rows (404) so the CLI
		// retries transient DB outages instead of treating them as expired.
		if apperr.CodeOf(err) == apperr.CodeStoreFault {
			s.log.Error("pair-status: store lookup failed", "err", errShort(err))
			http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		// Return 404 for not-found AND for wrong credentials — no oracle.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Constant-time comparison against stored verifier (prevents timing oracle).
	secretBytes, err := base64.RawURLEncoding.DecodeString(req.PollSecret)
	if err != nil || len(pr.PollVerifier) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	hash := sha256.Sum256(secretBytes)
	if subtle.ConstantTimeCompare(hash[:], pr.PollVerifier) != 1 {
		s.db.Audit("agent", "", "", "pair-status", "denied", "wrong poll secret")
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	status := pr.Status
	if status == "pending" && time.Now().After(pr.ExpiresAt) {
		status = "expired"
	}

	resp := pairStatusResp{Status: status}
	if status == "approved" {
		resp.TenantID = pr.ResolvedTenantID
		resp.KeyID = pr.KeyID
	}
	writeJSON(w, http.StatusOK, resp)
}

// ApprovePairingRequest looks up a pending pairing request by display code,
// directly enrolls the publisher's key into the specified tenant, and marks
// the request as approved. It is a narrow store operation (no Server needed).
// The operator provides the display code they see on the publisher's screen.
// If the key is already active in the same tenant, approval is idempotent;
// if the key is revoked or belongs to a different tenant, approval fails closed.
func ApprovePairingRequest(db *store.DB, displayCode, tenantID string) (keyID string, err error) {
	pr, err := db.GetPairingRequest(displayCode)
	if err != nil {
		return "", err
	}
	if pr.Status != "pending" {
		return "", apperr.E(apperr.CodeEnrollAuth, "pairing request already resolved", nil)
	}
	if time.Now().After(pr.ExpiresAt) {
		return "", apperr.E(apperr.CodeEnrollAuth, "pairing request expired", nil)
	}

	now := time.Now().UTC()
	var authErr error
	err = withTx(db.SQL(), func(tx *sql.Tx) error {
		// Validate tenant state atomically inside the approval transaction.
		if tenantID != "" {
			var tStatus string
			terr := tx.QueryRow(`SELECT status FROM tenants WHERE id=?`, tenantID).Scan(&tStatus)
			switch {
			case terr == sql.ErrNoRows:
				// New tenant will be created below.
			case terr != nil:
				return terr
			case tStatus == "suspended":
				authErr = apperr.E(apperr.CodeEnrollAuth, fmt.Sprintf("tenant %q is suspended", tenantID), nil)
				return authErr
			}
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO tenants(id, status, created_at, quotas_json) VALUES(?,?,?,?)`,
			tenantID, "active", now.Format(time.RFC3339Nano), "{}"); err != nil {
			return err
		}
		var existingTenant, existingStatus string
		kerr := tx.QueryRow(`SELECT tenant_id, status FROM agent_keys WHERE id=?`, pr.KeyID).Scan(&existingTenant, &existingStatus)
		switch {
		case kerr == sql.ErrNoRows:
			if _, err := tx.Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?,?,?)`,
				pr.KeyID, tenantID, pr.PublicKey, "active", now.Format(time.RFC3339Nano)); err != nil {
				return err
			}
		case kerr != nil:
			return kerr
		case existingStatus == "active" && existingTenant == tenantID:
			// Idempotent: key is already active in this exact tenant.
		default:
			authErr = apperr.E(apperr.CodeEnrollAuth,
				fmt.Sprintf("key %s cannot be enrolled in tenant %q (existing status=%q tenant=%q)", pr.KeyID, tenantID, existingStatus, existingTenant), nil)
			return authErr
		}
		res, err := tx.Exec(
			`UPDATE pairing_requests SET status='approved', resolved_at=?, resolved_tenant_id=?
			 WHERE display_code=? AND status='pending'`,
			now.Format(time.RFC3339Nano), tenantID, displayCode)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			authErr = apperr.E(apperr.CodeEnrollAuth, "pairing request already resolved", nil)
			return authErr
		}
		return nil
	})
	if authErr != nil {
		return "", authErr
	}
	if err != nil {
		return "", apperr.E(apperr.CodeStoreFault, "approving pairing request", err)
	}
	db.Audit("operator", tenantID, "", "pair-approve", "ok", "key enrolled key="+pr.KeyID)
	return pr.KeyID, nil
}

// isPairingUniqueConstraintError returns true when err is a SQLite UNIQUE
// constraint violation, indicating a display_code or poll_id collision.
func isPairingUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "unique constraint failed")
}

// mintPairingCode generates a 12-hex-char display code in XXXX-XXXX-XXXX format
// using crypto/rand. This is the human-readable operator display code only.
func mintPairingCode() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("CSPRNG failure: %w", err)
	}
	s := hex.EncodeToString(b) // 12 lowercase hex chars
	return fmt.Sprintf("%s-%s-%s", s[0:4], s[4:8], s[8:12]), nil
}

// mintPollCredentials generates a high-entropy poll ID and secret.
// The poll_id is used for database lookup; the poll_secret is returned to the
// publisher and never stored — only its SHA-256 hash (poll_verifier) is stored.
func mintPollCredentials() (pollID, pollSecret string, verifier []byte, err error) {
	idBuf := make([]byte, 16)
	secBuf := make([]byte, 32)
	if _, err = rand.Read(idBuf); err != nil {
		return "", "", nil, fmt.Errorf("CSPRNG failure: %w", err)
	}
	if _, err = rand.Read(secBuf); err != nil {
		return "", "", nil, fmt.Errorf("CSPRNG failure: %w", err)
	}
	pollID = base64.RawURLEncoding.EncodeToString(idBuf)
	pollSecret = base64.RawURLEncoding.EncodeToString(secBuf)
	hash := sha256.Sum256(secBuf)
	verifier = hash[:]
	return pollID, pollSecret, verifier, nil
}
