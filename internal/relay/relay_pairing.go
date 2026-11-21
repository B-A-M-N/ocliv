package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/identity"
	"ocliv/internal/store"
)

const (
	pairingTTL        = 10 * time.Minute
	pairingRateLimit  = 5                // max pending per IP per window
	pairingRateWindow = 10 * time.Minute // window for rate limiting
)

type pairRequestBody struct {
	PublicKey string `json:"public_key"` // base64 std ed25519 public key
}

type pairRequestResp struct {
	PairingCode      string `json:"pairing_code"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

type pairStatusResp struct {
	Status   string `json:"status"`
	TenantID string `json:"tenant_id,omitempty"` // set when approved
	KeyID    string `json:"key_id,omitempty"`    // set when approved
}

// handlePairRequest handles POST /v1/agent/pair-request.
// Publisher submits its public key; relay stores a pending pairing request
// and returns a short human-readable display code for the operator to approve.
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

	displayCode, err := mintPairingCode()
	if err != nil {
		s.log.Error("pair-request: mint code failed", "err", errShort(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	id := fmt.Sprintf("pair-%d", now.UnixNano())

	if err := s.db.CreatePairingRequest(id, displayCode, rawPub, keyID, sourceIP, now.Add(pairingTTL)); err != nil {
		s.log.Error("pair-request: store failed", "err", errShort(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.db.Audit("agent", "", "", "pair-request", "ok", "created key="+keyID)
	writeJSON(w, http.StatusOK, pairRequestResp{
		PairingCode:      displayCode,
		ExpiresInSeconds: int(pairingTTL.Seconds()),
	})
}

// handlePairStatus handles GET /v1/agent/pair-status?code=XXXX-XXXX-XXXX.
// Returns the current status and, when approved, the tenant and key IDs.
func (s *Server) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	if !s.checkPreAuth(w, r, "pair-status") {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code parameter", http.StatusBadRequest)
		return
	}

	pr, err := s.db.GetPairingRequest(code)
	if err != nil {
		var ae *apperr.Error
		if asApperr(err, &ae) && ae.Code == apperr.CodeEnrollAuth {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.log.Error("pair-status: lookup failed", "err", errShort(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	status := pr.Status
	if status == "pending" && time.Now().After(pr.ExpiresAt) {
		status = "expired"
	}

	resp := pairStatusResp{Status: status}

	if status == "approved" {
		// Return the tenant and key so the publisher can finalize local config.
		resp.TenantID = pr.EnrollmentCodeID // repurposed: holds tenant_id after approval
		resp.KeyID = pr.KeyID
	}

	writeJSON(w, http.StatusOK, resp)
}

// ApprovePairingRequest looks up a pending pairing request by display code,
// directly enrolls the publisher's key into the specified tenant, and marks
// the request as approved. It is a narrow store operation (no Server needed).
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

	// Suspended tenants cannot receive new publishers (same gate as enrollment).
	if tenantID != "" {
		var tst string
		if err := db.SQL().QueryRow(`SELECT status FROM tenants WHERE id=?`, tenantID).Scan(&tst); err == nil && tst == "suspended" {
			return "", apperr.E(apperr.CodeEnrollAuth, "tenant suspended", nil)
		}
	}

	now := time.Now().UTC()
	err = withTx(db.SQL(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO tenants(id, status, created_at, quotas_json) VALUES(?,?,?,?)`,
			tenantID, "active", now.Format(time.RFC3339Nano), "{}"); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?,?,?)`,
			pr.KeyID, tenantID, pr.PublicKey, "active", now.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		// EnrollmentCodeID is repurposed to hold the tenant_id for status polling.
		if _, err := tx.Exec(
			`UPDATE pairing_requests SET status='approved', resolved_at=?, enrollment_code_id=?
			 WHERE display_code=? AND status='pending'`,
			now.Format(time.RFC3339Nano), tenantID, displayCode); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return "", apperr.E(apperr.CodeStoreFault, "approving pairing request", err)
	}
	db.Audit("operator", tenantID, "", "pair-approve", "ok", "key enrolled key="+pr.KeyID)
	return pr.KeyID, nil
}

// mintPairingCode generates a 12-hex-char display code in XXXX-XXXX-XXXX format
// using crypto/rand.
func mintPairingCode() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("CSPRNG failure: %w", err)
	}
	s := hex.EncodeToString(b) // 12 lowercase hex chars
	return fmt.Sprintf("%s-%s-%s", s[0:4], s[4:8], s[8:12]), nil
}
