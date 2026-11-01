package relay

import (
	"crypto/ed25519"
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

type enrollReq struct {
	Code      string `json:"code"`
	PublicKey string `json:"public_key"` // base64 ed25519
}

type enrollResp struct {
	KeyID    string `json:"key_id"`
	TenantID string `json:"tenant_id"`
}

// handleEnroll exchanges a one-time enrollment code for key registration.
// Unauthenticated public enrollment is prohibited (B05).
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.checkPreAuth(w, r, "enroll") {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req enrollReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rawPub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(rawPub) != ed25519.PublicKeySize {
		http.Error(w, "bad public key", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(rawPub)
	keyID := hex.EncodeToString(sum[:identity.KeyIDBytes])
	now := time.Now().UTC()
	var tenantID string
	err = withTx(s.db.SQL(), func(tx *sql.Tx) error {
		// Find the matching code by verifier comparison.
		rows, err := tx.Query(`SELECT id, verifier, tenant_id, expires_at, used_at FROM enrollment_codes WHERE used_at IS NULL`)
		if err != nil {
			return err
		}
		defer rows.Close()
		var matchedID, matchedTenant string
		for rows.Next() {
			var cid, cv, ct, ce string
			var cu sql.NullString
			if err := rows.Scan(&cid, &cv, &ct, &ce, &cu); err != nil {
				return err
			}
			if cu.Valid {
				continue
			}
			exp, err := time.Parse(time.RFC3339Nano, ce)
			if err != nil || now.After(exp) {
				continue
			}
			if identity.VerifyEnrollmentCode(req.Code, cv) {
				matchedID, matchedTenant = cid, ct
				break
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if matchedID == "" {
			return apperr.E(apperr.CodeEnrollAuth, "invalid or expired enrollment code", nil)
		}
		if _, err := tx.Exec(`UPDATE enrollment_codes SET used_at=? WHERE id=?`, now.Format(time.RFC3339Nano), matchedID); err != nil {
			return err
		}
		tenantID = matchedTenant
		kid := "key-" + keyID
		if _, err := tx.Exec(`INSERT OR IGNORE INTO tenants(id, status, created_at) VALUES(?,?,?)`,
			tenantID, "active", now.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?,?,?)`,
			kid, tenantID, rawPub, "active", now.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		var ae *apperr.Error
		if ok := asApperr(err, &ae); ok && ae.Code == apperr.CodeEnrollAuth {
			s.db.Audit("agent", "", "", "enrollment", "denied", "code rejected")
			http.Error(w, "enrollment denied", http.StatusUnauthorized)
			return
		}
		s.log.Error("enroll failed", "err", errShort(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.db.Audit("agent", tenantID, "", "enrollment", "ok", "key enrolled")
	writeJSON(w, http.StatusOK, enrollResp{KeyID: "key-" + keyID, TenantID: tenantID})
}

// IssueEnrollment mints a one-time operator enrollment grant (B05).
// Operator-authenticated endpoint in production; here guarded by the fact
// that only the internal/admin listener exposes it (H01).
// IssueEnrollmentCode mints a one-time operator enrollment grant (B05).
// It is a narrow store operation, NOT a relay instance method: building a
// *Server runs reconcileBoot, which mutates unrelated live lease rows.
// The operator enroll path must never construct a Server (P0-01).
func IssueEnrollmentCode(db *store.DB, tenantID string, ttl time.Duration, issuedBy string) (string, error) {
	code, verifier, err := identity.MintEnrollmentCode()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	id := fmt.Sprintf("enr-%d", now.UnixNano())
	if tenantID == "" {
		tenantID = "tenant-" + id
	}
	_, err = db.SQL().Exec(
		`INSERT INTO enrollment_codes(id, verifier, tenant_id, expires_at, issued_by) VALUES(?,?,?,?,?)`,
		id, verifier, tenantID, now.Add(ttl).Format(time.RFC3339Nano), issuedBy)
	if err != nil {
		return "", apperr.E(apperr.CodeStoreFault, "storing enrollment code", err)
	}
	db.Audit(issuedBy, tenantID, "", "enrollment_issue", "ok", "code issued")
	return code, nil
}
