// Signed agent key lifecycle: atomic key rotation with ownership transfer,
// proof-of-possession, and live session fencing (P0-3/P0-4/P1-13), plus full
// transactional self-revocation for remote-first logout (P0-1/P1-14).
package relay

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ocliv/internal/identity"
)

// handleAgentKeyRotate atomically enrolls a replacement Ed25519 public key
// under the caller's tenant, transfers ownership of all leases and MCP
// publications from the old key to the new key, revokes the old key in a
// single SQLite transaction, and immediately evicts live sessions authenticated
// under the old key.
//
// Requires body-bound ocliv-mgmt-v2 signature from the old key AND a
// proof-of-possession signature (new_key_proof) from the replacement key
// bound to the management nonce.
func (s *Server) handleAgentKeyRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, oldKeyID, ok := s.agentKeyAuth(r)
	if !ok {
		s.db.Audit("agent", "", "", "key_rotate", "denied", "auth failed")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	nonce := strings.TrimSpace(r.Header.Get("X-Ocliv-Nonce"))
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		NewPublicKey string `json:"new_public_key"`
		NewKeyProof  string `json:"new_key_proof"`
	}
	if err := json.Unmarshal(rawBody, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	newPub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.NewPublicKey))
	if err != nil || len(newPub) != ed25519.PublicKeySize {
		http.Error(w, "invalid new_public_key", http.StatusBadRequest)
		return
	}
	newKeyID := "key-" + string(identity.KeyIDFor(ed25519.PublicKey(newPub)))
	if newKeyID == oldKeyID {
		http.Error(w, "new key must differ from current key", http.StatusBadRequest)
		return
	}
	// Proof of possession (P0-4): the replacement private key must sign
	// (old_key_id, new_key_id, nonce) so an old key cannot transfer ownership
	// to an unowned or mistyped public key.
	proofSig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.NewKeyProof))
	if err != nil || len(proofSig) != ed25519.SignatureSize {
		s.db.AuditKey("agent", tenant, oldKeyID, "", "key_rotate", "denied", "missing or malformed new_key_proof")
		http.Error(w, "missing or invalid new_key_proof", http.StatusBadRequest)
		return
	}
	proofMsg := []byte(fmt.Sprintf("ocliv-key-rotation-v1\n%s\n%s\n%s", oldKeyID, newKeyID, nonce))
	if !ed25519.Verify(ed25519.PublicKey(newPub), proofMsg, proofSig) {
		s.db.AuditKey("agent", tenant, oldKeyID, "", "key_rotate", "denied", "invalid new_key_proof signature")
		http.Error(w, "invalid new_key_proof", http.StatusForbidden)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	var leasesMoved, pubsMoved int64
	var transferredLeaseIDs []string
	err = withTx(s.db.SQL(), func(tx *sql.Tx) error {
		var curStatus string
		if err := tx.QueryRow(`SELECT status FROM agent_keys WHERE id=? AND tenant_id=?`, oldKeyID, tenant).Scan(&curStatus); err != nil {
			return fmt.Errorf("old key not found")
		}
		if curStatus != "active" {
			return fmt.Errorf("old key is not active")
		}
		rows, err := tx.Query(`SELECT id FROM leases WHERE tenant_id=? AND agent_key_id=?`, tenant, oldKeyID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var lid string
			if err := rows.Scan(&lid); err != nil {
				rows.Close()
				return err
			}
			transferredLeaseIDs = append(transferredLeaseIDs, lid)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if _, err := tx.Exec(
			`INSERT INTO agent_keys(id, tenant_id, ed25519_public, status, created_at) VALUES(?,?,?,?,?)`,
			newKeyID, tenant, newPub, "active", now,
		); err != nil {
			return err
		}
		if res, err := tx.Exec(
			`UPDATE leases SET agent_key_id=? WHERE tenant_id=? AND agent_key_id=?`,
			newKeyID, tenant, oldKeyID,
		); err != nil {
			return err
		} else if n, _ := res.RowsAffected(); n > 0 {
			leasesMoved = n
		}
		if res, err := tx.Exec(
			`UPDATE mcp_publications SET owner_key_id=?, updated_at=? WHERE tenant_id=? AND owner_key_id=?`,
			newKeyID, now, tenant, oldKeyID,
		); err != nil {
			return err
		} else if n, _ := res.RowsAffected(); n > 0 {
			pubsMoved = n
		}
		if _, err := tx.Exec(
			`UPDATE agent_keys SET status='revoked', revoked_at=? WHERE id=? AND tenant_id=?`,
			now, oldKeyID, tenant,
		); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		s.db.AuditKey("agent", tenant, oldKeyID, "", "key_rotate", "denied", errShort(err))
		http.Error(w, "key rotation failed: "+errShort(err), http.StatusConflict)
		return
	}
	// Fence all transferred leases immediately (P0-3): sessions authenticated
	// under the revoked old key must never remain active after ownership transfer.
	for _, lid := range transferredLeaseIDs {
		s.evictLease(lid)
	}
	s.db.AuditKey("agent", tenant, newKeyID, "", "key_rotate", "ok",
		fmt.Sprintf("rotated from %s (leases=%d pubs=%d evicted=%d)", oldKeyID, leasesMoved, pubsMoved, len(transferredLeaseIDs)))
	writeJSON(w, http.StatusOK, map[string]any{
		"old_key_id":               oldKeyID,
		"new_key_id":               newKeyID,
		"tenant_id":                tenant,
		"leases_transferred":       leasesMoved,
		"publications_transferred": pubsMoved,
	})
}

// handleAgentKeyRevoke revokes the authenticated agent's key AND all of its
// live authority (ACTIVE/RECONNECTING leases, visitor credentials, publications,
// and live yamux sessions) using the exact same transactional primitive as
// operator key revocation (P0-1/P1-14).
func (s *Server) handleAgentKeyRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, keyID, ok := s.agentKeyAuth(r)
	if !ok {
		s.db.Audit("agent", "", "", "key_self_revoke", "denied", "auth failed")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	affected, err := s.RevokeAgentKeyAs(keyID, "agent", "self-revoked on logout")
	if err != nil {
		s.db.AuditKey("agent", tenant, keyID, "", "key_self_revoke", "error", errShort(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.db.AuditKey("agent", tenant, keyID, "", "key_self_revoke", "ok",
		fmt.Sprintf("self-revoked on logout (revoked_leases=%d)", len(affected)))
	writeJSON(w, http.StatusOK, map[string]any{
		"key_id":         keyID,
		"revoked":        true,
		"revoked_leases": len(affected),
	})
}
