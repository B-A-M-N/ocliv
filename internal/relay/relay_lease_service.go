// Lease-service operations (relay side): the durable business-state
// transitions behind the signed agent-management endpoint.
//
// handleAgentLease (relay_mgmt.go) remains a thin HTTP adapter: it parses,
// authenticates, audits, evicts, and responds. Every authoritative state
// transition below commits atomically and reports an error unless every
// effect commits; no caller may claim success otherwise (qualification
// P0). The authenticated ownership context is established once by
// agentLeaseAuth before any of these run.
package relay

import (
	"database/sql"
	"time"

	"ocliv/internal/access"
	"ocliv/internal/apperr"
	"ocliv/internal/lease"
)

// revokeVisitorCredentials revokes all visitor access tokens and browser
// sessions for leaseID and bumps token_generation in one transaction, WITHOUT
// revoking the lease itself or tombstoning publications (P0-6). Verifies
// RowsAffected == 1 on the lease update (P2).
func (s *Server) revokeVisitorCredentials(leaseID string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return withTx(s.db.SQL(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE access_tokens SET revoked_at=? WHERE lease_id=? AND revoked_at IS NULL`, now, leaseID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE visitor_sessions SET revoked_at=? WHERE lease_id=? AND revoked_at IS NULL`, now, leaseID); err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE leases SET token_generation = token_generation + 1 WHERE id=?`, leaseID)
		if err != nil {
			return err
		}
		if n, rerr := res.RowsAffected(); rerr != nil || n != 1 {
			return apperr.E(apperr.CodeUnknownHost, "lease no longer exists during visitor credential revoke", rerr)
		}
		return nil
	})
}

// revokeLease applies the full terminal revocation transition atomically:
// visitor credentials revoked, token generation bumped, lease marked
// REVOKED so no later resume can re-activate it and the router denies new
// traffic including public-mode requests (P0-02, C10, B09). It reports an
// error unless every effect commits; callers must not claim success
// otherwise (qualification P0).
func (s *Server) revokeLease(leaseID string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return withTx(s.db.SQL(), func(tx *sql.Tx) error {
		return revokeLeaseTx(tx, leaseID, now)
	})
}

// revokeLeaseTx is the transaction-capable lease revocation core shared
// by single-lease revocation and operator key/tenant revocation (P0-A):
// one tx can terminally revoke many leases plus their publications
// without interleaved partial commits.
func revokeLeaseTx(tx *sql.Tx, leaseID, now string) error {
	if _, err := tx.Exec(`UPDATE access_tokens SET revoked_at=? WHERE lease_id=? AND revoked_at IS NULL`, now, leaseID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE visitor_sessions SET revoked_at=? WHERE lease_id=? AND revoked_at IS NULL`, now, leaseID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE leases SET token_generation=token_generation+1 WHERE id=?`, leaseID); err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE leases SET status=? WHERE id=?`, lease.StateRevoked, leaseID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return apperr.E(apperr.CodeStoreFault, "revoke affected no lease", err)
	}
	// Tombstone the lease's publications (P1-A): the stable route
	// is permanently denied and can never rebind, distinguishing
	// revocation from intentional shutdown (whose route DELETE
	// removes the row) and from ordinary restart (rebind allowed).
	if _, err := tx.Exec(`UPDATE mcp_publications SET revoked_at=?, updated_at=? WHERE lease_id=? AND revoked_at IS NULL`,
		now, now, leaseID); err != nil {
		return apperr.E(apperr.CodeStoreFault, "revoking publications", err)
	}
	return nil
}

// revokeAgentKeyTx marks one key revoked and terminally revokes every
// live lease it owns, returning the affected lease IDs for post-commit
// session eviction. Already-revoked leases are skipped (convergent:
// repeated operator revocation is a safe no-op, never an error).
func revokeAgentKeyTx(tx *sql.Tx, keyID, now string) ([]string, error) {
	rows, err := tx.Query(`SELECT id FROM leases WHERE agent_key_id=? AND status IN (?,?)`,
		keyID, lease.StateActive, lease.StateReconnecting)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		if err := revokeLeaseTx(tx, id, now); err != nil {
			return nil, err
		}
	}
	// P1-3: tombstone ALL publications owned by this key (including those on
	// already-closed/detached leases) so revoking an identity retires all
	// durable authority owned by it.
	if _, err := tx.Exec(
		`UPDATE mcp_publications SET revoked_at=?, updated_at=? WHERE owner_key_id=? AND revoked_at IS NULL`,
		now, now, keyID); err != nil {
		return nil, err
	}
	res, err := tx.Exec(`UPDATE agent_keys SET status='revoked', revoked_at=? WHERE id=?`, now, keyID)
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return nil, apperr.E(apperr.CodeEnrollAuth, "unknown agent key", err)
	}
	return ids, nil
}

// RevokeAgentKey is the operator key-revocation primitive (P0-A).
func (s *Server) RevokeAgentKey(keyID, reason string) ([]string, error) {
	return s.RevokeAgentKeyAs(keyID, "operator", reason)
}

// RevokeAgentKeyAs executes the full transactional key-revocation primitive
// and audits with the caller's actual actor identity ("operator" or "agent",
// P1-2) so self-logout never fabricates an operator audit entry.
func (s *Server) RevokeAgentKeyAs(keyID, actor, reason string) ([]string, error) {
	affected, err := RevokeAgentKeyDB(s.db, keyID)
	if err != nil {
		return nil, err
	}
	for _, id := range affected {
		s.evictLease(id)
	}
	s.db.Audit(actor, "", keyID, "agent_key_revoke", "ok", reason)
	return affected, nil
}

// SuspendTenant revokes every key under the tenant and marks the tenant
// suspended so later enrollment and attach paths deny it (P0-A). Keys
// stay revoked on unsuspend: restoring service requires explicit
// re-enrollment, never a silent resurrection of old authority.
func (s *Server) SuspendTenant(tenantID, reason string) error {
	affected, err := SuspendTenantDB(s.db, tenantID)
	if err != nil {
		return err
	}
	for _, id := range affected {
		s.evictLease(id)
	}
	s.db.Audit("operator", tenantID, "", "tenant_suspend", "ok", reason)
	return nil
}

// UnsuspendTenant re-admits a suspended tenant for future enrollment.
// Previously revoked keys are NOT restored; the operator must re-enroll
// affected publishers explicitly (P0-A).
func (s *Server) UnsuspendTenant(tenantID, reason string) error {
	if err := UnsuspendTenantDB(s.db, tenantID); err != nil {
		return err
	}
	s.db.Audit("operator", tenantID, "", "tenant_unsuspend", "ok", reason)
	return nil
}

// issueShareToken mints one single-redeem visitor token for an owned
// lease. The raw secret is returned for delivery to the owning agent only.
func (s *Server) issueShareToken(leaseID string) (string, error) {
	return s.newAccessToken(leaseID, "visitor", 1, access.ShareLinkTTL)
}

// rotateCredentials atomically revokes prior visitor credentials and
// mints the replacement token in one transaction: rotation never leaves
// a lease tokenless, and a commit failure revokes nothing. The secret is
// prepared before the transaction (no DB side effect) and must be
// disclosed only after a successful commit.
func (s *Server) rotateCredentials(leaseID string) (string, error) {
	raw, row, err := prepareAccessToken("visitor", 0, 0)
	if err != nil {
		return "", err
	}
	err = withTx(s.db.SQL(), func(tx *sql.Tx) error {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := tx.Exec(`UPDATE access_tokens SET revoked_at=? WHERE lease_id=? AND revoked_at IS NULL`,
			now, leaseID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE visitor_sessions SET revoked_at=? WHERE lease_id=? AND revoked_at IS NULL`,
			now, leaseID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE leases SET token_generation=token_generation+1 WHERE id=?`, leaseID); err != nil {
			return err
		}
		return insertAccessTokenRow(tx, leaseID, "visitor", 0, row)
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

// closeLeaseDurable transitions an owned lease to closed. The caller
// evicts the live session and audits after a successful return.
func (s *Server) closeLeaseDurable(leaseID string) error {
	if _, err := s.db.SQL().Exec(`UPDATE leases SET status=? WHERE id=?`, lease.StateClosed, leaseID); err != nil {
		return apperr.E(apperr.CodeStoreFault, "closing lease", err)
	}
	return nil
}
