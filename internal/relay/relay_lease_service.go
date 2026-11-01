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

// revokeLease applies the full terminal revocation transition atomically:
// visitor credentials revoked, token generation bumped, lease marked
// REVOKED so no later resume can re-activate it and the router denies new
// traffic including public-mode requests (P0-02, C10, B09). It reports an
// error unless every effect commits; callers must not claim success
// otherwise (qualification P0).
func (s *Server) revokeLease(leaseID string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return withTx(s.db.SQL(), func(tx *sql.Tx) error {
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
		return nil
	})
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
