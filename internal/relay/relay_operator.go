// Operator identity administration (P0-A): DB-level key and tenant
// lifecycle used by BOTH the running Server (which additionally evicts
// live sessions post-commit) and the operator CLI (which opens the
// database directly and must never construct a Server — P0-01). The
// running relay converges on the committed durable state through
// per-request admission and its periodic supervise revalidation, so
// CLI-driven revocation terminates forwarding without a restart.
package relay

import (
	"database/sql"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/store"
)

// KeyInfo is one enrolled publisher identity for operator listing.
// Key IDs are public identifiers, never secrets.
type KeyInfo struct {
	ID        string
	TenantID  string
	Status    string
	CreatedAt string
	RevokedAt *string
}

// ListAgentKeys returns every enrolled key, newest last.
func ListAgentKeys(db *store.DB) ([]KeyInfo, error) {
	rows, err := db.SQL().Query(`SELECT id, tenant_id, status, created_at, revoked_at FROM agent_keys ORDER BY created_at`)
	if err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "listing agent keys", err)
	}
	defer rows.Close()
	var out []KeyInfo
	for rows.Next() {
		var k KeyInfo
		if err := rows.Scan(&k.ID, &k.TenantID, &k.Status, &k.CreatedAt, &k.RevokedAt); err != nil {
			return nil, apperr.E(apperr.CodeStoreFault, "reading agent key", err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "listing agent keys", err)
	}
	return out, nil
}

// RevokeAgentKeyDB marks one key revoked and terminally revokes every
// live lease it owns, tombstoning affected publications, in a single
// transaction. It performs no session eviction and no audit: the Server
// wrapper evicts post-commit and audits, as does the CLI. Lease
// revocation converges (already-terminal leases are skipped); unknown
// keys error.
func RevokeAgentKeyDB(db *store.DB, keyID string) ([]string, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var affected []string
	err := withTx(db.SQL(), func(tx *sql.Tx) error {
		ids, err := revokeAgentKeyTx(tx, keyID, now)
		if err != nil {
			return err
		}
		affected = ids
		return nil
	})
	if err != nil {
		return nil, err
	}
	return affected, nil
}

// SuspendTenantDB revokes every active key under the tenant and marks
// the tenant suspended so later enrollment and attach paths deny it.
// Keys stay revoked on unsuspend: restoring service requires explicit
// re-enrollment, never a silent resurrection of old authority.
func SuspendTenantDB(db *store.DB, tenantID string) ([]string, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var affected []string
	err := withTx(db.SQL(), func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT id FROM agent_keys WHERE tenant_id=? AND status='active'`, tenantID)
		if err != nil {
			return err
		}
		var keys []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, k)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, k := range keys {
			ids, err := revokeAgentKeyTx(tx, k, now)
			if err != nil {
				return err
			}
			affected = append(affected, ids...)
		}
		res, err := tx.Exec(`UPDATE tenants SET status='suspended' WHERE id=?`, tenantID)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return apperr.E(apperr.CodeEnrollAuth, "unknown tenant", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return affected, nil
}

// UnsuspendTenantDB re-admits a suspended tenant for future enrollment.
// Previously revoked keys are NOT restored.
func UnsuspendTenantDB(db *store.DB, tenantID string) error {
	res, err := db.SQL().Exec(`UPDATE tenants SET status='active' WHERE id=? AND status='suspended'`, tenantID)
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "unsuspending tenant", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return apperr.E(apperr.CodeEnrollAuth, "unknown or active tenant", err)
	}
	return nil
}
