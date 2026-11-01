// Offline snapshot and restore with revocation-rollback refusal (P0-E).
//
// SQLite is the authority for identity and revocation, so restoring an
// older snapshot can resurrect revoked keys, leases, and publications.
// Restore therefore never silently rolls authority backward:
//
//   - Backup is a consistent snapshot (VACUUM INTO) written atomically
//     with owner-only permissions.
//   - Validate opens a scratch copy through store.Open: unknown-newer
//     schemas fail closed, older schemas migrate forward, and
//     integrity_check must pass.
//   - Restore compares revocation sets: every key/tenant/lease/
//     publication revoked in the live database must already be revoked
//     (or absent only by intentional deletion) in the backup;
//     otherwise restore refuses and names the rollback.
//   - --reset-authority is the explicit escape hatch: install the
//     backup, then terminally revoke every key, lease, and
//     publication in it, so nothing restored is trusted until the
//     operator re-enrolls. The reset itself is audited.
//
// Restore is an offline operation: stop the relay first, restore, then
// start. The install is an atomic rename plus fsync; a running relay
// keeps its open handle until restart (documented in OPERATOR.md).
package relay

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/lease"
	"ocliv/internal/store"

	_ "modernc.org/sqlite"
)

// relayDBName is the single state file inside a relay data directory.
const relayDBName = "ocliv.db"

// BackupState writes a consistent snapshot of db to destPath atomically:
// VACUUM INTO a temp file (VACUUM INTO refuses an existing target),
// owner-only permissions, then rename over the destination.
func BackupState(db *store.DB, destPath string) error {
	if destPath == "" {
		return apperr.E(apperr.CodeCLIValidation, "backup destination required", nil)
	}
	tmp := destPath + ".tmp"
	_ = os.Remove(tmp)
	if _, err := db.SQL().Exec(`VACUUM INTO ?`, tmp); err != nil {
		return apperr.E(apperr.CodeStoreFault, "snapshotting state database", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return apperr.E(apperr.CodeStoreFault, "securing backup file", err)
	}
	if err := os.Rename(tmp, destPath); err != nil {
		_ = os.Remove(tmp)
		return apperr.E(apperr.CodeStoreFault, "installing backup file", err)
	}
	dirSync(filepath.Dir(destPath))
	return nil
}

// revocationSet is the security-relevant truth that must never roll
// backward across a restore. Beyond explicit revocations it covers
// every terminal lease state (P0-B): a CLOSED or EXPIRED lease must
// never read ACTIVE again, a rotated token_generation must never
// step back (that would revalidate rotated-out credentials), and an
// explicitly deleted publication must never reappear.
type revocationSet struct {
	keys    map[string]bool // agent_keys with status='revoked'
	tenants map[string]bool // tenants with status<>'active'
	leases  map[string]bool // leases with status=REVOKED
	pubs    map[string]bool // mcp_publications with revoked_at set
	// leaseTerminal maps every terminal lease (REVOKED/CLOSED/EXPIRED)
	// to its status. A terminal lease must stay terminal across a
	// restore; absence in the backup is also a rollback (the row's
	// terminality would be forgotten, freeing the hostname for a
	// fresh allocation under the same identity).
	leaseTerminal map[string]string
	// leaseTokGen maps every live lease to its token_generation.
	// Rotation and revocation are the only bumpers, so any step
	// back revalidates distrusted credentials and is refused.
	leaseTokGen map[string]int64
	// tokens/sessions are explicitly revoked capability rows.
	tokens   map[string]bool
	sessions map[string]bool
	// pubIDs is every publication route_id present. A backup row
	// (active or tombstoned) absent from live means the publication
	// was explicitly deleted after the snapshot — restoring would
	// resurrect it. Guarded by live-table existence: a live database
	// predating publications cannot distinguish deletion.
	pubIDs     map[string]bool
	pubsListed bool
}

func collectStrings(q *sql.DB, query string) (map[string]bool, error) {
	rows, err := q.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// readRevocations extracts the revocation set from an open database.
func readRevocations(q *sql.DB) (*revocationSet, error) {
	s := &revocationSet{}
	var err error
	if s.keys, err = collectStrings(q, `SELECT id FROM agent_keys WHERE status='revoked'`); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading key revocations", err)
	}
	if s.tenants, err = collectStrings(q, `SELECT id FROM tenants WHERE status<>'active'`); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading tenant suspensions", err)
	}
	if s.leases, err = collectStrings(q, `SELECT id FROM leases WHERE status='`+lease.StateRevoked+`'`); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading lease revocations", err)
	}
	// Every terminal lease state (P0-B): REVOKED, CLOSED, EXPIRED.
	s.leaseTerminal = map[string]string{}
	rows, err := q.Query(`SELECT id, status FROM leases WHERE status IN (?,?,?)`,
		lease.StateRevoked, lease.StateClosed, lease.StateExpired)
	if err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading terminal leases", err)
	}
	for rows.Next() {
		var id, st string
		if err := rows.Scan(&id, &st); err != nil {
			rows.Close()
			return nil, apperr.E(apperr.CodeStoreFault, "reading terminal leases", err)
		}
		s.leaseTerminal[id] = st
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading terminal leases", err)
	}
	// Token generations for every lease (P0-B): rotation and
	// revocation are the only bumpers.
	s.leaseTokGen = map[string]int64{}
	trows, err := q.Query(`SELECT id, token_generation FROM leases`)
	if err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading token generations", err)
	}
	for trows.Next() {
		var id string
		var g int64
		if err := trows.Scan(&id, &g); err != nil {
			trows.Close()
			return nil, apperr.E(apperr.CodeStoreFault, "reading token generations", err)
		}
		s.leaseTokGen[id] = g
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading token generations", err)
	}
	if s.tokens, err = collectStrings(q, `SELECT id FROM access_tokens WHERE revoked_at IS NOT NULL`); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading token revocations", err)
	}
	if s.sessions, err = collectStrings(q, `SELECT id FROM visitor_sessions WHERE revoked_at IS NOT NULL`); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading session revocations", err)
	}
	var pubTable string
	if err := q.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_publications'`).Scan(&pubTable); err == nil && pubTable != "" {
		if s.pubs, err = collectStrings(q, `SELECT route_id FROM mcp_publications WHERE revoked_at IS NOT NULL`); err != nil {
			return nil, apperr.E(apperr.CodeStoreFault, "reading publication tombstones", err)
		}
		if s.pubIDs, err = collectStrings(q, `SELECT route_id FROM mcp_publications`); err != nil {
			return nil, apperr.E(apperr.CodeStoreFault, "reading publication ids", err)
		}
		s.pubsListed = true
	} else {
		// Pre-publication databases have no such table: empty set.
		s.pubs = map[string]bool{}
		s.pubIDs = map[string]bool{}
	}
	return s, nil
}

// isTerminalLease reports whether a lease status is terminal: it must
// never become active again through a restore.
func isTerminalLease(st string) bool {
	return st == lease.StateRevoked || st == lease.StateClosed || st == lease.StateExpired
}

// rollbackDiff lists live-revoked IDs missing from the backup set: a
// restore would resurrect them.
func rollbackDiff(live, backup *revocationSet) []string {
	var missing []string
	for id := range live.keys {
		if !backup.keys[id] {
			missing = append(missing, "key:"+id)
		}
	}
	for id := range live.tenants {
		if !backup.tenants[id] {
			missing = append(missing, "tenant:"+id)
		}
	}
	for id := range live.leases {
		if !backup.leases[id] {
			missing = append(missing, "lease:"+id)
		}
	}
	for id := range live.pubs {
		if !backup.pubs[id] {
			missing = append(missing, "publication:"+id)
		}
	}
	// Terminal leases (P0-B) stay terminal: a live CLOSED/EXPIRED/
	// REVOKED lease that reads non-terminal — or is simply absent —
	// in the backup would come back to life. REVOKED is already
	// covered above; the loop skips it to avoid duplicate reasons.
	for id, st := range live.leaseTerminal {
		if st == lease.StateRevoked {
			continue
		}
		if bs, ok := backup.leaseTerminal[id]; !ok || !isTerminalLease(bs) {
			missing = append(missing, "lease-terminal:"+id)
		}
	}
	// Token generations never step back (P0-B): rotation and
	// revocation are the only bumpers, so a lower backup generation
	// would revalidate rotated-out credentials. Rows absent from the
	// backup are forward data loss (operator's explicit act), not
	// resurrection — except live-terminal rows, caught above. The
	// comparison assumes the live database is the newer side (the
	// same direction the revocation checks assume): only a step
	// back refuses.
	for id, g := range live.leaseTokGen {
		if bg, ok := backup.leaseTokGen[id]; ok && bg < g {
			missing = append(missing, "token-generation:"+id)
		}
	}
	for id := range live.tokens {
		if !backup.tokens[id] {
			missing = append(missing, "token:"+id)
		}
	}
	for id := range live.sessions {
		if !backup.sessions[id] {
			missing = append(missing, "session:"+id)
		}
	}
	// Deleted publications (P0-B): a backup row whose route_id is
	// entirely absent from live was explicitly unpublished after the
	// snapshot — restoring would resurrect it. Skipped when the live
	// database predates publications (indistinguishable from an
	// upgrade restore).
	if live.pubsListed {
		for id := range backup.pubIDs {
			if !backup.pubs[id] && !live.pubIDs[id] && !live.pubs[id] {
				missing = append(missing, "publication-deleted:"+id)
			}
		}
	}
	return missing
}

// ValidateBackup proves a backup file is restorable without touching it:
// copy to scratch, open through store.Open (unknown-newer schemas fail
// closed, older ones migrate forward in the copy only), and require a
// clean integrity_check.
func ValidateBackup(backupPath string) error {
	fi, err := os.Stat(backupPath)
	if err != nil || fi.IsDir() {
		return apperr.E(apperr.CodeCLIValidation, "backup file not readable", err)
	}
	scratch, err := os.MkdirTemp("", "ocliv-validate-")
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "creating scratch directory", err)
	}
	defer os.RemoveAll(scratch)
	candidate := filepath.Join(scratch, relayDBName)
	if err := copyFile(backupPath, candidate); err != nil {
		return apperr.E(apperr.CodeStoreFault, "copying backup for validation", err)
	}
	db, err := store.Open(candidate)
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "backup schema not restorable", err)
	}
	defer db.Close()
	var check string
	if err := db.SQL().QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		return apperr.E(apperr.CodeStoreFault, fmt.Sprintf("backup integrity check: %q", check), err)
	}
	return nil
}

// sameFile reports whether two paths name the same file. A missing
// destination is never "same": a first-time restore installs fresh.
func sameFile(a, b string) (bool, error) {
	fa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	fb, err := os.Stat(b)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return os.SameFile(fa, fb), nil
}

// dirSync flushes directory metadata so a preceding rename is durable
// before success is reported. Best-effort on filesystems without
// directory fsync; the file-level fsyncs in copyFile/installValidated
// already protect content.
func dirSync(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, 1<<20)
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return rerr
		}
	}
	return out.Sync()
}

// RestoreState validates backupPath, refuses revocation rollback unless
// resetAuthority is set, installs the backup atomically over the data
// directory database, and records the restore in the new database's
// audit log. resetAuthority additionally revokes every key, lease, and
// publication in the restored copy: nothing restored is trusted until
// the operator re-enrolls.
//
// Offline discipline: relayStopped must be true — the operator attests
// the relay is stopped (the CLI requires --relay-stopped). As a
// tripwire, restore additionally refuses when an active writer holds
// the live database. Neither proves an idle relay is stopped: a running
// relay keeps its open handle on the pre-restore inode until restart,
// so the restored image takes effect at the next start. Stop the relay
// first; restore; start the relay.
func RestoreState(dataDir, backupPath string, resetAuthority, relayStopped bool) error {
	if !relayStopped {
		return apperr.E(apperr.CodeCLIValidation,
			"refusing online restore: stop the relay first (systemctl stop ocliv-relay), then re-run with --relay-stopped", nil)
	}
	if err := ValidateBackup(backupPath); err != nil {
		return err
	}
	livePath := filepath.Join(dataDir, relayDBName)
	// A symlinked data directory would install the database somewhere
	// the operator did not audit (P0-B filesystem safety).
	if fi, serr := os.Lstat(dataDir); serr != nil {
		return apperr.E(apperr.CodeStoreFault, "restore target unreachable", serr)
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return apperr.E(apperr.CodeStoreFault, "refusing to restore into a symlinked data directory", nil)
	}
	// Installing a file onto itself would truncate the very snapshot
	// being validated, destroying both sides (P0-B same-path safety).
	if same, serr := sameFile(backupPath, livePath); serr != nil {
		return apperr.E(apperr.CodeStoreFault, "restore source unreachable", serr)
	} else if same {
		return apperr.E(apperr.CodeStoreFault, "refusing to restore a database onto itself", nil)
	}
	if active, derr := liveWriterActive(livePath); derr != nil {
		return derr
	} else if active {
		return apperr.E(apperr.CodeStoreFault,
			"live database has an active writer: the relay may still be running; stop it and retry", nil)
	}
	live, err := openRevocations(livePath)
	if err != nil {
		return err
	}
	scratch, err := os.MkdirTemp("", "ocliv-restore-")
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "creating scratch directory", err)
	}
	defer os.RemoveAll(scratch)
	candidate := filepath.Join(scratch, relayDBName)
	if err := copyFile(backupPath, candidate); err != nil {
		return apperr.E(apperr.CodeStoreFault, "copying backup for restore", err)
	}
	candDB, err := store.Open(candidate)
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "backup schema not restorable", err)
	}
	backup, err := readRevocations(candDB.SQL())
	candDB.Close()
	if err != nil {
		return err
	}
	if live != nil {
		if missing := rollbackDiff(live, backup); len(missing) > 0 && !resetAuthority {
			return apperr.E(apperr.CodeStoreFault,
				fmt.Sprintf("restore would resurrect %d revoked identities/capabilities (%s ...); re-backup, revoke in the backup first, or pass --reset-authority",
					len(missing), missing[0]), nil)
		}
	}
	if resetAuthority {
		if err := resetRestoredAuthority(candidate); err != nil {
			return err
		}
	}
	if err := installValidated(candidate, filepath.Join(dataDir, relayDBName)); err != nil {
		return err
	}
	// Audit the restore in the installed database.
	db, err := store.Open(filepath.Join(dataDir, relayDBName))
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "reopening restored database", err)
	}
	defer db.Close()
	mode := "restore"
	if resetAuthority {
		mode = "restore+reset-authority"
	}
	db.Audit("operator", "", "", mode, "ok", "restored from "+backupPath)
	return nil
}

// liveWriterActive reports whether the live database currently has an
// active writer transaction. It opens a dedicated connection with a
// bounded busy timeout and attempts BEGIN IMMEDIATE: success means no
// writer is active right now. A missing database means no writer.
// Any other failure fails closed (unknown liveness refuses restore).
// This is a tripwire, not proof of stopped: an idle-but-running relay
// passes it, which is why operator attestation is also required.
func liveWriterActive(livePath string) (bool, error) {
	if _, err := os.Stat(livePath); os.IsNotExist(err) {
		return false, nil
	}
	probe, err := sql.Open("sqlite", livePath)
	if err != nil {
		return false, apperr.E(apperr.CodeStoreFault, "probing live database liveness", err)
	}
	defer probe.Close()
	if _, err := probe.Exec(`PRAGMA busy_timeout=3000`); err != nil {
		return false, apperr.E(apperr.CodeStoreFault, "probing live database liveness", err)
	}
	if _, err := probe.Exec(`BEGIN IMMEDIATE`); err != nil {
		// A busy database has an active writer (or reader blocking
		// upgrade): treat as live.
		return true, nil
	}
	_, _ = probe.Exec(`ROLLBACK`)
	return false, nil
}

// openRevocations reads the live revocation set, or nil when no live
// database exists yet (fresh install: nothing to roll back).
func openRevocations(livePath string) (*revocationSet, error) {
	if _, err := os.Stat(livePath); os.IsNotExist(err) {
		return nil, nil
	}
	db, err := store.Open(livePath)
	if err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "opening live database", err)
	}
	defer db.Close()
	return readRevocations(db.SQL())
}

// resetRestoredAuthority terminally revokes every key, lease, token,
// session, and publication in an offline database copy. The operator
// must re-enroll; nothing restored is usable.
func resetRestoredAuthority(candidatePath string) error {
	db, err := store.Open(candidatePath)
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "opening restore candidate", err)
	}
	defer db.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	err = withTx(db.SQL(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE agent_keys SET status='revoked', revoked_at=? WHERE status<>'revoked'`, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE leases SET status=?, token_generation=token_generation+1 WHERE status IN (?,?)`,
			lease.StateRevoked, lease.StateActive, lease.StateReconnecting); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE access_tokens SET revoked_at=? WHERE revoked_at IS NULL`, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE visitor_sessions SET revoked_at=? WHERE revoked_at IS NULL`, now); err != nil {
			return err
		}
		var pubTable string
		if err := tx.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_publications'`).Scan(&pubTable); err == nil && pubTable != "" {
			if _, err := tx.Exec(`UPDATE mcp_publications SET revoked_at=?, updated_at=? WHERE revoked_at IS NULL`, now, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "resetting restored authority", err)
	}
	return nil
}

// installValidated atomically installs a validated candidate over the
// live database path: owner-only copy, fsync, rename. Stale WAL
// sidecars from the previous database generation are removed — the
// candidate is a clean VACUUM-produced image with no WAL.
func installValidated(candidatePath, livePath string) error {
	if err := os.MkdirAll(filepath.Dir(livePath), 0o700); err != nil {
		return apperr.E(apperr.CodeStoreFault, "creating state directory", err)
	}
	staged := livePath + ".restore-tmp"
	_ = os.Remove(staged)
	if err := copyFile(candidatePath, staged); err != nil {
		return apperr.E(apperr.CodeStoreFault, "staging restore candidate", err)
	}
	if err := os.Chmod(staged, 0o600); err != nil {
		_ = os.Remove(staged)
		return apperr.E(apperr.CodeStoreFault, "securing staged database", err)
	}
	if err := os.Rename(staged, livePath); err != nil {
		_ = os.Remove(staged)
		return apperr.E(apperr.CodeStoreFault, "installing restored database", err)
	}
	for _, sidecar := range []string{livePath + "-wal", livePath + "-shm", livePath + "-journal"} {
		_ = os.Remove(sidecar)
	}
	// The rename is atomic; the directory sync makes it durable, so a
	// power loss cannot revert to a torn mix of old and new files.
	dirSync(filepath.Dir(livePath))
	return nil
}
