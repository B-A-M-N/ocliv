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
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/lease"
	"github.com/B-A-M-N/ocliv/internal/store"

	_ "modernc.org/sqlite"
)

// relayDBName is the single state file inside a relay data directory.
const relayDBName = "ocliv.db"

// BackupState writes a new, immutable snapshot and checksum sidecar. The
// pending marker makes the two-file publication recoverable: an interrupted
// snapshot without its checksum is rejected, while an intact pair is valid
// even if power failed before marker cleanup. Existing backup names are never
// overwritten, so a failed replacement cannot destroy the prior snapshot.
func BackupState(db *store.DB, destPath string) error {
	return backupState(db, destPath, nil)
}

func backupState(db *store.DB, destPath string, afterStage func(string) error) error {
	if destPath == "" {
		return apperr.E(apperr.CodeCLIValidation, "backup destination required", nil)
	}
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.E(apperr.CodeStoreFault, "creating backup directory", err)
	}
	for _, path := range []string{destPath, checksumPath(destPath), backupPendingPath(destPath)} {
		if _, err := os.Lstat(path); err == nil {
			return apperr.E(apperr.CodeCLIValidation, "backup destination already exists; choose a new timestamped path", nil)
		} else if !os.IsNotExist(err) {
			return apperr.E(apperr.CodeStoreFault, "checking backup destination", err)
		}
	}
	tmpFile, err := os.CreateTemp(dir, ".ocliv-backup-*.db")
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "creating backup staging file", err)
	}
	tmp := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return apperr.E(apperr.CodeStoreFault, "closing backup staging file", err)
	}
	if err := os.Remove(tmp); err != nil {
		return apperr.E(apperr.CodeStoreFault, "preparing backup staging file", err)
	}
	defer os.Remove(tmp)
	if _, err := db.SQL().Exec(`VACUUM INTO ?`, tmp); err != nil {
		return apperr.E(apperr.CodeStoreFault, "snapshotting state database", err)
	}
	if err := markBackupFormat(tmp); err != nil {
		return apperr.E(apperr.CodeStoreFault, "marking versioned backup format", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return apperr.E(apperr.CodeStoreFault, "securing backup file", err)
	}
	if err := syncFile(tmp); err != nil {
		return apperr.E(apperr.CodeStoreFault, "syncing backup file", err)
	}
	sum, err := checksumFile(tmp)
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "checksumming backup file", err)
	}
	sideTmpFile, err := os.CreateTemp(dir, ".ocliv-backup-*.sha256")
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "creating backup checksum staging file", err)
	}
	sideTmp := sideTmpFile.Name()
	defer os.Remove(sideTmp)
	if err := sideTmpFile.Chmod(0o600); err != nil {
		_ = sideTmpFile.Close()
		return apperr.E(apperr.CodeStoreFault, "securing backup checksum", err)
	}
	if _, err := sideTmpFile.Write([]byte(sum + "\n")); err != nil {
		_ = sideTmpFile.Close()
		return apperr.E(apperr.CodeStoreFault, "writing backup checksum", err)
	}
	if err := sideTmpFile.Sync(); err != nil {
		_ = sideTmpFile.Close()
		return apperr.E(apperr.CodeStoreFault, "syncing backup checksum", err)
	}
	if err := sideTmpFile.Close(); err != nil {
		return apperr.E(apperr.CodeStoreFault, "closing backup checksum", err)
	}
	marker, err := os.OpenFile(backupPendingPath(destPath), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "marking backup publication in progress", err)
	}
	if _, err := marker.Write([]byte("backup and checksum publication in progress\n")); err != nil {
		_ = marker.Close()
		_ = os.Remove(backupPendingPath(destPath))
		return apperr.E(apperr.CodeStoreFault, "writing backup publication marker", err)
	}
	if err := marker.Sync(); err != nil {
		_ = marker.Close()
		_ = os.Remove(backupPendingPath(destPath))
		return apperr.E(apperr.CodeStoreFault, "syncing backup publication marker", err)
	}
	if err := marker.Close(); err != nil {
		_ = os.Remove(backupPendingPath(destPath))
		return apperr.E(apperr.CodeStoreFault, "closing backup publication marker", err)
	}
	if err := dirSync(dir); err != nil {
		return apperr.E(apperr.CodeStoreFault, "syncing backup publication marker", err)
	}
	if afterStage != nil {
		if err := afterStage("pending"); err != nil {
			return err
		}
	}
	// Hard-link publication is atomic and fails if another process created
	// the chosen immutable name after the initial existence check.
	if err := os.Link(tmp, destPath); err != nil {
		return apperr.E(apperr.CodeStoreFault, "installing backup file", err)
	}
	if err := os.Remove(tmp); err != nil {
		return apperr.E(apperr.CodeStoreFault, "retiring backup staging file", err)
	}
	if err := dirSync(dir); err != nil {
		return apperr.E(apperr.CodeStoreFault, "syncing installed backup", err)
	}
	if afterStage != nil {
		if err := afterStage("snapshot"); err != nil {
			return err
		}
	}
	if err := os.Link(sideTmp, checksumPath(destPath)); err != nil {
		return apperr.E(apperr.CodeStoreFault, "installing backup checksum", err)
	}
	if err := os.Remove(sideTmp); err != nil {
		return apperr.E(apperr.CodeStoreFault, "retiring checksum staging file", err)
	}
	if err := dirSync(dir); err != nil {
		return apperr.E(apperr.CodeStoreFault, "syncing installed backup checksum", err)
	}
	if afterStage != nil {
		if err := afterStage("checksum"); err != nil {
			return err
		}
	}
	if err := os.Remove(backupPendingPath(destPath)); err != nil {
		return apperr.E(apperr.CodeStoreFault, "clearing backup publication marker", err)
	}
	if err := dirSync(dir); err != nil {
		return apperr.E(apperr.CodeStoreFault, "syncing completed backup publication", err)
	}
	return nil
}

// checksumPath is the sidecar path for a backup's SHA-256.
func checksumPath(backupPath string) string { return backupPath + ".sha256" }

// writeChecksum records the SHA-256 of the backup file next to it.
func backupPendingPath(backupPath string) string { return backupPath + ".pending" }

func checksumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// markBackupFormat puts the checksum requirement inside the SQLite snapshot
// itself. If an operator later loses both sidecar and pending marker, this
// durable marker still distinguishes a new-format backup from a legacy one.
func markBackupFormat(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS ocliv_backup_manifest (format_version INTEGER NOT NULL CHECK(format_version=1))`); err != nil {
		return err
	}
	if _, err := db.Exec(`DELETE FROM ocliv_backup_manifest`); err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO ocliv_backup_manifest(format_version) VALUES(1)`)
	return err
}

func backupRequiresChecksum(path string) (bool, error) {
	u := (&url.URL{Scheme: "file", Path: path}).String() + "?mode=ro"
	db, err := sql.Open("sqlite", u)
	if err != nil {
		return false, err
	}
	defer db.Close()
	var version int
	err = db.QueryRow(`SELECT format_version FROM ocliv_backup_manifest`).Scan(&version)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return false, nil // legacy raw SQLite backup
		}
		return false, err
	}
	if version != 1 {
		return false, fmt.Errorf("unsupported backup format version %d", version)
	}
	return true, nil
}

// verifyChecksum checks the sidecar checksum when one exists. A missing
// sidecar is accepted for backups written before checksums existed; their
// integrity is still checked by SQLite.
func verifyChecksum(backupPath string) error {
	rawSum, err := os.ReadFile(checksumPath(backupPath))
	if err != nil {
		if os.IsNotExist(err) {
			if _, pendingErr := os.Lstat(backupPendingPath(backupPath)); pendingErr == nil {
				return apperr.E(apperr.CodeStoreFault, "backup publication was interrupted before checksum installation", nil)
			} else if !os.IsNotExist(pendingErr) {
				return apperr.E(apperr.CodeStoreFault, "reading backup publication marker", pendingErr)
			}
			requires, formatErr := backupRequiresChecksum(backupPath)
			if formatErr != nil {
				return apperr.E(apperr.CodeStoreFault, "reading backup format manifest", formatErr)
			}
			if requires {
				return apperr.E(apperr.CodeStoreFault, "versioned backup is missing its required checksum sidecar", nil)
			}
			return nil
		}
		return apperr.E(apperr.CodeStoreFault, "reading backup checksum", err)
	}
	sum, err := checksumFile(backupPath)
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "reading backup for checksum", err)
	}
	want := strings.TrimSpace(string(rawSum))
	if want == "" || !hmac.Equal([]byte(sum), []byte(want)) {
		return apperr.E(apperr.CodeStoreFault, "backup checksum mismatch (file modified after backup)", nil)
	}
	return nil
}

// authzGrantKey is the full identity of a managed grant: the
// (tenant_id, route_id, client_id) composite primary key. Keying the
// rollback guard on client_id alone would let one route's active grant
// mask another route's revocation (a cross-route authorization
// rollback). A typed struct, never a concatenated string.
type authzGrantKey struct {
	tenantID string
	routeID  string
	clientID string
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
	// leaseGen maps every live lease to its fencing generation.
	// Reconnects are the only bumpers, so a step back would let a
	// superseded generation fence and regain live authority (P0-B).
	leaseGen map[string]int64
	// tokens/sessions are explicitly revoked capability rows.
	tokens   map[string]bool
	sessions map[string]bool
	// Managed-authorization authority that must never roll backward:
	// a revoked managed client (authz_clients.revoked_at), a non-active
	// managed grant (authz_grants.status != 'active'), or a revoked
	// managed token jti (authz_revocations). Restoring an older database
	// would otherwise reactivate managed OAuth clients/grants/tokens.
	authzClients         map[string]bool        // authz_clients with revoked_at set
	authzGrants          map[authzGrantKey]bool // authz_grants with status != 'active' (keyed by tenant/route/client tuple)
	authzJTIs            map[string]bool        // authz_revocations jti
	authzTrustPolicies   map[string]bool        // authz_trust_policies with revoked_at set or enabled=0
	authzVisitorPolicies map[string]bool        // authz_visitor_policies (tenant/route) with revoked_at set or enabled=0
	authzTablesLive      bool                   // live DB has the managed tables
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
	// Fencing generations for every lease (P0-B): only reconnects
	// bump them, so any step back is refused like a rotation
	// rollback.
	s.leaseGen = map[string]int64{}
	grows, err := q.Query(`SELECT id, generation FROM leases`)
	if err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading fencing generations", err)
	}
	for grows.Next() {
		var id string
		var g int64
		if err := grows.Scan(&id, &g); err != nil {
			grows.Close()
			return nil, apperr.E(apperr.CodeStoreFault, "reading fencing generations", err)
		}
		s.leaseGen[id] = g
	}
	grows.Close()
	if err := grows.Err(); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading fencing generations", err)
	}
	if s.tokens, err = collectStrings(q, `SELECT id FROM access_tokens WHERE revoked_at IS NOT NULL`); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading token revocations", err)
	}
	if s.sessions, err = collectStrings(q, `SELECT id FROM visitor_sessions WHERE revoked_at IS NOT NULL`); err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "reading session revocations", err)
	}
	// Managed-authorization authority. A database predating the managed
	// tables (pre-V8) has none: empty sets, and the guard treats missing
	// tables as "no live managed state to protect" (nothing to roll back).
	s.authzClients = map[string]bool{}
	s.authzGrants = map[authzGrantKey]bool{}
	s.authzJTIs = map[string]bool{}
	s.authzTrustPolicies = map[string]bool{}
	s.authzVisitorPolicies = map[string]bool{}
	var authzTable string
	if err := q.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='authz_clients'`).Scan(&authzTable); err == nil && authzTable != "" {
		s.authzTablesLive = true
		if s.authzClients, err = collectStrings(q, `SELECT id FROM authz_clients WHERE revoked_at IS NOT NULL`); err != nil {
			return nil, apperr.E(apperr.CodeStoreFault, "reading managed client revocations", err)
		}
		grows, err := q.Query(`SELECT tenant_id, route_id, client_id FROM authz_grants WHERE status<>'active'`)
		if err != nil {
			return nil, apperr.E(apperr.CodeStoreFault, "reading managed grant terminations", err)
		}
		for grows.Next() {
			var k authzGrantKey
			if err := grows.Scan(&k.tenantID, &k.routeID, &k.clientID); err != nil {
				grows.Close()
				return nil, apperr.E(apperr.CodeStoreFault, "reading managed grant terminations", err)
			}
			s.authzGrants[k] = true
		}
		grows.Close()
		if err := grows.Err(); err != nil {
			return nil, apperr.E(apperr.CodeStoreFault, "reading managed grant terminations", err)
		}
	}
	var authzRevTable string
	if err := q.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='authz_revocations'`).Scan(&authzRevTable); err == nil && authzRevTable != "" {
		if s.authzJTIs, err = collectStrings(q, `SELECT jti FROM authz_revocations`); err != nil {
			return nil, apperr.E(apperr.CodeStoreFault, "reading managed token revocations", err)
		}
	}
	var trustPolTable string
	if err := q.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='authz_trust_policies'`).Scan(&trustPolTable); err == nil && trustPolTable != "" {
		if s.authzTrustPolicies, err = collectStrings(q, `SELECT id FROM authz_trust_policies WHERE revoked_at IS NOT NULL OR enabled=0`); err != nil {
			return nil, apperr.E(apperr.CodeStoreFault, "reading trust policy revocations", err)
		}
	}
	var visitorPolTable string
	if err := q.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='authz_visitor_policies'`).Scan(&visitorPolTable); err == nil && visitorPolTable != "" {
		if s.authzVisitorPolicies, err = collectStrings(q, `SELECT tenant_id || '/' || route_id FROM authz_visitor_policies WHERE revoked_at IS NOT NULL OR enabled=0`); err != nil {
			return nil, apperr.E(apperr.CodeStoreFault, "reading visitor auth policy revocations", err)
		}
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
	// Fencing generations never step back (P0-B): a lower backup
	// generation would let a superseded generation fence and regain
	// live authority. Rows absent from the backup are forward data
	// loss (operator's explicit act), not resurrection — except
	// live-terminal rows, caught above.
	for id, g := range live.leaseGen {
		if bg, ok := backup.leaseGen[id]; ok && bg < g {
			missing = append(missing, "fencing-generation:"+id)
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
	// Managed-authorization rollback: a live revoked managed client,
	// terminated grant, or revoked token jti that reads active/unrevoked
	// (or absent) in the backup would come back to life. Only enforced
	// when the live DB actually has managed tables.
	if live.authzTablesLive {
		for id := range live.authzClients {
			if !backup.authzClients[id] {
				missing = append(missing, "authz-client:"+id)
			}
		}
		for k := range live.authzGrants {
			if !backup.authzGrants[k] {
				missing = append(missing, "authz-grant:"+k.tenantID+"/"+k.routeID+"/"+k.clientID)
			}
		}
		for jti := range live.authzJTIs {
			if !backup.authzJTIs[jti] {
				missing = append(missing, "authz-token:"+jti)
			}
		}
		for id := range live.authzTrustPolicies {
			if !backup.authzTrustPolicies[id] {
				missing = append(missing, "authz-trust-policy:"+id)
			}
		}
		for id := range live.authzVisitorPolicies {
			if !backup.authzVisitorPolicies[id] {
				missing = append(missing, "authz-visitor-policy:"+id)
			}
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
	if err := verifyChecksum(backupPath); err != nil {
		return err
	}
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

// dirSync flushes directory metadata so preceding links, removals, or
// renames are durable before success is reported. Filesystems that do not
// support directory fsync fail the operation instead of claiming durability.
func dirSync(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
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
	// Fail-closed visitor session continuity on restore (P1-6, P2): compare
	// the non-secret SHA-256 fingerprint of <dataDir>/visitor-hmac.key against
	// the latest fingerprint recorded in the restored database. If the key is
	// absent, unreadable, or does not match the restored DB's fingerprint,
	// explicitly invalidate all restored visitor_sessions and audit why.
	reason := ""
	keyBytes, kerr := readVisitorKeyStrict(filepath.Join(dataDir, visitorKeyFileName))
	if kerr != nil {
		reason = "visitor-hmac.key absent or unreadable"
	} else {
		var recordedFP string
		_ = db.SQL().QueryRow(`SELECT detail FROM audit_events WHERE category='visitor_hmac_fingerprint' AND result='ok' ORDER BY id DESC LIMIT 1`).Scan(&recordedFP)
		if recordedFP == "" {
			reason = "restored DB has no visitor HMAC fingerprint"
		} else if recordedFP != VisitorKeyFingerprint(keyBytes) {
			reason = "visitor-hmac.key fingerprint mismatch"
		}
	}
	if reason != "" {
		nowStr := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := db.SQL().Exec(`UPDATE visitor_sessions SET revoked_at=? WHERE revoked_at IS NULL`, nowStr); err != nil {
			return apperr.E(apperr.CodeStoreFault, "invalidating restored visitor sessions", err)
		}
		db.Audit("operator", "", "", "restore_visitor_sessions", "invalidated", reason+"; restored visitor sessions invalidated")
	}
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
// database exists yet (fresh install: nothing to roll back). It NEVER calls
// store.Open on the live database — that would forward-migrate it before
// the rollback guard has decided whether the restore is acceptable. The
// read-only path inspects the schema version and refuses unknown/newer
// schemas instead of migrating.
func openRevocations(livePath string) (*revocationSet, error) {
	if _, err := os.Stat(livePath); os.IsNotExist(err) {
		return nil, nil
	}
	db, err := openReadOnly(livePath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return readRevocations(db)
}

// openReadOnly opens an existing SQLite database in genuine read-only mode
// (uri mode=ro, no create) and fails closed on unknown or newer schemas.
// It never creates the database and never migrates it.
func openReadOnly(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "opening database read-only", err)
	}
	var v int
	err = db.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&v)
	if err != nil {
		db.Close()
		return nil, apperr.E(apperr.CodeStoreFault, "reading schema version (not an ocliv database?)", err)
	}
	if v > store.SchemaVersion {
		db.Close()
		return nil, apperr.E(apperr.CodeStoreFault,
			fmt.Sprintf("database schema version %d is newer than this binary knows (%d)", v, store.SchemaVersion), nil)
	}
	// Older schemas are readable as-is: readRevocations guards on table
	// existence, so a V7 database simply has no managed-authorization
	// tables to read. No migration, no writes.
	return db, nil
}

// resetRestoredAuthority terminally revokes every key, lease, token,
// session, publication, AND managed OAuth authority (clients, grants)
// in an offline database copy, and retires the JWT signing key so any
// token minted under it fails closed. The operator must re-enroll and
// clients must re-register/re-approve; nothing restored is usable.
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
		// Managed OAuth authority: clients and grants are terminally
		// revoked, outstanding authorization codes and consent challenges
		// are consumed, and the JWT signing key is DELETED so every token
		// minted under the restored authority fails closed (a fresh key is
		// generated on first use). Without this, --reset-authority would
		// leave restored managed clients/grants usable.
		var authzTable string
		if err := tx.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='authz_clients'`).Scan(&authzTable); err == nil && authzTable != "" {
			if _, err := tx.Exec(`UPDATE authz_clients SET revoked_at=? WHERE revoked_at IS NULL`, now); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE authz_grants SET status='revoked', updated_at=? WHERE status<>'revoked'`, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`UPDATE authz_codes SET consumed_at=? WHERE consumed_at IS NULL`, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE authz_consent SET consumed_at=? WHERE consumed_at IS NULL`, now); err != nil {
			return err
		}
		var trustPolTable string
		if err := tx.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='authz_trust_policies'`).Scan(&trustPolTable); err == nil && trustPolTable != "" {
			if _, err := tx.Exec(`UPDATE authz_trust_policies SET enabled=0, revoked_at=? WHERE revoked_at IS NULL OR enabled<>0`, now); err != nil {
				return err
			}
		}
		var visitorPolTable string
		if err := tx.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='authz_visitor_policies'`).Scan(&visitorPolTable); err == nil && visitorPolTable != "" {
			if _, err := tx.Exec(`UPDATE authz_visitor_policies SET enabled=0, revoked_at=?, updated_at=?, client_secret='' WHERE revoked_at IS NULL OR enabled<>0 OR client_secret<>''`, now, now); err != nil {
				return err
			}
		}
		var oidcTxTable string
		if err := tx.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='authz_oidc_tx'`).Scan(&oidcTxTable); err == nil && oidcTxTable != "" {
			if _, err := tx.Exec(`UPDATE authz_oidc_tx SET consumed_at=? WHERE consumed_at IS NULL`, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`DELETE FROM authz_issuer_key`); err != nil {
			return err
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
	return installValidatedWithHook(candidatePath, livePath, nil)
}

func installValidatedWithHook(candidatePath, livePath string, afterStage func(string) error) error {
	if err := os.MkdirAll(filepath.Dir(livePath), 0o700); err != nil {
		return apperr.E(apperr.CodeStoreFault, "creating state directory", err)
	}
	stageFile, err := os.CreateTemp(filepath.Dir(livePath), ".ocliv-restore-*.db")
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "creating restore staging file", err)
	}
	staged := stageFile.Name()
	if err := stageFile.Close(); err != nil {
		_ = os.Remove(staged)
		return apperr.E(apperr.CodeStoreFault, "closing restore staging file", err)
	}
	defer os.Remove(staged)
	if err := copyFile(candidatePath, staged); err != nil {
		return apperr.E(apperr.CodeStoreFault, "staging restore candidate", err)
	}
	if err := os.Chmod(staged, 0o600); err != nil {
		return apperr.E(apperr.CodeStoreFault, "securing staged database", err)
	}
	if err := syncFile(staged); err != nil {
		return apperr.E(apperr.CodeStoreFault, "syncing staged database", err)
	}
	// Checkpoint the old DB before retiring its sidecars. If power fails
	// before the atomic rename, the old main file still contains every
	// committed WAL transaction. After sidecar removal, the rename can no
	// longer expose a new DB alongside an old WAL.
	if err := checkpointAndRemoveSidecars(livePath); err != nil {
		return apperr.E(apperr.CodeStoreFault, "preparing restore target", err)
	}
	if afterStage != nil {
		if err := afterStage("sidecars-removed"); err != nil {
			return err
		}
	}
	if err := os.Rename(staged, livePath); err != nil {
		return apperr.E(apperr.CodeStoreFault, "installing restored database", err)
	}
	if err := dirSync(filepath.Dir(livePath)); err != nil {
		return apperr.E(apperr.CodeStoreFault, "syncing restored database directory", err)
	}
	if afterStage != nil {
		if err := afterStage("installed"); err != nil {
			return err
		}
	}
	return nil
}

func checkpointAndRemoveSidecars(livePath string) error {
	if _, err := os.Stat(livePath); err == nil {
		live, err := sql.Open("sqlite", livePath)
		if err != nil {
			return err
		}
		if _, err := live.Exec(`PRAGMA busy_timeout=3000`); err != nil {
			_ = live.Close()
			return err
		}
		var busy, logFrames, checkpointed int
		if err := live.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil {
			_ = live.Close()
			return err
		}
		if err := live.Close(); err != nil {
			return err
		}
		if busy != 0 {
			return fmt.Errorf("live database checkpoint is busy (%d frames remain)", logFrames-checkpointed)
		}
		if err := syncFile(livePath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, sidecar := range []string{livePath + "-wal", livePath + "-shm", livePath + "-journal"} {
		if err := os.Remove(sidecar); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return dirSync(filepath.Dir(livePath))
}
