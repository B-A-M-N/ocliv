// Durable lease lifecycle (relay side): allocation, resume fencing,
// naming, TTL/grace expiry bookkeeping, and boot reconciliation.
//
// This layer owns durable transitions in the leases table. It never
// manipulates the live session registry directly: session eviction goes
// through the session layer (relay_sessions.go), and SQLite remains the
// single authority for whether a lease is ACTIVE.
package relay

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/lease"
	"ocliv/internal/metrics"
)

// allocateOrResume creates a new lease or resumes a valid one (F04, F05).
// Resume requires same key ownership, live window, non-revoked status, and
// compatible version. A revoked or closed resume is terminal: it never
// silently mints a replacement lease (AS-047). An expired resume is also
// terminal server-side, but carries a replacement-permitted denial so the
// same valid identity may drop its stale record and reconnect for a fresh
// lease. Only an unknown lease id falls through to a new separately
// authorized lease; the old URL is never hijacked.
func (s *Server) allocateOrResume(tenantID, keyID string, intent LeaseIntent) (*lease.Lease, attachedMsg, error) {
	// Operator identity gate (P0-A): a revoked key or suspended tenant
	// can neither resume nor allocate, closing the reconnect path that
	// per-lease status checks alone do not cover.
	if _, _, status, err := s.lookupKey(keyID); err != nil || !s.identityAdmitted(tenantID, status) {
		return nil, attachedMsg{}, apperr.E(apperr.CodeEnrollAuth, "unknown, revoked, or suspended agent key", err)
	}
	if intent.Persistent && strings.TrimSpace(intent.Name) == "" {
		return nil, attachedMsg{}, apperr.E(apperr.CodeCLIValidation,
			"persistent lease requires an explicit named hostname", nil)
	}
	now := time.Now().UTC()
	if intent.LeaseID != "" {
		ls, err := s.resumeLease(tenantID, keyID, intent)
		if err == nil {
			return ls, s.attachedFor(ls), nil
		}
		var ae *apperr.Error
		if asApperr(err, &ae) && ae.Code == apperr.CodeQuotaLease {
			// Fall through: unknown lease id, mint a new separately
			// authorized lease.
		} else {
			return nil, attachedMsg{}, err
		}
	}
	// Every path below mints a new lease (no resume id, unknown resume id,
	// or a resume denied for mode/name change): all of them require
	// confirmed local readiness, never an unverified allocation (F06).
	// Resumes of a known lease re-authenticate the same owner instead.
	if !intent.Ready {
		return nil, attachedMsg{}, apperr.E(apperr.CodeCLIValidation,
			"local readiness not confirmed", nil)
	}
	if intent.Name != "" {
		return s.allocateNamed(tenantID, keyID, intent, now)
	}
	return s.allocateEphemeral(tenantID, keyID, intent, now)
}

func (s *Server) attachedFor(ls *lease.Lease) attachedMsg {
	msg := attachedMsg{
		Type: "attached", SessionID: "sess-" + ls.ID + "-g" + itoa(ls.Generation),
		LeaseID: ls.ID, Hostname: ls.Hostname, Generation: ls.Generation,
		AccessMode: ls.AccessMode,
		URL:        "https://" + ls.Hostname,
	}
	if !ls.ExpiresAt.IsZero() {
		msg.ExpiresAt = ls.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return msg
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [24]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// resumeLease validates resume proof then fences the generation (F03, F05).
// wantMode resolves the requested access mode from a signed intent. An
// explicit access_mode selects the policy verbatim (validated against the
// closed set); an empty one preserves the legacy protected/public
// derivation from the Public flag. A Public flag contradicting an
// explicit non-public mode fails closed rather than guessing. The result
// participates in strict equality at resume and allocation: modes are
// never silently inherited in either direction (P0-04).
func wantMode(intent LeaseIntent) (string, error) {
	if intent.AccessMode == "" {
		if intent.Public {
			return "public", nil
		}
		return "protected", nil
	}
	switch intent.AccessMode {
	case "protected", "public", AccessModeMCPUpstreamOAuth, AccessModeMCPAnonymousFixture, AccessModeMCPManaged:
		if intent.Public && intent.AccessMode != "public" {
			return "", apperr.E(apperr.CodeCLIValidation, "public flag contradicts explicit access mode", nil)
		}
		return intent.AccessMode, nil
	default:
		return "", apperr.E(apperr.CodeCLIValidation, "unknown access mode", nil)
	}
}

func (s *Server) resumeLease(tenantID, keyID string, intent LeaseIntent) (*lease.Lease, error) {
	var ls lease.Lease
	var state string
	var persistentInt int
	var expiresAt, reconnectUntil sql.NullString
	err := s.db.SQL().QueryRow(
		`SELECT id, tenant_id, agent_key_id, hostname, port, access_mode, generation, token_generation, status, expires_at, reconnect_until, COALESCE(persistent, 0)
		 FROM leases WHERE id=?`, intent.LeaseID,
	).Scan(&ls.ID, &ls.TenantID, &ls.AgentKeyID, &ls.Hostname, &ls.Port, &ls.AccessMode,
		&ls.Generation, new(int), &state, &expiresAt, &reconnectUntil, &persistentInt)
	if err != nil {
		// Unknown id is the only resume path that may mint a new lease;
		// any other read failure fails closed (B09, F12).
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperr.E(apperr.CodeQuotaLease, "unknown lease", nil)
		}
		return nil, apperr.E(apperr.CodeStoreFault, "reading lease", err)
	}
	ls.State = state
	if ls.TenantID != tenantID || ls.AgentKeyID != keyID {
		return nil, apperr.E(apperr.CodeConflict, "lease owned by a different identity", nil)
	}
	if state == string(lease.StateRevoked) {
		return nil, apperr.E(apperr.CodeRevoked, "lease revoked", nil)
	}
	// Expired and closed leases are both terminal, but they authorize
	// different recovery: an expired lease (TTL lapse, downtime) may be
	// replaced by the same identity holding a valid key, while a closed
	// lease was intentionally terminated and must never be silently
	// renewed. The agent tells them apart by error code (P0-4).
	if state == string(lease.StateExpired) {
		return nil, apperr.E(apperr.CodeExpired, "lease expired", nil)
	}
	if state == string(lease.StateClosed) {
		return nil, apperr.E(apperr.CodeClosed, "lease closed", nil)
	}
	// TTL expiry is terminal: a lease past expires_at never resumes (V1).
	// The row is marked EXPIRED so traffic and status agree (F01). An
	// unparseable timestamp fails closed rather than reading as valid
	// (F12): corrupt state is terminal (CodeClosed — no resume and no
	// replacement), while a well-formed lapse stays replaceable
	// (CodeExpired → 4410). Never conflate the two.
	if expiresAt.Valid {
		exp, err := time.Parse(time.RFC3339Nano, expiresAt.String)
		if err != nil {
			// Evict first: a live session must not survive its lease (R4).
			s.evictLease(ls.ID)
			_, _ = s.db.SQL().Exec(`UPDATE leases SET status=? WHERE id=?`, lease.StateExpired, ls.ID)
			s.db.Audit("agent", ls.TenantID, ls.ID, "resume", "denied", "unparseable expires_at")
			return nil, apperr.E(apperr.CodeClosed, "lease timestamp unreadable", nil)
		}
		if time.Now().UTC().After(exp) {
			// Evict first: a live session must not survive its lease (R4).
			s.evictLease(ls.ID)
			_, _ = s.db.SQL().Exec(`UPDATE leases SET status=? WHERE id=?`, lease.StateExpired, ls.ID)
			s.db.Audit("agent", ls.TenantID, ls.ID, "resume", "denied", "lease ttl expired")
			return nil, apperr.E(apperr.CodeExpired, "lease ttl expired", nil)
		}
		ls.ExpiresAt = exp
	}
	if reconnectUntil.Valid {
		t, err := time.Parse(time.RFC3339Nano, reconnectUntil.String)
		if err != nil {
			return nil, apperr.E(apperr.CodeClosed, "reconnect window unreadable", nil)
		}
		if time.Now().UTC().After(t) {
			return nil, apperr.E(apperr.CodeExpired, "reconnect grace elapsed", nil)
		}
	}
	if (persistentInt != 0) != intent.Persistent {
		s.db.Audit("agent", tenantID, ls.ID, "resume", "denied", "persistent mode mismatch")
		return nil, apperr.E(apperr.CodeConflict, "resume persistent mode mismatch", nil)
	}
	if ls.Port != intent.Port && persistentInt == 0 {
		return nil, apperr.E(apperr.CodeConflict, "resume with different port requires a new lease", nil)
	}
	// Access mode is part of the lease identity: a changed mode must never
	// be silently inherited (secure-by-default, P0-04). Returning QuotaLease
	// falls through to a fresh allocation below, so the caller gets exactly
	// the mode it requested on a new lease — never the old exposure. An
	// explicit intent mode participates in the same strict equality, so an
	// MCP-mode agent resumes its own lease while a mismatched intent still
	// falls through to a fresh lease.
	wantMode, err := wantMode(intent)
	if err != nil {
		return nil, apperr.E(apperr.CodeCLIValidation, "invalid access mode", err)
	}
	if ls.AccessMode != wantMode {
		s.db.Audit("agent", tenantID, ls.ID, "resume", "denied", "access mode changed; new lease")
		return nil, apperr.E(apperr.CodeQuotaLease, "access mode changed; allocating a new lease", nil)
	}
	// Same for the requested name: a different name is a different lease.
	if intent.Name != "" && ls.Hostname != intent.Name+"."+s.namespace {
		s.db.Audit("agent", tenantID, ls.ID, "resume", "denied", "name changed; new lease")
		return nil, apperr.E(apperr.CodeQuotaLease, "name changed; allocating a new lease", nil)
	}
	// Fence atomically: the WHERE guard turns a concurrent lost update
	// into a conflict the loser retries instead of a duplicated live
	// generation (R1, F02/F03). The predicate also re-enforces everything
	// the SELECT validated — eligible status, owner identity, live window —
	// so a close, revoke, expiry, or ownership change landing between the
	// read and the write cannot be overwritten by a stale resume (P0-02).
	// Terminal states stay terminal; only a fenced generation wins.
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)
	newGen := ls.Generation + 1
	newPort := ls.Port
	if persistentInt != 0 && intent.Port > 0 {
		newPort = intent.Port
	}
	res, err := s.db.SQL().Exec(
		`UPDATE leases SET generation=?, port=?, status=?, reconnect_until=NULL
		 WHERE id=? AND generation=? AND status IN (?,?)
		 AND tenant_id=? AND agent_key_id=?
		 AND (expires_at IS NULL OR expires_at > ?)`,
		newGen, newPort, lease.StateActive, ls.ID, ls.Generation,
		string(lease.StateActive), string(lease.StateReconnecting),
		tenantID, keyID, nowStr)
	if err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "resuming lease", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, apperr.E(apperr.CodeStoreFault, "resuming lease", err)
	}
	if n != 1 {
		// The fence lost: distinguish a superseded generation (retryable)
		// from a terminal/expired lease (permanent) so the agent backs off
		// versus stops (F09). Best effort: a read failure stays a conflict.
		return nil, s.resumeDenyReason(ls.ID)
	}
	// Fence won: only now retire the older live session, and only if it is
	// still older — a newer generation may have registered meanwhile, and
	// must never be evicted by this stale winner (P0-03). Documented order:
	// (1) fence the row, (2) evict strictly-older map entries,
	// (3) register only the fenced generation (see registerSession).
	s.evictIfOlder(ls.ID, newGen)
	ls.Generation = newGen
	ls.Port = newPort
	ls.UpdatedAt = time.Now()
	ls.State = lease.StateActive
	metrics.Global.SessionReconnects.Add(1)
	s.db.Audit("agent", tenantID, ls.ID, "resume", "ok", "generation fenced")
	return &ls, nil
}

// resumeDenyReason re-reads the row after a lost fence and maps it to a
// terminal versus retryable denial. Terminal states (closed, revoked,
// expired, unknown) stop the agent; a mere generation loss stays a
// conflict the agent retries with backoff (F09, P0-02).
func (s *Server) resumeDenyReason(leaseID string) *apperr.Error {
	var state string
	var tenantID, keyID string
	err := s.db.SQL().QueryRow(
		`SELECT status, tenant_id, agent_key_id FROM leases WHERE id=?`, leaseID,
	).Scan(&state, &tenantID, &keyID)
	if err != nil {
		return apperr.E(apperr.CodeConflict, "concurrent resume superseded", nil)
	}
	switch state {
	case string(lease.StateRevoked):
		return apperr.E(apperr.CodeRevoked, "lease revoked", nil)
	case string(lease.StateClosed):
		return apperr.E(apperr.CodeClosed, "lease closed", nil)
	case string(lease.StateExpired):
		return apperr.E(apperr.CodeExpired, "lease expired", nil)
	default:
		return apperr.E(apperr.CodeConflict, "concurrent resume superseded", nil)
	}
}

// allocateEphemeral mints a fresh random hostname (D05) and access token.
func (s *Server) allocateEphemeral(tenantID, keyID string, intent LeaseIntent, now time.Time) (*lease.Lease, attachedMsg, error) {
	if !s.throttle.Allow("reg:" + tenantID) {
		return nil, attachedMsg{}, apperr.E(apperr.CodeQuotaLease, "registration rate limited", nil)
	}
	label, err := lease.RandomHostname()
	if err != nil {
		return nil, attachedMsg{}, err
	}
	return s.insertLease(tenantID, keyID, label, intent, now, nil)
}

// allocateNamed binds an owner-locked persistent subdomain (P1). A name
// owned by another tenant is a conflict, never a takeover (D04). A name
// held by another AGENT KEY in the same tenant is also a conflict: the
// reclaim path inherits the retired lease's publications and (for managed
// routes) their operator approval state, so allowing a different key to
// reclaim would hand one publisher another publisher's route. Automatic
// reclaim is reserved for the SAME key that owns the hostname (the
// publisher-restart case); a cross-key takeover requires an explicit,
// audited ownership-transfer operation, which does not exist yet.
const (
	maxPersistentLeasesPerKey    = 32
	maxPersistentLeasesPerTenant = 128
)

func (s *Server) allocateNamed(tenantID, keyID string, intent LeaseIntent, now time.Time) (*lease.Lease, attachedMsg, error) {
	if !s.throttle.Allow("reg:" + tenantID) {
		return nil, attachedMsg{}, apperr.E(apperr.CodeQuotaLease, "registration rate limited", nil)
	}
	label := strings.ToLower(intent.Name)
	if err := lease.ValidateLabel(label); err != nil {
		return nil, attachedMsg{}, err
	}
	// Enforce per-tenant persistent lease quota before the expensive insert.
	if policy := s.db.GetTenantPolicy(tenantID); policy.MaxPersistentLeases > 0 {
		var persistent int
		_ = s.db.SQL().QueryRow(
			`SELECT COUNT(*) FROM leases WHERE tenant_id=? AND COALESCE(persistent,0)=1 AND status NOT IN ('REVOKED','CLOSED','EXPIRED')`,
			tenantID).Scan(&persistent)
		if persistent >= policy.MaxPersistentLeases {
			return nil, attachedMsg{}, apperr.E(apperr.CodeQuotaLease, "tenant persistent lease limit reached", nil)
		}
	}
	return s.insertLease(tenantID, keyID, label, intent, now, &label)
}

func (s *Server) insertLease(tenantID, keyID, label string, intent LeaseIntent, now time.Time, named *string) (*lease.Lease, attachedMsg, error) {
	id, err := lease.MintID()
	if err != nil {
		return nil, attachedMsg{}, err
	}
	mode, err := wantMode(intent)
	if err != nil {
		return nil, attachedMsg{}, err
	}
	// Enforce tenant policy before the expensive DB transaction.
	// The relay is authoritative: a publisher cannot bypass this by
	// constructing a modified client.
	policy := s.db.GetTenantPolicy(tenantID)
	if mode == "public" && !policy.AllowPublic {
		return nil, attachedMsg{}, apperr.E(apperr.CodeCLIValidation, "relay tenant policy denies public exposure; operator must enable allow_public for this tenant", nil)
	}
	if policy.MaxActiveLeases > 0 {
		var active int
		_ = s.db.SQL().QueryRow(
			`SELECT COUNT(*) FROM leases WHERE tenant_id=? AND status IN ('ACTIVE','RECONNECTING','PENDING')`,
			tenantID).Scan(&active)
		if active >= policy.MaxActiveLeases {
			return nil, attachedMsg{}, apperr.E(apperr.CodeQuotaLease, "tenant active lease limit reached", nil)
		}
	}
	hostname := label + "." + s.namespace
	// The initial share secret is prepared before the transaction (no DB
	// side effect) and its verifier is inserted inside the same
	// transaction as the lease row: allocation never leaves a committed
	// lease without a deliverable share URL.
	var shareRaw string
	var shareRow tokenRow
	sharePrepared := false
	if mode == "protected" {
		var err error
		shareRaw, shareRow, err = prepareAccessToken("visitor", 1, 15*time.Minute)
		if err != nil {
			return nil, attachedMsg{}, err
		}
		sharePrepared = true
	}
	var retiredID string
	var reclaimDenied bool
	var reboundPersistent bool
	var reboundGen uint64
	persistentVal := 0
	if intent.Persistent && named != nil {
		persistentVal = 1
	}
	err = withTx(s.db.SQL(), func(tx *sql.Tx) error {
		if named != nil {
			var owner, ownerKey, st, oldID, oldMode string
			var oldGen uint64
			var oldPersistent int
			var oldExpires sql.NullString
			err := tx.QueryRow(`SELECT tenant_id, agent_key_id, status, id, access_mode, generation, COALESCE(persistent, 0), expires_at FROM leases WHERE hostname=?`, hostname).
				Scan(&owner, &ownerKey, &st, &oldID, &oldMode, &oldGen, &oldPersistent, &oldExpires)
			if err == nil {
				if owner != tenantID {
					return apperr.E(apperr.CodeOwnershipConflict, "named host owned by another tenant", nil)
				}
				if ownerKey != keyID {
					reclaimDenied = true
					return apperr.E(apperr.CodeOwnershipConflict, "named host is held by another agent key in this tenant", nil)
				}
				// Persistent named rebind: ONLY explicitly resumable states
				// (ACTIVE, RECONNECTING) with an unexpired deadline qualify for
				// in-place transport rebind (P0-5). Past or malformed expires_at
				// MUST fall through to terminal replacement so old visitor
				// tokens and browser sessions are never revived.
				resumableState := st == string(lease.StateActive) || st == string(lease.StateReconnecting)
				unexpired := !oldExpires.Valid || strings.TrimSpace(oldExpires.String) == ""
				if oldExpires.Valid && strings.TrimSpace(oldExpires.String) != "" {
					if parsedExp, perr := time.Parse(time.RFC3339Nano, oldExpires.String); perr == nil && parsedExp.After(now) {
						unexpired = true
					}
				}
				if oldPersistent != 0 && intent.Persistent && oldMode == mode && resumableState && unexpired {
					var expires any
					if intent.TTLSeconds > 0 {
						expires = now.Add(time.Duration(intent.TTLSeconds) * time.Second).Format(time.RFC3339Nano)
					}
					nextGen := oldGen + 1
					nowStr := now.Format(time.RFC3339Nano)
					res, err := tx.Exec(
						`UPDATE leases SET port=?, generation=?, status=?, reconnect_until=NULL, expires_at=?
						 WHERE id=? AND tenant_id=? AND agent_key_id=? AND status IN (?,?)
						   AND (expires_at IS NULL OR expires_at = '' OR expires_at > ?)`,
						intent.Port, nextGen, lease.StateActive, expires, oldID, tenantID, keyID,
						string(lease.StateActive), string(lease.StateReconnecting), nowStr)
					if err != nil {
						return err
					}
					if n, _ := res.RowsAffected(); n == 1 {
						id = oldID
						reboundPersistent = true
						reboundGen = nextGen
						sharePrepared = false
						return nil
					}
				}
				// Ephemeral reclaim or post-revoke/close replacement: old
				// credentials and sessions are explicitly wiped.
				if _, err := tx.Exec(`DELETE FROM access_tokens WHERE lease_id IN (SELECT id FROM leases WHERE hostname=?)`, hostname); err != nil {
					return err
				}
				if _, err := tx.Exec(`DELETE FROM visitor_sessions WHERE lease_id IN (SELECT id FROM leases WHERE hostname=?)`, hostname); err != nil {
					return err
				}
				if _, err := tx.Exec(
					`UPDATE mcp_publications SET lease_id=NULL, updated_at=? WHERE lease_id=? AND revoked_at IS NOT NULL`,
					now.Format(time.RFC3339Nano), oldID); err != nil {
					return err
				}
				if _, err := tx.Exec(`DELETE FROM leases WHERE hostname=?`, hostname); err != nil {
					return err
				}
				retiredID = oldID
			}
		}
		if persistentVal != 0 {
			var keyCount, tenantCount int
			if err := tx.QueryRow(
				`SELECT COUNT(*) FROM leases WHERE agent_key_id=? AND COALESCE(persistent, 0)!=0 AND status IN (?,?)`,
				keyID, string(lease.StateActive), string(lease.StateReconnecting),
			).Scan(&keyCount); err != nil {
				return err
			}
			if keyCount >= maxPersistentLeasesPerKey {
				return apperr.E(apperr.CodeQuotaLease, "persistent lease quota exceeded for agent key", nil)
			}
			if err := tx.QueryRow(
				`SELECT COUNT(*) FROM leases WHERE tenant_id=? AND COALESCE(persistent, 0)!=0 AND status IN (?,?)`,
				tenantID, string(lease.StateActive), string(lease.StateReconnecting),
			).Scan(&tenantCount); err != nil {
				return err
			}
			if tenantCount >= maxPersistentLeasesPerTenant {
				return apperr.E(apperr.CodeQuotaLease, "persistent lease quota exceeded for tenant", nil)
			}
		}
		var expires any
		if intent.TTLSeconds > 0 {
			expires = now.Add(time.Duration(intent.TTLSeconds) * time.Second).Format(time.RFC3339Nano)
		}
		if _, err := tx.Exec(
			`INSERT INTO leases(id, tenant_id, agent_key_id, hostname, label, port, access_mode, generation, status, expires_at, persistent, created_at)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			id, tenantID, keyID, hostname, label, intent.Port, mode, 1, lease.StateActive, expires, persistentVal, now.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		if retiredID != "" {
			// Same-owner reclaim: carry live publications to the
			// replacement lease atomically, preserving the stable
			// public route — but never its verification: the new
			// upstream binding is unproven until re-verified (P0).
			// Revoked publications keep their tombstone.
			//
			// EXCEPTION: a MANAGED publication has no upstream binding
			// to prove — the relay is the Authorization Server. Clearing
			// its verified_at would 404 the route forever, because there
			// is no discovery verification to re-activate it. Its
			// verification is the operator's grant, which survives the
			// restart untouched, so it is preserved.
			if _, err := tx.Exec(
				`UPDATE mcp_publications SET lease_id=?,
				   verified_at=CASE WHEN profile=? THEN verified_at ELSE NULL END,
				   updated_at=?
				 WHERE lease_id=? AND revoked_at IS NULL`,
				id, ingressProfileManaged, now.Format(time.RFC3339Nano), retiredID); err != nil {
				return err
			}
		}
		if sharePrepared {
			if err := insertAccessTokenRow(tx, id, "visitor", 1, shareRow); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if reclaimDenied {
			// Audited outside the transaction: the audit store shares the
			// relay's single connection, which the transaction holds.
			s.db.Audit("agent", tenantID, "", "lease_reclaim", "denied",
				"named host held by a different agent key in this tenant")
		}
		if isUniqueConflict(err) {
			return nil, attachedMsg{}, apperr.E(apperr.CodeConflict, "hostname already allocated", nil)
		}
		var ae *apperr.Error
		if asApperr(err, &ae) {
			return nil, attachedMsg{}, err
		}
		return nil, attachedMsg{}, apperr.E(apperr.CodeStoreFault, "allocating lease", err)
	}
	if reboundPersistent {
		s.evictIfOlder(id, reboundGen)
		s.db.Audit("agent", tenantID, id, "lease_rebind", "ok", "persistent lease rebound; visitor sessions preserved")
	} else if retiredID != "" && retiredID != id {
		// The reclaimed lease loses forwarding authority immediately:
		// kill its live session and drop its budget (P1-04).
		s.evictLease(retiredID)
		s.db.Audit("agent", tenantID, retiredID, "lease_reclaim", "ok", "named lease replaced; old session retired")
	}
	var expiresAt time.Time
	if intent.TTLSeconds > 0 {
		expiresAt = now.Add(time.Duration(intent.TTLSeconds) * time.Second)
	}
	gen := uint64(1)
	if reboundPersistent {
		gen = reboundGen
	}
	ls := &lease.Lease{ID: id, TenantID: tenantID, AgentKeyID: keyID, Hostname: hostname,
		Port: intent.Port, AccessMode: mode, State: lease.StateActive, Generation: gen, ExpiresAt: expiresAt}
	// Every protected lease gets one initial single-redeem share token; the
	// raw secret goes to the agent over the authenticated session only.
	// The verifier committed inside the allocation transaction above, so
	// the share URL is always backed by a durable row here.
	att := s.attachedFor(ls)
	if sharePrepared {
		att.ShareURL = "https://" + hostname + "/_ocliv/unlock#t=" + shareRaw
	}
	s.db.Audit("agent", tenantID, id, "lease_allocate", "ok", "mode="+mode)
	return ls, att, nil
}

func isUniqueConflict(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}

// reconcileBoot repairs durable lifecycle state after a restart (F01, F11,
// AS-083). In-memory sessions are gone, so every ACTIVE row becomes
// RECONNECTING with a fresh grace window, rows already past a persisted
// deadline (grace or TTL, in either state) become EXPIRED, and every
// surviving RECONNECTING row gets its in-memory expiry timer re-armed. No
// traffic routes until the owner reauthenticates and resumes.
// Every persistence failure is returned: New refuses startup rather than
// serving on unknown durable state (P1-05).
func (s *Server) reconcileBoot() error {
	now := time.Now().UTC()
	// TTL-exhausted ACTIVE rows never come back.
	if _, err := s.db.SQL().Exec(
		`UPDATE leases SET status=? WHERE status=? AND expires_at IS NOT NULL AND expires_at < ?`,
		lease.StateExpired, lease.StateActive, now.Format(time.RFC3339Nano)); err != nil {
		return apperr.E(apperr.CodeStoreFault, "reconciling active leases", err)
	}
	// Rows already RECONNECTING past their persisted grace deadline — or
	// past TTL, which the old sweep missed (P1-05).
	if _, err := s.db.SQL().Exec(
		`UPDATE leases SET status=? WHERE status=?
		 AND ((reconnect_until IS NOT NULL AND reconnect_until < ?)
		   OR (expires_at IS NOT NULL AND expires_at < ?))`,
		lease.StateExpired, lease.StateReconnecting,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return apperr.E(apperr.CodeStoreFault, "reconciling reconnecting leases", err)
	}
	// Surviving ACTIVE rows: ephemeral leases enter RECONNECTING with a
	// bounded grace window; persistent hosted leases enter RECONNECTING with
	// reconnect_until=NULL so they survive arbitrarily long restarts/outages.
	if _, err := s.db.SQL().Exec(
		`UPDATE leases
		 SET status=?,
		     reconnect_until=CASE WHEN COALESCE(persistent, 0) != 0 THEN NULL ELSE ? END
		 WHERE status=?`,
		lease.StateReconnecting, now.Add(lease.ReconnectGrace).Format(time.RFC3339Nano), lease.StateActive); err != nil {
		return apperr.E(apperr.CodeStoreFault, "reconciling active leases", err)
	}
	// Bound audit evidence (Stage 6, chaos finding A2): every denied
	// request writes an audit row, so prune rows older than the
	// documented retention window. Revocation authority lives in
	// leases/agent_keys, not audit rows, so pruning cannot resurrect
	// access. Like every other persistence failure here, a prune error
	// refuses startup rather than serving on unknown durable state.
	if _, err := s.db.PruneAuditEvents(now); err != nil {
		return apperr.E(apperr.CodeStoreFault, "pruning audit events", err)
	}
	// Authorization-plane lifecycle (schemaV11): expired codes, consumed
	// or expired consent challenges, and revocations past their retention
	// window. Pruning cannot resurrect access — authority lives in
	// grants and clients — and, like every other persistence failure
	// here, a prune error refuses startup rather than serving on unknown
	// durable state. Absent when the relay has no managed mode.
	if s.authz != nil {
		if err := s.authz.Store().PruneAuthzExpired(now); err != nil {
			return apperr.E(apperr.CodeStoreFault, "pruning authorization state", err)
		}
	}
	// Re-arm in-memory expiry for ephemeral rows still waiting on a resume.
	rows, err := s.db.SQL().Query(
		`SELECT id, reconnect_until FROM leases WHERE status=? AND COALESCE(persistent, 0)=0`, lease.StateReconnecting)
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "reconciling expiry timers", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var until sql.NullString
		if err := rows.Scan(&id, &until); err != nil {
			continue
		}
		at := now.Add(lease.ReconnectGrace)
		if until.Valid {
			if t, err := time.Parse(time.RFC3339Nano, until.String); err == nil {
				at = t
			}
		}
		s.armExpiry(id, at)
	}
	return rows.Err()
}
