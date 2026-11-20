package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"ocliv/internal/config"
	"ocliv/internal/identity"
)

type relayInventoryItem struct {
	RouteID         string  `json:"route_id"`
	Name            string  `json:"pub_name"`
	Profile         string  `json:"profile"`
	URL             *string `json:"url"`
	DesiredEnabled  bool    `json:"desired_enabled"`
	StateGeneration int64   `json:"state_generation"`
	SessionLive     bool    `json:"session_live"`
}

// resolveRelayPublication queries the authenticated relay inventory for
// an exact (pub_name, profile) match. Ambiguous matches fail closed.
func resolveRelayPublication(relayURL string, k *identity.KeyPair, keyID string, rec config.ServiceRecord, ops serviceOps) (pubID, pubURL string, found bool, err error) {
	st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes")
	if callErr != nil {
		return "", "", false, fmt.Errorf("relay inventory unreachable: %w", callErr)
	}
	if st != http.StatusOK {
		return "", "", false, fmt.Errorf("relay inventory returned HTTP %d: %s", st, strings.TrimSpace(string(body)))
	}
	var inv struct {
		Publications []relayInventoryItem `json:"publications"`
	}
	if jerr := json.Unmarshal(body, &inv); jerr != nil {
		return "", "", false, fmt.Errorf("invalid relay inventory JSON: %w", jerr)
	}
	wantProfile := mcpIngressProfile(rec.Auth)
	var matches []relayInventoryItem
	for _, p := range inv.Publications {
		if rec.PublicationID != "" && p.RouteID == rec.PublicationID {
			matches = append(matches, p)
			continue
		}
		if p.Name == rec.Name && (wantProfile == "" || p.Profile == wantProfile) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		return "", "", false, nil
	}
	if len(matches) > 1 {
		return "", "", false, fmt.Errorf("ambiguous relay publications (%d matches for %q/%q); specify exact publication ID", len(matches), rec.Name, wantProfile)
	}
	m := matches[0]
	u := ""
	if m.URL != nil {
		u = *m.URL
	}
	return m.RouteID, u, true, nil
}

type relayHTTPLeaseItem struct {
	LeaseID        string `json:"lease_id"`
	Hostname       string `json:"hostname"`
	Label          string `json:"label"`
	Port           int    `json:"port"`
	AccessMode     string `json:"access_mode"`
	Status         string `json:"status"`
	Generation     int64  `json:"generation"`
	Persistent     bool   `json:"persistent,omitempty"`
	URL            string `json:"url"`
	RouteLive      bool   `json:"route_live"`
	RouteAvailable bool   `json:"route_available"`
	ExpiresAt      string `json:"lease_expires_at,omitempty"`
}

// resolveRelayHTTPLeases queries the authenticated relay HTTP lease inventory
// and returns all leases owned by the calling key that match rec (using
// canonical lowercased wire-label comparison).
func resolveRelayHTTPLeases(relayURL string, k *identity.KeyPair, keyID string, rec config.ServiceRecord, ops serviceOps) ([]relayHTTPLeaseItem, error) {
	if ops.mgmtCall == nil {
		return nil, fmt.Errorf("relay management client unavailable")
	}
	st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/leases")
	if callErr != nil {
		return nil, fmt.Errorf("relay lease inventory unreachable: %w", callErr)
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("relay lease inventory returned HTTP %d: %s", st, strings.TrimSpace(string(body)))
	}
	var inv struct {
		Leases []relayHTTPLeaseItem `json:"leases"`
	}
	if jerr := json.Unmarshal(body, &inv); jerr != nil {
		return nil, fmt.Errorf("invalid relay lease inventory JSON: %w", jerr)
	}
	wantLabel := canonicalHTTPLabel(rec.Name)
	var matches []relayHTTPLeaseItem
	for _, l := range inv.Leases {
		if (rec.LeaseID != "" && l.LeaseID == rec.LeaseID) ||
			(wantLabel != "" && strings.ToLower(strings.TrimSpace(l.Label)) == wantLabel) ||
			(rec.PublicURL != "" && l.URL == rec.PublicURL) {
			matches = append(matches, l)
		}
	}
	return matches, nil
}

// validateIdentitySchemaVersion rejects unsupported future identity schema versions.
func validateIdentitySchemaVersion(rec config.ServiceRecord) error {
	if rec.Identity != nil && rec.Identity.SchemaVersion > config.CurrentIdentitySchemaVersion {
		return fmt.Errorf("unsupported identity schema version %d for service %q (max supported %d)",
			rec.Identity.SchemaVersion, rec.Name, config.CurrentIdentitySchemaVersion)
	}
	return nil
}

// identityNeedsBinding reports whether rec's HostedServiceIdentity is absent,
// older than CurrentIdentitySchemaVersion, or missing any required bound field.
func identityNeedsBinding(rec config.ServiceRecord) bool {
	if rec.Identity == nil {
		return true
	}
	if rec.Identity.SchemaVersion != config.CurrentIdentitySchemaVersion {
		return true
	}
	if rec.Identity.ServiceID == "" || rec.Identity.Name != rec.Name || rec.Identity.OwnerKeyID == "" || rec.Identity.RelayID == "" {
		return true
	}
	return false
}

func hasPriorPublicationEvidence(rec config.ServiceRecord) bool {
	return rec.PublicationID != "" || rec.LeaseID != "" || rec.PublicURL != ""
}

// migrateLegacyServiceIdentity binds a durable HostedServiceIdentity onto a
// pre-remediation or incompletely bound ServiceRecord only after proving
// ownership against the authenticated relay inventory whenever prior
// publication evidence exists. Read-only status never calls this function.
func migrateLegacyServiceIdentity(store *config.ServiceStore, rec config.ServiceRecord, k *identity.KeyPair, keyID, relayURL string, ops serviceOps) (config.ServiceRecord, error) {
	if err := validateIdentitySchemaVersion(rec); err != nil {
		return rec, err
	}
	if !identityNeedsBinding(rec) {
		return rec, nil
	}
	// If an owner key or relay ID is already recorded, it must match before binding.
	if err := verifyServiceIdentityOwnership(rec, keyID, relayURL); err != nil {
		return rec, err
	}
	resolvedPubID := rec.PublicationID
	resolvedURL := rec.PublicURL
	if rec.Type == "http" {
		if hasPriorPublicationEvidence(rec) {
			matches, err := resolveRelayHTTPLeases(relayURL, k, keyID, rec, ops)
			if err != nil {
				return rec, fmt.Errorf("legacy identity migration blocked for HTTP service %q: %w", rec.Name, err)
			}
			if len(matches) == 0 {
				return rec, fmt.Errorf("legacy identity migration denied for HTTP service %q: existing lease/URL not owned by key %s", rec.Name, keyID)
			}
		}
	} else if hasPriorPublicationEvidence(rec) {
		if ops.mgmtCall == nil {
			return rec, fmt.Errorf("legacy identity migration blocked for service %q: relay client unavailable", rec.Name)
		}
		foundID, foundURL, found, rerr := resolveRelayPublication(relayURL, k, keyID, rec, ops)
		if rerr != nil {
			return rec, fmt.Errorf("legacy identity migration blocked for service %q: %w", rec.Name, rerr)
		}
		if !found {
			return rec, fmt.Errorf("legacy identity migration denied for service %q: publication %q is not owned by key %s", rec.Name, rec.PublicationID, keyID)
		}
		if resolvedPubID == "" {
			resolvedPubID = foundID
		}
		if resolvedURL == "" && foundURL != "" {
			resolvedURL = foundURL
		}
	}
	svcID := ""
	if rec.Identity != nil && rec.Identity.ServiceID != "" {
		svcID = rec.Identity.ServiceID
	} else {
		var idErr error
		svcID, idErr = config.NewServiceID()
		if idErr != nil {
			return rec, idErr
		}
	}
	migrated, err := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
		r.Identity = &config.HostedServiceIdentity{
			SchemaVersion: config.CurrentIdentitySchemaVersion,
			ServiceID:     svcID,
			Name:          r.Name,
			OwnerKeyID:    keyID,
			RelayID:       relayAuthority(relayURL),
			PublicationID: resolvedPubID,
		}
		if resolvedPubID != "" && r.PublicationID == "" {
			r.PublicationID = resolvedPubID
		}
		if resolvedURL != "" && r.PublicURL == "" {
			r.PublicURL = resolvedURL
		}
		return nil
	})
	if err != nil {
		return rec, err
	}
	return migrated, nil
}

// confirmHTTPOffline verifies public denial on /_ocliv/healthz (or probePub
// fallback in legacy mocks). ONLY 404 or 503 constitutes offline proof; 200,
// 401, 403, and 3xx all indicate a live route and fail verification.
func confirmHTTPOffline(publicURL string, ops serviceOps) error {
	if publicURL == "" {
		return nil
	}
	var code int
	var err error
	if ops.probeEdge != nil {
		code, err = ops.probeEdge(publicURL, 5*time.Second)
	} else if ops.probePub != nil {
		code, err = ops.probePub(publicURL, 5*time.Second)
	} else {
		return nil
	}
	if err != nil {
		return fmt.Errorf("public HTTP route denial probe failed: %w", err)
	}
	if code != http.StatusNotFound && code != http.StatusServiceUnavailable {
		return fmt.Errorf("public HTTP route still reachable (HTTP %d; require 404 or 503)", code)
	}
	return nil
}

// revokeAllMatchingHTTPLeases revokes rec.LeaseID (if known) AND sweeps the
// authoritative /v1/agent/leases inventory whenever LeaseID is missing or
// returned 404 (stale LeaseID), ensuring no rebound lease survives disable/remove.
func revokeAllMatchingHTTPLeases(relayURL string, k *identity.KeyPair, keyID string, rec config.ServiceRecord, ops serviceOps) (revokedIDs []string, discoveredURL string, err error) {
	if ops.mgmtCall == nil {
		return nil, "", fmt.Errorf("relay management client unavailable during HTTP lease revoke")
	}
	needSweep := rec.LeaseID == ""
	if rec.LeaseID != "" {
		st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/lease/"+rec.LeaseID+"/revoke")
		if callErr != nil {
			return nil, "", fmt.Errorf("relay unreachable during HTTP lease revoke: %w", callErr)
		}
		switch st {
		case http.StatusOK:
			revokedIDs = append(revokedIDs, rec.LeaseID)
		case http.StatusNotFound:
			// Stale LeaseID: DO NOT conclude success — sweep authoritative inventory!
			needSweep = true
		default:
			return nil, "", fmt.Errorf("relay HTTP lease revoke returned %d: %s", st, strings.TrimSpace(string(body)))
		}
	}
	if needSweep {
		matches, lerr := resolveRelayHTTPLeases(relayURL, k, keyID, rec, ops)
		if lerr != nil {
			return revokedIDs, discoveredURL, fmt.Errorf("cannot resolve remote HTTP lease for disable: %w", lerr)
		}
		for _, m := range matches {
			if m.Status == "ACTIVE" || m.Status == "RECONNECTING" || m.RouteLive {
				if discoveredURL == "" && m.URL != "" {
					discoveredURL = m.URL
				}
				st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/lease/"+m.LeaseID+"/revoke")
				if callErr != nil {
					return revokedIDs, discoveredURL, fmt.Errorf("relay unreachable during HTTP lease revoke: %w", callErr)
				}
				if st != http.StatusOK && st != http.StatusNotFound {
					return revokedIDs, discoveredURL, fmt.Errorf("relay HTTP lease revoke returned %d: %s", st, strings.TrimSpace(string(body)))
				}
				revokedIDs = append(revokedIDs, m.LeaseID)
			}
		}
	}
	return revokedIDs, discoveredURL, nil
}

// clearLocalRevokedLeases removes confirmed-revoked HTTP lease IDs from both
// ServiceRecord.LeaseID and the agent LeaseStore while preserving permanent
// service identity and stable PublicURL so subsequent `start` allocates cleanly.
func clearLocalRevokedLeases(store *config.ServiceStore, rec config.ServiceRecord, revokedIDs []string) {
	_, _ = store.UpdateCAS(rec.Name, 0, func(r *config.ServiceRecord) error {
		r.LeaseID = ""
		return nil
	})
	prof := rec.Profile
	if prof == "" {
		prof = "default"
	}
	if dir, err := config.DataDirForProfile(prof); err == nil {
		if ls, lerr := config.OpenLeaseStore(dir); lerr == nil {
			seen := map[string]bool{}
			if rec.LeaseID != "" {
				seen[rec.LeaseID] = true
				_ = ls.Remove(rec.LeaseID)
			}
			for _, id := range revokedIDs {
				if id != "" && !seen[id] {
					seen[id] = true
					_ = ls.Remove(id)
				}
			}
		}
	}
}

// 1. Persist DesiredDisabled locally.
// 2. Disable public forwarding on the relay FIRST (desired_enabled=0, close lease, evict session).
// 3. Confirm public route admission is denied (404/503).
// 4. Stop local supervisor units (publisher + managed backend if any).
// Never deletes/unpublishes the route and never converts uncertainty into success.
func stopServiceAuthoritatively(store *config.ServiceStore, rec config.ServiceRecord, k *identity.KeyPair, keyID string, ops serviceOps) serviceStopResult {
	res := serviceStopResult{
		Name:          rec.Name,
		PublicationID: rec.PublicationID,
		RetainedURL:   rec.PublicURL,
	}

	prevDesired := rec.DesiredState

	// 1. Record desired disabled state durably via CAS.
	updated, err := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
		r.DesiredState = config.DesiredDisabled
		return nil
	})
	if err != nil {
		res.State = ServiceStateUnknown
		res.Detail = "failed to persist desired disabled state: " + err.Error()
		return res
	}
	rec = updated

	prof := rec.Profile
	if prof == "" {
		prof = "default"
	}
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURLForProfile(prof)
	}

	// Enforce ownership invariant before reasoning about remote absence.
	// Never interpret "nothing visible under key B" as "nothing exists under key A".
	// When an explicit PublicationID or LeaseID is already known, the signed
	// POST /disable or /revoke itself enforces relay-side ownership directly
	// without requiring an extra preflight GET inventory round-trip.
	var remoteErr string
	needAbsenceProof := (rec.Type == "http" && rec.LeaseID == "") || (rec.Type != "http" && rec.PublicationID == "")
	if err := validateIdentitySchemaVersion(rec); err != nil {
		remoteErr = err.Error()
	} else if err := verifyServiceIdentityOwnership(rec, keyID, relayURL); err != nil {
		remoteErr = err.Error()
	} else if needAbsenceProof && identityNeedsBinding(rec) && hasPriorPublicationEvidence(rec) {
		if migrated, merr := migrateLegacyServiceIdentity(store, rec, k, keyID, relayURL, ops); merr != nil {
			remoteErr = merr.Error()
		} else {
			rec = migrated
		}
	}

	// 2. Revoke public forwarding authority FIRST (for MCP routes AND HTTP leases),
	//    recording any remote uncertainty without skipping local shutdown.
	httpNeverPublished := rec.Type == "http" && rec.LeaseID == "" && rec.PublicURL == "" && prevDesired == config.DesiredConfigured
	var revokedHTTPIDs []string
	if remoteErr == "" && rec.Type == "http" {
		if !httpNeverPublished {
			ids, discURL, rerr := revokeAllMatchingHTTPLeases(relayURL, k, keyID, rec, ops)
			revokedHTTPIDs = ids
			if res.RetainedURL == "" && discURL != "" {
				res.RetainedURL = discURL
			}
			if rerr != nil {
				remoteErr = rerr.Error()
			}
			if len(revokedHTTPIDs) > 0 {
				// Any lease ID already confirmed revoked by the relay must be
				// cleared locally immediately so a subsequent `service start`
				// never attempts to resume a dead REVOKED lease even if the
				// public edge denial probe is unconfirmed.
				clearLocalRevokedLeases(store, rec, revokedHTTPIDs)
			}
			if remoteErr == "" && res.RetainedURL != "" {
				if perr := confirmHTTPOffline(res.RetainedURL, ops); perr != nil {
					remoteErr = perr.Error()
				}
			}
		}
	} else if remoteErr == "" {
		pubID := rec.PublicationID
		if pubID == "" {
			foundID, foundURL, found, rerr := resolveRelayPublication(relayURL, k, keyID, rec, ops)
			if rerr != nil {
				remoteErr = rerr.Error()
			} else if found {
				pubID = foundID
				res.PublicationID = foundID
				if foundURL != "" {
					res.RetainedURL = foundURL
				}
				_, _ = store.UpdateCAS(rec.Name, 0, func(r *config.ServiceRecord) error {
					r.PublicationID = foundID
					if foundURL != "" {
						r.PublicURL = foundURL
					}
					return nil
				})
			}
		}

		if pubID != "" && remoteErr == "" {
			st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+pubID+"/disable")
			if callErr != nil {
				remoteErr = "relay unreachable during disable confirmation: " + callErr.Error()
			} else if st != http.StatusOK && st != http.StatusNotFound {
				remoteErr = fmt.Sprintf("relay disable returned %d: %s", st, strings.TrimSpace(string(body)))
			} else if st == http.StatusOK {
				var dis struct {
					DesiredEnabled  bool  `json:"desired_enabled"`
					StateGeneration int64 `json:"state_generation"`
					SessionLive     bool  `json:"session_live"`
				}
				if err := json.Unmarshal(body, &dis); err != nil || dis.DesiredEnabled || dis.SessionLive {
					remoteErr = "relay did not confirm session teardown"
				} else {
					_, _ = store.UpdateCAS(rec.Name, 0, func(r *config.ServiceRecord) error {
						if dis.StateGeneration > 0 {
							r.StateGeneration = dis.StateGeneration
						}
						return nil
					})
				}
			}
		}

		// 3. Confirm public-route admission is denied (404/503, never 200/401).
		if remoteErr == "" && res.RetainedURL != "" {
			code, err := ops.probePub(res.RetainedURL, 5*time.Second)
			if err != nil {
				remoteErr = "public route denial probe failed: " + err.Error()
			} else if code != http.StatusNotFound && code != http.StatusServiceUnavailable {
				remoteErr = fmt.Sprintf("public route still answered HTTP %d after disable", code)
			}
		}
	}

	// 4. Always stop local supervisor units once DesiredDisabled is persisted.
	localStopped := true
	var localErr string
	if rec.SystemdUnit != "" {
		ev := stopAndVerifyUnit(rec.SystemdUnit, false, ops)
		if !ev.StoppedNow {
			localStopped = false
			localErr = ev.Error
		}
	}
	if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
		evBe := stopAndVerifyUnit(rec.BackendUnit, false, ops)
		if !evBe.StoppedNow {
			localStopped = false
			if localErr != "" {
				localErr += "; " + evBe.Error
			} else {
				localErr = evBe.Error
			}
		}
	}

	if remoteErr == "" && httpNeverPublished {
		res.RemoteDisabled = false
		res.RemoteDisableStatus = "NEVER_PUBLISHED"
	} else if remoteErr == "" {
		res.RemoteDisabled = true
		res.RemoteDisableStatus = "CONFIRMED"
	} else {
		res.RemoteDisabled = false
		if rec.Type == "http" {
			res.RemoteDisableStatus = "REMOTE_DISABLE_UNCONFIRMED"
		} else {
			res.RemoteDisableStatus = "UNCONFIRMED"
		}
	}
	res.LocalStopped = localStopped

	if remoteErr != "" {
		res.State = "STOP_UNCONFIRMED"
		if localStopped {
			res.Detail = "local units stopped, but remote disable unconfirmed: " + remoteErr
		} else {
			res.Detail = localErr + "; remote: " + remoteErr
		}
		return res
	}
	if !localStopped {
		res.State = "STOP_UNCONFIRMED"
		res.Detail = "public route disabled, but " + localErr
		return res
	}

	res.Stopped = true
	res.State = ServiceStateDisabled
	return res
}

func stopAndCleanupLocalService(store *config.ServiceStore, rec config.ServiceRecord, ops serviceOps) error {
	if rec.SystemdUnit != "" {
		ev := stopAndVerifyUnit(rec.SystemdUnit, true, ops)
		if !ev.StoppedNow || !ev.DisabledForReboot {
			return fmt.Errorf("%s", ev.Error)
		}
	}
	if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
		evBe := stopAndVerifyUnit(rec.BackendUnit, true, ops)
		if !evBe.StoppedNow || !evBe.DisabledForReboot {
			return fmt.Errorf("%s", evBe.Error)
		}
	}
	if envPath, err := serviceEnvPath(rec); err == nil {
		_ = os.Remove(envPath)
	}
	_, err := store.Delete(rec.Name)
	return err
}

func forgetLocalService(store *config.ServiceStore, rec config.ServiceRecord, ops serviceOps) error {
	fmt.Fprintf(os.Stderr, "warning: --forget-local deletes local service %q without verifying or removing remote relay publication %q\n", rec.Name, rec.PublicationID)
	return stopAndCleanupLocalService(store, rec, ops)
}

// removeServiceAuthoritatively verifies remote publication ownership in the
// signed inventory, deletes it remotely, confirms absence, and only then
// stops local units and deletes the local service definition.
func removeServiceAuthoritatively(store *config.ServiceStore, rec config.ServiceRecord, k *identity.KeyPair, keyID string, ops serviceOps) (string, error) {
	prof := rec.Profile
	if prof == "" {
		prof = "default"
	}
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURLForProfile(prof)
	}
	// Enforce ownership invariant before reasoning about remote absence.
	if err := validateIdentitySchemaVersion(rec); err != nil {
		return "", err
	}
	if err := verifyServiceIdentityOwnership(rec, keyID, relayURL); err != nil {
		return "", err
	}
	needAbsenceProof := (rec.Type == "http" && rec.LeaseID == "") || (rec.Type != "http" && rec.PublicationID == "")
	if needAbsenceProof && identityNeedsBinding(rec) && hasPriorPublicationEvidence(rec) {
		migrated, merr := migrateLegacyServiceIdentity(store, rec, k, keyID, relayURL, ops)
		if merr != nil {
			return "", merr
		}
		rec = migrated
	}
	if rec.Type == "http" {
		httpNeverPublished := rec.LeaseID == "" && rec.PublicURL == "" && rec.DesiredState == config.DesiredConfigured
		if !httpNeverPublished {
			revokedIDs, discURL, rerr := revokeAllMatchingHTTPLeases(relayURL, k, keyID, rec, ops)
			if rerr != nil {
				return rec.LeaseID, fmt.Errorf("cannot verify/revoke remote HTTP lease before removal (retryable): %w", rerr)
			}
			checkURL := rec.PublicURL
			if checkURL == "" {
				checkURL = discURL
			}
			if checkURL != "" {
				if perr := confirmHTTPOffline(checkURL, ops); perr != nil {
					return rec.LeaseID, perr
				}
			}
			clearLocalRevokedLeases(store, rec, revokedIDs)
		}
		return rec.LeaseID, stopAndCleanupLocalService(store, rec, ops)
	}
	foundID, _, found, err := resolveRelayPublication(relayURL, k, keyID, rec, ops)
	if err != nil {
		return "", fmt.Errorf("cannot verify remote route before removal (retryable): %w", err)
	}
	if !found && rec.PublicationID != "" {
		return rec.PublicationID, fmt.Errorf("publication %q not found under current key (stale key or wrong owner; use --forget-local to remove local state only)", rec.PublicationID)
	}
	pubID := foundID
	if pubID != "" {
		st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodDelete, "/v1/agent/mcp-routes/"+pubID)
		if callErr != nil {
			return pubID, fmt.Errorf("relay delete failed (retryable): %w", callErr)
		}
		if st != http.StatusOK {
			return pubID, fmt.Errorf("relay delete returned HTTP %d: %s", st, strings.TrimSpace(string(body)))
		}
		// Confirm absence from the same authorized inventory.
		if _, _, stillPresent, verr := resolveRelayPublication(relayURL, k, keyID, rec, ops); verr != nil {
			return pubID, fmt.Errorf("cannot confirm remote route absence after delete: %w", verr)
		} else if stillPresent {
			return pubID, fmt.Errorf("publication %q still present in relay inventory after delete", pubID)
		}
	}
	if err := stopAndCleanupLocalService(store, rec, ops); err != nil {
		return pubID, err
	}
	return pubID, nil
}

// reconcileBackoff computes bounded exponential backoff (5s base, capped at 5m)
// with deterministic bounded jitter (up to +20%).
func reconcileBackoff(attempt uint32, jitterSeed int64) time.Duration {
	shift := attempt
	if shift > 6 {
		shift = 6
	}
	d := (5 * time.Second) << shift
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	if jitterSeed < 0 {
		jitterSeed = -jitterSeed
	}
	jitter := time.Duration(jitterSeed % int64(d/5+1))
	return d + jitter
}

var serviceTransitions struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func serviceFence(name string) *sync.Mutex {
	serviceTransitions.mu.Lock()
	defer serviceTransitions.mu.Unlock()
	if serviceTransitions.m == nil {
		serviceTransitions.m = map[string]*sync.Mutex{}
	}
	l, ok := serviceTransitions.m[name]
	if !ok {
		l = &sync.Mutex{}
		serviceTransitions.m[name] = l
	}
	return l
}

func classifyFailureLayer(rep ServiceStatusReport) (layer, classification, code string) {
	if rep.State == ServiceStateRevoked || rep.RelayState == "REVOKED" ||
		rep.Layers.Authorization == "revoked" || rep.Layers.Authorization == "forbidden" ||
		strings.Contains(strings.ToLower(rep.LastFailure), "ownership") ||
		strings.Contains(strings.ToLower(rep.LastFailure), "unauthorized") {
		return "authorization", "terminal", "TERMINAL_REVOKED_OR_AUTH"
	}
	if !rep.BackendAvailable {
		return "backend", "retryable", "BACKEND_UNAVAILABLE"
	}
	if rep.ProcessState != "active" {
		return "process", "retryable", "PROCESS_NOT_ACTIVE"
	}
	if rep.Layers.Edge == "tls_error" {
		return "edge", "retryable", "EDGE_TLS_ERROR"
	}
	if rep.Layers.Edge == "unreachable" {
		return "edge", "retryable", "EDGE_UNREACHABLE"
	}
	if rep.Layers.Agent == "disconnected" {
		return "agent", "retryable", "AGENT_DISCONNECTED"
	}
	if rep.Layers.Lease == "offline" || rep.Layers.Lease == "expired" || rep.Layers.Lease == "stale" || rep.Layers.Lease == "unknown" {
		return "lease", "retryable", "LEASE_OFFLINE"
	}
	return "publication", "retryable", "TRANSIENT_NOT_SERVING"
}

// reconcileServiceOnce reconciles a single service's runtime state against its
// persisted DesiredState under CAS discipline and a per-service transition fence.
// It never restarts disabled or revoked services, never reapproves OAuth grants,
// triggers the narrowest safe recovery per failing layer, and stops the unit
// if a concurrent disable committed during restart.
func reconcileServiceOnce(store *config.ServiceStore, name string, k *identity.KeyPair, keyID string, ops serviceOps, now time.Time) (ServiceStatusReport, error) {
	fence := serviceFence(name)
	fence.Lock()
	defer fence.Unlock()

	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		return ServiceStatusReport{}, fmt.Errorf("unknown service %q", name)
	}
	prevGoodGen := int64(0)
	prevGoodURL := rec.PublicURL
	if rec.Reconcile != nil {
		prevGoodGen = rec.Reconcile.LastGoodGeneration
		if rec.Reconcile.LastVerifiedPublicURL != "" {
			prevGoodURL = rec.Reconcile.LastVerifiedPublicURL
		}
	}

	relayURL := rec.RelayURL
	if relayURL == "" {
		prof := rec.Profile
		if prof == "" {
			prof = "default"
		}
		relayURL = agentRelayURLForProfile(prof)
	}
	if oerr := verifyServiceIdentityOwnership(rec, keyID, relayURL); oerr != nil {
		rep := ServiceStatusReport{
			Name:        rec.Name,
			State:       ServiceStateRevoked,
			Health:      HealthBlocked,
			LastFailure: oerr.Error(),
		}
		_, _ = store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
			r.LastFailure = oerr.Error()
			r.Reconcile = &config.ReconcileStatus{
				ObservedGeneration:    r.StateGeneration,
				LastGoodGeneration:    prevGoodGen,
				LastTransitionAt:      now.UTC().Format(time.RFC3339),
				FailureLayer:          "authorization",
				ErrorClassification:   "terminal",
				LastErrorCode:         "TERMINAL_OWNERSHIP_MISMATCH",
				LastErrorDetail:       oerr.Error(),
				LastVerifiedPublicURL: prevGoodURL,
				Terminal:              true,
			}
			return nil
		})
		return rep, nil
	}

	rep := inspectServiceStatus(rec, k, keyID, ops)
	if rec.DesiredState != config.DesiredEnabled {
		if _, uerr := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
			r.Reconcile = &config.ReconcileStatus{
				ObservedGeneration:    rep.StateGeneration,
				LastGoodGeneration:    prevGoodGen,
				LastTransitionAt:      now.UTC().Format(time.RFC3339),
				ErrorClassification:   "terminal",
				LastErrorCode:         "DESIRED_NOT_ENABLED",
				LastConfirmedStage:    rep.VerificationLevel,
				LastVerifiedPublicURL: prevGoodURL,
				Terminal:              true,
			}
			return nil
		}); uerr != nil {
			return rep, uerr
		}
		return rep, nil
	}

	layer, classification, errCode := classifyFailureLayer(rep)

	// Terminal fence: never restart or reauthorize revoked/auth-failed services.
	if classification == "terminal" {
		if _, uerr := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
			r.Reconcile = &config.ReconcileStatus{
				ObservedGeneration:    rep.StateGeneration,
				LastGoodGeneration:    prevGoodGen,
				LastTransitionAt:      now.UTC().Format(time.RFC3339),
				FailureLayer:          layer,
				ErrorClassification:   "terminal",
				LastErrorCode:         errCode,
				LastErrorDetail:       rep.LastFailure,
				LastConfirmedStage:    rep.VerificationLevel,
				LastVerifiedPublicURL: prevGoodURL,
				Terminal:              true,
			}
			return nil
		}); uerr != nil {
			return rep, uerr
		}
		return rep, nil
	}

	if rep.State == ServiceStateServing && rec.ConfigGeneration <= rec.AppliedConfigGeneration {
		goodGen := rep.StateGeneration
		if goodGen == 0 {
			goodGen = prevGoodGen
		}
		goodURL := rep.PublicURL
		if goodURL == "" {
			goodURL = prevGoodURL
		}
		if _, uerr := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
			if rep.PublicationID != "" && r.PublicationID == "" {
				r.PublicationID = rep.PublicationID
				if r.Identity != nil {
					r.Identity.PublicationID = rep.PublicationID
				}
			}
			if rep.LeaseID != "" && r.LeaseID == "" {
				r.LeaseID = rep.LeaseID
			}
			if rep.PublicURL != "" {
				r.PublicURL = rep.PublicURL
			}
			if r.ConfigGeneration > r.AppliedConfigGeneration {
				r.AppliedConfigGeneration = r.ConfigGeneration
			}
			r.Reconcile = &config.ReconcileStatus{
				ObservedGeneration:    rep.StateGeneration,
				LastGoodGeneration:    goodGen,
				Attempt:               0,
				LastTransitionAt:      now.UTC().Format(time.RFC3339),
				LastConfirmedStage:    "SERVING",
				LastVerifiedPublicURL: goodURL,
				Terminal:              false,
			}
			return nil
		}); uerr != nil {
			return rep, uerr
		}
		return rep, nil
	}

	// Pending mutable target config change: restart publisher/backend to apply.
	if rec.ConfigGeneration > rec.AppliedConfigGeneration && rec.SystemdUnit != "" {
		if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
			_, _ = ops.systemctl("restart", rec.BackendUnit)
		}
		if out, serr := ops.systemctl("restart", rec.SystemdUnit); serr != nil {
			return rep, fmt.Errorf("config rebind restart failed: %v (%s)", serr, strings.TrimSpace(out))
		}
		return rep, nil
	}

	// Check bounded backoff before attempting restart.
	if rec.Reconcile != nil && rec.Reconcile.NextRetryAt != "" {
		if nextAt, perr := time.Parse(time.RFC3339, rec.Reconcile.NextRetryAt); perr == nil && now.Before(nextAt) {
			return rep, nil
		}
	}

	var attempt uint32
	if rec.Reconcile != nil {
		attempt = rec.Reconcile.Attempt
	}
	errDetail := rep.LastFailure
	if errDetail == "" {
		if layer == "backend" {
			errDetail = rep.BackendDetail
		} else {
			errDetail = rep.IngressDetail
		}
	}

	// Narrowest safe recovery by failing layer:
	// - Backend layer down with active publisher -> restart ONLY managed backend, retain route.
	// - Agent/publisher inactive -> restart publisher (and managed backend if applicable).
	if layer == "backend" && rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
		freshRec, fok, ferr := store.Get(name)
		if ferr != nil || !fok || freshRec.DesiredState != config.DesiredEnabled {
			return rep, nil
		}
		if out, serr := ops.systemctl("restart", rec.BackendUnit); serr != nil {
			errCode = "BACKEND_RESTART_FAILED"
			errDetail = fmt.Sprintf("%v (%s)", serr, strings.TrimSpace(out))
		} else if afterRec, aok, _ := store.Get(name); aok && afterRec.DesiredState != config.DesiredEnabled {
			_, _ = ops.systemctl("stop", rec.BackendUnit)
			return rep, fmt.Errorf("concurrent disable committed during backend restart for %q", name)
		}
	} else if rep.ProcessState != "active" && rec.SystemdUnit != "" {
		// Re-read DesiredState immediately before external restart side effects.
		freshRec, fok, ferr := store.Get(name)
		if ferr != nil || !fok || freshRec.DesiredState != config.DesiredEnabled {
			return rep, nil
		}
		if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
			_, _ = ops.systemctl("start", rec.BackendUnit)
		}
		if out, serr := ops.systemctl("start", rec.SystemdUnit); serr != nil {
			errCode = "SYSTEMD_START_FAILED"
			errDetail = fmt.Sprintf("%v (%s)", serr, strings.TrimSpace(out))
		} else {
			// Recheck DesiredState after restart; stop immediately if concurrently disabled.
			if afterRec, aok, _ := store.Get(name); aok && afterRec.DesiredState != config.DesiredEnabled {
				_, _ = ops.systemctl("stop", rec.SystemdUnit)
				if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
					_, _ = ops.systemctl("stop", rec.BackendUnit)
				}
				return rep, fmt.Errorf("concurrent disable committed during restart for %q", name)
			}
		}
	}
	nextRetry := now.Add(reconcileBackoff(attempt, now.UnixNano()))
	if _, uerr := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
		r.Reconcile = &config.ReconcileStatus{
			ObservedGeneration:    rep.StateGeneration,
			LastGoodGeneration:    prevGoodGen,
			Attempt:               attempt + 1,
			NextRetryAt:           nextRetry.UTC().Format(time.RFC3339),
			LastTransitionAt:      now.UTC().Format(time.RFC3339),
			FailureLayer:          layer,
			ErrorClassification:   classification,
			LastErrorCode:         errCode,
			LastErrorDetail:       errDetail,
			LastConfirmedStage:    rep.VerificationLevel,
			LastVerifiedPublicURL: prevGoodURL,
			Terminal:              false,
		}
		return nil
	}); uerr != nil {
		return rep, uerr
	}
	return rep, nil
}

var activeReconcilers struct {
	mu sync.Mutex
	m  map[string]bool
}

// runServiceReconcilerLoop runs an initial reconciliation pass and periodic
// bounded passes until ctx is canceled, guaranteeing at most one active
// reconciler per service name in this process.
func runServiceReconcilerLoop(ctx context.Context, store *config.ServiceStore, name string, k *identity.KeyPair, keyID string, ops serviceOps, interval time.Duration) error {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	activeReconcilers.mu.Lock()
	if activeReconcilers.m == nil {
		activeReconcilers.m = map[string]bool{}
	}
	if activeReconcilers.m[name] {
		activeReconcilers.mu.Unlock()
		return fmt.Errorf("reconciler already active for service %q", name)
	}
	activeReconcilers.m[name] = true
	activeReconcilers.mu.Unlock()
	defer func() {
		activeReconcilers.mu.Lock()
		delete(activeReconcilers.m, name)
		activeReconcilers.mu.Unlock()
	}()

	runPass := func() {
		rep, err := reconcileServiceOnce(store, name, k, keyID, ops, time.Now())
		if err != nil && strings.Contains(err.Error(), "concurrent modification") {
			// Reload freshly on CAS conflict.
			rep, _ = reconcileServiceOnce(store, name, k, keyID, ops, time.Now())
		}
		_ = rep
	}
	runPass()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			runPass()
		}
	}
}
