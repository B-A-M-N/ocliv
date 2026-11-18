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

// stopServiceAuthoritatively enforces the security-first stop contract:
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

	// 2. Revoke public forwarding authority FIRST (for MCP services),
	//    recording any remote uncertainty without skipping local shutdown.
	var remoteErr string
	if rec.Type != "http" {
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

	res.RemoteDisabled = remoteErr == ""
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
	if rec.Type == "http" {
		return "", stopAndCleanupLocalService(store, rec, ops)
	}
	prof := rec.Profile
	if prof == "" {
		prof = "default"
	}
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURLForProfile(prof)
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

// reconcileServiceOnce reconciles a single service's runtime state against its
// persisted DesiredState under CAS discipline. It never restarts disabled or
// revoked services, never reapproves OAuth grants, and preserves PublicationID.
func reconcileServiceOnce(store *config.ServiceStore, name string, k *identity.KeyPair, keyID string, ops serviceOps, now time.Time) (ServiceStatusReport, error) {
	rec, ok, err := store.Get(name)
	if err != nil || !ok {
		return ServiceStatusReport{}, fmt.Errorf("unknown service %q", name)
	}
	rep := inspectServiceStatus(rec, k, keyID, ops)
	if rec.DesiredState != config.DesiredEnabled {
		if _, uerr := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
			r.Reconcile = &config.ReconcileStatus{
				ObservedGeneration: rep.StateGeneration,
				LastTransitionAt:   now.UTC().Format(time.RFC3339),
				LastErrorCode:      "DESIRED_NOT_ENABLED",
				LastConfirmedStage: rep.VerificationLevel,
				Terminal:           true,
			}
			return nil
		}); uerr != nil {
			return rep, uerr
		}
		return rep, nil
	}

	// Terminal fence: never restart or reauthorize revoked/auth-failed services.
	if rep.State == ServiceStateRevoked || rep.RelayState == "REVOKED" ||
		strings.Contains(strings.ToLower(rep.LastFailure), "ownership") ||
		strings.Contains(strings.ToLower(rep.LastFailure), "unauthorized") {
		if _, uerr := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
			r.Reconcile = &config.ReconcileStatus{
				ObservedGeneration: rep.StateGeneration,
				LastTransitionAt:   now.UTC().Format(time.RFC3339),
				LastErrorCode:      "TERMINAL_REVOKED_OR_AUTH",
				LastErrorDetail:    rep.LastFailure,
				LastConfirmedStage: rep.VerificationLevel,
				Terminal:           true,
			}
			return nil
		}); uerr != nil {
			return rep, uerr
		}
		return rep, nil
	}

	if rep.State == ServiceStateServing {
		if _, uerr := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
			if rep.PublicationID != "" && r.PublicationID == "" {
				r.PublicationID = rep.PublicationID
			}
			if rep.PublicURL != "" {
				r.PublicURL = rep.PublicURL
			}
			r.Reconcile = &config.ReconcileStatus{
				ObservedGeneration: rep.StateGeneration,
				Attempt:            0,
				LastTransitionAt:   now.UTC().Format(time.RFC3339),
				LastConfirmedStage: "SERVING",
				Terminal:           false,
			}
			return nil
		}); uerr != nil {
			return rep, uerr
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
	errCode := "TRANSIENT_NOT_SERVING"
	errDetail := rep.LastFailure
	if rep.ProcessState != "active" && rec.SystemdUnit != "" {
		if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
			_, _ = ops.systemctl("start", rec.BackendUnit)
		}
		if out, serr := ops.systemctl("start", rec.SystemdUnit); serr != nil {
			errCode = "SYSTEMD_START_FAILED"
			errDetail = fmt.Sprintf("%v (%s)", serr, strings.TrimSpace(out))
		}
	}
	nextRetry := now.Add(reconcileBackoff(attempt, now.UnixNano()))
	if _, uerr := store.UpdateCAS(rec.Name, rec.Revision, func(r *config.ServiceRecord) error {
		r.Reconcile = &config.ReconcileStatus{
			ObservedGeneration: rep.StateGeneration,
			Attempt:            attempt + 1,
			NextRetryAt:        nextRetry.UTC().Format(time.RFC3339),
			LastTransitionAt:   now.UTC().Format(time.RFC3339),
			LastErrorCode:      errCode,
			LastErrorDetail:    errDetail,
			LastConfirmedStage: rep.VerificationLevel,
			Terminal:           false,
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
