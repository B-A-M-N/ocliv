package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
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
		stBefore := queryUnitState(rec.SystemdUnit, ops)
		if stBefore != "not-found" && stBefore != "not-configured" {
			_, stopErr := ops.systemctl("stop", rec.SystemdUnit)
			act := queryUnitState(rec.SystemdUnit, ops)
			if act == "active" || act == "activating" || act == "deactivating" {
				localStopped = false
				localErr = fmt.Sprintf("local publisher unit still %s (%v)", act, stopErr)
			}
		}
	}
	if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
		stBe := queryUnitState(rec.BackendUnit, ops)
		if stBe != "not-found" && stBe != "not-configured" {
			_, _ = ops.systemctl("stop", rec.BackendUnit)
		}
	}

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
		_, _ = ops.systemctl("stop", rec.SystemdUnit)
	}
	if rec.BackendMode == config.BackendManaged && rec.BackendUnit != "" {
		_, _ = ops.systemctl("stop", rec.BackendUnit)
	}
	if envPath, err := serviceEnvPath(rec); err == nil {
		_ = os.Remove(envPath)
	}
	_, err := store.Delete(rec.Name)
	return err
}

func forgetLocalService(store *config.ServiceStore, rec config.ServiceRecord, ops serviceOps) error {
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
