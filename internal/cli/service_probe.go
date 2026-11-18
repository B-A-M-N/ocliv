package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ocliv/internal/config"
	"ocliv/internal/identity"
)

// ServiceStatusReport is the structured diagnostic output for `ocliv service status --json`.
type ServiceStatusReport struct {
	Name                 string                       `json:"name"`
	Type                 string                       `json:"type"`
	Profile              string                       `json:"profile"`
	BackendMode          string                       `json:"backend_mode"`
	DesiredState         string                       `json:"desired_state"`
	Revision             int64                        `json:"revision"`
	StateGeneration      int64                        `json:"state_generation,omitempty"`
	State                string                       `json:"state"`
	Health               string                       `json:"health"`
	ProcessState         string                       `json:"process_state"`
	UnitEnabled          bool                         `json:"unit_enabled"`
	BackendUnitState     string                       `json:"backend_unit_state,omitempty"`
	RelayState           string                       `json:"relay_state"`
	PublicationID        string                       `json:"publication_id,omitempty"`
	LeaseID              string                       `json:"lease_id,omitempty"`
	PublicURL            string                       `json:"public_url,omitempty"`
	AuthProfile          string                       `json:"auth_profile"`
	BackendAvailable     bool                         `json:"backend_available"`
	BackendDetail        string                       `json:"backend_detail,omitempty"`
	PublicTransport      bool                         `json:"public_transport"`
	PublicVerified       bool                         `json:"public_verified"`
	VerificationLevel    string                       `json:"verification_level,omitempty"`
	VerificationEvidence *config.VerificationEvidence `json:"verification_evidence,omitempty"`
	IngressReady         bool                         `json:"ingress_ready"`
	IngressDetail        string                       `json:"ingress_detail,omitempty"`
	LastVerifiedAt       string                       `json:"last_verified_at,omitempty"`
	LastFailure          string                       `json:"last_failure,omitempty"`
	LastRecoveryAction   string                       `json:"last_recovery_action,omitempty"`
	Reconcile            *config.ReconcileStatus      `json:"reconcile,omitempty"`
}

func inspectServiceStatus(rec config.ServiceRecord, k *identity.KeyPair, keyID string, ops serviceOps) ServiceStatusReport {
	prof := rec.Profile
	if prof == "" {
		prof = "default"
	}
	bmode := rec.BackendMode
	if bmode == "" {
		bmode = config.BackendAttached
	}
	rep := ServiceStatusReport{
		Name:               rec.Name,
		Type:               rec.Type,
		Profile:            prof,
		BackendMode:        bmode,
		DesiredState:       rec.DesiredState,
		Revision:           rec.Revision,
		StateGeneration:    rec.StateGeneration,
		State:              ServiceStateConfigured,
		Health:             HealthUnknown,
		ProcessState:       "unknown",
		RelayState:         "unknown",
		PublicationID:      rec.PublicationID,
		PublicURL:          rec.PublicURL,
		PublicVerified:     false,
		AuthProfile:        rec.Auth,
		LastVerifiedAt:     rec.LastVerifiedAt,
		LastFailure:        rec.LastFailure,
		LastRecoveryAction: rec.LastRecoveryAction,
		Reconcile:          rec.Reconcile,
	}

	// 1. Supervisor process state (distinguishing not-found vs inactive vs failed vs manager-unreachable).
	unitInfo := inspectUnit(rec.SystemdUnit, ops)
	rep.ProcessState = unitInfo.ActiveState
	rep.UnitEnabled = unitInfo.Enabled
	if !unitInfo.ManagerReachable && unitInfo.Error != "" {
		rep.LastFailure = unitInfo.Error
	}
	if bmode == config.BackendManaged && rec.BackendUnit != "" {
		rep.BackendUnitState = queryUnitState(rec.BackendUnit, ops)
	}

	// 2. Local backend availability & protocol readiness.
	if len(rec.StdioCmd) > 0 {
		rep.BackendAvailable = true
		rep.BackendDetail = "stdio subprocess configured"
	} else if target, _, err := localTargetFromURL(rec.LocalURL); err != nil {
		rep.BackendDetail = err.Error()
	} else if perr := ops.probeLoc(target, 2*time.Second); perr != nil {
		rep.BackendDetail = perr.Error()
	} else {
		rep.BackendAvailable = true
		rep.BackendDetail = "reachable"
	}
	if rep.BackendAvailable {
		rep.VerificationLevel = "LOCAL_READY"
	}

	// HTTP tunnel services have their own lifecycle independent of MCP route inventory.
	if rec.Type == "http" {
		rep.RelayState = "http-tunnel"
		if rec.DesiredState == config.DesiredDisabled {
			rep.State = ServiceStateDisabled
			rep.Health = HealthReady
			return rep
		}
		if rec.DesiredState == config.DesiredConfigured {
			rep.State = ServiceStateConfigured
			rep.Health = HealthReady
			return rep
		}
		if rep.ProcessState == "active" && rep.BackendAvailable {
			rep.State = ServiceStateServing
			rep.Health = HealthReady
			return rep
		}
		if rep.ProcessState == "activating" {
			rep.State = ServiceStateStarting
			rep.Health = HealthDegraded
			return rep
		}
		rep.State = ServiceStateOffline
		rep.Health = HealthFailed
		return rep
	}

	// 3. Authenticated relay inventory using the service's bound profile & relay.
	relayURL := rec.RelayURL
	if relayURL == "" {
		relayURL = agentRelayURLForProfile(prof)
	}
	st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes")
	if callErr != nil {
		rep.State = ServiceStateUnknown
		rep.Health = HealthUnknown
		rep.RelayState = "unreachable"
		rep.IngressDetail = callErr.Error()
		return rep
	}
	if st != http.StatusOK {
		rep.State = ServiceStateUnknown
		rep.Health = HealthUnknown
		rep.RelayState = fmt.Sprintf("http_%d", st)
		if st == http.StatusForbidden {
			rep.IngressDetail = fmt.Sprintf("relay auth 403 for profile=%q key=%s", prof, keyID)
		}
		return rep
	}

	var inv struct {
		Publications []struct {
			RouteID          string  `json:"route_id"`
			Name             string  `json:"pub_name"`
			Profile          string  `json:"profile"`
			URL              *string `json:"url"`
			LeaseID          *string `json:"lease_id"`
			PublicationState string  `json:"publication_state"`
			DesiredEnabled   bool    `json:"desired_enabled"`
			StateGeneration  int64   `json:"state_generation"`
			SessionLive      bool    `json:"session_live"`
			Admission        string  `json:"admission"`
			AdmissionReason  string  `json:"admission_reason"`
		} `json:"publications"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		rep.State = ServiceStateUnknown
		rep.Health = HealthUnknown
		rep.RelayState = "invalid_json"
		return rep
	}

	wantIngress := mcpIngressProfile(rec.Auth)
	var matched bool
	var pubState, admission, admissionReason string
	var relayDesired, sessionLive bool
	for _, p := range inv.Publications {
		if (rec.PublicationID != "" && p.RouteID == rec.PublicationID) ||
			(p.Name == rec.Name && (wantIngress == "" || p.Profile == wantIngress)) {
			matched = true
			rep.PublicationID = p.RouteID
			if p.URL != nil {
				rep.PublicURL = *p.URL
			}
			if p.LeaseID != nil {
				rep.LeaseID = *p.LeaseID
			}
			if p.StateGeneration > 0 {
				rep.StateGeneration = p.StateGeneration
			}
			pubState = p.PublicationState
			relayDesired = p.DesiredEnabled
			sessionLive = p.SessionLive
			admission = p.Admission
			admissionReason = p.AdmissionReason
			break
		}
	}

	if !matched {
		rep.RelayState = "not_registered"
		if rec.DesiredState == config.DesiredDisabled {
			rep.State = ServiceStateDisabled
			rep.Health = HealthReady
		} else if rec.DesiredState == config.DesiredConfigured {
			rep.State = ServiceStateConfigured
			rep.Health = HealthReady
		} else if rep.ProcessState == "activating" {
			rep.State = ServiceStateStarting
			rep.Health = HealthDegraded
		} else {
			rep.State = ServiceStateOffline
			rep.Health = HealthFailed
		}
		return rep
	}

	rep.RelayState = pubState
	if pubState != "" && pubState != "REVOKED" {
		rep.VerificationLevel = "RELAY_READY"
	}
	if pubState == "REVOKED" {
		rep.State = ServiceStateRevoked
		rep.Health = HealthBlocked
		rep.IngressDetail = "publication revoked"
		return rep
	}
	if rec.DesiredState == config.DesiredDisabled || !relayDesired {
		rep.State = ServiceStateDisabled
		if sessionLive {
			rep.Health = HealthDegraded
			rep.IngressDetail = "disabled but session still live"
		} else {
			rep.Health = HealthReady
			rep.IngressDetail = "disabled (404)"
		}
		return rep
	}

	// Desired enabled: separate transport check from structured verification evidence.
	if admission == "READY" && sessionLive && rep.BackendAvailable {
		if rep.PublicURL == "" {
			rep.State = ServiceStateOffline
			rep.Health = HealthDegraded
			rep.IngressDetail = "missing canonical public URL"
			return rep
		}
		code, err := ops.probePub(rep.PublicURL, 3*time.Second)
		if err == nil && (code == http.StatusUnauthorized || code == http.StatusOK) {
			rep.PublicTransport = true
			rep.VerificationLevel = "TRANSPORT_READY"
			if validEvidence(rec.VerificationEvidence, rep.PublicationID, rep.PublicURL, rep.StateGeneration) {
				rep.VerificationEvidence = rec.VerificationEvidence
				rep.VerificationLevel = rec.VerificationEvidence.Stage
				if rec.VerificationEvidence.Stage == "MCP_AUTHENTICATED" || rec.VerificationEvidence.Stage == "EXTERNAL_CLIENT_VERIFIED" {
					rep.PublicVerified = true
				}
			}
			rep.IngressReady = true
			rep.IngressDetail = fmt.Sprintf("HTTP %d (transport ok; stage=%s)", code, rep.VerificationLevel)
			rep.State = ServiceStateServing
			rep.Health = HealthReady
			return rep
		}
		rep.IngressDetail = fmt.Sprintf("probe code=%d err=%v", code, err)
		rep.State = ServiceStateOffline
		rep.Health = HealthDegraded
		return rep
	}
	if rep.ProcessState == "failed" || rep.ProcessState == "not-found" {
		rep.State = ServiceStateFaulted
		rep.Health = HealthFailed
		rep.IngressDetail = admissionReason
		return rep
	}
	if rep.ProcessState == "activating" {
		rep.State = ServiceStateStarting
		rep.Health = HealthDegraded
		rep.IngressDetail = admissionReason
		return rep
	}
	rep.State = ServiceStateOffline
	rep.Health = HealthFailed
	rep.IngressDetail = admissionReason
	return rep
}

func validEvidence(ev *config.VerificationEvidence, routeID, publicURL string, gen int64) bool {
	if ev == nil || ev.RouteID == "" || ev.PublicURL == "" {
		return false
	}
	switch ev.Stage {
	case "TRANSPORT_READY", "OAUTH_READY", "MCP_AUTHENTICATED", "EXTERNAL_CLIENT_VERIFIED":
	default:
		return false
	}
	if ev.RouteID != routeID || ev.PublicURL != publicURL {
		return false
	}
	if gen <= 0 || ev.StateGeneration <= 0 || ev.StateGeneration != gen {
		return false
	}
	if ev.VerifiedAt == "" || ev.ExpiresAt == "" {
		return false
	}
	verAt, err := time.Parse(time.RFC3339, ev.VerifiedAt)
	if err != nil {
		return false
	}
	now := time.Now()
	if verAt.After(now.Add(30 * time.Second)) {
		return false
	}
	exp, err := time.Parse(time.RFC3339, ev.ExpiresAt)
	if err != nil || now.After(exp) || exp.Before(verAt) {
		return false
	}
	return true
}
