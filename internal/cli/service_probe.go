package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

// ServiceLayers reports the independent, evidence-backed health of each
// hosting layer. Supervisor process state (`Process`) is kept strictly
// separate from authenticated transport connectivity (`Agent`), which is only
// `"connected"` when authoritative relay state confirms a live session.
type ServiceLayers struct {
	Process       string `json:"process"`
	Backend       string `json:"backend"`
	Agent         string `json:"agent"`
	Lease         string `json:"lease"`
	Publication   string `json:"publication"`
	Authorization string `json:"authorization"`
	Edge          string `json:"edge"`
	Client        string `json:"client"`
}

// ServiceStatusReport is the structured diagnostic output for `ocliv service status --json`.
type ServiceStatusReport struct {
	Name                 string                       `json:"name"`
	ServiceID            string                       `json:"service_id,omitempty"`
	Type                 string                       `json:"type"`
	Profile              string                       `json:"profile"`
	BackendMode          string                       `json:"backend_mode"`
	DesiredState         string                       `json:"desired_state"`
	Revision             int64                        `json:"revision"`
	StateGeneration      int64                        `json:"state_generation,omitempty"`
	State                string                       `json:"state"`
	Health               string                       `json:"health"`
	RunningNow           bool                         `json:"running_now"`
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
	Layers               ServiceLayers                `json:"layers"`
	LastVerifiedAt       string                       `json:"last_verified_at,omitempty"`
	LastFailure          string                       `json:"last_failure,omitempty"`
	LastRecoveryAction   string                       `json:"last_recovery_action,omitempty"`
	Reconcile            *config.ReconcileStatus      `json:"reconcile,omitempty"`
}

func canonicalHTTPLabel(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func localPortFromURL(raw string) int {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}

// resolveHostedHTTPLease discovers an authoritative live/reconnecting HTTP
// lease for a newly started hosted service whose ServiceRecord does not yet
// have a LeaseID. It requires exactly one match on canonical label, expected
// local port, and expected access mode, failing closed on 0 or >1 matches.
func resolveHostedHTTPLease(relayURL string, k *identity.KeyPair, keyID string, rec config.ServiceRecord, ops serviceOps) (*relayHTTPLeaseItem, error) {
	matches, err := resolveRelayHTTPLeases(relayURL, k, keyID, rec, ops)
	if err != nil {
		return nil, err
	}
	wantLabel := canonicalHTTPLabel(rec.Name)
	wantPort := localPortFromURL(rec.LocalURL)
	wantAuth := strings.TrimSpace(rec.Auth)
	if wantAuth == "" {
		wantAuth = "protected"
	}
	var eligible []relayHTTPLeaseItem
	for _, l := range matches {
		if l.Status != "ACTIVE" && l.Status != "RECONNECTING" {
			continue
		}
		if wantLabel != "" && strings.ToLower(strings.TrimSpace(l.Label)) != wantLabel {
			continue
		}
		if wantPort > 0 && l.Port > 0 && l.Port != wantPort {
			continue
		}
		if wantAuth != "" && l.AccessMode != "" && l.AccessMode != wantAuth {
			continue
		}
		eligible = append(eligible, l)
	}
	if len(eligible) == 0 {
		return nil, nil
	}
	if len(eligible) > 1 {
		return nil, fmt.Errorf("ambiguous HTTP leases (%d matching %q port=%d mode=%s)", len(eligible), wantLabel, wantPort, wantAuth)
	}
	out := eligible[0]
	return &out, nil
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
	serviceID := ""
	if rec.Identity != nil {
		serviceID = rec.Identity.ServiceID
	}
	rep := ServiceStatusReport{
		Name:               rec.Name,
		ServiceID:          serviceID,
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
		LeaseID:            rec.LeaseID,
		PublicURL:          rec.PublicURL,
		PublicVerified:     false,
		AuthProfile:        rec.Auth,
		LastVerifiedAt:     rec.LastVerifiedAt,
		LastFailure:        rec.LastFailure,
		LastRecoveryAction: rec.LastRecoveryAction,
		Reconcile:          rec.Reconcile,
		Layers: ServiceLayers{
			Process:       "unknown",
			Backend:       "unknown",
			Agent:         "unknown",
			Lease:         "unknown",
			Publication:   "unknown",
			Authorization: "unknown",
			Edge:          "unknown",
			Client:        "unverified",
		},
	}

	// 1. Supervisor process state (distinguishing not-found vs inactive vs failed vs manager-unreachable).
	//    Process state is NEVER promoted into transport connectivity (`Layers.Agent`).
	unitInfo := inspectUnit(rec.SystemdUnit, ops)
	rep.ProcessState = unitInfo.ActiveState
	rep.Layers.Process = unitInfo.ActiveState
	rep.RunningNow = unitInfo.ActiveState == "active"
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
		rep.Layers.Backend = "ready"
	} else if target, _, err := localTargetFromURL(rec.LocalURL); err != nil {
		rep.BackendDetail = err.Error()
		rep.Layers.Backend = "unreachable"
	} else if perr := ops.probeLoc(target, 2*time.Second); perr != nil {
		rep.BackendDetail = perr.Error()
		rep.Layers.Backend = "unreachable"
	} else {
		rep.BackendAvailable = true
		rep.BackendDetail = "reachable"
		rep.Layers.Backend = "ready"
	}
	if rep.BackendAvailable {
		rep.VerificationLevel = "LOCAL_READY"
	}

	// HTTP tunnel services have their own lease lifecycle independent of MCP route inventory.
	// An HTTP service NEVER reports SERVING without authoritative relay lease and live-session proof.
	if rec.Type == "http" {
		rep.RelayState = "unknown"
		if rec.DesiredState == config.DesiredDisabled {
			rep.State = ServiceStateDisabled
			rep.Health = HealthReady
			rep.Layers.Publication = "disabled"
			return rep
		}
		if rec.DesiredState == config.DesiredConfigured {
			rep.State = ServiceStateConfigured
			rep.Health = HealthReady
			return rep
		}
		if !rep.BackendAvailable {
			rep.State = ServiceStateOffline
			rep.Health = HealthFailed
			rep.IngressDetail = "local backend unavailable"
			return rep
		}
		if rep.ProcessState == "activating" {
			rep.State = ServiceStateStarting
			rep.Health = HealthDegraded
			return rep
		}
		if rep.ProcessState != "active" {
			rep.State = ServiceStateOffline
			rep.Health = HealthFailed
			return rep
		}
		relayURL := rec.RelayURL
		if relayURL == "" {
			relayURL = agentRelayURLForProfile(prof)
		}
		var ls struct {
			LeaseID        string `json:"lease_id"`
			Status         string `json:"status"`
			URL            string `json:"url"`
			Port           int    `json:"port"`
			AccessMode     string `json:"access_mode"`
			RouteLive      bool   `json:"route_live"`
			RouteAvailable bool   `json:"route_available"`
			Generation     int64  `json:"generation"`
			ExpiresAt      string `json:"lease_expires_at"`
		}
		if rec.LeaseID == "" {
			if ops.mgmtCall == nil {
				rep.State = ServiceStateUnknown
				rep.Health = HealthUnknown
				rep.RelayState = "lease_unknown"
				rep.Layers.Lease = "unknown"
				rep.Layers.Agent = "unknown"
				rep.IngressDetail = "no authoritative lease ID recorded"
				return rep
			}
			discovered, derr := resolveHostedHTTPLease(relayURL, k, keyID, rec, ops)
			if derr != nil {
				rep.State = ServiceStateUnknown
				rep.Health = HealthUnknown
				rep.RelayState = "unreachable"
				if strings.Contains(derr.Error(), "unreachable") {
					rep.Layers.Edge = "unreachable"
				}
				rep.Layers.Lease = "unknown"
				rep.Layers.Agent = "unknown"
				rep.IngressDetail = derr.Error()
				return rep
			}
			if discovered == nil {
				rep.State = ServiceStateUnknown
				rep.Health = HealthUnknown
				rep.RelayState = "lease_unknown"
				rep.Layers.Lease = "unknown"
				rep.Layers.Agent = "unknown"
				rep.IngressDetail = "no authoritative HTTP lease found on relay"
				return rep
			}
			rep.LeaseID = discovered.LeaseID
			ls.LeaseID = discovered.LeaseID
			ls.Status = discovered.Status
			ls.URL = discovered.URL
			ls.Port = discovered.Port
			ls.AccessMode = discovered.AccessMode
			ls.RouteLive = discovered.RouteLive
			ls.RouteAvailable = discovered.RouteAvailable
			ls.Generation = discovered.Generation
			ls.ExpiresAt = discovered.ExpiresAt
		} else {
			if ops.mgmtCall == nil {
				rep.State = ServiceStateUnknown
				rep.Health = HealthUnknown
				rep.RelayState = "unreachable"
				rep.Layers.Edge = "unreachable"
				rep.IngressDetail = "relay management client unavailable"
				return rep
			}
			st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/lease/"+rec.LeaseID+"/status")
			if callErr != nil {
				rep.State = ServiceStateUnknown
				rep.Health = HealthUnknown
				rep.RelayState = "unreachable"
				rep.Layers.Edge = "unreachable"
				rep.Layers.Lease = "unknown"
				rep.Layers.Agent = "unknown"
				rep.IngressDetail = callErr.Error()
				return rep
			}
			if st == http.StatusForbidden || st == http.StatusUnauthorized {
				rep.RelayState = fmt.Sprintf("http_%d", st)
				rep.Layers.Authorization = "forbidden"
				rep.State = ServiceStateRevoked
				rep.Health = HealthBlocked
				rep.LastFailure = fmt.Sprintf("relay auth %d for HTTP lease", st)
				rep.IngressDetail = rep.LastFailure
				return rep
			}
			if st == http.StatusNotFound {
				rep.RelayState = "not_found"
				rep.Layers.Lease = "offline"
				rep.Layers.Publication = "not_registered"
				rep.Layers.Agent = "disconnected"
				rep.State = ServiceStateOffline
				rep.Health = HealthFailed
				rep.IngressDetail = "lease not found on relay"
				return rep
			}
			if st != http.StatusOK {
				rep.RelayState = fmt.Sprintf("http_%d", st)
				rep.State = ServiceStateUnknown
				rep.Health = HealthUnknown
				rep.IngressDetail = fmt.Sprintf("relay lease status HTTP %d", st)
				return rep
			}
			if err := json.Unmarshal(body, &ls); err != nil {
				rep.RelayState = "invalid_json"
				rep.State = ServiceStateUnknown
				rep.Health = HealthUnknown
				rep.IngressDetail = "invalid relay lease JSON"
				return rep
			}
		}
		rep.Layers.Authorization = "valid"
		rep.RelayState = ls.Status
		if ls.URL != "" {
			rep.PublicURL = ls.URL
		}
		if ls.Status == "REVOKED" {
			rep.Layers.Lease = "revoked"
			rep.Layers.Publication = "revoked"
			rep.Layers.Agent = "disconnected"
			rep.State = ServiceStateRevoked
			rep.Health = HealthBlocked
			rep.IngressDetail = "HTTP lease revoked"
			return rep
		}
		expired := ls.Status == "EXPIRED"
		if !expired && ls.ExpiresAt != "" {
			if parsed, perr := time.Parse(time.RFC3339Nano, ls.ExpiresAt); perr == nil && !parsed.After(time.Now().UTC()) {
				expired = true
			}
		}
		if expired {
			rep.Layers.Lease = "expired"
			rep.Layers.Publication = "offline"
			rep.Layers.Agent = "disconnected"
			rep.State = ServiceStateOffline
			rep.Health = HealthFailed
			rep.IngressDetail = "HTTP lease expired"
			return rep
		}
		if ls.Status == "CLOSED" {
			rep.Layers.Lease = "offline"
			rep.Layers.Publication = "offline"
			rep.Layers.Agent = "disconnected"
			rep.State = ServiceStateOffline
			rep.Health = HealthFailed
			rep.IngressDetail = "HTTP lease closed"
			return rep
		}
		if rec.StateGeneration > 0 && ls.Generation > 0 && ls.Generation < rec.StateGeneration {
			rep.Layers.Lease = "stale"
			rep.Layers.Agent = "disconnected"
			rep.State = ServiceStateUnknown
			rep.Health = HealthDegraded
			rep.IngressDetail = fmt.Sprintf("stale lease generation %d < expected %d", ls.Generation, rec.StateGeneration)
			return rep
		}
		// Verify lease target binding matches configured local port & access mode.
		if wantPort := localPortFromURL(rec.LocalURL); wantPort > 0 && ls.Port > 0 && ls.Port != wantPort {
			rep.Layers.Lease = "stale"
			rep.State = ServiceStateOffline
			rep.Health = HealthDegraded
			rep.IngressDetail = fmt.Sprintf("lease target port %d != configured port %d (rebind required)", ls.Port, wantPort)
			return rep
		}
		if rec.Auth != "" && ls.AccessMode != "" && ls.AccessMode != rec.Auth {
			rep.Layers.Authorization = "forbidden"
			rep.State = ServiceStateFaulted
			rep.Health = HealthBlocked
			rep.IngressDetail = fmt.Sprintf("lease access_mode %q != configured %q", ls.AccessMode, rec.Auth)
			return rep
		}
		if ls.Generation > 0 {
			rep.StateGeneration = ls.Generation
		}
		if ls.Status != "ACTIVE" || !ls.RouteLive || !ls.RouteAvailable {
			rep.Layers.Agent = "disconnected"
			rep.Layers.Lease = "offline"
			rep.Layers.Publication = "offline"
			rep.State = ServiceStateOffline
			rep.Health = HealthDegraded
			rep.IngressDetail = fmt.Sprintf("HTTP lease not live (status=%s route_live=%v route_available=%v)", ls.Status, ls.RouteLive, ls.RouteAvailable)
			return rep
		}
		rep.Layers.Agent = "connected"
		rep.Layers.Lease = "valid"
		rep.Layers.Publication = "active"
		rep.VerificationLevel = "RELAY_READY"
		// Separate relay liveness from verified public edge reachability.
		if ops.probeEdge != nil && rep.PublicURL != "" {
			code, perr := ops.probeEdge(rep.PublicURL, 3*time.Second)
			if perr == nil && code == http.StatusOK {
				rep.Layers.Edge = "reachable"
				rep.PublicTransport = true
				rep.VerificationLevel = "EDGE_READY"
				rep.IngressReady = true
				rep.IngressDetail = "HEAD /_ocliv/healthz 200 (EDGE_READY)"
				rep.State = ServiceStateServing
				rep.Health = HealthReady
				return rep
			}
			if perr != nil && (strings.Contains(strings.ToLower(perr.Error()), "x509") || strings.Contains(strings.ToLower(perr.Error()), "tls")) {
				rep.Layers.Edge = "tls_error"
			} else {
				rep.Layers.Edge = "unreachable"
			}
			rep.IngressDetail = fmt.Sprintf("edge probe code=%d err=%v", code, perr)
			rep.State = ServiceStateOffline
			rep.Health = HealthDegraded
			return rep
		}
		// Without an edge probe function, report relay-level readiness honestly
		// without falsely claiming Layers.Edge=reachable or PublicTransport=true.
		rep.State = ServiceStateServing
		rep.Health = HealthReady
		rep.IngressDetail = "relay lease active (edge unprobed)"
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
		rep.Layers.Edge = "unreachable"
		rep.IngressDetail = callErr.Error()
		return rep
	}
	if st != http.StatusOK {
		rep.State = ServiceStateUnknown
		rep.Health = HealthUnknown
		rep.RelayState = fmt.Sprintf("http_%d", st)
		if st == http.StatusForbidden || st == http.StatusUnauthorized {
			rep.Layers.Authorization = "forbidden"
			rep.IngressDetail = fmt.Sprintf("relay auth %d for profile=%q key=%s", st, prof, keyID)
			rep.LastFailure = rep.IngressDetail
		}
		return rep
	}
	rep.Layers.Authorization = "valid"

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
		rep.Layers.Publication = "not_registered"
		rep.Layers.Lease = "offline"
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
	if sessionLive {
		rep.Layers.Agent = "connected"
		rep.Layers.Lease = "valid"
	} else {
		rep.Layers.Agent = "disconnected"
		rep.Layers.Lease = "offline"
	}
	if pubState != "" && pubState != "REVOKED" {
		rep.VerificationLevel = "RELAY_READY"
	}
	if pubState == "REVOKED" {
		rep.Layers.Publication = "revoked"
		rep.Layers.Authorization = "revoked"
		rep.State = ServiceStateRevoked
		rep.Health = HealthBlocked
		rep.IngressDetail = "publication revoked"
		return rep
	}
	if rec.DesiredState == config.DesiredDisabled || !relayDesired {
		rep.Layers.Publication = "disabled"
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
	rep.Layers.Publication = "active"

	// Desired enabled: separate transport check from structured verification evidence.
	if admission == "READY" && sessionLive && rep.BackendAvailable {
		if rep.PublicURL == "" {
			rep.Layers.Edge = "unreachable"
			rep.State = ServiceStateOffline
			rep.Health = HealthDegraded
			rep.IngressDetail = "missing canonical public URL"
			return rep
		}
		code, err := ops.probePub(rep.PublicURL, 3*time.Second)
		if err == nil && (code == http.StatusUnauthorized || code == http.StatusOK) {
			rep.Layers.Edge = "reachable"
			rep.PublicTransport = true
			rep.VerificationLevel = "TRANSPORT_READY"
			if validEvidence(rec.VerificationEvidence, rep.PublicationID, rep.PublicURL, rep.StateGeneration) {
				rep.VerificationEvidence = rec.VerificationEvidence
				rep.VerificationLevel = rec.VerificationEvidence.Stage
				if rec.VerificationEvidence.Stage == "MCP_AUTHENTICATED" || rec.VerificationEvidence.Stage == "EXTERNAL_CLIENT_VERIFIED" {
					rep.PublicVerified = true
					rep.Layers.Client = "verified"
				}
			}
			rep.IngressReady = true
			rep.IngressDetail = fmt.Sprintf("HTTP %d (transport ok; stage=%s)", code, rep.VerificationLevel)
			rep.State = ServiceStateServing
			rep.Health = HealthReady
			return rep
		}
		if err != nil && (strings.Contains(strings.ToLower(err.Error()), "x509") || strings.Contains(strings.ToLower(err.Error()), "tls")) {
			rep.Layers.Edge = "tls_error"
		} else {
			rep.Layers.Edge = "unreachable"
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
