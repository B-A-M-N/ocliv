package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

// relayPublication models an item returned by GET /v1/agent/mcp-routes
// (matching internal/relay.agentPublicationView).
type relayPublication struct {
	RouteID          string   `json:"route_id"`
	Host             string   `json:"external_host,omitempty"`
	URL              *string  `json:"url"`
	Profile          string   `json:"profile,omitempty"`
	Name             string   `json:"pub_name,omitempty"`
	LeaseID          *string  `json:"lease_id"`
	CreatedAt        string   `json:"created_at,omitempty"`
	RevokedAt        *string  `json:"revoked_at"`
	VerifiedAt       *string  `json:"verified_at"`
	PublicationState string   `json:"publication_state"`
	DesiredEnabled   bool     `json:"desired_enabled"`
	StateGeneration  int64    `json:"state_generation"`
	LeaseState       *string  `json:"lease_state"`
	SessionLive      bool     `json:"session_live"`
	HostBinding      string   `json:"host_binding"`
	Admission        string   `json:"admission"`
	AdmissionReason  string   `json:"admission_reason"`
	TrustedClients   []string `json:"trusted_clients,omitempty"`
}

func (p relayPublication) urlString() string {
	if p.URL == nil {
		return ""
	}
	return *p.URL
}

func (p relayPublication) leaseIDString() string {
	if p.LeaseID == nil {
		return ""
	}
	return *p.LeaseID
}

func (p relayPublication) isRevoked() bool {
	return p.PublicationState == "REVOKED" || p.RevokedAt != nil || p.AdmissionReason == "PUBLICATION_REVOKED"
}

func (p relayPublication) isHostMismatch() bool {
	return p.HostBinding == "MISMATCH" || p.AdmissionReason == "HOST_MISMATCH"
}

// isCompatibleForDiscovery reports whether p is eligible for ordinary unbound
// or stale-binding discovery by service name.
//
// Historical revoked, HOST_MISMATCH, and profile-incompatible publications are
// excluded from ordinary name discovery so they never block or hijack a valid
// service, while remaining visible in administrative inventory (`ocliv mcp list`).
// Intentionally disabled valid publications (`!DesiredEnabled` / `DISABLED`)
// are NOT excluded — they retain their service identity.
func (p relayPublication) isCompatibleForDiscovery(wantIngress string) bool {
	if p.isRevoked() || p.isHostMismatch() {
		return false
	}
	if wantIngress != "" && p.Profile != "" && p.Profile != wantIngress {
		return false
	}
	return true
}

// PublicationResolutionStatus classifies the outcome of canonical publication
// resolution against the authoritative relay inventory.
type PublicationResolutionStatus string

const (
	ResolutionExactID             PublicationResolutionStatus = "EXACT_ID"
	ResolutionBoundValid          PublicationResolutionStatus = "BOUND_VALID"
	ResolutionRecoveredUnique     PublicationResolutionStatus = "RECOVERED_UNIQUE"
	ResolutionNotFound            PublicationResolutionStatus = "NOT_FOUND"
	ResolutionBindingRevoked      PublicationResolutionStatus = "BINDING_REVOKED"
	ResolutionBindingHostMismatch PublicationResolutionStatus = "BINDING_HOST_MISMATCH"
	ResolutionBindingIncompatible PublicationResolutionStatus = "BINDING_INCOMPATIBLE"
	ResolutionAmbiguous           PublicationResolutionStatus = "AMBIGUOUS"
)

// PublicationResolution is the single typed result returned by the canonical
// publication resolver across status, reconcile, mcp url/check, pending,
// approve, trust, and connect commands.
type PublicationResolution struct {
	Status            PublicationResolutionStatus
	Publication       *relayPublication
	PreviousBindingID string
	Candidates        []relayPublication
	Detail            string
}

func (r PublicationResolution) Found() bool {
	switch r.Status {
	case ResolutionExactID, ResolutionBoundValid, ResolutionRecoveredUnique:
		return r.Publication != nil
	default:
		return false
	}
}

func (r PublicationResolution) IsPermanentConflict() bool {
	switch r.Status {
	case ResolutionBindingRevoked, ResolutionBindingHostMismatch, ResolutionBindingIncompatible, ResolutionAmbiguous:
		return true
	default:
		return false
	}
}

func (r PublicationResolution) NeedsBindingRepair(localPubID, localURL string) bool {
	if !r.Found() {
		return false
	}
	if localPubID != r.Publication.RouteID {
		return true
	}
	if u := r.Publication.urlString(); u != "" && localURL != u {
		return true
	}
	return false
}

func (r PublicationResolution) ErrorString() string {
	if r.Found() {
		return ""
	}
	if r.Detail != "" {
		return r.Detail
	}
	return string(r.Status)
}

// fetchRelayPublications fetches and parses the authenticated relay inventory
// from GET /v1/agent/mcp-routes.
func fetchRelayPublications(relayURL string, k *identity.KeyPair, keyID string, ops serviceOps) ([]relayPublication, int, error) {
	if ops.mgmtCall == nil {
		return nil, 0, fmt.Errorf("relay management client unavailable")
	}
	st, body, callErr := ops.mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/mcp-routes")
	if callErr != nil {
		return nil, 0, callErr
	}
	if st != http.StatusOK {
		return nil, st, fmt.Errorf("relay inventory HTTP %d: %s", st, strings.TrimSpace(string(body)))
	}
	var inv struct {
		Publications []relayPublication `json:"publications"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		return nil, st, fmt.Errorf("unparseable relay inventory: %w", err)
	}
	return inv.Publications, st, nil
}

// resolvePublicationFromInventory enforces the single canonical OCL-011
// resolution precedence against the authoritative relay inventory:
//
//  1. Explicit publication/route ID (`target == p.RouteID`) resolves ONLY that
//     exact ID, even if disabled, revoked, or host-mismatched.
//  2. Existing durable local binding (`localRec.PublicationID`) takes precedence
//     over label matching when still valid (present, compatible profile, not
//     revoked, not HOST_MISMATCH) — including when intentionally disabled.
//  3. Unbound or stale-binding discovery matches by service name among
//     compatible non-revoked, non-HOST_MISMATCH publications (retaining
//     intentionally disabled valid publications). If exactly one compatible
//     candidate exists, returns ResolutionRecoveredUnique.
//  4. Genuine ambiguity (multiple compatible candidates) fails closed with
//     ResolutionAmbiguous.
//  5. No compatible candidates returns a typed permanent conflict when a stale
//     binding or historical HOST_MISMATCH/REVOKED route explains the failure,
//     or ResolutionNotFound when no route exists yet.
func resolvePublicationFromInventory(target string, localRec *config.ServiceRecord, pubs []relayPublication) PublicationResolution {
	wantIngress := ""
	serviceName := target
	if localRec != nil {
		if localRec.Name != "" {
			serviceName = localRec.Name
		}
		if localRec.Auth != "" {
			wantIngress = mcpIngressProfile(localRec.Auth)
		}
	}

	// Rule 1: Explicit publication/route ID always resolves ONLY that exact ID.
	if target != "" {
		for i := range pubs {
			if pubs[i].RouteID == target {
				p := pubs[i]
				return PublicationResolution{
					Status:      ResolutionExactID,
					Publication: &p,
				}
			}
		}
	}

	// Rule 2: Existing durable local binding takes precedence over label matching when valid.
	var staleStatus PublicationResolutionStatus
	var stalePub *relayPublication
	var staleDetail string
	var prevBindingID string
	if localRec != nil && localRec.PublicationID != "" {
		prevBindingID = localRec.PublicationID
		for i := range pubs {
			if pubs[i].RouteID == localRec.PublicationID {
				p := pubs[i]
				switch {
				case p.isRevoked():
					staleStatus = ResolutionBindingRevoked
					stalePub = &p
					staleDetail = fmt.Sprintf("bound publication %s for service %q is REVOKED", p.RouteID, serviceName)
				case p.isHostMismatch():
					staleStatus = ResolutionBindingHostMismatch
					stalePub = &p
					staleDetail = fmt.Sprintf("bound publication %s for service %q has HOST_MISMATCH (host=%q)", p.RouteID, serviceName, p.Host)
				case wantIngress != "" && p.Profile != "" && p.Profile != wantIngress:
					staleStatus = ResolutionBindingIncompatible
					stalePub = &p
					staleDetail = fmt.Sprintf("bound publication %s for service %q has incompatible profile %q (want %q)", p.RouteID, serviceName, p.Profile, wantIngress)
				default:
					return PublicationResolution{
						Status:      ResolutionBoundValid,
						Publication: &p,
					}
				}
				break
			}
		}
	}

	// Rule 3: Unbound or stale-binding discovery by service name (excluding
	// revoked, HOST_MISMATCH, and profile-incompatible historical routes, while
	// preserving intentionally disabled valid publications).
	var compatible []relayPublication
	var hostMismatches []relayPublication
	var revoked []relayPublication
	if serviceName != "" {
		for _, p := range pubs {
			if p.Name != serviceName {
				continue
			}
			if p.isCompatibleForDiscovery(wantIngress) {
				compatible = append(compatible, p)
				continue
			}
			if p.isHostMismatch() {
				hostMismatches = append(hostMismatches, p)
			} else if p.isRevoked() {
				revoked = append(revoked, p)
			}
		}
	}

	if len(compatible) == 1 {
		p := compatible[0]
		detail := ""
		if prevBindingID != "" && prevBindingID != p.RouteID {
			detail = fmt.Sprintf("stale binding %s uniquely recovered to compatible publication %s", prevBindingID, p.RouteID)
		}
		return PublicationResolution{
			Status:            ResolutionRecoveredUnique,
			Publication:       &p,
			PreviousBindingID: prevBindingID,
			Detail:            detail,
		}
	}

	// Rule 4: Genuine ambiguity fails closed.
	if len(compatible) > 1 {
		ids := make([]string, 0, len(compatible))
		for _, c := range compatible {
			ids = append(ids, c.RouteID)
		}
		return PublicationResolution{
			Status:            ResolutionAmbiguous,
			PreviousBindingID: prevBindingID,
			Candidates:        compatible,
			Detail:            fmt.Sprintf("ambiguous publication name %q (%d compatible routes: %s); pass an explicit route ID or run `ocliv mcp list`", serviceName, len(compatible), strings.Join(ids, ", ")),
		}
	}

	// Rule 5: No compatible candidates found. Report permanent binding/host
	// conflict if one was observed so callers stop infinite retry loops.
	if staleStatus != "" {
		return PublicationResolution{
			Status:            staleStatus,
			Publication:       stalePub,
			PreviousBindingID: prevBindingID,
			Detail:            staleDetail,
		}
	}
	if len(hostMismatches) > 0 {
		p := hostMismatches[0]
		return PublicationResolution{
			Status:            ResolutionBindingHostMismatch,
			Publication:       &p,
			PreviousBindingID: prevBindingID,
			Detail:            fmt.Sprintf("service %q matches only HOST_MISMATCH publication %s (host=%q); run `ocliv service reconcile %s` or republish on the current relay host", serviceName, p.RouteID, p.Host, serviceName),
		}
	}
	if len(revoked) > 0 && prevBindingID != "" {
		p := revoked[0]
		return PublicationResolution{
			Status:            ResolutionBindingRevoked,
			Publication:       &p,
			PreviousBindingID: prevBindingID,
			Detail:            fmt.Sprintf("service %q matches only REVOKED publication %s", serviceName, p.RouteID),
		}
	}
	return PublicationResolution{
		Status:            ResolutionNotFound,
		PreviousBindingID: prevBindingID,
		Detail:            fmt.Sprintf("no publication found for %q", serviceName),
	}
}

// resolveServicePublication queries the relay inventory and runs the canonical
// publication resolver for target + optional localRec.
func resolveServicePublication(relayURL string, k *identity.KeyPair, keyID, target string, localRec *config.ServiceRecord, ops serviceOps) (PublicationResolution, int, error) {
	pubs, st, err := fetchRelayPublications(relayURL, k, keyID, ops)
	if err != nil {
		return PublicationResolution{}, st, err
	}
	return resolvePublicationFromInventory(target, localRec, pubs), st, nil
}
