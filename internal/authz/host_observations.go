package authz

import (
	"net/http"
	"strings"
	"time"
)

// Retention bounds for privacy-safe host observations (OCL-009).
const (
	MaxHostObservationsPerRoute = 200
	HostObservationRetention    = 30 * 24 * time.Hour
	DefaultObservationMaxAge    = 24 * time.Hour
)

// Evidence-backed external host verification stages (OCL-009).
const (
	StageEndpointReady                = "ENDPOINT_READY"
	StageOAuthCompatible              = "OAUTH_COMPATIBLE"
	StageClientRegistered             = "CLIENT_REGISTERED"
	StageClientAuthorized             = "CLIENT_AUTHORIZED"
	StageClientMCPObserved            = "CLIENT_MCP_OBSERVED"
	StageEventsDiscoveryObserved      = "EVENTS_DISCOVERY_OBSERVED"
	StageEventsSubscriptionObserved   = "EVENTS_SUBSCRIPTION_OBSERVED"
	StageExternalAcceptanceUnverified = "EXTERNAL_ACCEPTANCE_UNVERIFIED"
)

// HostObservation is a privacy-safe, non-secret record of an OAuth or MCP
// lifecycle observation for one route publication (OCL-009). It NEVER stores
// raw tokens, authorization codes, callback secrets, tool arguments, or event
// payloads. TransportStatus ("ok"|"error") is recorded separately from
// ResultCategory ("ok"|"denied"|"error") so an HTTP 200 containing a JSON-RPC
// error is never misclassified as protocol success.
type HostObservation struct {
	TenantID              string    `json:"tenant_id,omitempty"`
	RouteID               string    `json:"route_id"`
	CanonicalURL          string    `json:"canonical_url"`
	ClientID              string    `json:"client_id,omitempty"`
	ClientKind            string    `json:"client_kind"` // "chatgpt-preset" | "generic" | "synthetic-probe"
	ProtocolVersion       string    `json:"protocol_version,omitempty"`
	PublicationGeneration int64     `json:"publication_generation,omitempty"`
	Stage                 string    `json:"stage"`
	TransportStatus       string    `json:"transport_status,omitempty"` // "ok" | "error"
	ResultCategory        string    `json:"result_category"`            // "ok" | "denied" | "error"
	IsSynthetic           bool      `json:"is_synthetic"`
	ObservedAt            time.Time `json:"observed_at"`
}

// HostObservationFilter scopes verification evidence to a specific tenant,
// route, canonical URL, client identity, publication generation, and freshness
// window so stale or prior-generation observations are separated from current
// evidence.
type HostObservationFilter struct {
	TenantID              string
	RouteID               string
	CanonicalURL          string
	ClientID              string
	PublicationGeneration int64
	MaxAge                time.Duration
	Now                   time.Time
}

// HostVerificationSummary distills observed route evidence into honest,
// non-conflating verification stages. Preset-matched OAuth client activity,
// synthetic probes, and historical/prior-generation observations are explicitly
// separated from currently verified evidence and from independently verified
// external host acceptance.
type HostVerificationSummary struct {
	HighestStage               string            `json:"highest_stage"`
	StagesObserved             []string          `json:"stages_observed"`
	HistoricalStagesObserved   []string          `json:"historical_stages_observed,omitempty"`
	SyntheticStagesObserved    []string          `json:"synthetic_stages_observed,omitempty"`
	ClientRegistration         string            `json:"client_registration"` // OBSERVED | UNKNOWN
	ClientAuthorization        string            `json:"client_authorization"`
	ClientMCPObserved          string            `json:"client_mcp_observed"`
	EventsDiscoveryObserved    string            `json:"events_discovery_observed"`
	EventsSubscriptionObserved string            `json:"events_subscription_observed"`
	PresetClientObserved       bool              `json:"preset_client_observed"`
	ExternalAcceptance         string            `json:"external_acceptance"` // EXTERNAL_ACCEPTANCE_UNVERIFIED (never overstated)
	LastObservedAt             string            `json:"last_observed_at,omitempty"`
	Latest                     *HostObservation  `json:"latest,omitempty"`
	Observations               []HostObservation `json:"observations,omitempty"`
}

// IsSyntheticProbeRequest reports whether an HTTP request originates from
// Ocliv's own diagnostic/qualification probes so relay observations never
// conflate synthetic test runs with actual external host (e.g. ChatGPT) traffic.
func IsSyntheticProbeRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	ua := strings.ToLower(strings.TrimSpace(r.Header.Get("User-Agent")))
	if strings.HasPrefix(ua, "ocliv-probe/") || strings.HasPrefix(ua, "ocliv-doctor/") {
		return true
	}
	return strings.TrimSpace(r.Header.Get("X-Ocliv-Synthetic-Probe")) != ""
}

// ClassifyClientKind classifies a registered client's redirect URIs against
// built-in client presets without conflating preset match with verified host
// acceptance.
func ClassifyClientKind(redirectURIs []string, isSynthetic bool) string {
	if isSynthetic {
		return "synthetic-probe"
	}
	if preset, ok := LookupTrustPreset("chatgpt"); ok && ExactRedirectURISetEqual(preset.RedirectURIs, redirectURIs) {
		return "chatgpt-preset"
	}
	return "generic"
}

var stageOrder = []string{
	StageEndpointReady,
	StageOAuthCompatible,
	StageClientRegistered,
	StageClientAuthorized,
	StageClientMCPObserved,
	StageEventsDiscoveryObserved,
	StageEventsSubscriptionObserved,
}

// SummarizeHostObservations computes an honest, evidence-backed summary from
// readiness booleans and recorded observations without generation/freshness
// filtering. Prefer SummarizeHostObservationsFiltered when publication
// generation and canonical URL are known.
func SummarizeHostObservations(endpointReady, oauthCompatible bool, obs []HostObservation) HostVerificationSummary {
	return SummarizeHostObservationsFiltered(endpointReady, oauthCompatible, obs, HostObservationFilter{})
}

// SummarizeHostObservationsFiltered computes an honest, evidence-backed summary
// scoped by tenant, route, canonical URL, client identity, publication
// generation, and freshness. Observations that fail transport or protocol
// checks are never promoted. Observations from older publication generations
// or outside the freshness window are recorded under HistoricalStagesObserved
// rather than current StagesObserved.
func SummarizeHostObservationsFiltered(endpointReady, oauthCompatible bool, obs []HostObservation, filter HostObservationFilter) HostVerificationSummary {
	now := filter.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	realSeen := map[string]bool{}
	histSeen := map[string]bool{}
	synthSeen := map[string]bool{}
	if endpointReady {
		realSeen[StageEndpointReady] = true
	}
	if oauthCompatible {
		realSeen[StageOAuthCompatible] = true
	}
	var latest *HostObservation
	presetObserved := false
	filteredObs := make([]HostObservation, 0, len(obs))

	for i := range obs {
		o := obs[i]
		// Strict tenant and route scoping: foreign rows are discarded entirely.
		if filter.TenantID != "" && o.TenantID != "" && o.TenantID != filter.TenantID {
			continue
		}
		if filter.RouteID != "" && o.RouteID != "" && o.RouteID != filter.RouteID {
			continue
		}
		if filter.ClientID != "" && o.ClientID != filter.ClientID {
			continue
		}
		filteredObs = append(filteredObs, o)

		// Transport-level errors and JSON-RPC/protocol-level errors never count as success.
		if o.TransportStatus == "error" {
			continue
		}
		if o.ResultCategory != "" && o.ResultCategory != "ok" {
			continue
		}
		if o.IsSynthetic || o.ClientKind == "synthetic-probe" {
			synthSeen[o.Stage] = true
			continue
		}

		// Distinguish currently verified evidence from historical/stale evidence.
		isCurrent := true
		if filter.CanonicalURL != "" && o.CanonicalURL != "" && o.CanonicalURL != filter.CanonicalURL {
			isCurrent = false
		}
		if filter.PublicationGeneration > 0 && o.PublicationGeneration != filter.PublicationGeneration {
			isCurrent = false
		}
		if filter.MaxAge > 0 && !o.ObservedAt.IsZero() && now.Sub(o.ObservedAt) > filter.MaxAge {
			isCurrent = false
		}
		if !isCurrent {
			histSeen[o.Stage] = true
			continue
		}

		realSeen[o.Stage] = true
		if o.ClientKind == "chatgpt-preset" {
			presetObserved = true
		}
		if latest == nil || o.ObservedAt.After(latest.ObservedAt) {
			cp := o
			latest = &cp
		}
	}
	summary := HostVerificationSummary{
		HighestStage:               StageExternalAcceptanceUnverified,
		ClientRegistration:         "UNKNOWN",
		ClientAuthorization:        "UNKNOWN",
		ClientMCPObserved:          "UNKNOWN",
		EventsDiscoveryObserved:    "UNKNOWN",
		EventsSubscriptionObserved: "UNKNOWN",
		PresetClientObserved:       presetObserved,
		ExternalAcceptance:         StageExternalAcceptanceUnverified,
		Observations:               filteredObs,
	}
	for _, st := range stageOrder {
		if realSeen[st] {
			summary.StagesObserved = append(summary.StagesObserved, st)
			summary.HighestStage = st
		} else if histSeen[st] {
			summary.HistoricalStagesObserved = append(summary.HistoricalStagesObserved, st)
		}
		if synthSeen[st] {
			summary.SyntheticStagesObserved = append(summary.SyntheticStagesObserved, st)
		}
	}
	if realSeen[StageClientRegistered] {
		summary.ClientRegistration = "OBSERVED"
	}
	if realSeen[StageClientAuthorized] {
		summary.ClientAuthorization = "OBSERVED"
	}
	if realSeen[StageClientMCPObserved] {
		summary.ClientMCPObserved = "OBSERVED"
	}
	if realSeen[StageEventsDiscoveryObserved] {
		summary.EventsDiscoveryObserved = "OBSERVED"
	}
	if realSeen[StageEventsSubscriptionObserved] {
		summary.EventsSubscriptionObserved = "OBSERVED"
	}
	if latest != nil {
		summary.Latest = latest
		summary.LastObservedAt = latest.ObservedAt.UTC().Format(time.RFC3339)
	}
	return summary
}
