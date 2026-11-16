package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// PublicationEventType enumerates the deterministic lifecycle events
// emitted by `ocliv mcp publish --json-events`.
const (
	EventPublicationStarting   = "publication_starting"
	EventPublicationRegistered = "publication_registered"
	EventPublicationReady      = "publication_ready"
	EventPublicationOffline    = "publication_offline"
	EventPublicationFailed     = "publication_failed"
	EventPublicationStopped    = "publication_stopped"
)

// PublicationEvent is one newline-delimited JSON lifecycle record for
// automation (Skybridge controller, `ocliv service`, systemd wrappers).
type PublicationEvent struct {
	Event          string `json:"event"`
	Timestamp      string `json:"timestamp"`
	ServiceName    string `json:"service_name,omitempty"`
	PublicationID  string `json:"publication_id,omitempty"`
	PublicURL      string `json:"public_url,omitempty"`
	RelayURL       string `json:"relay_url,omitempty"`
	Profile        string `json:"profile,omitempty"`
	OwnerKeyID     string `json:"owner_key_id,omitempty"`
	LeaseID        string `json:"lease_id,omitempty"`
	AuthMode       string `json:"auth_mode,omitempty"`
	IngressProfile string `json:"ingress_profile,omitempty"`
	Verified       bool   `json:"verified"`
	Created        bool   `json:"created,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Error          string `json:"error,omitempty"`
}

// PublicationContext binds the controller, CLI, and relay registration
// to one explicit, validated identity so they cannot drift apart.
type PublicationContext struct {
	RelayURL       string
	RelayOrigin    string
	Profile        string
	OwnerKeyID     string
	ServiceName    string
	AuthMode       string
	IngressProfile string
	LocalBackend   string
}

var retiredFunnelHosts = map[string]bool{
	"pop-os.tail8d285a.ts.net": true,
}

// normalizeOrigin returns scheme://host[:port] in lowercase.
func normalizeOrigin(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid URL %q", rawURL)
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

// validateRelayTarget rejects retired Funnel hostnames and malformed origins.
func validateRelayTarget(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid relay URL %q", rawURL)
	}
	host := strings.ToLower(u.Hostname())
	if retiredFunnelHosts[host] {
		return "", fmt.Errorf("refusing retired Funnel relay host %q", host)
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

// validateRegistrationResponse verifies the relay's route registration
// response matches the intended PublicationContext (exact route URL shape,
// route ID match, profile match, and non-retired host).
func (pc PublicationContext) validateRegistrationResponse(routeID, routeURL, routeAuth string) error {
	if routeID == "" || routeURL == "" {
		return fmt.Errorf("relay returned empty route_id or url")
	}
	u, err := url.Parse(routeURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("relay returned invalid public route URL %q", routeURL)
	}
	host := strings.ToLower(u.Hostname())
	if retiredFunnelHosts[host] {
		return fmt.Errorf("relay returned retired Funnel host in route URL %q", routeURL)
	}
	wantPath := "/r/" + routeID + "/mcp"
	if u.Path != wantPath {
		return fmt.Errorf("relay route URL path %q does not match route_id %q", u.Path, routeID)
	}
	if routeAuth != "" && pc.IngressProfile != "" && routeAuth != pc.IngressProfile {
		return fmt.Errorf("relay returned unexpected auth profile %q (expected %q)", routeAuth, pc.IngressProfile)
	}
	// When the relay itself is accessed over a non-loopback hostname, the
	// public route hostname must match the relay's hostname unless an
	// explicit split-host relay is used; reject obvious cross-origin drift.
	if ru, err := url.Parse(pc.RelayURL); err == nil {
		rhost := strings.ToLower(ru.Hostname())
		if rhost != "" && rhost != "127.0.0.1" && rhost != "::1" && rhost != "localhost" && host != rhost {
			// Allow relay.<domain> -> <domain> if same base domain, otherwise reject.
			if !strings.HasSuffix(rhost, "."+host) && !strings.HasSuffix(host, "."+rhost) {
				return fmt.Errorf("relay route URL host %q does not match relay origin %q", host, rhost)
			}
		}
	}
	return nil
}

type eventEmitter struct {
	enabled bool
	ctx     PublicationContext
}

func (e eventEmitter) emit(eventType, routeID, routeURL, leaseID string, verified, created bool, reason, errMsg string) {
	if !e.enabled {
		return
	}
	ev := PublicationEvent{
		Event:          eventType,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		ServiceName:    e.ctx.ServiceName,
		PublicationID:  routeID,
		PublicURL:      routeURL,
		RelayURL:       e.ctx.RelayURL,
		Profile:        e.ctx.Profile,
		OwnerKeyID:     e.ctx.OwnerKeyID,
		LeaseID:        leaseID,
		AuthMode:       e.ctx.AuthMode,
		IngressProfile: e.ctx.IngressProfile,
		Verified:       verified,
		Created:        created,
		Reason:         reason,
		Error:          errMsg,
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	fmt.Fprintln(os.Stdout, string(b))
}
