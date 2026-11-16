package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicationContextRejectsMismatches(t *testing.T) {
	ctx := PublicationContext{
		RelayURL:       "https://relay.bamnlabs.test",
		RelayOrigin:    "https://relay.bamnlabs.test",
		Profile:        "default",
		OwnerKeyID:     "key-1",
		ServiceName:    "my-tools",
		AuthMode:       "ocliv-managed",
		IngressProfile: "managed-oauth",
		LocalBackend:   "http://127.0.0.1:8765/mcp",
	}

	if err := ctx.validateRegistrationResponse("abc123", "https://relay.bamnlabs.test/r/abc123/mcp", "managed-oauth"); err != nil {
		t.Fatalf("valid registration rejected: %v", err)
	}

	cases := []struct {
		name     string
		routeID  string
		routeURL string
		auth     string
	}{
		{"retired funnel", "abc123", "https://pop-os.tail8d285a.ts.net/r/abc123/mcp", "managed-oauth"},
		{"foreign origin", "abc123", "https://evil.example/r/abc123/mcp", "managed-oauth"},
		{"profile mismatch", "abc123", "https://relay.bamnlabs.test/r/abc123/mcp", "upstream-oauth"},
		{"route id mismatch", "abc123", "https://relay.bamnlabs.test/r/other999/mcp", "managed-oauth"},
		{"non-https", "abc123", "http://relay.bamnlabs.test/r/abc123/mcp", "managed-oauth"},
		{"userinfo", "abc123", "https://user@relay.bamnlabs.test/r/abc123/mcp", "managed-oauth"},
		{"query", "abc123", "https://relay.bamnlabs.test/r/abc123/mcp?x=1", "managed-oauth"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ctx.validateRegistrationResponse(tc.routeID, tc.routeURL, tc.auth); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestValidateRelayTargetRejectsRetiredFunnel(t *testing.T) {
	if _, err := validateRelayTarget("https://pop-os.tail8d285a.ts.net"); err == nil {
		t.Fatal("expected retired Funnel relay URL to be rejected")
	}
	orig, err := validateRelayTarget("https://BAMNLABS.dynv6.net:8443/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if orig != "https://bamnlabs.dynv6.net:8443" {
		t.Fatalf("got origin %q, want https://bamnlabs.dynv6.net:8443", orig)
	}
}

func TestEventEmitterFormat(t *testing.T) {
	em := eventEmitter{
		enabled: true,
		ctx: PublicationContext{
			RelayURL:       "https://relay.test",
			Profile:        "default",
			OwnerKeyID:     "k123",
			ServiceName:    "svc1",
			AuthMode:       "ocliv-managed",
			IngressProfile: "managed-oauth",
		},
	}
	ev := PublicationEvent{
		Event:          EventPublicationReady,
		ServiceName:    em.ctx.ServiceName,
		PublicationID:  "route-1",
		PublicURL:      "https://relay.test/r/route-1/mcp",
		RelayURL:       em.ctx.RelayURL,
		OwnerKeyID:     em.ctx.OwnerKeyID,
		LeaseID:        "lease-1",
		AuthMode:       em.ctx.AuthMode,
		IngressProfile: em.ctx.IngressProfile,
		Verified:       true,
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`"event":"publication_ready"`, `"service_name":"svc1"`, `"publication_id":"route-1"`, `"verified":true`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
}
