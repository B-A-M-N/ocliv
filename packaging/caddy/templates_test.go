package caddy

// Pins the embedded edge templates to the reviewed packaging sources.

import (
	"os"
	"strings"
	"testing"
)

// The embed directive is the single source of truth for what
// `relay init` / `ocliv setup --edge` renders. If a second, divergent
// copy of a template ever appears and the embed starts following it,
// everything operators get from setup stops being the file that was
// reviewed and (for the single-host edge) verified with a real
// `caddy adapt` by scripts/verify-single-host-edge.sh.
func TestEmbeddedTemplatesMatchOnDiskFiles(t *testing.T) {
	for _, tc := range []struct{ file, rendered string }{
		{"Caddyfile.single-host", SingleHost()},
		{"Caddyfile", Wildcard()},
		{"Caddyfile.tunnel", TunnelOnDemand()},
	} {
		want, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("cannot read %s: %v", tc.file, err)
		}
		if tc.rendered != string(want) {
			t.Errorf("%s: rendered template differs from the on-disk source; "+
				"a divergent or second copy is being embedded", tc.file)
		}
	}
}

// The single-host edge must carry the trusted-edge contract the relay
// relies on: overwrite (never append) the forwarding headers, strip a
// smuggled forwarded host, and proxy to the loopback relay.
func TestSingleHostTemplateCarriesHeaderContract(t *testing.T) {
	s := SingleHost()
	for _, want := range []string{
		"reverse_proxy 127.0.0.1:8080",
		"header_up X-Forwarded-For {remote_host}",
		"header_up X-Forwarded-Proto {scheme}",
		"header_up -X-Forwarded-Host",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("single-host template missing %q; the relay trusts these "+
				"headers to identify the client", want)
		}
	}
}

// The single-host edge must PIN the ACME challenge, not hope for one.
// Caddy enables HTTP-01 and TLS-ALPN-01 by default, so "no challenge
// override in the adapted JSON" is not evidence of anything: with the
// default set the issuer still attempts HTTP-01 (port 80) before
// falling back. On a host where another service owns :80 (Pi-hole),
// the edge must explicitly disable HTTP-01. This assertion is
// intentional-but-strict: it pins disable_http_challenge in the
// template, and scripts/verify-single-host-edge.sh proves with a real
// `caddy adapt` that the adapted issuer honours it.
func TestSingleHostTemplatePinsTLSALPNChallenge(t *testing.T) {
	s := SingleHost()
	if !strings.Contains(s, "disable_http_challenge") {
		t.Error("single-host template does not disable the HTTP-01 challenge; " +
			"Caddy enables HTTP-01 and TLS-ALPN-01 by default, so the edge would " +
			"attempt issuance over port 80 (owned by Pi-hole on the intended host) " +
			"and only fall back to TLS-ALPN-01. Pin it with disable_http_challenge.")
	}
	if !strings.Contains(s, "issuer acme") {
		t.Error("single-host template must select the acme issuer explicitly to carry the challenge pin")
	}
	if !strings.Contains(s, "email {$OCLIV_ACME_EMAIL}") {
		t.Error("single-host template lost the ACME contact email in the explicit issuer block")
	}
}

// The single-host edge serves ONE apex hostname. Anything belonging to
// the tunnel namespace in it would mean relay init is emitting the wrong
// ingress for MCP hosting.
func TestSingleHostTemplateHasNoTunnelNamespace(t *testing.T) {
	s := SingleHost()
	for _, unwanted := range []string{"on_demand_tls", "/v1/internal/ask", "*.t."} {
		if strings.Contains(s, unwanted) {
			t.Errorf("single-host template contains %q, which belongs to the "+
				"tunnel edge; single-host serves one apex hostname", unwanted)
		}
	}
}

// The on-demand tunnel edge dispenses a certificate for any hostname
// pointed at the IP. Its ask stanza is what stops that from being an
// open cert factory, and templates.go says never to render without it.
func TestTunnelTemplateKeepsAskGuard(t *testing.T) {
	s := TunnelOnDemand()
	for _, want := range []string{
		"on_demand_tls",
		"ask http://127.0.0.1:8080/v1/internal/ask",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("tunnel template missing %q; on-demand issuance would "+
				"dispense certificates for any hostname pointed at the IP", want)
		}
	}
}

func TestWildcardTemplateNonEmpty(t *testing.T) {
	if strings.TrimSpace(Wildcard()) == "" {
		t.Error("wildcard template is empty")
	}
}
