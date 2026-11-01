// Package caddy exposes the embedded edge templates as the single source
// of truth for `relay init` generation: the CLI renders these exact
// files with operator values substituted, so generated deployments can
// never drift from the reviewed packaging sources.
package caddy

import _ "embed"

//go:embed Caddyfile.single-host
var singleHost string

//go:embed Caddyfile
var wildcard string

//go:embed Caddyfile.tunnel
var tunnel string

// SingleHost is the one-hostname ACME edge (no wildcard DNS needed).
func SingleHost() string { return singleHost }

// Wildcard is the relay.* + *.t.* edge (needs DNS-01 for the wildcard).
func Wildcard() string { return wildcard }

// TunnelOnDemand serves the apex over plain ACME plus *.t.* tunnel
// hostnames via on-demand issuance gated by the relay ask endpoint —
// no wildcard DNS record or DNS-01 plugin needed. The ask stanza in
// the template is the abuse guard; never render without it.
func TunnelOnDemand() string { return tunnel }
