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

// SingleHost is the one-hostname ACME edge (no wildcard DNS needed).
func SingleHost() string { return singleHost }

// Wildcard is the relay.* + *.t.* edge (needs DNS-01 for the wildcard).
func Wildcard() string { return wildcard }
