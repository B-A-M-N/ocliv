// Package systemd exposes the embedded relay unit as the single source
// of truth for `relay init` generation.
package systemd

import _ "embed"

//go:embed ocliv-relay.service
var relayUnit string

// RelayUnit is the hardened loopback-only relay service.
func RelayUnit() string { return relayUnit }
