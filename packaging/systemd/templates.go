// Package systemd exposes the embedded relay unit as the single source
// of truth for `relay init` generation.
package systemd

import _ "embed"

//go:embed ocliv-relay.service
var relayUnit string

// RelayUnit is the hardened loopback-only relay service.
func RelayUnit() string { return relayUnit }

//go:embed ocliv-dns-refresh.service
var dnsRefreshService string

// RefreshService is the optional DNS-only refresh service. It is
// inert until the operator creates its env file and enables the
// companion timer; nothing in the ordinary client path needs it.
func RefreshService() string { return dnsRefreshService }

//go:embed ocliv-dns-refresh.timer
var dnsRefreshTimer string

// RefreshTimer retriggers the DNS refresh on a fixed schedule.
func RefreshTimer() string { return dnsRefreshTimer }

//go:embed ocliv-relay-launch.sh
var relayLauncher string

// RelayLauncher is the ExecStart wrapper the relay unit runs. The
// embedded copy is what `setup --auto` installs on a clean host, so a
// freshly provisioned relay has exactly the script the reviewed unit
// expects — no source checkout required.
func RelayLauncher() string { return relayLauncher }
