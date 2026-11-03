package setup

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

// LookupHost resolves a hostname for the refresh path. It is a
// variable so tests can stub DNS without touching the resolver.
var LookupHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// RefreshDynDNS re-checks observed egress against the hostname's
// current DNS and pushes an update only when the address actually
// changed. It never restarts the relay (DNS-only change), never
// invents an address it did not observe, and refuses loudly when
// there is no viable direct path instead of "confirming" DNS it
// cannot see. Intended for cron/systemd-timer use between full
// `setup --auto` runs.
func RefreshDynDNS(ctx context.Context, endpoint, hostname, token, echoV4URL, echoV6URL string) (bool, error) {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if hostname == "" {
		return false, fmt.Errorf("refresh requires a hostname")
	}
	d := Gather(ctx, echoV4URL, echoV6URL)
	if d.Path != PathDirectV4 && d.Path != PathDirectV6 && d.Path != PathNATV4 {
		return false, fmt.Errorf("no viable direct path (%s): leaving DNS untouched; re-run `ocliv setup --auto` after fixing inbound reachability", d.Path)
	}
	current, err := LookupHost(ctx, hostname)
	if err != nil {
		return false, fmt.Errorf("refresh lookup for %s failed: %w", hostname, err)
	}
	if sameAddrSet(current, []string{d.EgressV4, d.EgressV6}) {
		return false, nil
	}
	if err := UpdateDynv6(ctx, endpoint, hostname, token, d.EgressV4, d.EgressV6); err != nil {
		return false, err
	}
	return true, nil
}

func sameAddrSet(a, b []string) bool {
	norm := func(in []string) []string {
		var out []string
		for _, s := range in {
			if s = strings.TrimSpace(s); s != "" && s != "(unobserved)" {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	}
	na, nb := norm(a), norm(b)
	if len(na) != len(nb) {
		return false
	}
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}
