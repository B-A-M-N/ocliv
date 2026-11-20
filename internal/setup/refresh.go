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

// refreshDynamicDNS implements the shared network-safety policy for all
// dynamic DNS providers (dynv6 and DuckDNS, P1-7):
//   - requires a viable direct/NAT inbound path (refuses CGNAT / no egress)
//   - resolves current DNS A/AAAA records via LookupHost
//   - skips the provider API call when normalized address sets match
func refreshDynamicDNS(ctx context.Context, hostname, echoV4URL, echoV6URL string, update func(v4, v6 string) error) (bool, error) {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if hostname == "" {
		return false, fmt.Errorf("refresh requires a hostname")
	}
	d := Gather(ctx, echoV4URL, echoV6URL)
	if d.Path != PathDirectV4 && d.Path != PathDirectV6 && d.Path != PathNATV4 {
		return false, fmt.Errorf("no viable direct path (%s): leaving DNS untouched; re-run `ocliv setup --auto` after fixing inbound reachability", d.Path)
	}
	if d.EgressV4 == "" && d.EgressV6 == "" {
		return false, fmt.Errorf("no observed egress address: leaving DNS untouched")
	}
	current, err := LookupHost(ctx, hostname)
	if err != nil {
		return false, fmt.Errorf("refresh lookup for %s failed: %w", hostname, err)
	}
	if sameAddrSet(current, []string{d.EgressV4, d.EgressV6}) {
		return false, nil
	}
	if err := update(d.EgressV4, d.EgressV6); err != nil {
		return false, err
	}
	return true, nil
}

// RefreshDynDNS re-checks observed egress against the hostname's
// current DNS and pushes a dynv6 update only when the address actually
// changed.
func RefreshDynDNS(ctx context.Context, endpoint, hostname, token, echoV4URL, echoV6URL string) (bool, error) {
	return refreshDynamicDNS(ctx, hostname, echoV4URL, echoV6URL, func(v4, v6 string) error {
		return UpdateDynv6(ctx, endpoint, hostname, token, v4, v6)
	})
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
