// Package setup implements `ocliv setup`: automated detection and
// bootstrapping of a self-hosted public relay on ordinary hardware.
// Detection is read-only; provisioning steps always report what they
// will change and require explicit user authorization for account
// access, credentials, and router changes.
package setup

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Path is the recommended hosting route from detection.
type Path int

const (
	// PathUnknown: egress unobserved; no recommendation possible.
	PathUnknown Path = iota
	// PathDirectV6: host holds its own global IPv6; serve directly.
	PathDirectV6
	// PathDirectV4: host holds its own public IPv4; serve directly.
	PathDirectV4
	// PathNATV4: public v4 exists upstream of a router; needs a port
	// forward (TCP 80/443) or UPnP mapping before inbound works.
	PathNATV4
	// PathCGNAT: egress is carrier-grade NAT; no direct IPv4 path.
	// IPv6 (if present) or a provider relay is the only route.
	PathCGNAT
)

// InboundState reports whether inbound reachability was proven. Local
// detection can never prove it: outbound echo success is not inbound
// evidence, so detection always reports InboundUnknown with guidance.
type InboundState int

const (
	InboundUnknown InboundState = iota
)

// Detection is the result of capability detection.
type Detection struct {
	LocalV4   []string     `json:"local_v4"`
	LocalV6   []string     `json:"local_v6"`
	EgressV4  string       `json:"egress_v4"` // "" when the v4 echo failed
	EgressV6  string       `json:"egress_v6"` // "" when the v6 echo failed or unconfigured
	CGNATv4   bool         `json:"cgnat_v4"`
	DirectV4  bool         `json:"direct_v4"`
	DirectV6  bool         `json:"direct_v6"`
	Path      Path         `json:"path"`
	PathName  string       `json:"path_name"`
	InboundV4 InboundState `json:"inbound_v4"`
	InboundV6 InboundState `json:"inbound_v6"`
	Notes     []string     `json:"notes"`
}

// String renders the recommended path as a stable machine-readable name.
func (p Path) String() string {
	switch p {
	case PathDirectV6:
		return "direct-ipv6"
	case PathDirectV4:
		return "direct-ipv4"
	case PathNATV4:
		return "nat-ipv4-needs-forward"
	case PathCGNAT:
		return "cgnat-no-direct-ipv4"
	default:
		return "unknown"
	}
}

var cgnatV4 = netip.MustParsePrefix("100.64.0.0/10")

// Classify compares local interface addresses against independently
// observed egress addresses. ok4/ok6 report whether each echo
// succeeded; a failed echo is missing evidence, never a negative.
func Classify(localV4, localV6 []netip.Addr, egressV4, egressV6 netip.Addr, ok4, ok6 bool) Detection {
	d := Detection{InboundV4: InboundUnknown, InboundV6: InboundUnknown}
	for _, a := range localV4 {
		d.LocalV4 = append(d.LocalV4, a.String())
	}
	for _, a := range localV6 {
		if a.IsLinkLocalUnicast() {
			continue
		}
		d.LocalV6 = append(d.LocalV6, a.String())
	}
	if ok4 {
		d.EgressV4 = egressV4.String()
		d.CGNATv4 = cgnatV4.Contains(egressV4)
		d.DirectV4 = contains(localV4, egressV4) && !d.CGNATv4
	}
	if ok6 {
		d.EgressV6 = egressV6.String()
		d.DirectV6 = contains(globalV6(localV6), egressV6)
	}
	switch {
	case d.DirectV6:
		d.Path = PathDirectV6
		d.Notes = append(d.Notes, "global IPv6 on-host: Caddy can serve :80/:443 directly; verify inbound from an external network")
	case d.DirectV4:
		d.Path = PathDirectV4
		d.Notes = append(d.Notes, "public IPv4 on-host: Caddy can serve :80/:443 directly; verify inbound from an external network")
	case ok4 && !d.CGNATv4:
		d.Path = PathNATV4
		d.Notes = append(d.Notes, "behind a router: forward TCP 80 and 443 to this host (or enable UPnP), then verify inbound from an external network")
	case d.CGNATv4:
		d.Path = PathCGNAT
		d.Notes = append(d.Notes, "carrier-grade NAT: no direct IPv4 inbound path exists; use IPv6 if available, else a provider relay")
		if ok6 {
			d.Notes = append(d.Notes, "egress IPv6 observed: check DirectV6 once the address is stable")
		}
	default:
		d.Path = PathUnknown
		d.Notes = append(d.Notes, "egress unobserved (echo failed or offline): connect the network and re-run")
	}
	d.Notes = append(d.Notes, "inbound reachability is UNKNOWN until proven by an external client; outbound success does not prove it")
	d.PathName = d.Path.String()
	return d
}

func contains(as []netip.Addr, want netip.Addr) bool {
	for _, a := range as {
		if a == want {
			return true
		}
	}
	return false
}

func globalV6(as []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range as {
		if a.IsGlobalUnicast() {
			out = append(out, a)
		}
	}
	return out
}

// echoClient fetches one echo URL and parses the body as an IP address.
func echoClient(ctx context.Context, url string) (netip.Addr, bool) {
	if strings.TrimSpace(url) == "" {
		return netip.Addr{}, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return netip.Addr{}, false
	}
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil || resp.StatusCode != http.StatusOK {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}

// Gather scans local interfaces and queries the given echo endpoints
// for observed egress addresses. Empty echo URLs are skipped (the
// corresponding egress stays unobserved, never guessed).
func Gather(ctx context.Context, echoV4URL, echoV6URL string) Detection {
	var localV4, localV6 []netip.Addr
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				addr, ok := netip.AddrFromSlice(ip.To16())
				if !ok {
					continue
				}
				addr = addr.Unmap()
				if addr.Is4() {
					localV4 = append(localV4, addr)
				} else {
					localV6 = append(localV6, addr)
				}
			}
		}
	}
	egressV4, ok4 := echoClient(ctx, echoV4URL)
	egressV6, ok6 := echoClient(ctx, echoV6URL)
	return Classify(localV4, localV6, egressV4, egressV6, ok4, ok6)
}
