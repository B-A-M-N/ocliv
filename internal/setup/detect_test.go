package setup

// Detection classification contract (Slice 1): given local interface
// addresses and independently observed egress addresses, Classify must
// distinguish directly-addressed hosts, NAT/router hosts needing a port
// forward, CGNAT hosts with no direct IPv4 path, and the unknown case.
// Outbound echo success is never reported as inbound reachability.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func mustAddrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("bad test addr %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

func TestClassifyCGNAT(t *testing.T) {
	d := Classify(
		mustAddrs(t, "192.168.1.20"),
		nil,
		netip.MustParseAddr("100.64.5.6"), netip.Addr{},
		true, false,
	)
	if !d.CGNATv4 {
		t.Error("CGNAT egress not flagged")
	}
	if d.DirectV4 {
		t.Error("CGNAT host reported as directly reachable over v4")
	}
	if d.Path != PathCGNAT {
		t.Errorf("Path = %v, want PathCGNAT", d.Path)
	}
	if d.InboundV4 != InboundUnknown {
		t.Errorf("InboundV4 = %v, want InboundUnknown (echo is outbound-only evidence)", d.InboundV4)
	}
}

func TestClassifyDirectV6(t *testing.T) {
	d := Classify(
		nil,
		mustAddrs(t, "2001:db8::1234"),
		netip.Addr{}, netip.MustParseAddr("2001:db8::1234"),
		false, true,
	)
	if !d.DirectV6 {
		t.Error("matching global v6 not reported as direct")
	}
	if d.Path != PathDirectV6 {
		t.Errorf("Path = %v, want PathDirectV6", d.Path)
	}
}

func TestClassifyNATNeedsForward(t *testing.T) {
	d := Classify(
		mustAddrs(t, "192.168.1.20"),
		nil,
		netip.MustParseAddr("203.0.113.7"), netip.Addr{},
		true, false,
	)
	if d.CGNATv4 || d.DirectV4 {
		t.Errorf("CGNAT=%v DirectV4=%v, want false/false behind a router", d.CGNATv4, d.DirectV4)
	}
	if d.Path != PathNATV4 {
		t.Errorf("Path = %v, want PathNATV4 (forward TCP 80/443 or UPnP)", d.Path)
	}
}

func TestClassifyDirectV4(t *testing.T) {
	d := Classify(
		mustAddrs(t, "203.0.113.7"),
		nil,
		netip.MustParseAddr("203.0.113.7"), netip.Addr{},
		true, false,
	)
	if !d.DirectV4 || d.Path != PathDirectV4 {
		t.Errorf("DirectV4=%v Path=%v, want true/PathDirectV4", d.DirectV4, d.Path)
	}
}

func TestClassifyUnknownWhenEchoFails(t *testing.T) {
	d := Classify(mustAddrs(t, "192.168.1.20"), nil, netip.Addr{}, netip.Addr{}, false, false)
	if d.Path != PathUnknown {
		t.Errorf("Path = %v, want PathUnknown when egress is unobserved", d.Path)
	}
}

// Gather must use the injected echo endpoints (never a hardcoded
// third-party service inside the test) and report their answers.
func TestGatherUsesEchoEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := Gather(ctx, srv.URL, "")
	if d.EgressV4 != "203.0.113.9" {
		t.Errorf("EgressV4 = %q, want echo answer", d.EgressV4)
	}
	if d.EgressV6 != "" {
		t.Errorf("EgressV6 = %q, want empty when no v6 echo URL is configured", d.EgressV6)
	}
}
