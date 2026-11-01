package doctor

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// localPort extracts the loopback port from an httptest server URL.
func localPort(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// stagingCAFile writes cert DER as PEM and returns its path.
func stagingCAFile(t *testing.T, der []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "staging-ca.crt")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return p
}

// Untrusted TLS must be a verified negative — never an error-shaped
// unknown, and never bypassed.
func TestAgentProbeRejectsUntrustedTLS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()
	res := CheckAgent(AgentInput{KeyPath: "/nonexistent/key", RelayURL: ts.URL})
	byName := map[string]Finding{}
	for _, f := range res.Findings {
		byName[f.Name] = f
	}
	tlsF, ok := byName["relay TLS identity"]
	if !ok {
		t.Fatal("relay TLS identity finding missing")
	}
	if !tlsF.Verified || tlsF.OK {
		t.Errorf("untrusted TLS must be a verified negative: %+v", tlsF)
	}
	if res.OK {
		t.Error("result OK despite untrusted TLS")
	}
}

// The same server with its CA explicitly trusted must verify.
func TestAgentProbeTrustsStagingCA(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()
	ca := stagingCAFile(t, ts.Certificate().Raw)
	res := CheckAgent(AgentInput{KeyPath: "/nonexistent/key", RelayURL: ts.URL, CACertPath: ca})
	byName := map[string]Finding{}
	for _, f := range res.Findings {
		byName[f.Name] = f
	}
	if r := byName["relay reachability"]; !r.Verified || !r.OK {
		t.Errorf("challenge probe through trusted TLS must verify reachability: %+v", r)
	}
	if t2 := byName["relay TLS identity"]; !t2.Verified || !t2.OK {
		t.Errorf("staging CA trust must verify TLS identity: %+v", t2)
	}
}

// Local service must be a real HTTP probe with a recorded status.
func TestAgentProbeHitsLocalHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer ts.Close()
	res := CheckAgent(AgentInput{KeyPath: "/nonexistent/key", RelayURL: "http://127.0.0.1:1", Port: localPort(t, ts.URL)})
	byName := map[string]Finding{}
	for _, f := range res.Findings {
		byName[f.Name] = f
	}
	if l := byName["local service"]; !l.Verified || !l.OK {
		t.Errorf("local HTTP probe must verify: %+v", l)
	}
}

// An IPv6 tunnel has nothing on 127.0.0.1: the doctor must probe the
// recorded family (Round 18). An [::1] server verifies OK with
// IPv6:true; the same port with IPv6:false must be a verified negative,
// never a silent IPv4 misdiagnosis.
func TestAgentProbeHonorsIPv6Family(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	defer srv.Close()
	go func() { _ = srv.Serve(ln) }()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	byName := func(in AgentInput) map[string]Finding {
		m := map[string]Finding{}
		for _, f := range CheckAgent(in).Findings {
			m[f.Name] = f
		}
		return m
	}
	base := AgentInput{KeyPath: "/nonexistent/key", RelayURL: "http://127.0.0.1:1", Port: n}
	if got := byName(base)["local service"]; !got.Verified || got.OK {
		t.Errorf("IPv4 probe of an IPv6-only server must be a verified negative: %+v", got)
	}
	v6 := base
	v6.IPv6 = true
	if got := byName(v6)["local service"]; !got.Verified || !got.OK {
		t.Errorf("IPv6 probe of an IPv6 server must verify OK: %+v", got)
	}
}

// relayAuthorityHost: explicit --relay-host wins, default is
// relay.<domain>, nothing known is empty.
func TestRelayAuthorityHostSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   RelayInput
		want string
	}{
		{"default", RelayInput{Domain: "ocliv.test"}, "relay.ocliv.test"},
		{"explicit wins", RelayInput{Domain: "ocliv.test", RelayHost: "pop-os-3.tail1234.ts.net"}, "pop-os-3.tail1234.ts.net"},
		{"case and space trimmed", RelayInput{RelayHost: "  RELAY.Example.ORG "}, "relay.example.org"},
		{"nothing known", RelayInput{}, ""},
	} {
		if got := relayAuthorityHost(tc.in); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

// An explicit relay host must drive the DNS finding line instead of a
// relay.<domain> guess (Round 18): the finding names the probed host.
func TestRelayDoctorProbesExplicitHost(t *testing.T) {
	res := CheckRelay(RelayInput{DataDir: t.TempDir(), RelayHost: "relay.invalid"})
	found := false
	for _, f := range res.Findings {
		if f.Name == "relay DNS" && strings.Contains(f.Detail, "relay.invalid") {
			found = true
		}
		if f.Name == "relay DNS" && strings.Contains(f.Detail, "relay..") {
			t.Errorf("doctor fell back to an empty-domain guess: %+v", f)
		}
	}
	if !found {
		t.Errorf("relay DNS finding does not name the explicit host: %+v", res.Findings)
	}
}

// TestNoUnverifiedGreens: doctor must never present an unverified check as
// a verified pass. Clock and health-endpoint claims are explicitly
// unverified (H05).
func TestNoUnverifiedGreens(t *testing.T) {
	res := CheckAgent(AgentInput{KeyPath: "/nonexistent/key", RelayURL: "https://relay.example.com"})
	seen := map[string]bool{}
	for _, f := range res.Findings {
		seen[f.Name] = true
		if f.Name == "clock" && f.Verified {
			t.Errorf("clock finding claims verification: %+v", f)
		}
		if f.Name == "health endpoints" && f.Verified {
			t.Errorf("health-endpoints finding claims verification: %+v", f)
		}
	}
	if !seen["clock"] {
		t.Error("clock finding missing")
	}
	res2 := CheckRelay(RelayInput{DataDir: t.TempDir(), Domain: "example.test"})
	for _, f := range res2.Findings {
		if f.Name == "health endpoints" && f.Verified {
			t.Errorf("relay health-endpoints finding claims verification: %+v", f)
		}
	}
}

// Doctor must judge the local target by the tunnel's recorded probe
// contract (Domain A), not by a hardcoded GET /: the wrong path or the
// wrong expected status must be a verified negative, never a green
// "answered" line for a contract the tunnel never promised.
func TestAgentProbeHonorsRecordedContract(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()
	byName := func(in AgentInput) map[string]Finding {
		m := map[string]Finding{}
		for _, f := range CheckAgent(in).Findings {
			m[f.Name] = f
		}
		return m
	}
	base := AgentInput{KeyPath: "/nonexistent/key", RelayURL: "http://127.0.0.1:1",
		Port: localPort(t, ts.URL), ProbePath: "/healthz", ProbeStatus: 204}
	got, ok := byName(base)["local service"]
	if !ok || !got.Verified || !got.OK {
		t.Fatalf("matching probe contract not verified-OK: %+v", got)
	}
	mismatch := base
	mismatch.ProbeStatus = 200
	got, ok = byName(mismatch)["local service"]
	if !ok || !got.Verified || got.OK {
		t.Fatalf("wrong expected status not a verified negative: %+v", got)
	}
	wrongPath := base
	wrongPath.ProbePath = "/other"
	got, ok = byName(wrongPath)["local service"]
	if !ok || !got.Verified || got.OK {
		t.Fatalf("wrong probe path not a verified negative: %+v", got)
	}
}
