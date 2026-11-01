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
