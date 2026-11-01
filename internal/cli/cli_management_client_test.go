package cli

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMgmtHTTPClientTrustsLabBundle is the regression test for the
// publish-through-lab-edge failure: signed mgmt calls and OAuth
// discovery probes used a bare http.Client, so every HTTPS call against
// a private-CA edge (Caddy `tls internal`) failed while the agent's own
// transport (which honors OCLIV_CACERT) attached fine. Route
// registration therefore silently never happened.
func TestMgmtHTTPClientTrustsLabBundle(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Negative control: a bare client must NOT trust the test server's
	// private CA. If this ever passes, the fixture is misconfigured and
	// the positive assertion below proves nothing.
	bare := &http.Client{Timeout: 5 * time.Second}
	if _, err := bare.Get(srv.URL); err == nil {
		t.Fatal("bare client unexpectedly trusted httptest TLS server; fixture invalid")
	}

	// Export the server's CA the way the lab trusts Caddy's root.
	cert := srv.Certificate()
	if cert == nil || len(cert.Raw) == 0 {
		t.Fatal("httptest server exposed no CA certificate")
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "lab-ca.crt")
	if err := os.WriteFile(caFile, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCLIV_CACERT", caFile)

	client, err := mgmtHTTPClient(5 * time.Second)
	if err != nil {
		t.Fatalf("mgmtHTTPClient with valid bundle: %v", err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("bundle-trusted client could not reach private-CA server: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestMgmtHTTPClientBrokenBundleFailsClosed: a set-but-unreadable bundle
// must surface an error, never silently fall back to system roots (which
// would fail open in the other direction: unreachable lab edge reported
// as generic connection failure) or skip verification.
func TestMgmtHTTPClientBrokenBundleFailsClosed(t *testing.T) {
	t.Setenv("OCLIV_CACERT", filepath.Join(t.TempDir(), "does-not-exist.crt"))
	if _, err := mgmtHTTPClient(5 * time.Second); err == nil {
		t.Fatal("mgmtHTTPClient with missing bundle file: got nil error, want failure")
	}

	garbage := filepath.Join(t.TempDir(), "garbage.crt")
	if err := os.WriteFile(garbage, []byte("not a pem bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCLIV_CACERT", garbage)
	if _, err := mgmtHTTPClient(5 * time.Second); err == nil {
		t.Fatal("mgmtHTTPClient with unparseable bundle: got nil error, want failure")
	}
}

// TestMgmtHTTPClientUnsetKeepsDefaults: with no bundle configured the
// client must behave exactly like the previous bare client (default
// verification, no custom transport overrides that could weaken it).
func TestMgmtHTTPClientUnsetKeepsDefaults(t *testing.T) {
	t.Setenv("OCLIV_CACERT", "")
	client, err := mgmtHTTPClient(5 * time.Second)
	if err != nil {
		t.Fatalf("mgmtHTTPClient unset: %v", err)
	}
	if client.Transport != nil {
		t.Fatal("unset bundle must leave default transport (nil), permitting no verification overrides")
	}
}
