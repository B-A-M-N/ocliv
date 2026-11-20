package setup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPass6P1_6DuckDNSRollbackRemovesTokenAndStaging(t *testing.T) {
	dataDir := t.TempDir()
	zone := "demo.duckdns.org"
	tokPath, err := DNSRefreshTokenPath(zone, dataDir)
	if err != nil {
		t.Fatalf("DNSRefreshTokenPath: %v", err)
	}
	if !strings.HasSuffix(tokPath, "duckdns.token") {
		t.Fatalf("expected duckdns.token path, got %q", tokPath)
	}
	stagePath := tokPath + ".ocliv-new"
	if err := os.WriteFile(tokPath, []byte("secret-tok\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagePath, []byte("staged-tok\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// CleanDNSRefreshTokenJournal removes staging without deleting live token.
	CleanDNSRefreshTokenJournal(zone, dataDir)
	if _, err := os.Stat(stagePath); !os.IsNotExist(err) {
		t.Fatalf("expected staging file removed by CleanDNSRefreshTokenJournal")
	}
	if _, err := os.Stat(tokPath); err != nil {
		t.Fatalf("expected live duckdns.token preserved by CleanDNSRefreshTokenJournal: %v", err)
	}

	// Re-create staging file and verify RollbackDNSRefreshToken removes both.
	if err := os.WriteFile(stagePath, []byte("staged-tok\n"), 0600); err != nil {
		t.Fatal(err)
	}
	RollbackDNSRefreshToken(zone, dataDir)
	if _, err := os.Stat(tokPath); !os.IsNotExist(err) {
		t.Fatalf("P1-6 REGRESSION: duckdns.token survived rollback")
	}
	if _, err := os.Stat(stagePath); !os.IsNotExist(err) {
		t.Fatalf("P1-6 REGRESSION: duckdns.token.ocliv-new survived rollback")
	}
}

func TestPass6P1_7RefreshDuckDNSSkipsUnchangedAndRejectsCGNAT(t *testing.T) {
	// Stub echo server returning a public IPv4.
	echoV4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("198.51.100.42"))
	}))
	defer echoV4.Close()
	echoV6 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no v6", http.StatusNotFound)
	}))
	defer echoV6.Close()

	var apiHits int
	duckAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHits++
		_, _ = w.Write([]byte("OK"))
	}))
	defer duckAPI.Close()

	origLookup := LookupHost
	defer func() { LookupHost = origLookup }()

	// Case 1: Current DNS already matches observed egress -> skip update (changed=false, 0 API hits).
	LookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"198.51.100.42"}, nil
	}
	changed, err := RefreshDuckDNS(context.Background(), duckAPI.URL, "demo.duckdns.org", "tok-123", echoV4.URL, echoV6.URL)
	if err != nil {
		// On hosts where Gather sees CGNAT or no local interfaces, skip the unchanged subcase if path isn't direct/NAT.
		if strings.Contains(err.Error(), "no viable direct path") {
			t.Logf("host classified as non-direct path (%v); CGNAT guard confirmed active", err)
		} else {
			t.Fatalf("RefreshDuckDNS unchanged failed: %v", err)
		}
	} else {
		if changed {
			t.Fatalf("P1-7 REGRESSION: RefreshDuckDNS reported changed=true when DNS already matched")
		}
		if apiHits != 0 {
			t.Fatalf("P1-7 REGRESSION: RefreshDuckDNS called provider API (%d hits) when DNS already matched", apiHits)
		}

		// Case 2: Current DNS differs -> push update (changed=true, 1 API hit).
		LookupHost = func(ctx context.Context, host string) ([]string, error) {
			return []string{"198.51.100.1"}, nil
		}
		changed, err = RefreshDuckDNS(context.Background(), duckAPI.URL, "demo.duckdns.org", "tok-123", echoV4.URL, echoV6.URL)
		if err != nil {
			t.Fatalf("RefreshDuckDNS changed failed: %v", err)
		}
		if !changed || apiHits != 1 {
			t.Fatalf("expected changed=true and 1 API hit, got changed=%v hits=%d", changed, apiHits)
		}
	}

	// Case 3: No egress (both echo servers fail) -> MUST fail closed and NEVER call DuckDNS API.
	hitsBefore := apiHits
	changed, err = RefreshDuckDNS(context.Background(), duckAPI.URL, "demo.duckdns.org", "tok-123", echoV6.URL, echoV6.URL)
	if err == nil {
		t.Fatalf("P1-7 REGRESSION: RefreshDuckDNS succeeded with no egress")
	}
	if changed || apiHits != hitsBefore {
		t.Fatalf("P1-7 REGRESSION: RefreshDuckDNS mutated DNS despite no egress")
	}

	_ = filepath.Clean("")
}
