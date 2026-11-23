package cli

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/B-A-M-N/ocliv/internal/authz"
	"github.com/B-A-M-N/ocliv/internal/store"
)

func TestAuthzRegisterDirectAndGrantRouteCLI(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.Close()

	// Pre-register with --direct
	if code := cmdAuthz([]string{
		"register",
		"--data", dir,
		"--tenant", "default",
		"--route", "route-1",
		"--name", "ChatGPT",
		"--redirect", "https://chatgpt.com/connector_platform_oauth_redirect",
		"--direct",
	}); code != 0 {
		t.Fatalf("authz register --direct exit=%d", code)
	}

	ro, err := openRelayDBReadOnly(dir)
	if err != nil {
		t.Fatalf("openRO: %v", err)
	}
	st := authz.NewSQLStore(ro)
	grants, err := st.ListGrants()
	ro.Close()
	if err != nil || len(grants) != 1 {
		t.Fatalf("ListGrants: %v len=%d", err, len(grants))
	}
	if grants[0].ClientName != "ChatGPT" || grants[0].Status != authz.GrantActive || !grants[0].SkipPairing {
		t.Fatalf("unexpected grant: %+v", grants[0])
	}

	// Cross-route grant-route
	if code := cmdAuthz([]string{
		"grant-route",
		"--data", dir,
		"--tenant", "default",
		"--route", "route-2",
		"--client", grants[0].ClientID,
	}); code != 0 {
		t.Fatalf("authz grant-route exit=%d", code)
	}

	ro2, err := openRelayDBReadOnly(dir)
	if err != nil {
		t.Fatalf("openRO2: %v", err)
	}
	defer ro2.Close()
	st2 := authz.NewSQLStore(ro2)
	g2, err := st2.GetGrant(grants[0].ClientID, "default", "route-2")
	if err != nil || g2.Status != authz.GrantActive || !g2.SkipPairing {
		t.Fatalf("route-2 grant=%+v err=%v", g2, err)
	}
}

func TestAuthzApproveDirectCLI(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st := authz.NewSQLStore(db.SQL())
	now := time.Now()
	if err := st.RegisterClient(authz.Client{
		ID: "cli_direct", Name: "Mistral", RedirectURIs: []string{"https://chat.mistral.ai/cb"},
		CreatedAt: now, Tenant: "default", Route: "r1",
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := st.CreateGrant(authz.Grant{
		ClientID: "cli_direct", Tenant: "default", Route: "r1", Status: authz.GrantPending,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create grant: %v", err)
	}
	db.Close()

	if code := cmdAuthz([]string{
		"approve", "--data", dir, "--tenant", "default", "--route", "r1", "--client", "cli_direct", "--direct",
	}); code != 0 {
		t.Fatalf("authz approve --direct exit=%d", code)
	}

	ro, err := openRelayDBReadOnly(dir)
	if err != nil {
		t.Fatalf("openRO: %v", err)
	}
	defer ro.Close()
	g, err := authz.NewSQLStore(ro).GetGrant("cli_direct", "default", "r1")
	if err != nil || g.Status != authz.GrantActive || !g.SkipPairing {
		t.Fatalf("grant=%+v err=%v", g, err)
	}

	// `authz refresh` preserves direct mode
	if code := cmdAuthz([]string{
		"refresh", "--data", dir, "--tenant", "default", "--route", "r1", "--client", "cli_direct",
	}); code != 0 {
		t.Fatalf("authz refresh exit=%d", code)
	}
}
