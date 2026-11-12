package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ocliv/internal/apperr"
	"ocliv/internal/authz"
	"ocliv/internal/store"
)

// cmdAuthz handles the operator authorization workflow for managed MCP
// routes. These are relay-side, narrow operations on the local store: they
// never construct a relay Server (that would run boot reconciliation
// against live leases), and they never print secrets.
//
// Authorization is publication-level: approving a client grants it access
// to exactly one tenant + route. It is not tool-level permissioning.
func cmdAuthz(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv authz pending|list|approve|revoke|rotate-key [--data DIR] ...")
		return apperr.ExitCLIValidation
	}
	switch argv[0] {
	case "pending":
		return cmdAuthzPending(argv[1:])
	case "list":
		return cmdAuthzList(argv[1:])
	case "approve":
		return cmdAuthzApprove(argv[1:])
	case "revoke":
		return cmdAuthzRevoke(argv[1:])
	case "rotate-key":
		return cmdAuthzRotateKey(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown authz command %q\n", argv[0])
		return apperr.ExitCLIValidation
	}
}

// authzOpen opens the relay store for a narrow operator read/write.
func authzOpen(dataDir string) (*store.DB, error) {
	restrictFileCreation()
	return store.Open(filepath.Join(dataDir, "ocliv.db"))
}

// authzListFlags parses --data, --tenant, --route, --json.
func authzListFlags(argv []string) (dataDir, tenant, route string, asJSON bool) {
	dataDir = "./ocliv-relay-data"
	for i := 0; i < len(argv); i++ {
		switch {
		case argv[i] == "--data" && i+1 < len(argv):
			i++
			dataDir = argv[i]
		case strings.HasPrefix(argv[i], "--data="):
			dataDir = strings.TrimPrefix(argv[i], "--data=")
		case argv[i] == "--tenant" && i+1 < len(argv):
			i++
			tenant = argv[i]
		case strings.HasPrefix(argv[i], "--tenant="):
			tenant = strings.TrimPrefix(argv[i], "--tenant=")
		case argv[i] == "--route" && i+1 < len(argv):
			i++
			route = argv[i]
		case strings.HasPrefix(argv[i], "--route="):
			route = strings.TrimPrefix(argv[i], "--route=")
		case argv[i] == "--json":
			asJSON = true
		}
	}
	return dataDir, tenant, route, asJSON
}

type authzGrantRow struct {
	Client  string `json:"client"`
	Tenant  string `json:"tenant"`
	Route   string `json:"route"`
	Status  string `json:"status"`
	Created string `json:"created_at"`
	Updated string `json:"updated_at"`
}

func authzRender(rows []authzGrantRow, asJSON bool, emptyMsg string) int {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(rows)
		return apperr.ExitOK
	}
	if len(rows) == 0 {
		fmt.Println(emptyMsg)
		return apperr.ExitOK
	}
	for _, r := range rows {
		fmt.Printf("%s  tenant=%s route=%s status=%s created=%s updated=%s\n",
			r.Client, r.Tenant, r.Route, r.Status, r.Created, r.Updated)
	}
	return apperr.ExitOK
}

// cmdAuthzPending lists clients registered for a managed route that no
// operator has approved yet.
func cmdAuthzPending(argv []string) int {
	dataDir, tenant, route, asJSON := authzListFlags(argv)
	db, err := authzOpen(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db.SQL())
	grants, err := st.ListGrants()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	var out []authzGrantRow
	for _, g := range grants {
		if g.Status != authz.GrantPending {
			continue
		}
		if tenant != "" && g.Tenant != tenant {
			continue
		}
		if route != "" && g.Route != route {
			continue
		}
		out = append(out, authzGrantRow{g.ClientID, g.Tenant, g.Route, string(g.Status),
			g.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), g.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z")})
	}
	return authzRender(out, asJSON, "no pending client approvals")
}

// cmdAuthzList lists every grant.
func cmdAuthzList(argv []string) int {
	dataDir, tenant, route, asJSON := authzListFlags(argv)
	db, err := authzOpen(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db.SQL())
	grants, err := st.ListGrants()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	var out []authzGrantRow
	for _, g := range grants {
		if tenant != "" && g.Tenant != tenant {
			continue
		}
		if route != "" && g.Route != route {
			continue
		}
		out = append(out, authzGrantRow{g.ClientID, g.Tenant, g.Route, string(g.Status),
			g.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), g.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z")})
	}
	return authzRender(out, asJSON, "no client grants")
}

// authzClientFlags parses --client plus the shared filters.
func authzClientFlags(argv []string) (dataDir, client, tenant, route string, ok bool) {
	dataDir, tenant, route, _ = authzListFlags(argv)
	for i := 0; i < len(argv); i++ {
		switch {
		case argv[i] == "--client" && i+1 < len(argv):
			i++
			client = argv[i]
		case strings.HasPrefix(argv[i], "--client="):
			client = strings.TrimPrefix(argv[i], "--client=")
		}
	}
	if client == "" {
		fmt.Fprintln(os.Stderr, "--client is required")
		return dataDir, "", "", "", false
	}
	return dataDir, client, tenant, route, true
}

// cmdAuthzApprove approves a registered client for a tenant + route.
func cmdAuthzApprove(argv []string) int {
	dataDir, client, tenant, route, ok := authzClientFlags(argv)
	if !ok {
		return apperr.ExitCLIValidation
	}
	db, err := authzOpen(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db.SQL())
	grants, err := st.ListGrants()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	matched := false
	for _, g := range grants {
		if g.ClientID != client {
			continue
		}
		if tenant != "" && g.Tenant != tenant {
			continue
		}
		if route != "" && g.Route != route {
			continue
		}
		if g.Status == authz.GrantRevoked {
			fmt.Fprintf(os.Stderr, "client %s is revoked for tenant=%s route=%s; delete the grant first\n", client, g.Tenant, g.Route)
			return apperr.ExitCLIValidation
		}
		if err := st.ApproveGrant(g.ClientID, g.Tenant, g.Route); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		matched = true
		fmt.Printf("approved client %s for tenant=%s route=%s\n", g.ClientID, g.Tenant, g.Route)
	}
	if !matched {
		fmt.Fprintf(os.Stderr, "no pending grant for client %s (tenant=%q route=%q)\n", client, tenant, route)
		return apperr.ExitCLIValidation
	}
	return apperr.ExitOK
}

// cmdAuthzRevoke revokes a client's grant immediately.
func cmdAuthzRevoke(argv []string) int {
	dataDir, client, tenant, route, ok := authzClientFlags(argv)
	if !ok {
		return apperr.ExitCLIValidation
	}
	db, err := authzOpen(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db.SQL())
	grants, err := st.ListGrants()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	matched := false
	for _, g := range grants {
		if g.ClientID != client {
			continue
		}
		if tenant != "" && g.Tenant != tenant {
			continue
		}
		if route != "" && g.Route != route {
			continue
		}
		if err := st.RevokeGrant(g.ClientID, g.Tenant, g.Route); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		matched = true
		fmt.Printf("revoked client %s for tenant=%s route=%s\n", g.ClientID, g.Tenant, g.Route)
	}
	if !matched {
		fmt.Fprintf(os.Stderr, "no grant for client %s (tenant=%q route=%q)\n", client, tenant, route)
		return apperr.ExitCLIValidation
	}
	return apperr.ExitOK
}

// cmdAuthzRotateKey rotates the relay's authorization issuer key. Existing
// tokens signed by the retired key stop validating at admission.
func cmdAuthzRotateKey(argv []string) int {
	dataDir, _, _, _ := authzListFlags(argv)
	db, err := authzOpen(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db.SQL())
	issuer, err := st.RotateIssuer()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	fmt.Printf("rotated authorization issuer key (kid %s)\n", issuer.KeyID())
	return apperr.ExitOK
}
