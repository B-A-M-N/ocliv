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

// authzFlags is the strict parse result for authz subcommands. Every
// recognized flag must carry a nonempty value; unknown flags, missing
// values, duplicate flags, and unexpected positional arguments are
// rejected instead of silently ignored — a misspelled --data could
// otherwise target ./ocliv-relay-data and mutate the wrong database.
type authzFlags struct {
	dataDir string
	tenant  string
	route   string
	client  string
	asJSON  bool
}

// authzFlagSpec lists the flags a subcommand accepts and which are required.
type authzFlagSpec struct {
	allowed  map[string]bool
	required map[string]bool
}

func authzSpecFor(flags ...string) authzFlagSpec {
	s := authzFlagSpec{allowed: map[string]bool{"data": true}, required: map[string]bool{}}
	for _, f := range flags {
		s.allowed[f] = true
	}
	return s
}

// parseAuthzFlags strictly parses argv against the spec. dataDir defaults to
// ./ocliv-relay-data only when --data was not mentioned at all; a misspelled
// --data is an error, never a silent default.
func parseAuthzFlags(argv []string, spec authzFlagSpec) (*authzFlags, error) {
	f := &authzFlags{}
	seen := map[string]string{} // flag -> raw arg (for duplicate detection)
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		name := ""
		var val string
		hasVal := false
		switch {
		case strings.HasPrefix(arg, "--"):
			body := strings.TrimPrefix(arg, "--")
			if eq := strings.Index(body, "="); eq >= 0 {
				name = body[:eq]
				val = body[eq+1:]
				hasVal = true
			} else {
				name = body
			}
		default:
			return nil, fmt.Errorf("unexpected argument %q (authz subcommands take flags only)", arg)
		}
		if !spec.allowed[name] {
			return nil, fmt.Errorf("unknown flag --%s", name)
		}
		if !hasVal {
			if i+1 >= len(argv) {
				return nil, fmt.Errorf("--%s requires a value", name)
			}
			i++
			val = argv[i]
		}
		if val == "" {
			return nil, fmt.Errorf("--%s value must not be empty", name)
		}
		if prev, dup := seen[name]; dup {
			return nil, fmt.Errorf("--%s given twice (%q and %q)", name, prev, val)
		}
		seen[name] = val
		switch name {
		case "data":
			f.dataDir = val
		case "tenant":
			f.tenant = val
		case "route":
			f.route = val
		case "client":
			f.client = val
		case "json":
			if !hasVal {
				// bare --json: boolean flag, value form not supported
				f.asJSON = true
				continue
			}
			return nil, fmt.Errorf("--json does not take a value")
		}
	}
	for name := range spec.required {
		if _, ok := seen[name]; !ok {
			return nil, fmt.Errorf("--%s is required", name)
		}
	}
	if f.dataDir == "" {
		f.dataDir = "./ocliv-relay-data"
	}
	return f, nil
}

// authzListFlags is the strict list/pending parser (data, tenant, route, json).
// It returns ok=false on any parse error, printing the reason to stderr.
func authzListFlags(argv []string) (dataDir, tenant, route string, asJSON bool, ok bool) {
	f, err := parseAuthzFlags(argv, authzSpecFor("tenant", "route", "json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return "", "", "", false, false
	}
	return f.dataDir, f.tenant, f.route, f.asJSON, true
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
	dataDir, tenant, route, asJSON, okL := authzListFlags(argv)
	if !okL {
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
	dataDir, tenant, route, asJSON, okL := authzListFlags(argv)
	if !okL {
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

// authzClientFlags strictly parses --client plus the shared filters.
// --client is required; unknown flags and duplicates are rejected.
func authzClientFlags(argv []string) (dataDir, client, tenant, route string, ok bool) {
	spec := authzSpecFor("tenant", "route", "client")
	spec.required["client"] = true
	f, err := parseAuthzFlags(argv, spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return "", "", "", "", false
	}
	return f.dataDir, f.client, f.tenant, f.route, true
}

// authzAudit writes an authorization-plane decision record. The actor is
// the local operator: this CLI's authority is filesystem/DB access on the
// relay host, NOT the enrollment key. That distinction is deliberate and
// documented in the ADR.
func authzAudit(st *authz.SQLStore, tenant, route, client, action, result, detail string) {
	if err := st.AuditAuthz("operator", tenant, route, client, action, result, detail); err != nil {
		fmt.Fprintln(os.Stderr, "warning: audit record failed: "+err.Error())
	}
}

// cmdAuthzApprove approves a registered client for a tenant + route and
// issues the pairing secret the client must present to obtain a code.
func cmdAuthzApprove(argv []string) int {
	dataDir, client, tenant, route, ok := authzClientFlags(argv)
	if !ok {
		return apperr.ExitCLIValidation
	}
	// Tenant and route must be named explicitly. Approving by client alone
	// could silently cover several grants; ambiguity is an error, never a
	// guess.
	if tenant == "" || route == "" {
		fmt.Fprintln(os.Stderr, "--tenant and --route are required: a client may have grants on several routes, and an ambiguous approval is never guessed")
		return apperr.ExitCLIValidation
	}
	db, err := authzOpen(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db.SQL())
	grant, gerr := st.GetGrant(client, tenant, route)
	if gerr != nil {
		fmt.Fprintf(os.Stderr, "no pending grant for client %s tenant=%s route=%s; the client must initiate authorization first\n", client, tenant, route)
		return apperr.ExitCLIValidation
	}
	if grant.Status == authz.GrantRevoked {
		fmt.Fprintf(os.Stderr, "client %s is revoked for tenant=%s route=%s; delete the grant first\n", client, tenant, route)
		return apperr.ExitCLIValidation
	}
	secret, err := authz.MintPairingSecret()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	// Activation and credential issuance are ONE step: an approval that
	// cannot persist its credential must not leave an ACTIVE grant that no
	// consent can ever complete.
	if err := st.ApproveGrantWithPairingSecret(client, tenant, route, secret, authz.DefaultPairingTTL); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	authzAudit(st, tenant, route, client, "approve", "ok", "grant active; pairing secret issued")
	fmt.Printf("approved client %s for tenant=%s route=%s\n", client, tenant, route)
	fmt.Println("Pairing secret (show once; deliver it to the client operator over a private channel):")
	fmt.Println(secret)
	fmt.Println("The client must present it in the consent form (pairing_secret) when the")
	fmt.Println("authorization page is shown. It is single-use and expires; run this command")
	fmt.Println("again to authorize another authorization flow.")
	return apperr.ExitOK
}

// cmdAuthzRevoke revokes a client's grant immediately.
func cmdAuthzRevoke(argv []string) int {
	dataDir, client, tenant, route, ok := authzClientFlags(argv)
	if !ok {
		return apperr.ExitCLIValidation
	}
	if tenant == "" || route == "" {
		fmt.Fprintln(os.Stderr, "--tenant and --route are required: an ambiguous revocation is never guessed")
		return apperr.ExitCLIValidation
	}
	db, err := authzOpen(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db.SQL())
	if _, gerr := st.GetGrant(client, tenant, route); gerr != nil {
		fmt.Fprintf(os.Stderr, "no grant for client %s tenant=%s route=%s\n", client, tenant, route)
		return apperr.ExitCLIValidation
	}
	if err := st.RevokeGrant(client, tenant, route); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	authzAudit(st, tenant, route, client, "revoke", "ok", "grant revoked")
	fmt.Printf("revoked client %s for tenant=%s route=%s\n", client, tenant, route)
	fmt.Println("Existing tokens stop working on the next request.")
	return apperr.ExitOK
}

// cmdAuthzRotateKey rotates the relay's authorization issuer key. Existing
// tokens signed by the retired key stop validating at admission.
func cmdAuthzRotateKey(argv []string) int {
	f, err := parseAuthzFlags(argv, authzSpecFor())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}
	dataDir := f.dataDir
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
	authzAudit(st, "", "", "", "rotate-key", "ok", "issuer key rotated (kid "+issuer.KeyID()+")")
	fmt.Printf("rotated authorization issuer key (kid %s)\n", issuer.KeyID())
	return apperr.ExitOK
}
