package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/authz"
	"github.com/B-A-M-N/ocliv/internal/store"
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
		fmt.Fprintln(os.Stderr, "usage: ocliv authz pending|list|approve|refresh|grant-route|register|revoke|rotate-key [--data DIR] ...")
		return apperr.ExitCLIValidation
	}
	switch argv[0] {
	case "pending":
		return cmdAuthzPending(argv[1:])
	case "list":
		return cmdAuthzList(argv[1:])
	case "approve":
		return cmdAuthzApprove(argv[1:])
	case "refresh":
		return cmdAuthzRefresh(argv[1:])
	case "grant-route":
		return cmdAuthzGrantRoute(argv[1:])
	case "register":
		return cmdAuthzRegister(argv[1:])
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

// authzOpenReadOnly opens an EXISTING relay database read-only for
// observational commands (pending/list). It never creates the database,
// never migrates it, and never changes its bytes — an inventory command
// must not have store.Open's create/migrate side effects.
func authzOpenReadOnly(dataDir string) (*sql.DB, error) {
	return openRelayDBReadOnly(dataDir)
}

// authzFlags is the strict parse result for authz subcommands. Every
// recognized flag must carry a nonempty value; unknown flags, missing
// values, duplicate flags, and unexpected positional arguments are
// rejected instead of silently ignored — a misspelled --data could
// otherwise target ./ocliv-relay-data and mutate the wrong database.
type authzFlags struct {
	dataDir       string
	tenant        string
	route         string
	client        string
	name          string
	redirect      string
	refreshPolicy string
	secretOut     string
	asJSON        bool
	direct        bool
	confidential  bool
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
		if name == "json" {
			if hasVal {
				return nil, fmt.Errorf("--json does not take a value")
			}
			if f.asJSON {
				return nil, fmt.Errorf("--json given twice")
			}
			f.asJSON = true
			seen[name] = "true"
			continue
		}
		if name == "direct" {
			if hasVal {
				return nil, fmt.Errorf("--direct does not take a value")
			}
			if f.direct {
				return nil, fmt.Errorf("--direct given twice")
			}
			f.direct = true
			seen[name] = "true"
			continue
		}
		if name == "confidential" {
			if hasVal {
				return nil, fmt.Errorf("--confidential does not take a value")
			}
			if f.confidential {
				return nil, fmt.Errorf("--confidential given twice")
			}
			f.confidential = true
			seen[name] = "true"
			continue
		}
		if !hasVal {
			if i+1 >= len(argv) || strings.HasPrefix(argv[i+1], "-") {
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
		case "name":
			f.name = val
		case "redirect":
			f.redirect = val
		case "refresh-policy":
			f.refreshPolicy = val
		case "secret-out":
			f.secretOut = val
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
	Client       string   `json:"client"`
	Name         string   `json:"name,omitempty"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	Tenant       string   `json:"tenant"`
	Route        string   `json:"route"`
	Status       string   `json:"status"`
	SkipPairing  bool     `json:"skip_pairing,omitempty"`
	Created      string   `json:"created_at"`
	Updated      string   `json:"updated_at"`
}

func authzGrantRowFromGrant(g authz.Grant) authzGrantRow {
	return authzGrantRow{
		Client:       g.ClientID,
		Name:         g.ClientName,
		RedirectURIs: g.RedirectURIs,
		Tenant:       g.Tenant,
		Route:        g.Route,
		Status:       string(g.Status),
		SkipPairing:  g.SkipPairing,
		Created:      g.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Updated:      g.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
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
		redirects := "[]"
		if len(r.RedirectURIs) > 0 {
			redirects = "[" + strings.Join(r.RedirectURIs, ",") + "]"
		}
		fmt.Printf("%s  name=%q redirects=%s tenant=%s route=%s status=%s direct=%t created=%s updated=%s\n",
			r.Client, r.Name, redirects, r.Tenant, r.Route, r.Status, r.SkipPairing, r.Created, r.Updated)
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
	db, err := authzOpenReadOnly(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db)
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
		out = append(out, authzGrantRowFromGrant(g))
	}
	return authzRender(out, asJSON, "no pending client approvals")
}

// cmdAuthzList lists every grant.
func cmdAuthzList(argv []string) int {
	dataDir, tenant, route, asJSON, okL := authzListFlags(argv)
	if !okL {
		return apperr.ExitCLIValidation
	}
	db, err := authzOpenReadOnly(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db)
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
		out = append(out, authzGrantRowFromGrant(g))
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
// issues the pairing secret the client must present to obtain a code, or
// activates a direct grant (--direct) that skips the pairing consent form.
func cmdAuthzApprove(argv []string) int {
	spec := authzSpecFor("tenant", "route", "client", "direct")
	spec.required["client"] = true
	f, ferr := parseAuthzFlags(argv, spec)
	if ferr != nil {
		fmt.Fprintln(os.Stderr, "error: "+ferr.Error())
		return apperr.ExitCLIValidation
	}
	dataDir, client, tenant, route, direct := f.dataDir, f.client, f.tenant, f.route, f.direct
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
	if direct {
		if err := st.ApproveGrantDirect(client, tenant, route); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		authzAudit(st, tenant, route, client, "approve", "ok", "direct grant active; pairing bypassed")
		fmt.Printf("approved client %s for tenant=%s route=%s (direct; pairing bypassed)\n", client, tenant, route)
		return apperr.ExitOK
	}
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

// cmdAuthzGrantRoute grants an existing tenant-scoped client direct access to
// an additional route in the same tenant without re-registering.
func cmdAuthzGrantRoute(argv []string) int {
	spec := authzSpecFor("tenant", "route", "client")
	spec.required["client"] = true
	spec.required["tenant"] = true
	spec.required["route"] = true
	f, ferr := parseAuthzFlags(argv, spec)
	if ferr != nil {
		fmt.Fprintln(os.Stderr, "error: "+ferr.Error())
		return apperr.ExitCLIValidation
	}
	db, err := authzOpen(f.dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db.SQL())
	if err := st.ApproveGrantDirect(f.client, f.tenant, f.route); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	authzAudit(st, f.tenant, f.route, f.client, "grant-route", "ok", "cross-route direct grant active")
	fmt.Printf("granted client %s direct access to tenant=%s route=%s\n", f.client, f.tenant, f.route)
	return apperr.ExitOK
}

// cmdAuthzRegister pre-registers an OAuth client for a tenant + route and
// optionally approves it directly (--direct).
func cmdAuthzRegister(argv []string) int {
	spec := authzSpecFor("tenant", "route", "name", "redirect", "direct", "confidential", "refresh-policy", "secret-out")
	spec.required["tenant"] = true
	spec.required["route"] = true
	spec.required["name"] = true
	spec.required["redirect"] = true
	f, ferr := parseAuthzFlags(argv, spec)
	if ferr != nil {
		fmt.Fprintln(os.Stderr, "error: "+ferr.Error())
		return apperr.ExitCLIValidation
	}
	refreshPolicy := strings.TrimSpace(f.refreshPolicy)
	switch refreshPolicy {
	case "", "default":
		refreshPolicy = ""
	case "google_confidential":
		if !f.confidential {
			fmt.Fprintln(os.Stderr, "error: --refresh-policy google_confidential requires --confidential")
			return apperr.ExitCLIValidation
		}
	default:
		fmt.Fprintf(os.Stderr, "error: invalid --refresh-policy %q (must be default or google_confidential)\n", f.refreshPolicy)
		return apperr.ExitCLIValidation
	}
	if f.secretOut != "" && !f.confidential {
		fmt.Fprintln(os.Stderr, "error: --secret-out requires --confidential")
		return apperr.ExitCLIValidation
	}
	var redirects []string
	for _, r := range strings.Split(f.redirect, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			redirects = append(redirects, r)
		}
	}
	if len(redirects) == 0 {
		fmt.Fprintln(os.Stderr, "error: --redirect must contain at least one URI")
		return apperr.ExitCLIValidation
	}
	for _, uri := range redirects {
		if err := authz.ValidateRedirectURI(uri, redirects); err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid --redirect %q: %v\n", uri, err)
			return apperr.ExitCLIValidation
		}
	}
	id, err := authz.MintClientID()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	db, err := authzOpen(f.dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db.SQL())
	now := time.Now()
	clientMode := "public"
	var clientSecret, clientSecretHash string
	if f.confidential {
		sec, serr := authz.MintPairingSecret()
		if serr != nil {
			fmt.Fprintln(os.Stderr, "error: "+serr.Error())
			return apperr.ExitInternal
		}
		clientMode = "confidential"
		clientSecret = sec
		clientSecretHash = authz.HashSecret(sec)
	}
	client := authz.Client{
		ID:               id,
		Name:             f.name,
		RedirectURIs:     redirects,
		CreatedAt:        now,
		Tenant:           f.tenant,
		Route:            f.route,
		ClientMode:       clientMode,
		ClientSecretHash: clientSecretHash,
		RefreshPolicy:    refreshPolicy,
	}
	writeSecret := func() error {
		if clientSecret == "" {
			return nil
		}
		if f.secretOut != "" {
			if werr := os.WriteFile(f.secretOut, []byte(clientSecret+"\n"), 0o600); werr != nil {
				return fmt.Errorf("write --secret-out %s: %w", f.secretOut, werr)
			}
			fmt.Printf("Client secret written to %s (mode 0600; never stored in plaintext in database)\n", f.secretOut)
			return nil
		}
		fmt.Printf("Client secret (show once; never stored in plaintext):\n%s\n", clientSecret)
		return nil
	}
	if f.direct {
		if err := st.RegisterClient(client); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		if err := st.ApproveGrantDirect(id, f.tenant, f.route); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		authzAudit(st, f.tenant, f.route, id, "register", "ok", "pre-registered with direct grant")
		fmt.Printf("registered and approved client %s (name=%q mode=%s) for tenant=%s route=%s (direct)\n", id, f.name, clientMode, f.tenant, f.route)
		if err := writeSecret(); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		return apperr.ExitOK
	}
	if err := st.TryRegisterClientWithPendingGrant(client, f.tenant, f.route); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	authzAudit(st, f.tenant, f.route, id, "register", "ok", "pre-registered pending grant")
	fmt.Printf("registered client %s (name=%q mode=%s) for tenant=%s route=%s (status=pending)\n", id, f.name, clientMode, f.tenant, f.route)
	if err := writeSecret(); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	return apperr.ExitOK
}

// cmdAuthzRefresh refreshes an existing client grant without forcing the client
// to re-register: if --direct is set (or skip_pairing is already enabled), it
// keeps the grant active for immediate re-auth; otherwise it rotates a fresh
// pairing_secret.
func cmdAuthzRefresh(argv []string) int {
	spec := authzSpecFor("tenant", "route", "client", "direct")
	spec.required["client"] = true
	spec.required["tenant"] = true
	spec.required["route"] = true
	f, ferr := parseAuthzFlags(argv, spec)
	if ferr != nil {
		fmt.Fprintln(os.Stderr, "error: "+ferr.Error())
		return apperr.ExitCLIValidation
	}
	db, err := authzOpen(f.dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db.SQL())
	grant, gerr := st.GetGrant(f.client, f.tenant, f.route)
	if gerr != nil {
		fmt.Fprintf(os.Stderr, "no grant for client %s tenant=%s route=%s\n", f.client, f.tenant, f.route)
		return apperr.ExitCLIValidation
	}
	if grant.Status == authz.GrantRevoked {
		fmt.Fprintf(os.Stderr, "client %s is revoked for tenant=%s route=%s; revocation is terminal\n", f.client, f.tenant, f.route)
		return apperr.ExitCLIValidation
	}
	if f.direct || grant.SkipPairing {
		if err := st.ApproveGrantDirect(f.client, f.tenant, f.route); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		authzAudit(st, f.tenant, f.route, f.client, "refresh", "ok", "direct grant refreshed")
		fmt.Printf("refreshed client %s for tenant=%s route=%s (direct; pairing bypassed)\n", f.client, f.tenant, f.route)
		return apperr.ExitOK
	}
	secret, err := authz.MintPairingSecret()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	if err := st.ApproveGrantWithPairingSecret(f.client, f.tenant, f.route, secret, authz.DefaultPairingTTL); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	authzAudit(st, f.tenant, f.route, f.client, "refresh", "ok", "pairing secret rotated")
	fmt.Printf("refreshed client %s for tenant=%s route=%s\n", f.client, f.tenant, f.route)
	fmt.Println("Pairing secret (show once; deliver it to the client operator over a private channel):")
	fmt.Println(secret)
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
