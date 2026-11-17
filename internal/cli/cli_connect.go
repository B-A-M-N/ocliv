package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/authz"
	"ocliv/internal/config"
)

func cmdConnect(argv []string) int {
	return cmdConnectWithOps(argv, defaultServiceOps(), safeEgressHTTPClient())
}

func cmdConnectWithOps(argv []string, ops serviceOps, hc *http.Client) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv connect google SERVICE ... | ocliv connect status google SERVICE | ocliv connect revoke google SERVICE")
		return apperr.ExitCLIValidation
	}
	switch argv[0] {
	case "google":
		return cmdConnectGoogle(argv[1:], ops, hc)
	case "status":
		if len(argv) < 3 || argv[1] != "google" {
			fmt.Fprintln(os.Stderr, "usage: ocliv connect status google SERVICE [--profile PROFILE] [--json]")
			return apperr.ExitCLIValidation
		}
		return cmdConnectGoogleStatus(argv[2:], ops)
	case "revoke":
		if len(argv) < 3 || argv[1] != "google" {
			fmt.Fprintln(os.Stderr, "usage: ocliv connect revoke google SERVICE [--data DIR] [--tenant TENANT] [--profile PROFILE]")
			return apperr.ExitCLIValidation
		}
		return cmdConnectGoogleRevoke(argv[2:], ops)
	default:
		fmt.Fprintf(os.Stderr, "unknown connect target %q (supported: google, status, revoke)\n", argv[0])
		return apperr.ExitCLIValidation
	}
}

func googleBindingFingerprint(service, routeID, connType string, redirects []string) string {
	sorted := append([]string(nil), redirects...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(service + "\x00" + routeID + "\x00" + connType + "\x00" + strings.Join(sorted, ",")))
	return hex.EncodeToString(sum[:8])
}

func cmdConnectGoogle(argv []string, ops serviceOps, hc *http.Client) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv connect google SERVICE --redirect URI[,URI] [--type connected-app|gemini] [--data DIR] [--tenant TENANT] [--secret-out PATH] [--approve] [--update] [--profile PROFILE] [--json]")
		return apperr.ExitCLIValidation
	}
	serviceName := argv[0]
	connType := "connected-app"
	dataDir := "./ocliv-relay-data"
	tenant := "default"
	profile := ""
	redirectRaw := ""
	secretOut := ""
	approve := false
	update := false
	asJSON := false

	for i := 1; i < len(argv); i++ {
		switch {
		case argv[i] == "--approve":
			approve = true
		case argv[i] == "--update":
			update = true
		case argv[i] == "--json":
			asJSON = true
		case argv[i] == "--type" || strings.HasPrefix(argv[i], "--type="):
			v, ok := mcpFlagValue(argv, &i, "type")
			if !ok {
				return apperr.ExitCLIValidation
			}
			connType = strings.ToLower(v)
		case argv[i] == "--redirect" || strings.HasPrefix(argv[i], "--redirect="):
			v, ok := mcpFlagValue(argv, &i, "redirect")
			if !ok {
				return apperr.ExitCLIValidation
			}
			redirectRaw = v
		case argv[i] == "--data" || strings.HasPrefix(argv[i], "--data="):
			v, ok := mcpFlagValue(argv, &i, "data")
			if !ok {
				return apperr.ExitCLIValidation
			}
			dataDir = v
		case argv[i] == "--tenant" || strings.HasPrefix(argv[i], "--tenant="):
			v, ok := mcpFlagValue(argv, &i, "tenant")
			if !ok {
				return apperr.ExitCLIValidation
			}
			tenant = v
		case argv[i] == "--profile" || strings.HasPrefix(argv[i], "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profile = v
		case argv[i] == "--secret-out" || strings.HasPrefix(argv[i], "--secret-out="):
			v, ok := mcpFlagValue(argv, &i, "secret-out")
			if !ok {
				return apperr.ExitCLIValidation
			}
			secretOut = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if connType != "connected-app" && connType != "gemini" {
		fmt.Fprintf(os.Stderr, "invalid --type %q (want connected-app|gemini)\n", connType)
		return apperr.ExitCLIValidation
	}
	if profile == "" {
		profile = config.ActiveProfile()
	}

	var redirects []string
	for _, r := range strings.Split(redirectRaw, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			redirects = append(redirects, r)
		}
	}
	if len(redirects) == 0 {
		fmt.Fprintln(os.Stderr, "error: --redirect is required (supply the exact Google callback URI)")
		return apperr.ExitCLIValidation
	}
	for _, uri := range redirects {
		if err := authz.ValidateRedirectURI(uri, redirects); err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid --redirect %q: %v\n", uri, err)
			return apperr.ExitCLIValidation
		}
	}

	entry, code := resolveCatalogEntry(serviceName, profile, ops)
	if entry.Freshness != "AUTHORITATIVE" || entry.URL == "" || entry.RouteID == "" {
		fmt.Fprintf(os.Stderr, "connect google: service %q is not authoritatively published (%s: %s)\n", serviceName, entry.Freshness, entry.FailureReason)
		if code != 0 {
			return code
		}
		return apperr.ExitRelayTLS
	}

	disc := runReadOnlyDiscoveryCheck(hc, entry.URL)
	if disc.Transport != "PASS" || disc.Discovery != "PASS" {
		fmt.Fprintf(os.Stderr, "connect google: discovery preflight failed: %s\n", disc.Detail)
		return apperr.ExitRelayTLS
	}
	if connType == "connected-app" {
		u, uerr := safeDiscoveryURL(entry.URL)
		if uerr != nil {
			fmt.Fprintf(os.Stderr, "connect google: %v\n", uerr)
			return apperr.ExitRelayTLS
		}
		verifyURL := u.Scheme + "://" + u.Host + "/.well-known/google-connected-apps"
		vResp, verr := wrapNoRedirectClient(hc).Get(verifyURL)
		if verr != nil {
			fmt.Fprintf(os.Stderr, "connect google: domain verification check failed: %v\n", verr)
			return apperr.ExitRelayTLS
		}
		vBody, _ := io.ReadAll(io.LimitReader(vResp.Body, 32*1024))
		_ = vResp.Body.Close()
		if vResp.StatusCode != http.StatusOK || !json.Valid(vBody) {
			fmt.Fprintf(os.Stderr, "connect google: %s returned HTTP %d (run `ocliv google verify-domain` first)\n", verifyURL, vResp.StatusCode)
			return apperr.ExitRelayTLS
		}
	}

	svcStore, err := openServicesForProfile(profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	fp := googleBindingFingerprint(serviceName, entry.RouteID, connType, redirects)
	var existing *config.ProviderBinding
	if rec, ok, gerr := svcStore.Get(serviceName); gerr == nil && ok && rec.ProviderBindings != nil {
		if b, bok := rec.ProviderBindings["google"]; bok {
			existing = &b
		}
	}
	if existing != nil {
		if existing.Status == "revoked" {
			fmt.Fprintf(os.Stderr, "connect google: binding for %q was explicitly revoked; refusing to resurrect a revoked grant\n", serviceName)
			return apperr.ExitAuth
		}
		if existing.Fingerprint == fp {
			if asJSON {
				out, _ := json.MarshalIndent(existing, "", "  ")
				fmt.Println(string(out))
			} else {
				fmt.Printf("✓ Google binding for %q already configured (idempotent; client_id=%s status=%s)\n", serviceName, existing.ClientID, existing.Status)
			}
			return apperr.ExitOK
		}
		if !update {
			fmt.Fprintf(os.Stderr, "connect google: %q already has a Google binding with different callbacks/type; pass --update to replace intentionally\n", serviceName)
			return apperr.ExitCLIValidation
		}
	}

	db, err := authzOpen(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect google: %v\n", err)
		return apperr.ExitInternal
	}
	defer db.Close()
	st := authz.NewSQLStore(db.SQL())

	clientID, err := authz.MintClientID()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	clientSecret, err := authz.MintPairingSecret()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	now := time.Now().UTC()
	client := authz.Client{
		ID:               clientID,
		Name:             "Google (" + connType + ")",
		RedirectURIs:     redirects,
		CreatedAt:        now,
		Tenant:           tenant,
		Route:            entry.RouteID,
		ClientMode:       "confidential",
		ClientSecretHash: authz.HashSecret(clientSecret),
		RefreshPolicy:    "google_confidential",
	}
	status := "pending"
	nextAction := fmt.Sprintf("approve client explicitly: ocliv authz approve --data %s --tenant %s --route %s --client %s --direct", dataDir, tenant, entry.RouteID, clientID)
	if approve {
		if err := st.RegisterClient(client); err != nil {
			fmt.Fprintf(os.Stderr, "connect google: %v\n", err)
			return apperr.ExitInternal
		}
		if err := st.ApproveGrantDirect(clientID, tenant, entry.RouteID); err != nil {
			fmt.Fprintf(os.Stderr, "connect google: %v\n", err)
			return apperr.ExitInternal
		}
		status = "active"
		nextAction = "paste client_id, client_secret, authorization_endpoint, and token_endpoint into Google console"
	} else {
		if err := st.TryRegisterClientWithPendingGrant(client, tenant, entry.RouteID); err != nil {
			fmt.Fprintf(os.Stderr, "connect google: %v\n", err)
			return apperr.ExitInternal
		}
	}

	binding := config.ProviderBinding{
		Provider:       "google",
		ConnectionType: connType,
		ClientID:       clientID,
		RedirectURIs:   redirects,
		AuthMode:       "confidential+google_confidential",
		Fingerprint:    fp,
		Status:         status,
		LastVerifiedAt: now.Format(time.RFC3339),
		NextAction:     nextAction,
		UpdatedAt:      now.Format(time.RFC3339),
	}
	if _, ok, _ := svcStore.Get(serviceName); ok {
		_, _ = svcStore.UpdateCAS(serviceName, 0, func(r *config.ServiceRecord) error {
			if r.ProviderBindings == nil {
				r.ProviderBindings = map[string]config.ProviderBinding{}
			}
			r.ProviderBindings["google"] = binding
			return nil
		})
	} else {
		_ = svcStore.Put(config.ServiceRecord{
			Name:             serviceName,
			Type:             "mcp",
			Auth:             entry.AuthMethod,
			Profile:          profile,
			PublicationID:    entry.RouteID,
			PublicURL:        entry.URL,
			DesiredState:     config.DesiredConfigured,
			ProviderBindings: map[string]config.ProviderBinding{"google": binding},
		})
	}

	if secretOut != "" {
		if werr := os.WriteFile(secretOut, []byte(clientSecret+"\n"), 0o600); werr != nil {
			fmt.Fprintf(os.Stderr, "connect google: write --secret-out %s: %v\n", secretOut, werr)
			return apperr.ExitInternal
		}
	}
	authEP := disc.Issuer + "/authorize"
	tokenEP := disc.Issuer + "/token"
	if asJSON {
		out := map[string]any{
			"service":                serviceName,
			"route_id":               entry.RouteID,
			"url":                    entry.URL,
			"client_id":              clientID,
			"authorization_endpoint": authEP,
			"token_endpoint":         tokenEP,
			"status":                 status,
			"refresh_policy":         "google_confidential",
			"next_action":            nextAction,
		}
		if secretOut != "" {
			out["client_secret_file"] = secretOut
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return apperr.ExitOK
	}
	fmt.Printf("✓ Google %s client registered for %s (status=%s)\n", connType, serviceName, status)
	fmt.Printf("  MCP URL:                %s\n", entry.URL)
	fmt.Printf("  Client ID:              %s\n", clientID)
	fmt.Printf("  Authorization Endpoint: %s\n", authEP)
	fmt.Printf("  Token Endpoint:         %s\n", tokenEP)
	if secretOut != "" {
		fmt.Printf("  Client Secret:          written to %s (mode 0600)\n", secretOut)
	} else {
		fmt.Printf("  Client Secret (once):   %s\n", clientSecret)
	}
	fmt.Printf("  Next:                   %s\n", nextAction)
	return apperr.ExitOK
}

func cmdConnectGoogleStatus(argv []string, ops serviceOps) int {
	serviceName := argv[0]
	profile := ""
	asJSON := false
	for i := 1; i < len(argv); i++ {
		switch {
		case argv[i] == "--json":
			asJSON = true
		case argv[i] == "--profile" || strings.HasPrefix(argv[i], "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profile = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if profile == "" {
		profile = config.ActiveProfile()
	}
	svcStore, err := openServicesForProfile(profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := svcStore.Get(serviceName)
	if err != nil || !ok || rec.ProviderBindings == nil {
		fmt.Fprintf(os.Stderr, "no Google connection binding recorded for %q in profile %q\n", serviceName, profile)
		return apperr.ExitCLIValidation
	}
	b, bok := rec.ProviderBindings["google"]
	if !bok {
		fmt.Fprintf(os.Stderr, "no Google connection binding recorded for %q in profile %q\n", serviceName, profile)
		return apperr.ExitCLIValidation
	}
	if asJSON {
		out, _ := json.MarshalIndent(b, "", "  ")
		fmt.Println(string(out))
		return apperr.ExitOK
	}
	fmt.Printf("Service: %s  Provider: %s (%s)  Status: %s\n", serviceName, b.Provider, b.ConnectionType, b.Status)
	fmt.Printf("Client ID: %s  Auth: %s\n", b.ClientID, b.AuthMode)
	fmt.Printf("Redirects: %s\n", strings.Join(b.RedirectURIs, ", "))
	if b.NextAction != "" {
		fmt.Printf("Next: %s\n", b.NextAction)
	}
	return apperr.ExitOK
}

func cmdConnectGoogleRevoke(argv []string, ops serviceOps) int {
	serviceName := argv[0]
	profile := ""
	dataDir := "./ocliv-relay-data"
	tenant := "default"
	for i := 1; i < len(argv); i++ {
		switch {
		case argv[i] == "--profile" || strings.HasPrefix(argv[i], "--profile="):
			v, ok := mcpFlagValue(argv, &i, "profile")
			if !ok {
				return apperr.ExitCLIValidation
			}
			profile = v
		case argv[i] == "--data" || strings.HasPrefix(argv[i], "--data="):
			v, ok := mcpFlagValue(argv, &i, "data")
			if !ok {
				return apperr.ExitCLIValidation
			}
			dataDir = v
		case argv[i] == "--tenant" || strings.HasPrefix(argv[i], "--tenant="):
			v, ok := mcpFlagValue(argv, &i, "tenant")
			if !ok {
				return apperr.ExitCLIValidation
			}
			tenant = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if profile == "" {
		profile = config.ActiveProfile()
	}
	svcStore, err := openServicesForProfile(profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	rec, ok, err := svcStore.Get(serviceName)
	if err != nil || !ok || rec.ProviderBindings == nil {
		fmt.Fprintf(os.Stderr, "no Google connection binding recorded for %q\n", serviceName)
		return apperr.ExitCLIValidation
	}
	b, bok := rec.ProviderBindings["google"]
	if !bok {
		fmt.Fprintf(os.Stderr, "no Google connection binding recorded for %q\n", serviceName)
		return apperr.ExitCLIValidation
	}
	if db, derr := authzOpen(dataDir); derr == nil {
		defer db.Close()
		st := authz.NewSQLStore(db.SQL())
		if rec.PublicationID != "" && b.ClientID != "" {
			_ = st.RevokeGrant(b.ClientID, tenant, rec.PublicationID)
			_ = st.RevokeClient(b.ClientID)
		}
	}
	_, _ = svcStore.UpdateCAS(serviceName, 0, func(r *config.ServiceRecord) error {
		cur := r.ProviderBindings["google"]
		cur.Status = "revoked"
		cur.NextAction = "binding revoked; register a new client if reconnecting"
		cur.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		r.ProviderBindings["google"] = cur
		return nil
	})
	fmt.Printf("✓ revoked Google connection binding for %q (client_id=%s)\n", serviceName, b.ClientID)
	return apperr.ExitOK
}
