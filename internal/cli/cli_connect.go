package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/authz"
	"ocliv/internal/config"
	"ocliv/internal/store"
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

func googleBindingFingerprint(service, tenant, issuer, routeID, connType string, redirects []string) string {
	sorted := append([]string(nil), redirects...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(service + "\x00" + tenant + "\x00" + issuer + "\x00" + routeID + "\x00" + connType + "\x00" + strings.Join(sorted, ",")))
	return hex.EncodeToString(sum[:8])
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string(nil), a...)
	sb := append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

// openExistingAuthzDB requires an existing relay authorization database at
// dataDir/ocliv.db so desktop runs never silently create an empty local DB.
func openExistingAuthzDB(dataDir string) (*store.DB, error) {
	dbPath := filepath.Join(dataDir, "ocliv.db")
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("authoritative relay database %q not found (pass --data DIR on the relay host): %w", dbPath, err)
	}
	return authzOpen(dataDir)
}

func writeExclusiveSecret0600(path, secret string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing file or symlink %q", path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(secret + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dir, derr := os.Open(filepath.Dir(path))
	if derr != nil {
		return fmt.Errorf("secret written, but directory durability check failed: %w", derr)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return fmt.Errorf("secret written, but directory sync failed: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("secret written, but directory close failed: %w", closeErr)
	}
	return nil
}

// RecoverGoogleCutover completes or safely resolves interrupted PREPARED or
// CUTOVER_INCOMPLETE Google client replacements before new mutations occur.
func RecoverGoogleCutover(svcStore *config.ServiceStore, serviceName string, st *authz.SQLStore, now time.Time) error {
	rec, ok, err := svcStore.Get(serviceName)
	if err != nil || !ok || rec.ProviderBindings == nil {
		return nil
	}
	b, bok := rec.ProviderBindings["google"]
	if !bok || (b.Status != "PREPARED" && b.Status != "CUTOVER_INCOMPLETE") {
		return nil
	}
	if b.Cutover == nil || b.Cutover.OldClientID == "" {
		return fmt.Errorf("google binding for %q is in %s without cutover metadata", serviceName, b.Status)
	}
	oldID := b.Cutover.OldClientID
	newID := b.Cutover.NewClientID
	if newID != "" {
		if _, cerr := st.GetClient(newID); cerr == nil {
			// New candidate exists; ensure old client is revoked and promote newID.
			if rerr := st.RevokeOpaqueRefreshForClient(oldID); rerr != nil {
				return rerr
			}
			if rerr := st.RevokeGrant(oldID, b.Cutover.OldTenant, b.Cutover.RouteID); rerr != nil {
				return rerr
			}
			if rerr := st.RevokeClient(oldID); rerr != nil {
				return rerr
			}
			cOld, gerr := st.GetClient(oldID)
			if gerr != nil || cOld.RevokedAt == nil {
				return fmt.Errorf("failed to confirm revocation of old client %s during recovery", oldID)
			}
			_, uerr := svcStore.UpdateCAS(serviceName, rec.Revision, func(r *config.ServiceRecord) error {
				cur := r.ProviderBindings["google"]
				cur.ClientID = newID
				cur.CandidateClientID = ""
				cur.Status = "active"
				cur.RevokedClientIDs = append(cur.RevokedClientIDs, oldID)
				cur.Cutover.RecoveryState = "RECOVERED"
				cur.NextAction = "cutover recovered; old client revoked"
				cur.UpdatedAt = now.UTC().Format(time.RFC3339)
				r.ProviderBindings["google"] = cur
				return nil
			})
			return uerr
		}
	}
	// Candidate missing from DB: clear incomplete cutover if old client is still active.
	cOld, gerr := st.GetClient(oldID)
	if gerr == nil && cOld.RevokedAt == nil {
		_, uerr := svcStore.UpdateCAS(serviceName, rec.Revision, func(r *config.ServiceRecord) error {
			cur := r.ProviderBindings["google"]
			cur.ClientID = oldID
			cur.CandidateClientID = ""
			cur.Status = "active"
			cur.Cutover.RecoveryState = "ROLLED_BACK_TO_OLD"
			cur.NextAction = "abandoned candidate cleared; old client remains active"
			cur.UpdatedAt = now.UTC().Format(time.RFC3339)
			r.ProviderBindings["google"] = cur
			return nil
		})
		return uerr
	}
	return fmt.Errorf("cannot recover cutover for %q: candidate %q missing and old %q unavailable", serviceName, newID, oldID)
}

func cmdConnectGoogle(argv []string, ops serviceOps, hc *http.Client) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv connect google SERVICE --redirect URI[,URI] [--type connected-app|gemini] [--data DIR] [--tenant TENANT] [--secret-out PATH] [--verification-token-file PATH] [--approve] [--update] [--reconnect] [--profile PROFILE] [--json]")
		return apperr.ExitCLIValidation
	}
	serviceName := argv[0]
	connType := "connected-app"
	dataDir := ""
	dataExplicit := false
	tenant := "default"
	profile := ""
	redirectRaw := ""
	secretOut := ""
	verifyTokenFile := ""
	approve := false
	update := false
	reconnect := false
	asJSON := false

	for i := 1; i < len(argv); i++ {
		switch {
		case argv[i] == "--approve":
			approve = true
		case argv[i] == "--update":
			update = true
		case argv[i] == "--reconnect":
			reconnect = true
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
			dataExplicit = true
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
		case argv[i] == "--verification-token-file" || strings.HasPrefix(argv[i], "--verification-token-file="):
			v, ok := mcpFlagValue(argv, &i, "verification-token-file")
			if !ok {
				return apperr.ExitCLIValidation
			}
			verifyTokenFile = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if connType != "connected-app" && connType != "gemini" {
		fmt.Fprintf(os.Stderr, "invalid --type %q (want connected-app|gemini)\n", connType)
		return apperr.ExitCLIValidation
	}
	if asJSON && secretOut == "" {
		fmt.Fprintln(os.Stderr, "error: --json requires --secret-out PATH so the one-time client secret is safely delivered")
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

	expectedToken := ""
	if verifyTokenFile != "" {
		tokBytes, terr := os.ReadFile(verifyTokenFile)
		if terr != nil {
			fmt.Fprintf(os.Stderr, "connect google: read --verification-token-file %q: %v\n", verifyTokenFile, terr)
			return apperr.ExitCLIValidation
		}
		expectedToken = strings.TrimSpace(string(tokBytes))
		if expectedToken == "" {
			fmt.Fprintf(os.Stderr, "connect google: --verification-token-file %q is empty\n", verifyTokenFile)
			return apperr.ExitCLIValidation
		}
	}
	if entry.AuthMethod != "ocliv-managed" && entry.AuthMethod != "upstream-oauth" {
		fmt.Fprintf(os.Stderr, "connect google: unsupported/unmapped auth mode %q for publication %q\n", entry.AuthMethod, serviceName)
		return apperr.ExitCLIValidation
	}

	disc := runReadOnlyDiscoveryCheck(hc, entry.URL)
	if disc.Transport != "PASS" || disc.Discovery != "PASS" {
		fmt.Fprintf(os.Stderr, "connect google: discovery preflight failed: %s\n", disc.Detail)
		return apperr.ExitRelayTLS
	}
	now := time.Now().UTC()
	timestamps := map[string]string{"CONFIGURED": now.Format(time.RFC3339)}
	stage := "CONFIGURED"
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
		if vResp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "connect google: %s returned HTTP %d (run `ocliv google verify-domain` first)\n", verifyURL, vResp.StatusCode)
			return apperr.ExitRelayTLS
		}
		if ct := vResp.Header.Get("Content-Type"); ct != "" && !strings.Contains(strings.ToLower(ct), "application/json") {
			fmt.Fprintf(os.Stderr, "connect google: %s returned Content-Type %q (want application/json)\n", verifyURL, ct)
			return apperr.ExitRelayTLS
		}
		if verr := ValidateGoogleVerificationDocument(vBody, expectedToken); verr != nil {
			fmt.Fprintf(os.Stderr, "connect google: %s invalid verification document: %v\n", verifyURL, verr)
			return apperr.ExitRelayTLS
		}
		stage = "DOCUMENT_VALID"
		if expectedToken != "" {
			stage = "GOOGLE_TOKEN_MATCHED"
		}
		timestamps[stage] = now.Format(time.RFC3339)
	}

	svcStore, err := openServicesForProfile(profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return apperr.ExitInternal
	}
	fp := googleBindingFingerprint(serviceName, tenant, disc.Issuer, entry.RouteID, connType, redirects)
	rec, hasRec, gerr := svcStore.Get(serviceName)
	if gerr != nil {
		fmt.Fprintln(os.Stderr, gerr)
		return apperr.ExitInternal
	}
	var existing *config.ProviderBinding
	if hasRec && rec.ProviderBindings != nil {
		if b, bok := rec.ProviderBindings["google"]; bok {
			existing = &b
		}
	}
	useRemote := !dataExplicit
	if useRemote {
		if _, serr := os.Stat(filepath.Join("./ocliv-relay-data", "ocliv.db")); serr == nil {
			dataDir = "./ocliv-relay-data"
			useRemote = false
		}
	}

	var db *store.DB
	var st *authz.SQLStore
	if !useRemote {
		var derr error
		db, derr = openExistingAuthzDB(dataDir)
		if derr != nil {
			fmt.Fprintf(os.Stderr, "connect google: %v\n", derr)
			return apperr.ExitCLIValidation
		}
		defer db.Close()
		st = authz.NewSQLStore(db.SQL())
	}

	if !useRemote && existing != nil && (existing.Status == "PREPARED" || existing.Status == "CUTOVER_INCOMPLETE") {
		if rerr := RecoverGoogleCutover(svcStore, serviceName, st, now); rerr != nil {
			fmt.Fprintf(os.Stderr, "connect google: cutover recovery failed: %v\n", rerr)
			return apperr.ExitInternal
		}
		rec, hasRec, gerr = svcStore.Get(serviceName)
		if gerr != nil {
			fmt.Fprintln(os.Stderr, gerr)
			return apperr.ExitInternal
		}
		if hasRec && rec.ProviderBindings != nil {
			if b, bok := rec.ProviderBindings["google"]; bok {
				existing = &b
			}
		}
	}

	if existing != nil {
		if existing.Status == "revoked" && !reconnect {
			fmt.Fprintf(os.Stderr, "connect google: binding for %q was explicitly revoked; refusing to resurrect a revoked grant (pass --reconnect to create a new client)\n", serviceName)
			return apperr.ExitAuth
		}
		if existing.Status != "revoked" && existing.Fingerprint == fp && existing.Status != "CUTOVER_INCOMPLETE" && existing.Status != "PREPARED" {
			if !useRemote {
				cliRec, cerr := st.GetClient(existing.ClientID)
				grantRec, grErr := st.GetGrant(existing.ClientID, tenant, entry.RouteID)
				if cerr != nil || grErr != nil {
					fmt.Fprintf(os.Stderr, "connect google: local binding for %q is stale (client %s missing on authoritative database); pass --update to re-register\n", serviceName, existing.ClientID)
					return apperr.ExitCLIValidation
				}
				if cliRec.RevokedAt != nil || grantRec.Status == authz.GrantRevoked {
					fmt.Fprintf(os.Stderr, "connect google: client %s is revoked in authoritative database; refusing to resurrect a revoked grant\n", existing.ClientID)
					return apperr.ExitAuth
				}
				if cliRec.Tenant != tenant || cliRec.Route != entry.RouteID || cliRec.RefreshPolicy != "google_confidential" || !sameStringSet(cliRec.RedirectURIs, redirects) {
					fmt.Fprintf(os.Stderr, "connect google: authoritative client %s does not match requested tenant/route/redirects; pass --update to replace\n", existing.ClientID)
					return apperr.ExitCLIValidation
				}
			}
			if asJSON {
				out, _ := json.MarshalIndent(existing, "", "  ")
				fmt.Println(string(out))
			} else {
				fmt.Printf("✓ Google binding for %q already configured (idempotent; client_id=%s status=%s stage=%s)\n", serviceName, existing.ClientID, existing.Status, existing.Stage)
			}
			return apperr.ExitOK
		}
		if existing.Status != "revoked" && !update {
			fmt.Fprintf(os.Stderr, "connect google: %q already has a Google binding with different callbacks/tenant/issuer/type; pass --update to replace intentionally\n", serviceName)
			return apperr.ExitCLIValidation
		}
	}

	var clientID, clientSecret string
	status := "pending"
	nextAction := ""
	if useRemote {
		k, keyID, kerr := loadKeyForProfile(profile)
		if kerr != nil {
			fmt.Fprintf(os.Stderr, "connect google: not enrolled in profile %q: %v\n", profile, kerr)
			return apperr.ExitAuth
		}
		relayURL := agentRelayURLForProfile(profile)
		reqPayload, _ := json.Marshal(map[string]any{
			"name":           "Google (" + connType + ")",
			"redirect_uris":  redirects,
			"refresh_policy": "google_confidential",
			"approve":        approve,
		})
		stCode, body, callErr := mgmtCallBody(relayURL, k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+entry.RouteID+"/authz/register", reqPayload)
		if callErr != nil {
			fmt.Fprintf(os.Stderr, "connect google: remote registration failed: %v\n", callErr)
			return apperr.ExitRelayTLS
		}
		if stCode != http.StatusCreated {
			fmt.Fprintf(os.Stderr, "connect google: relay returned HTTP %d: %s\n", stCode, strings.TrimSpace(string(body)))
			return apperr.ExitInternal
		}
		var regResp struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
			Status       string `json:"status"`
		}
		if err := json.Unmarshal(body, &regResp); err != nil || regResp.ClientID == "" || regResp.ClientSecret == "" {
			fmt.Fprintf(os.Stderr, "connect google: invalid registration response from relay\n")
			return apperr.ExitInternal
		}
		clientID = regResp.ClientID
		clientSecret = regResp.ClientSecret
		if regResp.Status == "approved" {
			status = "active"
			stage = "CLIENT_APPROVED"
			timestamps["CLIENT_APPROVED"] = now.Format(time.RFC3339)
			nextAction = "paste client_id, client_secret, authorization_endpoint, and token_endpoint into Google console"
		} else {
			nextAction = fmt.Sprintf("approve client explicitly on relay for route %s client %s", entry.RouteID, clientID)
		}
	} else {
		var err error
		clientID, err = authz.MintClientID()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return apperr.ExitInternal
		}
		clientSecret, err = authz.MintPairingSecret()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return apperr.ExitInternal
		}
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
		nextAction = fmt.Sprintf("approve client explicitly: ocliv authz approve --data %s --tenant %s --route %s --client %s --direct", dataDir, tenant, entry.RouteID, clientID)
		if err := st.TryRegisterClientWithPendingGrant(client, tenant, entry.RouteID); err != nil {
			fmt.Fprintf(os.Stderr, "connect google: %v\n", err)
			return apperr.ExitInternal
		}
		if approve {
			if err := st.ApproveGrantDirect(clientID, tenant, entry.RouteID); err != nil {
				_ = st.RevokeClient(clientID)
				fmt.Fprintf(os.Stderr, "connect google: approve grant: %v\n", err)
				return apperr.ExitInternal
			}
			status = "active"
			stage = "CLIENT_APPROVED"
			timestamps["CLIENT_APPROVED"] = now.Format(time.RFC3339)
			nextAction = "paste client_id, client_secret, authorization_endpoint, and token_endpoint into Google console"
		}
		if _, err := st.GetClient(clientID); err != nil {
			fmt.Fprintf(os.Stderr, "connect google: authoritative verification failed: %v\n", err)
			return apperr.ExitInternal
		}
	}

	if secretOut != "" {
		if werr := writeExclusiveSecret0600(secretOut, clientSecret); werr != nil {
			if !useRemote {
				_ = st.RevokeGrant(clientID, tenant, entry.RouteID)
				_ = st.RevokeClient(clientID)
			}
			fmt.Fprintf(os.Stderr, "connect google: write --secret-out %s: %v\n", secretOut, werr)
			return apperr.ExitInternal
		}
	}

	// Crash-atomic two-identity cutover for --update:
	// 1. Durably persist PREPARED with CandidateClientID before revoking anything.
	// 2. Durably commit replacement ClientID before revoking oldID.
	// 3. Revoke oldID and verify RevokedAt != nil; record CUTOVER_INCOMPLETE on failure.
	var revokedIDs []string
	var oldID string
	if existing != nil {
		revokedIDs = append(revokedIDs, existing.RevokedClientIDs...)
		if existing.Status == "revoked" && existing.ClientID != "" {
			revokedIDs = append(revokedIDs, existing.ClientID)
		} else if existing.ClientID != "" && existing.ClientID != clientID {
			oldID = existing.ClientID
			if hasRec {
				opID := fmt.Sprintf("cutover-%d", now.UnixNano())
				updatedPrep, prepErr := svcStore.UpdateCAS(serviceName, rec.Revision, func(r *config.ServiceRecord) error {
					if r.ProviderBindings == nil {
						r.ProviderBindings = map[string]config.ProviderBinding{}
					}
					b := r.ProviderBindings["google"]
					b.CandidateClientID = clientID
					b.Status = "PREPARED"
					b.Cutover = &config.GoogleCutoverRecord{
						OperationID:     opID,
						OldClientID:     oldID,
						NewClientID:     clientID,
						OldTenant:       tenant,
						NewTenant:       tenant,
						RouteID:         entry.RouteID,
						CandidateStatus: status,
						RecoveryState:   "PREPARED",
					}
					b.NextAction = fmt.Sprintf("cutover prepared for candidate %s; completing replacement of %s", clientID, oldID)
					r.ProviderBindings["google"] = b
					return nil
				})
				if prepErr != nil {
					fmt.Fprintf(os.Stderr, "connect google: persist PREPARED cutover: %v\n", prepErr)
					return apperr.ExitInternal
				}
				rec = updatedPrep
			}
		}
	}

	binding := config.ProviderBinding{
		Provider:         "google",
		ConnectionType:   connType,
		ClientID:         clientID,
		RevokedClientIDs: revokedIDs,
		RedirectURIs:     redirects,
		AuthMode:         "confidential+google_confidential",
		Fingerprint:      fp,
		Status:           status,
		Stage:            stage,
		StageTimestamps:  timestamps,
		LastVerifiedAt:   now.Format(time.RFC3339),
		NextAction:       nextAction,
		UpdatedAt:        now.Format(time.RFC3339),
	}
	if hasRec {
		updatedCommit, err := svcStore.UpdateCAS(serviceName, rec.Revision, func(r *config.ServiceRecord) error {
			if r.ProviderBindings == nil {
				r.ProviderBindings = map[string]config.ProviderBinding{}
			}
			r.ProviderBindings["google"] = binding
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "connect google: save service binding: %v\n", err)
			return apperr.ExitInternal
		}
		rec = updatedCommit
	} else {
		if err := svcStore.Put(config.ServiceRecord{
			Name:             serviceName,
			Type:             "mcp",
			Auth:             entry.AuthMethod,
			Profile:          profile,
			PublicationID:    entry.RouteID,
			PublicURL:        entry.URL,
			DesiredState:     config.DesiredConfigured,
			ProviderBindings: map[string]config.ProviderBinding{"google": binding},
		}); err != nil {
			fmt.Fprintf(os.Stderr, "connect google: save service record: %v\n", err)
			return apperr.ExitInternal
		}
	}

	if oldID != "" {
		if useRemote {
			k, keyID, kerr := loadKeyForProfile(profile)
			if kerr != nil {
				fmt.Fprintf(os.Stderr, "connect google: remote cutover revoke failed: %v\n", kerr)
				return apperr.ExitAuth
			}
			stCode, _, callErr := mgmtCallBody(agentRelayURLForProfile(profile), k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+entry.RouteID+"/authz/revoke/"+oldID, nil)
			if callErr != nil || (stCode != http.StatusOK && stCode != http.StatusNotFound) {
				fmt.Fprintf(os.Stderr, "connect google: cutover incomplete (failed to revoke previous client %s remotely)\n", oldID)
				return apperr.ExitInternal
			}
		} else {
			rErr := st.RevokeOpaqueRefreshForClient(oldID)
			if rErr == nil {
				rErr = st.RevokeGrant(oldID, tenant, entry.RouteID)
			}
			if rErr == nil {
				rErr = st.RevokeClient(oldID)
			}
			cOld, gOldErr := st.GetClient(oldID)
			if rErr != nil || gOldErr != nil || cOld.RevokedAt == nil {
				if hasRec {
					if _, uerr := svcStore.UpdateCAS(serviceName, rec.Revision, func(r *config.ServiceRecord) error {
						b := r.ProviderBindings["google"]
						b.Status = "CUTOVER_INCOMPLETE"
						b.NextAction = fmt.Sprintf("old client %s revocation incomplete; run `ocliv authz revoke --data %s --tenant %s --route %s --client %s`", oldID, dataDir, tenant, entry.RouteID, oldID)
						r.ProviderBindings["google"] = b
						return nil
					}); uerr != nil {
						fmt.Fprintf(os.Stderr, "connect google: cutover incomplete AND failed to persist state: %v\n", uerr)
					}
				}
				fmt.Fprintf(os.Stderr, "connect google: cutover incomplete (failed to revoke previous client %s)\n", oldID)
				return apperr.ExitInternal
			}
		}
		if hasRec {
			if _, uerr := svcStore.UpdateCAS(serviceName, rec.Revision, func(r *config.ServiceRecord) error {
				b := r.ProviderBindings["google"]
				b.RevokedClientIDs = append(b.RevokedClientIDs, oldID)
				r.ProviderBindings["google"] = b
				return nil
			}); uerr != nil {
				fmt.Fprintf(os.Stderr, "connect google: old client revoked, but failed to record revoked_client_ids: %v\n", uerr)
				return apperr.ExitInternal
			}
		}
	}

	authEP := disc.AuthorizationEP
	tokenEP := disc.TokenEP
	if asJSON {
		out := map[string]any{
			"service":                serviceName,
			"route_id":               entry.RouteID,
			"url":                    entry.URL,
			"client_id":              clientID,
			"authorization_endpoint": authEP,
			"token_endpoint":         tokenEP,
			"status":                 status,
			"stage":                  stage,
			"refresh_policy":         "google_confidential",
			"client_secret_file":     secretOut,
			"next_action":            nextAction,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return apperr.ExitOK
	}
	fmt.Printf("✓ Google %s client registered for %s (status=%s stage=%s)\n", connType, serviceName, status, stage)
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
	fmt.Printf("Service: %s  Provider: %s (%s)  Status: %s  Stage: %s\n", serviceName, b.Provider, b.ConnectionType, b.Status, b.Stage)
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
	dataDir := ""
	dataExplicit := false
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
			dataExplicit = true
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
	if !bok || b.ClientID == "" {
		fmt.Fprintf(os.Stderr, "no Google connection binding recorded for %q\n", serviceName)
		return apperr.ExitCLIValidation
	}

	markUnconfirmed := func(reason string) int {
		_, _ = svcStore.UpdateCAS(serviceName, rec.Revision, func(r *config.ServiceRecord) error {
			cur := r.ProviderBindings["google"]
			cur.Status = "REVOCATION_UNCONFIRMED"
			cur.NextAction = reason
			cur.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			r.ProviderBindings["google"] = cur
			return nil
		})
		fmt.Fprintf(os.Stderr, "connect revoke: REVOCATION_UNCONFIRMED (%s)\n", reason)
		return apperr.ExitInternal
	}

	if rec.PublicationID == "" {
		return markUnconfirmed("missing publication_id on service record")
	}
	useRemote := !dataExplicit
	if useRemote {
		if _, serr := os.Stat(filepath.Join("./ocliv-relay-data", "ocliv.db")); serr == nil {
			dataDir = "./ocliv-relay-data"
			useRemote = false
		}
	}
	if useRemote {
		k, keyID, kerr := loadKeyForProfile(profile)
		if kerr != nil {
			return markUnconfirmed("not enrolled in profile " + profile + ": " + kerr.Error())
		}
		stCode, body, callErr := mgmtCallBody(agentRelayURLForProfile(profile), k, keyID, http.MethodPost, "/v1/agent/mcp-routes/"+rec.PublicationID+"/authz/revoke/"+b.ClientID, nil)
		if callErr != nil {
			return markUnconfirmed("remote revoke transport failed: " + callErr.Error())
		}
		if stCode != http.StatusOK {
			return markUnconfirmed(fmt.Sprintf("remote revoke returned HTTP %d: %s", stCode, strings.TrimSpace(string(body))))
		}
	} else {
		db, derr := openExistingAuthzDB(dataDir)
		if derr != nil {
			return markUnconfirmed(derr.Error())
		}
		defer db.Close()
		st := authz.NewSQLStore(db.SQL())
		if err := st.RevokeOpaqueRefreshForClient(b.ClientID); err != nil {
			return markUnconfirmed("revoke opaque refresh: " + err.Error())
		}
		if err := st.RevokeGrant(b.ClientID, tenant, rec.PublicationID); err != nil {
			return markUnconfirmed("revoke grant: " + err.Error())
		}
		if err := st.RevokeClient(b.ClientID); err != nil {
			return markUnconfirmed("revoke client: " + err.Error())
		}
		// Negative verification: confirm client is actually marked revoked in SQLite.
		cliRec, gerr := st.GetClient(b.ClientID)
		if gerr != nil || cliRec.RevokedAt == nil {
			return markUnconfirmed("post-revocation negative check failed: client still active")
		}
	}

	if _, uerr := svcStore.UpdateCAS(serviceName, rec.Revision, func(r *config.ServiceRecord) error {
		cur := r.ProviderBindings["google"]
		cur.Status = "revoked"
		cur.Stage = "REVOKED"
		if cur.StageTimestamps == nil {
			cur.StageTimestamps = map[string]string{}
		}
		cur.StageTimestamps["REVOKED"] = time.Now().UTC().Format(time.RFC3339)
		cur.NextAction = "binding revoked; register a new client if reconnecting"
		cur.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		r.ProviderBindings["google"] = cur
		return nil
	}); uerr != nil {
		fmt.Fprintf(os.Stderr, "connect revoke: database revoked, but failed to persist local binding state: %v\n", uerr)
		return apperr.ExitInternal
	}
	fmt.Printf("✓ revoked Google connection binding for %q (client_id=%s)\n", serviceName, b.ClientID)
	return apperr.ExitOK
}
