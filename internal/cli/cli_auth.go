// Agent enrollment, crash-safe key rotation, and remote-first logout.
package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/B-A-M-N/ocliv/internal/agent"
	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

type enrollPendingJournal struct {
	RelayURL  string `json:"relay_url"`
	KeyID     string `json:"key_id"`
	StartedAt string `json:"started_at"`
}

const (
	rotStateStaged                 = "STAGED"
	rotStateRemoteCommitted        = "REMOTE_COMMITTED"
	rotStateLocalKeyCommitted      = "LOCAL_KEY_COMMITTED"
	rotStateServiceMetadataRebound = "SERVICE_METADATA_REBOUND"
	rotStatePublishersRestarted    = "PUBLISHERS_RESTARTED"
	rotStateComplete               = "COMPLETE"
)

type keyRotationPendingJournal struct {
	RelayURL          string          `json:"relay_url"`
	OldKeyID          string          `json:"old_key_id"`
	NewKeyID          string          `json:"new_key_id"`
	StagedKeyPath     string          `json:"staged_key_path"`
	StartedAt         string          `json:"started_at"`
	State             string          `json:"state"`
	RecoveredServices map[string]bool `json:"recovered_services,omitempty"`
}

// Fault-injection hooks for crash-consistency tests (A2).
var (
	keyRotateJournalWriteFn = writeRotationJournal
	keyRotateAfterSaveHook  func() error
)

// cmdLogin performs one-time enrollment: generate a keypair, exchange the
// operator-issued code for registration.
func cmdLogin(argv []string) int {
	var relayURL, codeFile, cacert string
	for i := 0; i < len(argv); i++ {
		switch {
		case argv[i] == "--relay" && i+1 < len(argv):
			i++
			relayURL = argv[i]
		case strings.HasPrefix(argv[i], "--relay="):
			relayURL = strings.TrimPrefix(argv[i], "--relay=")
		case argv[i] == "--code-file" && i+1 < len(argv):
			i++
			codeFile = argv[i]
		case strings.HasPrefix(argv[i], "--code-file="):
			codeFile = strings.TrimPrefix(argv[i], "--code-file=")
		case argv[i] == "--cacert" && i+1 < len(argv):
			i++
			cacert = argv[i]
		case strings.HasPrefix(argv[i], "--cacert="):
			cacert = strings.TrimPrefix(argv[i], "--cacert=")
		default:
			fmt.Fprintf(os.Stderr, "unknown login flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if cacert == "" {
		cacert = config.CACertPath()
	}
	if relayURL == "" || codeFile == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv login --relay https://relay.example.com --code-file PATH")
		fmt.Fprintln(os.Stderr, "note: enrollment codes never pass through argv; use a file or - for stdin (A07)")
		return apperr.ExitCLIValidation
	}
	var code string
	if codeFile == "-" {
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: cannot read code from stdin: "+err.Error())
			return apperr.ExitCLIValidation
		}
		code = strings.TrimSpace(string(raw))
	} else {
		var err error
		// readSecretFileStrict enforces O_NOFOLLOW, regular-file, 0600 mode,
		// owner check, and bounded read — same treatment as other private credentials.
		code, err = readSecretFileStrict(codeFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: cannot read code file: "+err.Error())
			return apperr.ExitCLIValidation
		}
	}
	if code == "" {
		fmt.Fprintln(os.Stderr, "error: enrollment code file is empty")
		return apperr.ExitCLIValidation
	}
	if err := config.CheckRelayTLS(relayURL); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}
	if _, _, _, err := agentFiles(); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	keyID, exitCode := performEnroll(relayURL, code, cacert)
	if exitCode != apperr.ExitOK {
		return exitCode
	}
	fmt.Println("Enrolled as " + keyID)
	fmt.Println("Relay: " + relayURL)
	return apperr.ExitOK
}

// probeKeyAdmitted checks with the exact relay whether keyID is currently
// admitted by issuing a signed GET /v1/agent/leases. Returns (admitted, reachable).
func probeKeyAdmitted(relayURL string, k *identity.KeyPair, keyID string) (admitted bool, reachable bool) {
	code, _, err := mgmtCall(relayURL, k, keyID, http.MethodGet, "/v1/agent/leases")
	if err != nil {
		return false, false
	}
	return code == http.StatusOK, true
}

// probeChallengeAdmitted asks /v1/agent/challenge whether keyID is admitted on
// relayURL. Returns (admitted, deniedExplicitly, reachable).
func probeChallengeAdmitted(relayURL, keyID string) (admitted, denied, reachable bool) {
	body, _ := json.Marshal(map[string]string{"key_id": keyID})
	client, err := mgmtHTTPClient(10 * time.Second)
	if err != nil {
		return false, false, false
	}
	defer client.CloseIdleConnections()
	resp, err := client.Post(strings.TrimRight(relayURL, "/")+"/v1/agent/challenge", "application/json", bytes.NewReader(body))
	if err != nil {
		return false, false, false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusOK {
		return true, false, true
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false, true, true
	}
	return false, false, true
}

// performEnroll exchanges a one-time code for registration with full
// crash-recovery journal ordering (P0-3, P1-1):
//   - Inspects enroll-pending.json BEFORE checking agent.key so a crash after
//     key rename but before config.toml persistence recovers cleanly.
//   - Explicitly handles all 5 journal/file states.
//   - Validates relay's returned key_id against the locally generated key.
func performEnroll(relayURL, code, cacert string) (string, int) {
	if err := config.CheckRelayTLS(relayURL); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return "", apperr.ExitCLIValidation
	}
	dir, keyPath, cfgPath, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return "", apperr.ExitInternal
	}
	pendingKeyPath := filepath.Join(dir, "agent.key.pending")
	pendingJournalPath := filepath.Join(dir, "enroll-pending.json")

	var k *identity.KeyPair
	// P0-3: ALWAYS inspect enroll-pending.json BEFORE the "already enrolled"
	// agent.key short-circuit so post-rename/pre-config crashes recover cleanly.
	if rawJournal, jerr := os.ReadFile(pendingJournalPath); jerr == nil {
		var pj enrollPendingJournal
		if uerr := json.Unmarshal(rawJournal, &pj); uerr != nil || pj.RelayURL == "" || pj.KeyID == "" {
			fmt.Fprintf(os.Stderr, "enrollment recovery blocked: corrupt pending journal at %s\n", pendingJournalPath)
			return "", apperr.ExitInternal
		}
		if strings.TrimRight(pj.RelayURL, "/") != strings.TrimRight(relayURL, "/") {
			fmt.Fprintf(os.Stderr, "pending enrollment exists for %s (requested %s); finish or remove %s first\n",
				pj.RelayURL, relayURL, pendingJournalPath)
			return "", apperr.ExitInternal
		}
		_, pendingStatErr := os.Stat(pendingKeyPath)
		_, keyStatErr := os.Stat(keyPath)
		hasPending := pendingStatErr == nil
		hasKey := keyStatErr == nil

		switch {
		case !hasPending && !hasKey:
			fmt.Fprintf(os.Stderr, "enrollment recovery failed: %s exists for %s, but neither %s nor %s is present; refusing to silently generate a new identity\n",
				pendingJournalPath, pj.KeyID, pendingKeyPath, keyPath)
			return "", apperr.ExitInternal

		case hasKey && !hasPending:
			// Crash occurred AFTER key rename but BEFORE config.toml + journal removal!
			ek, lerr := identity.Load(keyPath)
			if lerr != nil {
				fmt.Fprintf(os.Stderr, "enrollment recovery failed: cannot load %s: %v\n", keyPath, lerr)
				return "", apperr.ExitInternal
			}
			ekID := "key-" + string(ek.ID())
			if ekID != pj.KeyID {
				fmt.Fprintf(os.Stderr, "enrollment recovery failed: %s has identity %s, journal expects %s; preserving files\n",
					keyPath, ekID, pj.KeyID)
				return "", apperr.ExitInternal
			}
			if admitted, reachable := probeKeyAdmitted(relayURL, ek, ekID); !reachable {
				fmt.Fprintf(os.Stderr, "enrollment recovery blocked: relay %s unreachable to verify %s\n", relayURL, ekID)
				return "", apperr.ExitRelayTLS
			} else if !admitted {
				fmt.Fprintf(os.Stderr, "enrollment recovery failed: key %s is not admitted on %s; preserving files\n", ekID, relayURL)
				return "", apperr.ExitAuth
			}
			if err := mergeRelayURL(cfgPath, relayURL); err != nil {
				fmt.Fprintln(os.Stderr, "enrollment recovery error persisting config: "+err.Error())
				return "", apperr.ExitInternal
			}
			if err := os.Remove(pendingJournalPath); err != nil && !os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, "enrollment recovery error removing journal: "+err.Error())
				return "", apperr.ExitInternal
			}
			return ekID, apperr.ExitOK

		case hasKey && hasPending:
			ek, lerr1 := identity.Load(keyPath)
			pk, lerr2 := identity.Load(pendingKeyPath)
			if lerr1 != nil || lerr2 != nil {
				fmt.Fprintf(os.Stderr, "enrollment recovery failed: unreadable key files (%v / %v); preserving all files\n", lerr1, lerr2)
				return "", apperr.ExitInternal
			}
			ekID := "key-" + string(ek.ID())
			pkID := "key-" + string(pk.ID())
			if ekID != pkID || ekID != pj.KeyID {
				fmt.Fprintf(os.Stderr, "enrollment recovery failed: conflicting identities (agent.key=%s pending=%s journal=%s); preserving all files\n",
					ekID, pkID, pj.KeyID)
				return "", apperr.ExitInternal
			}
			if err := mergeRelayURL(cfgPath, relayURL); err != nil {
				fmt.Fprintln(os.Stderr, "enrollment recovery error persisting config: "+err.Error())
				return "", apperr.ExitInternal
			}
			_ = os.Remove(pendingKeyPath)
			if err := os.Remove(pendingJournalPath); err != nil && !os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, "enrollment recovery error removing journal: "+err.Error())
				return "", apperr.ExitInternal
			}
			return ekID, apperr.ExitOK

		case hasPending && !hasKey:
			pk, lerr := identity.Load(pendingKeyPath)
			if lerr != nil {
				fmt.Fprintf(os.Stderr, "enrollment recovery failed: cannot load %s: %v\n", pendingKeyPath, lerr)
				return "", apperr.ExitInternal
			}
			pkID := "key-" + string(pk.ID())
			if pkID != pj.KeyID {
				fmt.Fprintf(os.Stderr, "enrollment recovery failed: pending key %s != journal %s; preserving files\n", pkID, pj.KeyID)
				return "", apperr.ExitInternal
			}
			if admitted, reachable := probeKeyAdmitted(relayURL, pk, pkID); reachable && admitted {
				if err := finalizeEnrollmentFiles(pendingKeyPath, keyPath, cfgPath, relayURL, pendingJournalPath, pk); err != nil {
					fmt.Fprintln(os.Stderr, "error finalizing recovered enrollment: "+err.Error())
					return "", apperr.ExitInternal
				}
				return pkID, apperr.ExitOK
			}
			// Not yet admitted on relay: reuse the SAME pending keypair.
			k = pk
		}
	}

	// Normal (non-recovery) guard: refuse to overwrite an existing enrollment.
	if _, err := os.Stat(keyPath); err == nil {
		fmt.Fprintln(os.Stderr, "already enrolled: run `ocliv logout` first or `ocliv key rotate` to replace the key")
		return "", apperr.ExitInternal
	}

	if k == nil {
		k, err = identity.Generate()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return "", apperr.ExitInternal
		}
		if err := k.Save(pendingKeyPath); err != nil {
			fmt.Fprintln(os.Stderr, "error: cannot write pending key: "+err.Error())
			return "", apperr.ExitInternal
		}
		journalRaw, _ := json.MarshalIndent(enrollPendingJournal{
			RelayURL:  relayURL,
			KeyID:     "key-" + string(k.ID()),
			StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}, "", "  ")
		if err := writeAtomic0600(pendingJournalPath, string(journalRaw)+"\n"); err != nil {
			_ = os.Remove(pendingKeyPath)
			fmt.Fprintln(os.Stderr, "error: cannot write pending enrollment journal: "+err.Error())
			return "", apperr.ExitInternal
		}
	}

	expectedKeyID := "key-" + string(k.ID())
	pub := base64.StdEncoding.EncodeToString(k.Public())
	body, _ := json.Marshal(map[string]string{"code": code, "public_key": pub})
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cacert != "" {
		pem, err := os.ReadFile(cacert)
		if err != nil {
			_ = os.Remove(pendingKeyPath)
			_ = os.Remove(pendingJournalPath)
			fmt.Fprintln(os.Stderr, "error: cannot read --cacert file: "+err.Error())
			return "", apperr.ExitCLIValidation
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			_ = os.Remove(pendingKeyPath)
			_ = os.Remove(pendingJournalPath)
			fmt.Fprintln(os.Stderr, "error: --cacert file holds no certificates")
			return "", apperr.ExitCLIValidation
		}
		tlsCfg.RootCAs = pool
	}
	// Enrollment carries a one-time secret; redirect following must be
	// refused to prevent leakage of the enrollment code to a redirect
	// target.
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if strings.HasPrefix(relayURL, "https") {
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	resp, err := client.Post(strings.TrimRight(relayURL, "/")+"/v1/agent/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		if isPreSendEnrollErr(err) {
			_ = os.Remove(pendingKeyPath)
			_ = os.Remove(pendingJournalPath)
			fmt.Fprintln(os.Stderr, "enrollment failed: relay unreachable; check the URL and try again")
			return "", apperr.ExitAuth
		}
		fmt.Fprintf(os.Stderr, "enrollment failed: ambiguous transport error (%v); pending enrollment journal preserved at %s\n", err, pendingJournalPath)
		return "", apperr.ExitAuth
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		_ = os.Remove(pendingKeyPath)
		_ = os.Remove(pendingJournalPath)
		fmt.Fprintln(os.Stderr, loginDeniedMessage(resp.StatusCode, string(respBody)))
		return "", apperr.ExitAuth
	}
	var out struct {
		KeyID    string `json:"key_id"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		fmt.Fprintf(os.Stderr, "enrollment failed: bad relay response; pending enrollment journal preserved at %s\n", pendingJournalPath)
		return "", apperr.ExitAuth
	}
	// A1: exact enrollment key identity invariant. The relay response MUST
	// prove that the admitted key matches the locally generated keypair.
	if out.KeyID == "" || out.KeyID != expectedKeyID {
		fmt.Fprintf(os.Stderr, "enrollment failed: relay returned key_id %q, expected %q; pending journal preserved at %s\n",
			out.KeyID, expectedKeyID, pendingJournalPath)
		return "", apperr.ExitAuth
	}
	if err := finalizeEnrollmentFiles(pendingKeyPath, keyPath, cfgPath, relayURL, pendingJournalPath, k); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return "", apperr.ExitInternal
	}
	return out.KeyID, apperr.ExitOK
}

// finalizeEnrollmentFiles commits BOTH agent.key and config.toml relay_url
// durably before removing enroll-pending.json (P0-2, P0-3, P1-1).
func finalizeEnrollmentFiles(pendingKeyPath, keyPath, cfgPath, relayURL, pendingJournalPath string, k *identity.KeyPair) error {
	if err := k.SaveDurableReplace(keyPath); err != nil {
		return err
	}
	_ = os.Remove(pendingKeyPath)
	if err := mergeRelayURL(cfgPath, relayURL); err != nil {
		return err
	}
	if err := os.Remove(pendingJournalPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func loginDeniedMessage(status int, body string) string {
	if status == http.StatusUnauthorized {
		return "enrollment denied: invalid or expired code"
	}
	msg := fmt.Sprintf("enrollment denied: relay reported HTTP %d", status)
	if d := shortDetail(body); d != "" {
		msg += " (" + d + ")"
	}
	return msg + "; the enrollment code was not consumed"
}

func mergeRelayURL(cfgPath, relayURL string) error {
	vals, err := config.LoadAgentFile(cfgPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		vals = map[string]string{}
	}
	if vals == nil {
		vals = map[string]string{}
	}
	vals["relay_url"] = relayURL
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %q\n", k, vals[k])
	}
	return writeAtomic0600(cfgPath, b.String())
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// cmdLogout revokes the agent key AND all its live authority on the exact
// persisted enrollment relay FIRST (P0-1, P1-1, P1-3, P1-4), performs checked
// local cleanup of hosted units bound to that key, then removes local identity
// files while preserving agent.conf preferences.
func cmdLogout(argv []string) int {
	return runLogout(argv, defaultServiceOps())
}

func runLogout(argv []string, ops serviceOps) int {
	forceLocal := false
	for _, a := range argv {
		switch a {
		case "--force-local":
			forceLocal = true
		default:
			fmt.Fprintf(os.Stderr, "unknown logout flag %q (usage: ocliv logout [--force-local])\n", a)
			return apperr.ExitCLIValidation
		}
	}
	dir, keyPath, cfgPath, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	remoteRevoked := false
	var revokedKeyID string
	if k, keyID, kerr := loadKey(); kerr == nil {
		revokedKeyID = keyID
		relayURL, berr := resolveBoundRelayURL(cfgPath)
		if berr != nil {
			if !forceLocal {
				fmt.Fprintf(os.Stderr, "logout blocked: %v; pass --force-local to remove local key without remote revocation\n", berr)
				return apperr.ExitAuth
			}
			fmt.Fprintf(os.Stderr, "warning: --force-local skipped remote revocation (%v)\n", berr)
		} else {
			code, body, callErr := mgmtCall(relayURL, k, keyID, http.MethodPost, "/v1/agent/key/revoke")
			if callErr == nil && code == http.StatusOK {
				remoteRevoked = true
			} else {
				admitted, denied, reachable := probeChallengeAdmitted(relayURL, keyID)
				if reachable && denied && !admitted {
					remoteRevoked = true
				} else if !forceLocal {
					if callErr != nil {
						fmt.Fprintf(os.Stderr, "logout blocked: could not revoke key %s on bound relay %s (%v); retry when reachable or pass --force-local\n", keyID, relayURL, callErr)
						return apperr.ExitRelayTLS
					}
					fmt.Fprintf(os.Stderr, "logout blocked: bound relay %s did not confirm revocation of %s (HTTP %d: %s); pass --force-local to remove local key anyway\n",
						relayURL, keyID, code, shortDetail(string(body)))
					return apperr.ExitAuth
				} else {
					fmt.Fprintf(os.Stderr, "warning: --force-local skipped remote revocation confirmation of %s\n", keyID)
				}
			}
		}
	}

	// P1-1: checked local cleanup of hosted services bound to the revoked key.
	var cleanupFailures []string
	svcStore, serr := openServices()
	if serr != nil {
		cleanupFailures = append(cleanupFailures, fmt.Sprintf("open service store: %v", serr))
	} else {
		svcs, lerr := svcStore.List()
		if lerr != nil {
			cleanupFailures = append(cleanupFailures, fmt.Sprintf("list services: %v", lerr))
		} else {
			for _, svc := range svcs {
				ownedByKey := revokedKeyID == "" || svc.Identity == nil || svc.Identity.OwnerKeyID == "" || svc.Identity.OwnerKeyID == revokedKeyID
				if !ownedByKey {
					continue
				}
				if _, uerr := svcStore.UpdateCAS(svc.Name, svc.Revision, func(r *config.ServiceRecord) error {
					r.DesiredState = config.DesiredDisabled
					r.LeaseID = ""
					return nil
				}); uerr != nil {
					cleanupFailures = append(cleanupFailures, fmt.Sprintf("service %s: persist disabled state failed: %v", svc.Name, uerr))
				}
				if svc.SystemdUnit != "" {
					ev := stopAndVerifyUnit(svc.SystemdUnit, true, ops)
					if !ev.StoppedNow || !ev.DisabledForReboot {
						cleanupFailures = append(cleanupFailures, fmt.Sprintf("service %s publisher %s: %s (run `systemctl --user disable --now %s`)",
							svc.Name, svc.SystemdUnit, ev.Error, svc.SystemdUnit))
					}
				}
				if svc.BackendMode == config.BackendManaged && svc.BackendUnit != "" {
					evBe := stopAndVerifyUnit(svc.BackendUnit, true, ops)
					if !evBe.StoppedNow || !evBe.DisabledForReboot {
						cleanupFailures = append(cleanupFailures, fmt.Sprintf("service %s backend %s: %s (run `systemctl --user disable --now %s`)",
							svc.Name, svc.BackendUnit, evBe.Error, svc.BackendUnit))
					}
				}
			}
		}
	}

	// Check every identity-file removal error; preserve agent.conf preferences.
	removeFiles := []string{
		keyPath,
		filepath.Join(dir, "agent.key.pending"),
		filepath.Join(dir, "enroll-pending.json"),
		filepath.Join(dir, "agent.key.rotating"),
		filepath.Join(dir, "key-rotation-pending.json"),
	}
	for _, p := range removeFiles {
		if rerr := os.Remove(p); rerr != nil && !os.IsNotExist(rerr) {
			cleanupFailures = append(cleanupFailures, fmt.Sprintf("remove %s: %v", p, rerr))
		}
	}
	if len(cleanupFailures) > 0 {
		fmt.Fprintln(os.Stderr, "LOGOUT_REMOTE_REVOKED_LOCAL_CLEANUP_INCOMPLETE:")
		for _, f := range cleanupFailures {
			fmt.Fprintln(os.Stderr, "  - "+f)
		}
		return apperr.ExitInternal
	}
	if remoteRevoked {
		fmt.Println("Logged out: agent key and live authority revoked on relay; local identity removed (preferences preserved).")
	} else {
		fmt.Println("Logged out: local identity removed (remote key revocation not confirmed; preferences preserved).")
	}
	return apperr.ExitOK
}

func isPreSendEnrollErr(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	var certErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invErr x509.CertificateInvalidError
	return errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &invErr)
}

// resolveBoundRelayURL returns the persisted relay_url from agent.conf ONLY,
// ignoring ambient OCLIV_RELAY_URL overrides (P1-3).
func resolveBoundRelayURL(cfgPath string) (string, error) {
	vals, err := config.LoadAgentFile(cfgPath)
	if err != nil {
		return "", fmt.Errorf("cannot read persisted relay config %s: %w", cfgPath, err)
	}
	u := strings.TrimSpace(vals["relay_url"])
	if u == "" {
		return "", fmt.Errorf("no persisted relay_url in %s", cfgPath)
	}
	return u, nil
}

// cmdKey manages the enrolled agent key lifecycle (`ocliv key rotate`).
func cmdKey(argv []string) int {
	if len(argv) == 0 || argv[0] != "rotate" {
		fmt.Fprintln(os.Stderr, "usage: ocliv key rotate [--json]")
		return apperr.ExitCLIValidation
	}
	return runKeyRotate(argv[1:], defaultServiceOps())
}

func cmdKeyRotate(argv []string) int {
	return runKeyRotate(argv, defaultServiceOps())
}

type keyRotateResult struct {
	OldKeyID                string   `json:"old_key_id"`
	NewKeyID                string   `json:"new_key_id"`
	TenantID                string   `json:"tenant_id,omitempty"`
	LeasesTransferred       int64    `json:"leases_transferred"`
	PublicationsTransferred int64    `json:"publications_transferred"`
	Recovered               bool     `json:"recovered,omitempty"`
	State                   string   `json:"state,omitempty"`
	RestartedPublishers     []string `json:"restarted_publishers,omitempty"`
}

func writeRotationJournal(path string, j keyRotationPendingJournal) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic0600(path, string(b)+"\n")
}

// runKeyRotate performs end-to-end crash-safe key rotation via a durable
// persisted state machine (P0-2, P0-3, P0-4, P1-3):
//
//	STAGED -> REMOTE_COMMITTED -> LOCAL_KEY_COMMITTED ->
//	SERVICE_METADATA_REBOUND -> PUBLISHERS_RESTARTED -> COMPLETE
func runKeyRotate(argv []string, ops serviceOps) int {
	jsonOut := false
	for _, a := range argv {
		if a == "--json" {
			jsonOut = true
		} else {
			fmt.Fprintf(os.Stderr, "unknown flag %q (usage: ocliv key rotate [--json])\n", a)
			return apperr.ExitCLIValidation
		}
	}
	dir, keyPath, cfgPath, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	relayURL, err := resolveBoundRelayURL(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "key rotate blocked: "+err.Error())
		return apperr.ExitAuth
	}
	rotatingPath := filepath.Join(dir, "agent.key.rotating")
	journalPath := filepath.Join(dir, "key-rotation-pending.json")

	var journal keyRotationPendingJournal
	var newKey *identity.KeyPair
	var oldKey *identity.KeyPair
	var oldKeyID string
	res := keyRotateResult{}

	// A3: check for an existing rotation journal BEFORE resolving/probing any
	// relay so an in-progress identity transaction can never be retargeted to
	// a different relay authority.
	if rawJ, jerr := os.ReadFile(journalPath); jerr == nil {
		if uerr := json.Unmarshal(rawJ, &journal); uerr != nil || journal.NewKeyID == "" || strings.TrimSpace(journal.RelayURL) == "" {
			fmt.Fprintf(os.Stderr, "key rotate blocked: corrupt rotation journal at %s\n", journalPath)
			return apperr.ExitInternal
		}
		journalAuth, jaErr := normalizeRelayAuthority(journal.RelayURL)
		curAuth, caErr := normalizeRelayAuthority(relayURL)
		if jaErr != nil || caErr != nil || journalAuth != curAuth {
			fmt.Fprintf(os.Stderr, "ROTATION_AUTHORITY_MISMATCH: rotation journal is bound to %s, but active relay_url is %s; preserving keys and journal at %s (zero relay requests sent)\n",
				journal.RelayURL, relayURL, journalPath)
			return apperr.ExitAuth
		}
		// Authoritative relay for this transaction is always the journal's URL.
		relayURL = journal.RelayURL
		res.OldKeyID = journal.OldKeyID
		res.NewKeyID = journal.NewKeyID
		res.Recovered = true

		// If remote already committed (or later), NEVER retry remote RPC!
		switch journal.State {
		case rotStateRemoteCommitted, rotStateLocalKeyCommitted, rotStateServiceMetadataRebound, rotStatePublishersRestarted:
			if journal.State != rotStateRemoteCommitted {
				ek, lerr := identity.Load(keyPath)
				if lerr != nil {
					fmt.Fprintf(os.Stderr, "key rotate recovery error: cannot load installed key %s: %v\n", keyPath, lerr)
					return apperr.ExitInternal
				}
				if "key-"+string(ek.ID()) != journal.NewKeyID {
					fmt.Fprintf(os.Stderr, "key rotate recovery error: installed key %s does not match journal %s\n",
						"key-"+string(ek.ID()), journal.NewKeyID)
					return apperr.ExitInternal
				}
				newKey = ek
			}
			if ferr := advanceKeyRotation(journal, keyPath, journalPath, newKey, &res, ops); ferr != nil {
				fmt.Fprintf(os.Stderr, "key rotate finalization incomplete (state=%s, journal preserved at %s): %v\n",
					res.State, journalPath, ferr)
				return apperr.ExitInternal
			}
			return emitKeyRotateResult(res, jsonOut)
		}

		// State == STAGED (ambiguous prior RPC): probe new staged key against journal's relay ONLY.
		stagedKey, lerr := identity.Load(journal.StagedKeyPath)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "key rotate blocked: cannot load staged key %s: %v\n", journal.StagedKeyPath, lerr)
			return apperr.ExitInternal
		}
		stagedKeyID := "key-" + string(stagedKey.ID())
		if stagedKeyID != journal.NewKeyID {
			fmt.Fprintf(os.Stderr, "key rotate blocked: staged key ID %s does not match journal %s\n", stagedKeyID, journal.NewKeyID)
			return apperr.ExitInternal
		}
		if newAdmitted, newReach := probeKeyAdmitted(relayURL, stagedKey, stagedKeyID); newReach && newAdmitted {
			journal.State = rotStateRemoteCommitted
			if werr := keyRotateJournalWriteFn(journalPath, journal); werr != nil {
				fmt.Fprintf(os.Stderr, "key rotate recovery error updating journal: %v\n", werr)
				return apperr.ExitInternal
			}
			if ferr := advanceKeyRotation(journal, keyPath, journalPath, stagedKey, &res, ops); ferr != nil {
				fmt.Fprintf(os.Stderr, "key rotate finalization incomplete (state=%s, journal preserved at %s): %v\n",
					res.State, journalPath, ferr)
				return apperr.ExitInternal
			}
			return emitKeyRotateResult(res, jsonOut)
		}
		// New key not admitted: probe OLD key.
		okKey, okKeyID, lerr := loadKey()
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "key rotate ambiguous: cannot load old key %s (%v); preserving %s\n", keyPath, lerr, journalPath)
			return apperr.ExitInternal
		}
		if oldAdmitted, oldReach := probeKeyAdmitted(relayURL, okKey, okKeyID); !oldReach || !oldAdmitted {
			fmt.Fprintf(os.Stderr, "key rotate ambiguous: neither new key (%s) nor old key (%s) confirmed admitted on %s; preserving %s and %s\n",
				stagedKeyID, okKeyID, relayURL, journal.StagedKeyPath, journalPath)
			return apperr.ExitRelayTLS
		}
		// Old key is still admitted -> remote did not commit -> retry with SAME staged key.
		oldKey = okKey
		oldKeyID = okKeyID
		newKey = stagedKey
		rotatingPath = journal.StagedKeyPath
	}

	if oldKey == nil {
		oldKey, oldKeyID, err = loadKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
			return apperr.ExitAuth
		}
	}
	if newKey == nil {
		newKey, err = identity.Generate()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		expectedNewKeyID := "key-" + string(newKey.ID())
		if err := newKey.Save(rotatingPath); err != nil {
			fmt.Fprintln(os.Stderr, "error: cannot stage replacement key: "+err.Error())
			return apperr.ExitInternal
		}
		journal = keyRotationPendingJournal{
			RelayURL:      relayURL,
			OldKeyID:      oldKeyID,
			NewKeyID:      expectedNewKeyID,
			StagedKeyPath: rotatingPath,
			StartedAt:     time.Now().UTC().Format(time.RFC3339Nano),
			State:         rotStateStaged,
		}
		if err := writeRotationJournal(journalPath, journal); err != nil {
			_ = os.Remove(rotatingPath)
			fmt.Fprintln(os.Stderr, "error: cannot write rotation journal: "+err.Error())
			return apperr.ExitInternal
		}
	}

	expectedNewKeyID := journal.NewKeyID
	nonce, err := agent.MgmtNonce()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error creating management nonce: "+err.Error())
		return apperr.ExitInternal
	}
	proof := ed25519.Sign(newKey.Private(), agent.KeyRotationProofMessage(oldKeyID, expectedNewKeyID, nonce))
	reqBody, _ := json.Marshal(map[string]string{
		"new_public_key": base64.StdEncoding.EncodeToString(newKey.Public()),
		"new_key_proof":  base64.StdEncoding.EncodeToString(proof),
	})
	code, respBody, callErr := mgmtCallBodyWithNonce(relayURL, oldKey, oldKeyID, http.MethodPost, "/v1/agent/key/rotate", nonce, reqBody)
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "key rotate failed (transport error: %v); staged key and journal preserved at %s — re-run `ocliv key rotate` to recover\n", callErr, journalPath)
		return apperr.ExitRelayTLS
	}
	if code != http.StatusOK {
		if oldAdmitted, reachable := probeKeyAdmitted(relayURL, oldKey, oldKeyID); reachable && oldAdmitted {
			_ = os.Remove(rotatingPath)
			_ = os.Remove(journalPath)
		}
		fmt.Fprintf(os.Stderr, "key rotate denied (HTTP %d): %s\n", code, shortDetail(string(respBody)))
		return apperr.ExitAuth
	}
	if err := json.Unmarshal(respBody, &res); err != nil || res.NewKeyID != expectedNewKeyID || res.OldKeyID != oldKeyID {
		fmt.Fprintf(os.Stderr, "key rotate error: relay response identity mismatch (got old=%q new=%q, want old=%q new=%q); staged key preserved at %s\n",
			res.OldKeyID, res.NewKeyID, oldKeyID, expectedNewKeyID, journalPath)
		return apperr.ExitInternal
	}
	journal.State = rotStateRemoteCommitted
	if err := writeRotationJournal(journalPath, journal); err != nil {
		fmt.Fprintf(os.Stderr, "key rotate error persisting REMOTE_COMMITTED journal: %v\n", err)
		return apperr.ExitInternal
	}
	if err := advanceKeyRotation(journal, keyPath, journalPath, newKey, &res, ops); err != nil {
		fmt.Fprintf(os.Stderr, "key rotate finalization incomplete (state=%s, journal preserved at %s): %v\n",
			res.State, journalPath, err)
		return apperr.ExitInternal
	}
	return emitKeyRotateResult(res, jsonOut)
}

// advanceKeyRotation steps deterministically through every local post-remote
// state, persisting each transition and propagating every failure so the
// journal is NEVER deleted until every durable step and authoritative
// post-rotation publisher verification succeed (A2, A7, P0-4).
func advanceKeyRotation(j keyRotationPendingJournal, keyPath, journalPath string, newKey *identity.KeyPair, res *keyRotateResult, ops serviceOps) error {
	res.State = j.State
	// Step 1 (A2): state-derived LOCAL_KEY_COMMITTED.
	// Inspect both installed agent.key and staged key rather than assuming the
	// staged file still exists; durably persist LOCAL_KEY_COMMITTED BEFORE
	// removing j.StagedKeyPath so a crash between replace and journal write
	// recovers cleanly without losing authority.
	if j.State == rotStateRemoteCommitted {
		installedKey, ierr := identity.Load(keyPath)
		stagedKey, serr := identity.Load(j.StagedKeyPath)
		installedID := ""
		if ierr == nil {
			installedID = "key-" + string(installedKey.ID())
		}
		stagedID := ""
		if serr == nil {
			stagedID = "key-" + string(stagedKey.ID())
		}
		switch {
		case ierr == nil && installedID == j.NewKeyID:
			// Already installed (e.g., crash after SaveDurableReplace before
			// LOCAL_KEY_COMMITTED was durably written).
			newKey = installedKey
		case ierr == nil && installedID == j.OldKeyID && serr == nil && stagedID == j.NewKeyID:
			newKey = stagedKey
			if err := newKey.SaveDurableReplace(keyPath); err != nil {
				return fmt.Errorf("installing rotated key: %w", err)
			}
			if keyRotateAfterSaveHook != nil {
				if herr := keyRotateAfterSaveHook(); herr != nil {
					return fmt.Errorf("post-key-install fault: %w", herr)
				}
			}
		default:
			return fmt.Errorf("cannot prove local key state during REMOTE_COMMITTED recovery (installed=%q err=%v; staged=%q err=%v; want old=%q new=%q)",
				installedID, ierr, stagedID, serr, j.OldKeyID, j.NewKeyID)
		}
		j.State = rotStateLocalKeyCommitted
		res.State = j.State
		if err := keyRotateJournalWriteFn(journalPath, j); err != nil {
			return fmt.Errorf("persisting %s state: %w", j.State, err)
		}
		if j.StagedKeyPath != "" {
			_ = os.Remove(j.StagedKeyPath)
		}
	}
	if newKey == nil {
		ek, lerr := identity.Load(keyPath)
		if lerr != nil {
			return fmt.Errorf("loading committed key %s: %w", keyPath, lerr)
		}
		newKey = ek
	}

	// Step 2: SERVICE_METADATA_REBOUND (openServices/List/UpdateCAS errors are fatal).
	svcStore, serr := openServices()
	if serr != nil {
		return fmt.Errorf("opening service store for owner rebind: %w", serr)
	}
	svcs, lerr := svcStore.List()
	if lerr != nil {
		return fmt.Errorf("listing services for owner rebind: %w", lerr)
	}
	if j.State == rotStateLocalKeyCommitted {
		for _, svc := range svcs {
			if svc.Identity != nil && svc.Identity.OwnerKeyID == j.OldKeyID {
				if _, uerr := svcStore.UpdateCAS(svc.Name, svc.Revision, func(r *config.ServiceRecord) error {
					if r.Identity != nil && r.Identity.OwnerKeyID == j.OldKeyID {
						r.Identity.OwnerKeyID = j.NewKeyID
					}
					return nil
				}); uerr != nil {
					return fmt.Errorf("updating owner key for service %q: %w", svc.Name, uerr)
				}
			}
		}
		j.State = rotStateServiceMetadataRebound
		res.State = j.State
		if err := keyRotateJournalWriteFn(journalPath, j); err != nil {
			return fmt.Errorf("persisting %s state: %w", j.State, err)
		}
	}

	// Step 3 (A7): PUBLISHERS_RESTARTED — restart each DesiredEnabled publisher
	// not yet verified under NewKeyID, then prove authoritative ownership and
	// live attachment via signed relay state under NewKeyID. Persist per-service
	// recovery progress so retries never disturb already-recovered services.
	if j.State == rotStateServiceMetadataRebound {
		if j.RecoveredServices == nil {
			j.RecoveredServices = map[string]bool{}
		}
		var restartErrs []string
		for _, svc := range svcs {
			if svc.DesiredState != config.DesiredEnabled || svc.SystemdUnit == "" {
				continue
			}
			if j.RecoveredServices[svc.Name] {
				continue
			}
			if outStr, rerr := ops.systemctl("restart", svc.SystemdUnit); rerr != nil {
				restartErrs = append(restartErrs, fmt.Sprintf("%s (%s): restart failed: %v %s", svc.Name, svc.SystemdUnit, rerr, strings.TrimSpace(outStr)))
				continue
			}
			if verr := verifyRotatedPublisher(j.RelayURL, newKey, j.NewKeyID, svc, ops); verr != nil {
				restartErrs = append(restartErrs, fmt.Sprintf("%s (%s): post-rotation verification failed: %v", svc.Name, svc.SystemdUnit, verr))
				continue
			}
			j.RecoveredServices[svc.Name] = true
			if werr := keyRotateJournalWriteFn(journalPath, j); werr != nil {
				return fmt.Errorf("persisting recovered service %q: %w", svc.Name, werr)
			}
			res.RestartedPublishers = append(res.RestartedPublishers, svc.Name)
		}
		if len(restartErrs) > 0 {
			return fmt.Errorf("restarting/verifying enabled publishers failed: %s", strings.Join(restartErrs, "; "))
		}
		j.State = rotStatePublishersRestarted
		res.State = j.State
		if err := keyRotateJournalWriteFn(journalPath, j); err != nil {
			return fmt.Errorf("persisting %s state: %w", j.State, err)
		}
	}

	// Step 4: COMPLETE — remove journal only after all prior states succeeded.
	if err := os.Remove(journalPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing rotation journal: %w", err)
	}
	res.State = rotStateComplete
	return nil
}

// verifyRotatedPublisher proves from signed relay state under newKeyID that
// the restarted publisher's lease or publication is owned by newKeyID and
// actively attached (A7).
func verifyRotatedPublisher(relayURL string, newKey *identity.KeyPair, newKeyID string, svc config.ServiceRecord, ops serviceOps) error {
	callFn := ops.mgmtCall
	if callFn == nil {
		callFn = mgmtCall
	}
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(150 * time.Millisecond)
		}
		if svc.Type == "mcp" {
			st, body, err := callFn(relayURL, newKey, newKeyID, http.MethodGet, "/v1/agent/mcp-routes")
			if err != nil {
				lastErr = fmt.Errorf("querying mcp-routes under %s: %w", newKeyID, err)
				continue
			}
			if st != http.StatusOK {
				lastErr = fmt.Errorf("mcp-routes under %s returned HTTP %d", newKeyID, st)
				continue
			}
			var resp struct {
				Routes []struct {
					RouteID    string `json:"route_id"`
					Name       string `json:"pub_name"`
					LeaseID    string `json:"lease_id"`
					RouteLive  bool   `json:"route_live"`
					OwnerKeyID string `json:"owner_key_id"`
				} `json:"routes"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				lastErr = fmt.Errorf("decoding mcp-routes: %w", err)
				continue
			}
			for _, rt := range resp.Routes {
				idMatch := (svc.PublicationID != "" && rt.RouteID == svc.PublicationID) || (svc.PublicationID == "" && strings.EqualFold(rt.Name, svc.Name))
				if !idMatch {
					continue
				}
				if rt.OwnerKeyID != "" && rt.OwnerKeyID != newKeyID {
					lastErr = fmt.Errorf("publication %s owner_key_id=%s, want %s", rt.RouteID, rt.OwnerKeyID, newKeyID)
					continue
				}
				if !rt.RouteLive {
					lastErr = fmt.Errorf("publication %s not yet live under %s", rt.RouteID, newKeyID)
					continue
				}
				return nil
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("publication for service %q not found under %s", svc.Name, newKeyID)
			}
			continue
		}

		// HTTP service: query signed /v1/agent/leases under newKeyID.
		st, body, err := callFn(relayURL, newKey, newKeyID, http.MethodGet, "/v1/agent/leases")
		if err != nil {
			lastErr = fmt.Errorf("querying leases under %s: %w", newKeyID, err)
			continue
		}
		if st != http.StatusOK {
			lastErr = fmt.Errorf("leases under %s returned HTTP %d", newKeyID, st)
			continue
		}
		var resp struct {
			Leases []relayHTTPLeaseItem `json:"leases"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			lastErr = fmt.Errorf("decoding leases: %w", err)
			continue
		}
		wantLabel := canonicalHTTPLabel(svc.Name)
		wantPort := localPortFromURL(svc.LocalURL)
		for _, ls := range resp.Leases {
			if svc.LeaseID != "" && ls.LeaseID != svc.LeaseID {
				continue
			}
			if svc.LeaseID == "" && (canonicalHTTPLabel(ls.Label) != wantLabel || (wantPort > 0 && ls.Port != wantPort)) {
				continue
			}
			if ls.Status == "ACTIVE" && ls.RouteLive {
				return nil
			}
			lastErr = fmt.Errorf("lease %s under %s status=%s route_live=%v", ls.LeaseID, newKeyID, ls.Status, ls.RouteLive)
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no active live lease for service %q owned by %s", svc.Name, newKeyID)
		}
	}
	return lastErr
}

func emitKeyRotateResult(res keyRotateResult, jsonOut bool) int {
	if jsonOut {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return apperr.ExitOK
	}
	fmt.Printf("✓ rotated agent key %s -> %s (leases=%d, publications=%d, state=%s)\n",
		res.OldKeyID, res.NewKeyID, res.LeasesTransferred, res.PublicationsTransferred, res.State)
	if len(res.RestartedPublishers) > 0 {
		fmt.Printf("  restarted publishers: %s\n", strings.Join(res.RestartedPublishers, ", "))
	}
	return apperr.ExitOK
}

// normalizeRelayAuthority canonicalizes a relay URL to scheme://host for
// rotation-journal authority binding comparisons.
func normalizeRelayAuthority(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty relay URL")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("relay URL has no host")
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}
