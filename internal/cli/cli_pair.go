// Publisher-initiated pairing flow: generate keypair, submit to relay,
// display the pairing code for the operator to approve, and wait for approval.
package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/control"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

// cmdPair implements `ocliv pair RELAY_URL [--no-wait] [--timeout D]`.
// By default the publisher submits its public key, displays the pairing code
// for the operator to approve, and waits for approval to complete enrollment.
// Use --no-wait to exit immediately (credentials are saved for `ocliv pair resume`).
func cmdPair(argv []string) int {
	// Handle "resume" subcommand.
	if len(argv) > 0 && argv[0] == "resume" {
		return cmdPairResume(argv[1:])
	}

	var relayURL, cacert string
	doWait := true // wait by default
	timeout := 10 * time.Minute

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Fprintln(os.Stderr, "usage: ocliv pair RELAY_URL [--no-wait] [--timeout DURATION] [--cacert FILE]")
			fmt.Fprintln(os.Stderr, "       ocliv pair resume [--timeout DURATION] [--cacert FILE]")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "  RELAY_URL           relay to pair with (https://...)")
			fmt.Fprintln(os.Stderr, "  --no-wait           print the pairing code and exit without waiting")
			fmt.Fprintln(os.Stderr, "  --timeout DURATION  max wait time (default 10m)")
			fmt.Fprintln(os.Stderr, "  --cacert FILE       trust this CA certificate for the relay TLS")
			fmt.Fprintln(os.Stderr, "  resume              resume polling a previous --no-wait pairing request")
			return apperr.ExitOK
		case a == "--no-wait":
			doWait = false
		case a == "--cacert" || strings.HasPrefix(a, "--cacert="):
			v, ok := mcpFlagValue(argv, &i, "cacert")
			if !ok {
				return apperr.ExitCLIValidation
			}
			cacert = v
		case a == "--timeout" || strings.HasPrefix(a, "--timeout="):
			v, ok := mcpFlagValue(argv, &i, "timeout")
			if !ok {
				return apperr.ExitCLIValidation
			}
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "pair: invalid --timeout %q\n", v)
				return apperr.ExitCLIValidation
			}
			timeout = d
		case !strings.HasPrefix(a, "-") && relayURL == "":
			relayURL = a
		default:
			fmt.Fprintf(os.Stderr, "pair: unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}

	if relayURL == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv pair RELAY_URL [--no-wait] [--timeout D]")
		return apperr.ExitCLIValidation
	}
	if err := control.ValidateRelayURL(relayURL); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}

	// Generate or load a keypair for this profile.
	_, keyPath, cfgPath, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	var k *identity.KeyPair
	if _, serr := os.Stat(keyPath); serr == nil {
		if k, err = identity.Load(keyPath); err != nil {
			fmt.Fprintln(os.Stderr, "error loading existing key: "+err.Error())
			return apperr.ExitInternal
		}
		fmt.Fprintln(os.Stderr, "note: using existing key "+("key-"+string(k.ID())))
	} else {
		if k, err = identity.Generate(); err != nil {
			fmt.Fprintln(os.Stderr, "error generating key: "+err.Error())
			return apperr.ExitInternal
		}
		if err := k.Save(keyPath); err != nil {
			fmt.Fprintln(os.Stderr, "error saving key: "+err.Error())
			return apperr.ExitInternal
		}
		fmt.Fprintln(os.Stderr, "generated new key "+("key-"+string(k.ID())))
	}

	client, err := control.NewHTTPClient(control.HTTPClientOptions{
		Timeout:    15 * time.Second,
		CACertPath: cacert,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error building HTTP client: "+err.Error())
		return apperr.ExitRelayTLS
	}
	defer client.CloseIdleConnections()

	pub := base64.StdEncoding.EncodeToString(k.Public())
	body, _ := json.Marshal(map[string]string{"public_key": pub})

	resp, err := client.Post(
		strings.TrimRight(relayURL, "/")+"/v1/agent/pair-request",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error contacting relay: "+err.Error())
		return apperr.ExitAuth
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "pair-request denied (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(respBytes)))
		return apperr.ExitAuth
	}

	var pairResp struct {
		PairingCode      string `json:"pairing_code"`
		PollID           string `json:"poll_id"`
		PollSecret       string `json:"poll_secret"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}
	if err := json.Unmarshal(respBytes, &pairResp); err != nil || pairResp.PairingCode == "" {
		fmt.Fprintln(os.Stderr, "error: unexpected relay response")
		return apperr.ExitAuth
	}
	if pairResp.PollID == "" || pairResp.PollSecret == "" {
		fmt.Fprintln(os.Stderr, "error: relay did not return poll credentials (upgrade relay)")
		return apperr.ExitAuth
	}

	expiry := time.Duration(pairResp.ExpiresInSeconds) * time.Second
	fmt.Printf("Pairing code: %s (expires %s)\n", pairResp.PairingCode, expiry.Round(time.Second))
	fmt.Printf("Ask the relay operator to run:\n  ocliv relay approve %s --tenant TENANT\n", pairResp.PairingCode)

	localKeyID := "key-" + string(k.ID())
	// Always persist poll credentials (bound to localKeyID) before proceeding so Ctrl-C + ocliv pair resume works.
	if err := savePairPending(relayURL, localKeyID, pairResp.PollID, pairResp.PollSecret, pairResp.ExpiresInSeconds, cacert); err != nil {
		fmt.Fprintln(os.Stderr, "error: could not save pairing state (required for resume): "+err.Error())
		return apperr.ExitInternal
	}

	if !doWait {
		fmt.Println("\nRun `ocliv pair resume` to complete enrollment when the operator approves.")
		return apperr.ExitOK
	}

	return doPairWait(client, relayURL, cfgPath, k, localKeyID, pairResp.PollID, pairResp.PollSecret, timeout)
}

// cmdPairResume loads saved poll credentials and waits for operator approval.
func cmdPairResume(argv []string) int {
	var cacert string
	timeout := 10 * time.Minute

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Fprintln(os.Stderr, "usage: ocliv pair resume [--timeout DURATION] [--cacert FILE]")
			return apperr.ExitOK
		case a == "--cacert" || strings.HasPrefix(a, "--cacert="):
			v, ok := mcpFlagValue(argv, &i, "cacert")
			if !ok {
				return apperr.ExitCLIValidation
			}
			cacert = v
		case a == "--timeout" || strings.HasPrefix(a, "--timeout="):
			v, ok := mcpFlagValue(argv, &i, "timeout")
			if !ok {
				return apperr.ExitCLIValidation
			}
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "pair resume: invalid --timeout %q\n", v)
				return apperr.ExitCLIValidation
			}
			timeout = d
		default:
			fmt.Fprintf(os.Stderr, "pair resume: unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		}
	}
	st, err := loadPairPending()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}
	// Validate persisted relay URL before making any network request.
	if err := control.ValidateRelayURL(st.RelayURL); err != nil {
		fmt.Fprintln(os.Stderr, "error: invalid relay URL in saved pairing state: "+err.Error())
		return apperr.ExitCLIValidation
	}

	// Check expiry.
	if exp, perr := time.Parse(time.RFC3339, st.ExpiresAt); perr == nil && time.Now().After(exp) {
		if p, perr2 := pairPendingPath(); perr2 == nil {
			_ = os.Remove(p)
		}
		fmt.Fprintln(os.Stderr, "error: saved pairing request has expired; run `ocliv pair RELAY_URL` again")
		return apperr.ExitAuth
	}

	// Use explicit --cacert flag; fall back to the path saved with the pending state.
	caCertPath := cacert
	if caCertPath == "" {
		caCertPath = st.CACertPath
	}

	_, keyPath, cfgPath, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}

	// Load the existing key (must already exist for resume) and verify it matches
	// the key bound to the saved pending pairing request.
	k, err := identity.Load(keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading key: "+err.Error())
		return apperr.ExitInternal
	}
	localKeyID := "key-" + string(k.ID())
	if st.KeyID == "" {
		fmt.Fprintln(os.Stderr, "error: saved pairing state is missing key_id binding; run `ocliv pair RELAY_URL` again")
		return apperr.ExitAuth
	}
	if st.KeyID != localKeyID {
		fmt.Fprintf(os.Stderr, "error: local identity key %s does not match pending pairing request key %s; refusing to resume\n", localKeyID, st.KeyID)
		return apperr.ExitAuth
	}

	client, err := control.NewHTTPClient(control.HTTPClientOptions{
		Timeout:    15 * time.Second,
		CACertPath: caCertPath,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error building HTTP client: "+err.Error())
		return apperr.ExitRelayTLS
	}
	defer client.CloseIdleConnections()

	fmt.Printf("Resuming pairing with %s...\n", st.RelayURL)
	return doPairWait(client, st.RelayURL, cfgPath, k, st.KeyID, st.PollID, st.PollSecret, timeout)
}

// doPairWait polls until approved/expired/denied and completes enrollment.
func doPairWait(client *http.Client, relayURL, cfgPath string, k *identity.KeyPair, expectedKeyID, pollID, pollSecret string, timeout time.Duration) int {
	fmt.Printf("\nWaiting for operator approval (timeout %s)...\n", timeout.Round(time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	pollURL := strings.TrimRight(relayURL, "/") + "/v1/agent/pair-status"
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	removePending := func() {
		if p, err := pairPendingPath(); err == nil {
			_ = os.Remove(p)
		}
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "timed out waiting for approval")
			return apperr.ExitAuth
		case <-tick.C:
			status, tenantID, approvedKeyID, done := pollPairStatus(client, pollURL, pollID, pollSecret)
			if !done {
				continue
			}
			switch status {
			case "approved":
				localKeyID := "key-" + string(k.ID())
				if approvedKeyID == "" || approvedKeyID != localKeyID || approvedKeyID != expectedKeyID {
					fmt.Fprintf(os.Stderr, "error: relay approved key %q, expected local key %q; refusing to complete pairing\n", approvedKeyID, localKeyID)
					removePending()
					return apperr.ExitAuth
				}
				if err := mergeRelayURL(cfgPath, relayURL); err != nil {
					fmt.Fprintln(os.Stderr, "error saving relay URL: "+err.Error())
					return apperr.ExitInternal
				}
				removePending()
				fmt.Printf("enrolled: %s in tenant %q on %s\n", localKeyID, tenantID, relayURL)
				return apperr.ExitOK
			case "expired":
				removePending()
				fmt.Fprintln(os.Stderr, "pairing request expired; run `ocliv pair` again")
				return apperr.ExitAuth
			case "denied":
				removePending()
				fmt.Fprintln(os.Stderr, "pairing request denied by operator")
				return apperr.ExitAuth
			default:
				fmt.Fprintf(os.Stderr, "unknown status %q\n", status)
				return apperr.ExitAuth
			}
		}
	}
}

// pollPairStatus calls the relay pair-status endpoint (POST) with the
// high-entropy poll credentials. Returns (status, tenantID, keyID, shouldStop).
// shouldStop is true when the status is terminal.
func pollPairStatus(client *http.Client, pollURL, pollID, pollSecret string) (status, tenantID, keyID string, stop bool) {
	body, _ := json.Marshal(map[string]string{"poll_id": pollID, "poll_secret": pollSecret})
	resp, err := client.Post(pollURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", "", "", false // transient network error; keep polling
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusNotFound {
		return "expired", "", "", true
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", "", false // server error (e.g. 503 store outage); keep polling
	}
	var sr struct {
		Status   string `json:"status"`
		TenantID string `json:"tenant_id"`
		KeyID    string `json:"key_id"`
	}
	if err := json.Unmarshal(b, &sr); err != nil {
		return "", "", "", false
	}
	switch sr.Status {
	case "approved":
		return "approved", sr.TenantID, sr.KeyID, true
	case "expired", "denied":
		return sr.Status, "", "", true
	default:
		return sr.Status, "", "", false
	}
}

// pairPendingState holds the poll credentials saved for `ocliv pair resume`.
type pairPendingState struct {
	RelayURL   string `json:"relay_url"`
	KeyID      string `json:"key_id"`
	PollID     string `json:"poll_id"`
	PollSecret string `json:"poll_secret"`
	ExpiresAt  string `json:"expires_at"`
	CACertPath string `json:"cacert_path,omitempty"`
}

func pairPendingPath() (string, error) {
	dir, _, _, err := agentFiles()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "pair-pending.json"), nil
}

func savePairPending(relayURL, keyID, pollID, pollSecret string, expiresInSeconds int, caCertPath string) error {
	p, err := pairPendingPath()
	if err != nil {
		return err
	}
	exp := time.Now().Add(time.Duration(expiresInSeconds) * time.Second).UTC().Format(time.RFC3339)
	b, err := json.Marshal(pairPendingState{
		RelayURL:   relayURL,
		KeyID:      keyID,
		PollID:     pollID,
		PollSecret: pollSecret,
		ExpiresAt:  exp,
		CACertPath: caCertPath,
	})
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(p, b)
}

func loadPairPending() (pairPendingState, error) {
	p, err := pairPendingPath()
	if err != nil {
		return pairPendingState{}, err
	}
	b, err := readPrivateBytesStrict(p, 4096)
	if err != nil {
		if os.IsNotExist(err) {
			return pairPendingState{}, fmt.Errorf("no pending pairing request found (run `ocliv pair RELAY_URL` first)")
		}
		return pairPendingState{}, fmt.Errorf("reading pairing state: %w", err)
	}
	var st pairPendingState
	if err := json.Unmarshal(b, &st); err != nil {
		return pairPendingState{}, fmt.Errorf("corrupt pending pairing state: %w", err)
	}
	return st, nil
}

// writePrivateFileAtomic writes data to path atomically via a sibling temp file
// in the same directory (same filesystem as dest). The temp file is created with
// mode 0600, fsynced, then renamed atomically; the parent directory is fsynced.
func writePrivateFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}
	if dfi, err := os.Lstat(dir); err != nil {
		return fmt.Errorf("stat directory: %w", err)
	} else if dfi.Mode()&os.ModeSymlink != 0 || !dfi.IsDir() {
		return fmt.Errorf("refusing to write into symlinked or non-directory %q", dir)
	}
	if pfi, err := os.Lstat(path); err == nil {
		if pfi.Mode()&os.ModeSymlink != 0 || !pfi.Mode().IsRegular() {
			return fmt.Errorf("refusing to overwrite symlink or non-regular file %q", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat target %q: %w", path, err)
	}
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path))
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmp := f.Name()
	if err := os.Chmod(tmp, 0600); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("writing: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// readPrivateBytesStrict reads up to maxSize bytes from a private state file,
// verifying it is a regular file (not a symlink) owned by the current user with
// mode 0600.
func readPrivateBytesStrict(path string, maxSize int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if err == syscall.ENOENT {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%q has mode %o (want 0600)", path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if int(st.Uid) != os.Getuid() {
			return nil, fmt.Errorf("%q is owned by uid %d (want %d)", path, st.Uid, os.Getuid())
		}
	}
	if fi.Size() > maxSize {
		return nil, fmt.Errorf("%q is too large (%d > %d)", path, fi.Size(), maxSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("%q exceeds %d byte limit", path, maxSize)
	}
	return data, nil
}
