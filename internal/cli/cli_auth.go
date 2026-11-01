// Agent enrollment: login, logout, and relay URL plumbing.
package cli

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
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
	// Enrollment codes must not appear in argv (process-list visible).
	// Read from a file, or "-" for stdin.
	var codeRaw []byte
	var err error
	if codeFile == "-" {
		codeRaw, err = io.ReadAll(io.LimitReader(os.Stdin, 4096))
	} else {
		codeRaw, err = os.ReadFile(codeFile)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot read code file: "+err.Error())
		return apperr.ExitCLIValidation
	}
	code := strings.TrimSpace(string(codeRaw))
	if code == "" {
		fmt.Fprintln(os.Stderr, "error: enrollment code file is empty")
		return apperr.ExitCLIValidation
	}
	// Never enroll over plaintext to the network: enrollment transmits the
	// tenant's public key binding and code; only loopback http is allowed
	// for local development (B01, B02).
	if err := config.CheckRelayTLS(relayURL); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}
	_, keyPath, cfgPath, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	// Refuse before touching the network: overwriting an existing
	// enrollment would silently destroy the secret and burn the one-time
	// code on a doomed attempt (H07). Destruction stays explicit via
	// logout, which tells the operator to revoke the relay-side key.
	if _, err := os.Stat(keyPath); err == nil {
		fmt.Fprintln(os.Stderr, "already enrolled: run `ocliv logout` first (then ask the operator to revoke the old key)")
		return apperr.ExitInternal
	}
	k, err := identity.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	pub := base64.StdEncoding.EncodeToString(k.Public())
	body, _ := json.Marshal(map[string]string{"code": code, "public_key": pub})
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	// Lab/private relay edges (e.g. Caddy `tls internal`): trust the
	// --cacert/OCLIV_CACERT bundle in addition to system roots. A
	// broken bundle fails enrollment; verification is never disabled.
	if cacert != "" {
		pem, err := os.ReadFile(cacert)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: cannot read --cacert file: "+err.Error())
			return apperr.ExitCLIValidation
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			fmt.Fprintln(os.Stderr, "error: --cacert file holds no certificates")
			return apperr.ExitCLIValidation
		}
		tlsCfg.RootCAs = pool
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if strings.HasPrefix(relayURL, "https") {
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	resp, err := client.Post(strings.TrimRight(relayURL, "/")+"/v1/agent/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "enrollment failed: relay unreachable; check the URL and try again")
		return apperr.ExitAuth
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "enrollment denied: invalid or expired code")
		return apperr.ExitAuth
	}
	var out struct {
		KeyID    string `json:"key_id"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		fmt.Fprintln(os.Stderr, "enrollment failed: bad relay response")
		return apperr.ExitAuth
	}
	if err := k.Save(keyPath); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	// Preserve operator/user settings already in the file: login only
	// records the relay URL, never truncates the config (R6).
	if err := mergeRelayURL(cfgPath, relayURL); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	fmt.Println("Enrolled as " + out.KeyID)
	fmt.Println("Relay: " + relayURL)
	return apperr.ExitOK
}

// mergeRelayURL records the relay URL while preserving every other key
// already present in the agent config file.
func mergeRelayURL(cfgPath, relayURL string) error {
	vals, err := config.LoadAgentFile(cfgPath)
	if err != nil {
		// Missing file is fine; anything else fail closed.
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
	return os.WriteFile(cfgPath, []byte(b.String()), 0o600)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// cmdLogout removes local enrollment; remote revocation requires operator action.
func cmdLogout(argv []string) int {
	_, keyPath, cfgPath, err := agentFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitInternal
	}
	_ = os.Remove(keyPath)
	_ = os.Remove(cfgPath)
	_ = argv
	fmt.Println("Logged out: local enrollment removed.")
	fmt.Println("Ask the relay operator to revoke the agent key to complete removal.")
	return apperr.ExitOK
}

// renderStatus builds the status report from the cached local lease and
// the authoritative relay record. The relay state wins whenever the query
// succeeded; anything else is UNKNOWN, never a stale cache echo (P1).
