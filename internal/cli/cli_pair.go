// Publisher-initiated pairing flow: generate keypair, submit to relay,
// display the pairing code for the operator to approve.
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
	"strings"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/control"
	"ocliv/internal/identity"
)

// cmdPair implements `ocliv pair RELAY_URL [--wait] [--timeout D]`.
// The publisher submits its public key to the relay, displays a short
// pairing code for the operator to approve, and optionally waits for
// the approval to complete enrollment automatically.
func cmdPair(argv []string) int {
	var relayURL, cacert string
	doWait := false
	timeout := 10 * time.Minute

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Fprintln(os.Stderr, "usage: ocliv pair RELAY_URL [--wait] [--timeout DURATION] [--cacert FILE]")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "  RELAY_URL           relay to pair with (https://...)")
			fmt.Fprintln(os.Stderr, "  --wait              poll until operator approves, then complete enrollment")
			fmt.Fprintln(os.Stderr, "  --timeout DURATION  max wait time (default 10m; only with --wait)")
			fmt.Fprintln(os.Stderr, "  --cacert FILE       trust this CA certificate for the relay TLS")
			return apperr.ExitOK
		case a == "--wait":
			doWait = true
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
		fmt.Fprintln(os.Stderr, "usage: ocliv pair RELAY_URL [--wait] [--timeout D]")
		return apperr.ExitCLIValidation
	}
	if err := control.ValidateRelayURL(relayURL); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return apperr.ExitCLIValidation
	}
	if cacert == "" {
		cacert = config.CACertPath()
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

	client, err := control.HTTPClient(15 * time.Second)
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
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}
	if err := json.Unmarshal(respBytes, &pairResp); err != nil || pairResp.PairingCode == "" {
		fmt.Fprintln(os.Stderr, "error: unexpected relay response")
		return apperr.ExitAuth
	}

	expiry := time.Duration(pairResp.ExpiresInSeconds) * time.Second
	fmt.Printf("Pairing code: %s (expires %s)\n", pairResp.PairingCode, expiry.Round(time.Second))
	fmt.Printf("Ask the relay operator to run:\n  ocliv relay approve %s --tenant TENANT\n", pairResp.PairingCode)

	if !doWait {
		fmt.Println("\nRun `ocliv pair --wait` to complete enrollment automatically when the operator approves.")
		return apperr.ExitOK
	}

	fmt.Printf("\nWaiting for operator approval (timeout %s)...\n", timeout.Round(time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	pollURL := strings.TrimRight(relayURL, "/") + "/v1/agent/pair-status?code=" + pairResp.PairingCode
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "timed out waiting for approval")
			return apperr.ExitAuth
		case <-tick.C:
			status, tenantID, done := pollPairStatus(client, pollURL)
			if !done {
				continue
			}
			switch status {
			case "approved":
				if err := mergeRelayURL(cfgPath, relayURL); err != nil {
					fmt.Fprintln(os.Stderr, "error saving relay URL: "+err.Error())
					return apperr.ExitInternal
				}
				fmt.Printf("enrolled: key-%s in tenant %q on %s\n", k.ID(), tenantID, relayURL)
				return apperr.ExitOK
			case "expired":
				fmt.Fprintln(os.Stderr, "pairing request expired; run `ocliv pair` again")
				return apperr.ExitAuth
			case "denied":
				fmt.Fprintln(os.Stderr, "pairing request denied by operator")
				return apperr.ExitAuth
			default:
				fmt.Fprintf(os.Stderr, "unknown status %q\n", status)
				return apperr.ExitAuth
			}
		}
	}
}

// pollPairStatus calls the relay pair-status endpoint and returns
// (status, tenantID, shouldStop). shouldStop is true when the status
// is terminal (approved/expired/denied) or the request fails.
func pollPairStatus(client *http.Client, pollURL string) (status, tenantID string, stop bool) {
	resp, err := client.Get(pollURL)
	if err != nil {
		return "", "", false // transient network error; keep polling
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusNotFound {
		return "expired", "", true
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", false // server error; keep polling
	}
	var sr struct {
		Status   string `json:"status"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(b, &sr); err != nil {
		return "", "", false
	}
	switch sr.Status {
	case "approved":
		return "approved", sr.TenantID, true
	case "expired", "denied":
		return sr.Status, "", true
	default:
		return sr.Status, "", false
	}
}
