package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ocliv/internal/apperr"
)

// ValidateGoogleVerificationDocument parses and validates a Google Connected
// Apps domain verification JSON document (requiring a non-empty
// verification_tokens array with unique non-empty entries and optional exact
// token match).
func ValidateGoogleVerificationDocument(raw []byte, expectedToken string) error {
	if len(raw) == 0 || len(raw) > 32*1024 {
		return fmt.Errorf("verification document size (%d bytes) out of bounds (1..32768)", len(raw))
	}
	var doc struct {
		VerificationTokens []string `json:"verification_tokens"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("invalid Google verification JSON schema: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("unexpected trailing data after Google verification JSON document")
	}
	if len(doc.VerificationTokens) == 0 {
		return fmt.Errorf("verification_tokens must contain at least one token")
	}
	seen := make(map[string]bool, len(doc.VerificationTokens))
	matched := expectedToken == ""
	for _, tok := range doc.VerificationTokens {
		if strings.TrimSpace(tok) == "" || tok != strings.TrimSpace(tok) {
			return fmt.Errorf("verification_tokens contains an empty or whitespace-padded token")
		}
		if seen[tok] {
			return fmt.Errorf("verification_tokens contains duplicate token %q", tok)
		}
		seen[tok] = true
		if expectedToken != "" && tok == expectedToken {
			matched = true
		}
	}
	if !matched {
		return fmt.Errorf("expected verification token not found in verification_tokens")
	}
	return nil
}

func cmdGoogle(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv google verify-domain|check-domain ...")
		return apperr.ExitCLIValidation
	}
	switch argv[0] {
	case "verify-domain":
		return cmdGoogleVerifyDomain(argv[1:])
	case "check-domain":
		return cmdGoogleCheckDomain(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown google command %q\n", argv[0])
		return apperr.ExitCLIValidation
	}
}

func cmdGoogleVerifyDomain(argv []string) int {
	tokenFile := ""
	outPath := "/etc/ocliv/google-connected-apps.json"
	for i := 0; i < len(argv); i++ {
		switch {
		case argv[i] == "--token-file" || strings.HasPrefix(argv[i], "--token-file="):
			v, ok := mcpFlagValue(argv, &i, "token-file")
			if !ok {
				return apperr.ExitCLIValidation
			}
			tokenFile = v
		case argv[i] == "--out" || strings.HasPrefix(argv[i], "--out="):
			v, ok := mcpFlagValue(argv, &i, "out")
			if !ok {
				return apperr.ExitCLIValidation
			}
			outPath = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if tokenFile == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv google verify-domain --token-file PATH [--out PATH]")
		return apperr.ExitCLIValidation
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "google verify-domain: read %q: %v\n", tokenFile, err)
		return apperr.ExitCLIValidation
	}
	if err := ValidateGoogleVerificationDocument(raw, ""); err != nil {
		fmt.Fprintf(os.Stderr, "google verify-domain: %q: %v\n", tokenFile, err)
		return apperr.ExitCLIValidation
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "google verify-domain: %v\n", err)
		return apperr.ExitInternal
	}
	if err := writeAtomic0600(outPath, string(raw)); err != nil {
		fmt.Fprintf(os.Stderr, "google verify-domain: write %q: %v\n", outPath, err)
		return apperr.ExitInternal
	}
	fmt.Printf("Installed Google Connected Apps verification JSON at %s\n", outPath)
	fmt.Printf("Set OCLIV_GOOGLE_VERIFICATION_FILE=%s in /etc/ocliv/relay.env and restart ocliv-relay.\n", outPath)
	return apperr.ExitOK
}

func cmdGoogleCheckDomain(argv []string) int {
	return cmdGoogleCheckDomainWithClient(argv, &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	})
}

func cmdGoogleCheckDomainWithClient(argv []string, hc *http.Client) int {
	host := ""
	expectedFile := ""
	expectedTokenFile := ""
	for i := 0; i < len(argv); i++ {
		switch {
		case argv[i] == "--host" || strings.HasPrefix(argv[i], "--host="):
			v, ok := mcpFlagValue(argv, &i, "host")
			if !ok {
				return apperr.ExitCLIValidation
			}
			host = v
		case argv[i] == "--expected-file" || strings.HasPrefix(argv[i], "--expected-file="):
			v, ok := mcpFlagValue(argv, &i, "expected-file")
			if !ok {
				return apperr.ExitCLIValidation
			}
			expectedFile = v
		case argv[i] == "--verification-token-file" || strings.HasPrefix(argv[i], "--verification-token-file="):
			v, ok := mcpFlagValue(argv, &i, "verification-token-file")
			if !ok {
				return apperr.ExitCLIValidation
			}
			expectedTokenFile = v
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if host == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv google check-domain --host HOST [--expected-file PATH] [--verification-token-file PATH]")
		return apperr.ExitCLIValidation
	}
	expectedToken := ""
	if expectedTokenFile != "" {
		tokBytes, terr := os.ReadFile(expectedTokenFile)
		if terr != nil {
			fmt.Fprintf(os.Stderr, "google check-domain: read %q: %v\n", expectedTokenFile, terr)
			return apperr.ExitCLIValidation
		}
		expectedToken = strings.TrimSpace(string(tokBytes))
		if expectedToken == "" {
			fmt.Fprintf(os.Stderr, "google check-domain: %q is empty\n", expectedTokenFile)
			return apperr.ExitCLIValidation
		}
	}
	normHost, err := parseHostname(host, "--host")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return apperr.ExitCLIValidation
	}
	u := "https://" + normHost + "/.well-known/google-connected-apps"
	resp, err := hc.Get(u)
	if err != nil {
		fmt.Fprintf(os.Stderr, "google check-domain: GET %s failed: %v\n", u, err)
		return apperr.ExitRelayTLS
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "google check-domain: GET %s returned HTTP %d (want 200 without redirect)\n", u, resp.StatusCode)
		return apperr.ExitRelayTLS
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.Contains(strings.ToLower(ct), "application/json") {
		fmt.Fprintf(os.Stderr, "google check-domain: %s returned Content-Type %q (want application/json)\n", u, ct)
		return apperr.ExitRelayTLS
	}
	if err := ValidateGoogleVerificationDocument(body, expectedToken); err != nil {
		fmt.Fprintf(os.Stderr, "google check-domain: %s invalid verification document: %v\n", u, err)
		return apperr.ExitRelayTLS
	}
	if expectedFile != "" {
		exp, rerr := os.ReadFile(expectedFile)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "google check-domain: read %q: %v\n", expectedFile, rerr)
			return apperr.ExitCLIValidation
		}
		if !bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(exp)) {
			fmt.Fprintf(os.Stderr, "google check-domain: response body mismatch against %s\n", expectedFile)
			return apperr.ExitRelayTLS
		}
	}
	fmt.Printf("PASS: %s returned HTTP 200 JSON (no redirect)\n", u)
	return apperr.ExitOK
}
