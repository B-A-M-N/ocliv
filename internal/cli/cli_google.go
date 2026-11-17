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
	if !json.Valid(raw) {
		fmt.Fprintf(os.Stderr, "google verify-domain: %q must contain valid JSON\n", tokenFile)
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
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if host == "" {
		fmt.Fprintln(os.Stderr, "usage: ocliv google check-domain --host HOST [--expected-file PATH]")
		return apperr.ExitCLIValidation
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
	if !json.Valid(body) {
		fmt.Fprintf(os.Stderr, "google check-domain: %s did not return valid JSON\n", u)
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
