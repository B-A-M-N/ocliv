// Visitor access management: share, rotate, revoke.
package cli

import (
	"fmt"
	"net/http"
	"os"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
)

// cmdAccess wraps share/rotate/revoke for the current lease.
func cmdAccess(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv access share|rotate|revoke")
		return apperr.ExitCLIValidation
	}
	action := argv[0]
	if action != "share" && action != "rotate" && action != "revoke" {
		fmt.Fprintf(os.Stderr, "unknown access command %q\n", action)
		return apperr.ExitCLIValidation
	}
	k, keyID, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "not enrolled: run `ocliv login` first")
		return apperr.ExitAuth
	}
	_, _, cfgPath, _ := agentFiles()
	relayURL := config.DefaultRelayURL
	if vals, _ := config.LoadAgentFile(cfgPath); vals["relay_url"] != "" {
		relayURL = vals["relay_url"]
	}
	if v := config.EnvRelay(); v != "" {
		relayURL = v
	}
	dir, _, _, _ := agentFiles()
	leaseID := lastLeaseID(dir)
	if leaseID == "" {
		fmt.Fprintln(os.Stderr, "no active lease; start a tunnel first")
		return apperr.ExitCLIValidation
	}
	method := "POST"
	code, body := mgmtCall(relayURL, k, keyID, method, "/v1/agent/lease/"+leaseID+"/"+action)
	if code != http.StatusOK {
		fmt.Fprintf(os.Stderr, "access %s failed (relay status %d)\n", action, code)
		return apperr.ExitAuth
	}
	fmt.Println(string(body))
	return apperr.ExitOK
}
