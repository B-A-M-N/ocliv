// Tunnel teardown: lease closure, cleanup receipts, and exit mapping.
package cli

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"ocliv/internal/agent"
	"ocliv/internal/apperr"
	"ocliv/internal/config"
)

// CleanupResult records remote revocation outcomes independently: local
// shutdown and remote revocation are different results, and a failed
// remote close must never present as a clean exit (P1-8). Status -1
// means the operation was not attempted; 0 means the relay was
// unreachable (mgmtCall transport failure). Details are trimmed relay
// error strings, never secrets.
type CleanupResult struct {
	LeaseID, RouteID         string
	LeaseCloseStatus         int // -1 = not attempted
	RouteDeleteStatus        int // -1 = not attempted (no route registered)
	LeaseDetail, RouteDetail string
}

func (c CleanupResult) leaseConfirmed() bool { return c.LeaseCloseStatus == http.StatusOK }

func (c CleanupResult) routeConfirmed() bool {
	return c.RouteDeleteStatus == -1 || c.RouteDeleteStatus == http.StatusOK
}

// RemoteConfirmed reports whether every attempted remote revocation is
// confirmed. Unattempted operations do not fail the result.
func (c CleanupResult) RemoteConfirmed() bool { return c.leaseConfirmed() && c.routeConfirmed() }

// ExitCode maps the cleanup onto a process exit: a nonzero local code is
// preserved, and unconfirmed remote revocation is an explicit nonzero
// (ExitInternal) naming the affected IDs via Report.
func (c CleanupResult) ExitCode(base int) int {
	if base != apperr.ExitOK {
		return base
	}
	if !c.RemoteConfirmed() {
		return apperr.ExitInternal
	}
	return apperr.ExitOK
}

// shortDetail trims a relay error body for diagnostics.
func shortDetail(body string) string {
	s := strings.TrimSpace(body)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// Report renders warnings for unconfirmed operations; "" when confirmed.
// A route deletion that fails while the lease close is confirmed is
// contained by the closed lease; any other unconfirmed operation may
// leave access reachable until TTL expiry.
func (c CleanupResult) Report() string {
	var sb strings.Builder
	if c.LeaseCloseStatus != -1 {
		if msg := closeWarning(c.LeaseID, c.LeaseCloseStatus, []byte(c.LeaseDetail)); msg != "" {
			sb.WriteString(msg + "\n")
		}
	}
	if c.RouteDeleteStatus != -1 && c.RouteDeleteStatus != http.StatusOK {
		detail := c.RouteDetail
		if detail == "" {
			detail = "no response from relay"
		}
		if c.leaseConfirmed() {
			fmt.Fprintf(&sb, "warning: route %s delete reported status %d (%s); the closed lease denies it anyway\n",
				c.RouteID, c.RouteDeleteStatus, detail)
		} else {
			fmt.Fprintf(&sb, "warning: route %s delete reported status %d (%s); the route may still be reachable until TTL expiry\n",
				c.RouteID, c.RouteDeleteStatus, detail)
		}
	}
	return sb.String()
}

// leaseCloser performs the signed remote lease close; status 0 means the
// relay was unreachable. It is a parameter so tests can simulate relay
// timeout, denial, and already-deleted routes without a network.
type leaseCloser func(ready tunnelReady, leaseID string) (int, string)

func defaultLeaseCloser(ready tunnelReady, leaseID string) (int, string) {
	status, body := mgmtCall(ready.opts.cfg.RelayURL, ready.key, ready.keyID, "POST", "/v1/agent/lease/"+leaseID+"/close")
	return status, string(body)
}

// closeLeaseWith closes one lease remotely and drops the local resume
// hint only on confirmation, so a later run cannot resume a closed lease
// while an unconfirmed close keeps its record for TTL-bounded retry.
func closeLeaseWith(closer leaseCloser, ready tunnelReady, leaseID string) CleanupResult {
	res := CleanupResult{LeaseID: leaseID, RouteDeleteStatus: -1}
	status, body := closer(ready, leaseID)
	res.LeaseCloseStatus = status
	res.LeaseDetail = shortDetail(body)
	if res.leaseConfirmed() {
		if store, err := config.OpenLeaseStore(ready.dir); err == nil {
			_ = store.Remove(leaseID)
		}
	}
	return res
}

// closeTunnelWith deregisters the lease and invalidates access (F10),
// with independently recorded remote outcomes. The lease ID must come
// from the live attachment: falling back to the store's latest record
// could close another tunnel's lease in a shared data directory (P1-1).
// Without an exact ID no close is attempted and the exit is nonzero
// (remote state unconfirmed), never a silent zero.
func closeTunnelWith(closer leaseCloser, ready tunnelReady, a agent.Attached, exitCode int) int {
	leaseID := a.LeaseID
	if leaseID == "" {
		fmt.Fprintln(os.Stderr, "warning: no live attachment lease ID; remote lease state unconfirmed (no close attempted)")
		if exitCode != apperr.ExitOK {
			return exitCode
		}
		return apperr.ExitInternal
	}
	res := closeLeaseWith(closer, ready, leaseID)
	if msg := res.Report(); msg != "" {
		fmt.Fprint(os.Stderr, msg)
	}
	return res.ExitCode(exitCode)
}

// closeTunnel deregisters the lease and invalidates access (F10). A failed
// close is reported with the lease ID — access may linger until TTL expiry
// — while the completed local shutdown keeps its own exit code.
func closeTunnel(ready tunnelReady, a agent.Attached, exitCode int) int {
	return closeTunnelWith(defaultLeaseCloser, ready, a, exitCode)
}

// closeWarning describes a failed lease close for the operator. Empty
// means the close succeeded.
func closeWarning(leaseID string, status int, body []byte) string {
	if status == http.StatusOK {
		return ""
	}
	detail := strings.TrimSpace(string(body))
	if detail == "" {
		detail = "no response from relay"
	}
	return fmt.Sprintf("warning: lease %s close reported status %d (%s); access may linger until TTL expiry",
		leaseID, status, detail)
}

// writeShareLinkFile delivers the share capability to an explicitly
// requested file with owner-only permissions (A07). Empty path or empty
// share URL is a no-op. Callers enforce --no-share-link above.
func writeShareLinkFile(path string, a agent.Attached) error {
	if path == "" || a.ShareURL == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("share-link file dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".share-*")
	if err != nil {
		return fmt.Errorf("share-link file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(a.ShareURL + "\n"); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("share-link file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("share-link file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("share-link file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("share-link file: %w", err)
	}
	return nil
}

// lastLeaseID is the informational latest-recorded-lease lookup. It
// must never select the target of a destructive shutdown (P1-1); only
// the live attachment ID may do that.
func lastLeaseID(dir string) string {
	store, err := config.OpenLeaseStore(dir)
	if err != nil {
		return ""
	}
	rec, ok := store.Latest()
	if !ok {
		return ""
	}
	return rec.LeaseID
}

// mgmtCall performs a signed agent management request. Mutations carry a
// one-time nonce the relay consumes; without a fresh nonce the relay
// rejects the call as a potential replay (P1-07).
