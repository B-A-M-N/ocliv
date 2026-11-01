// Shared relay helpers: transactions, redacted errors, loopback checks.
package relay

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"ocliv/internal/apperr"
	"ocliv/internal/metrics"
)

// withTx runs fn in a serializable transaction.
func withTx(db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return apperr.E(apperr.CodeStoreFault, "starting transaction", err)
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return apperr.E(apperr.CodeStoreFault, "committing transaction", err)
	}
	return nil
}

// asApperr unwraps a typed error.
func asApperr(err error, target **apperr.Error) bool {
	return errors.As(err, target)
}

// storeErr wraps a persistence failure (fail closed, F12).
func storeErr(msg string, err error) error {
	return apperr.E(apperr.CodeStoreFault, msg, err)
}

// errShort renders an error without secrets for logs.
func errShort(err error) string {
	var ae *apperr.Error
	if errors.As(err, &ae) {
		return string(ae.Code) + ": " + ae.Msg
	}
	return "internal error"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// isLoopback reports whether the remote address is loopback.
func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// remoteIP extracts the client IP for rate-limit keys (never logged raw).
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// clientIP is the rate-limit and audit identity for a visitor. The TLS
// edge strips inbound X-Forwarded-* and asserts the real client IP, so
// a loopback peer means the request came through the edge: the
// rightmost forwarded entry is the client (correct whether the edge
// sets or appends). A non-loopback peer means the edge was bypassed,
// so forwarded headers are ignored and the direct peer is used (P1-06).
// Unparseable values fall back to the direct peer.
func clientIP(r *http.Request) string {
	peer := remoteIP(r)
	if ip := net.ParseIP(peer); ip == nil || !isLoopbackIP(ip.String()) {
		return peer
	}
	fwd := r.Header.Get("X-Forwarded-For")
	if fwd == "" {
		return peer
	}
	parts := strings.Split(fwd, ",")
	candidate := strings.TrimSpace(parts[len(parts)-1])
	if net.ParseIP(candidate) == nil {
		return peer
	}
	return candidate
}

// isLoopbackIP reports whether host is a loopback IP literal.
func isLoopbackIP(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkPreAuth caps pre-authentication endpoints per client IP so
// challenge/enroll/unlock/redeem cannot be flooded or guessed at line
// rate (G07). Denials are 429 with an audit row, never silent drops.
func (s *Server) checkPreAuth(w http.ResponseWriter, r *http.Request, op string) bool {
	if s.preAuth.Allow("pre:" + clientIP(r)) {
		return true
	}
	s.db.Audit("agent", "", "", op, "denied", "pre-auth rate limit")
	metrics.Global.PreAuthRejects.Add(1)
	http.Error(w, "too many requests", http.StatusTooManyRequests)
	return false
}

// publicScheme derives https behind the TLS edge; direct test ingress is http.
// X-Forwarded-Proto is honored only from the trusted edge: direct TLS is
// authoritative, and loopback plaintext is assumed to be the local Caddy
// hop. A remote plaintext sender must never upgrade itself to https, or
// CSRF origin checks and the forwarded proto would be spoofable (D08).
// Deployments must configure Caddy to overwrite (not append) this header.
func publicScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if isLoopback(r.RemoteAddr) {
		if v := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); v == "https" {
			return "https"
		}
	}
	return "http"
}

// tunnelOrigin builds the exact public origin for CSRF checks (C08, C09).
func tunnelOrigin(r *http.Request) string {
	return publicScheme(r) + "://" + strings.ToLower(r.Host)
}
