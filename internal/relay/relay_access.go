// Visitor authentication and credential issuance (relay side).
//
// Unlock: GET /_ocliv/unlock serves a strict-CSP page; JS reads the token
// from the URI fragment (never sent in the HTTP request) and POSTs it to
// /_ocliv/redeem, which issues the host-only session cookie (C05). A
// non-JS access-code form is also accepted.
//
// This layer mints and redeems visitor credentials, but never forwards
// them: share URLs and raw tokens travel only to the authenticated agent
// (over its session) or to the redeemer as a cookie (C05, C07).
package relay

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ocliv/internal/access"
	"ocliv/internal/lease"
	"ocliv/internal/metrics"
)

// visitorAccess owns the relay's visitor-credential secret: the HMAC key
// binding session-cookie IDs to their stored verifiers. No other layer
// touches the key; issuance (handleRedeem) and validation (relay_public.go)
// both go through verifier(). The key is random per relay instance unless
// supplied via Options, so restarts invalidate existing cookies by design.
type visitorAccess struct {
	key []byte
}

func newVisitorAccess(key []byte) visitorAccess {
	return visitorAccess{key: key}
}

// verifier binds a session-cookie ID to its stored row verifier.
func (v visitorAccess) verifier(sessID string) string {
	return access.SessionVerifier(sessID, v.key)
}

// unlockPage is served with strict CSP, no external resources, no analytics,
// and no-store (C05).
const unlockPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'">
<meta name="referrer" content="no-referrer">
<title>Ocliv protected tunnel</title>
<style>body{font-family:system-ui,sans-serif;max-width:42em;margin:4em auto;padding:0 1em}</style>
</head><body>
<h1>Ocliv protected tunnel</h1>
<p id="msg">This tunnel is protected. Opening with a valid share link…</p>
<form id="codeform" method="post" action="/_ocliv/redeem">
<label>Access code: <input name="code" type="text" autocomplete="off"></label>
<button type="submit">Unlock</button>
</form>
<script>
(function(){
  var m = location.hash.match(/#t=([^&]+)/);
  if (m) {
    fetch('/_ocliv/redeem', {method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({token: decodeURIComponent(m[1])}),
      credentials:'same-origin'}).then(function(r){
      if (r.ok) { history.replaceState(null,'','/'); location.href='/'; }
      else { document.getElementById('msg').textContent='Invalid or expired share link.'; }
    });
    history.replaceState(null,' ','/');
  }
})();
</script>
</body></html>`

// handleUnlockPage serves the relay-owned unlock page. Reserved /_ocliv/
// URLs are never forwarded to the tenant app (C11).
func (s *Server) handleUnlockPage(w http.ResponseWriter, r *http.Request) {
	if !s.checkPreAuth(w, r, "unlock") {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = io.WriteString(w, unlockPage)
}

// redeemReq carries the fragment token via same-origin POST body.
type redeemReq struct {
	Token string `json:"token"`
	Code  string `json:"code"` // non-JS form field alternative
}

// handleRedeem converts an expiring capability into a host-only Secure
// HttpOnly SameSite=Lax session cookie (C05). Single-redeem tokens are
// consumed atomically.
func (s *Server) handleRedeem(w http.ResponseWriter, r *http.Request) {
	if !s.checkPreAuth(w, r, "redeem") {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// CSRF: the redeem endpoint sets auth state; require same-origin POST.
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" || origin != tunnelOrigin(r) {
		// Allow the non-JS same-origin form (no Origin on some POSTs is
		// treated as hostile here); form posts carry Origin in browsers.
		http.Error(w, "cross-origin redeem rejected", http.StatusForbidden)
		return
	}
	var presented string
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var req redeemReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		presented = strings.TrimSpace(req.Token)
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		presented = strings.TrimSpace(r.FormValue("code"))
	}
	if presented == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	leaseID, tokenGen, ok := s.consumeShareToken(r.Host, presented)
	if !ok {
		metrics.Global.VisitorAuthFails.Add(1)
		s.db.Audit("visitor", "", "", "redeem", "denied", "bad token")
		http.Error(w, "invalid or expired share link", http.StatusUnauthorized)
		return
	}
	sessID, err := access.MintSessionID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// P0-4: the bearer (sessID) is issued only to the browser cookie and
	// never stored. The row id is an independent non-secret identifier;
	// lookup stays keyed on the HMAC verifier (checkCookieSession).
	rowID, err := access.MintRowID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	verifier := s.visitors.verifier(sessID)
	_, err = s.db.SQL().Exec(
		`INSERT INTO visitor_sessions(id, lease_id, token_generation, session_verifier, created_at, idle_expires_at, absolute_expires_at)
		 VALUES(?,?,?,?,?,?,?)`,
		rowID, leaseID, tokenGen, verifier,
		now.Format(time.RFC3339Nano),
		now.Add(access.CookieIdleTTL).Format(time.RFC3339Nano),
		now.Add(access.CookieAbsTTL).Format(time.RFC3339Nano))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.db.Audit("visitor", "", leaseID, "redeem", "ok", "session issued")
	access.SetSessionCookie(w, sessID)
	if strings.Contains(ct, "application/json") {
		writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// consumeShareToken atomically redeems a share token for the exact lease
// bound to the request Host (one-use tokens cannot be redeemed twice, C07).
func (s *Server) consumeShareToken(hostport, presented string) (leaseID string, tokenGen int64, ok bool) {
	label, good := lease.SplitHost(hostport, s.namespace)
	if !good {
		return "", 0, false
	}
	var leaseRowID string
	var tg int64
	err := s.db.SQL().QueryRow(
		`SELECT id, token_generation FROM leases WHERE hostname=? AND status=?`,
		label+"."+s.namespace, lease.StateActive).Scan(&leaseRowID, &tg)
	if err != nil {
		return "", 0, false
	}
	ph := sha256.Sum256([]byte(presented))
	sum := hex.EncodeToString(ph[:])
	now := time.Now().UTC()
	var tokID, verifier string
	var exp sql.NullString
	var maxUses, uses int
	err = withTx(s.db.SQL(), func(tx *sql.Tx) error {
		row := tx.QueryRow(`SELECT id, verifier, expires_at, max_uses, uses FROM access_tokens
			WHERE lease_id=? AND verifier=? AND revoked_at IS NULL`, leaseRowID, sum)
		if err := row.Scan(&tokID, &verifier, &exp, &maxUses, &uses); err != nil {
			return err
		}
		if exp.Valid {
			if et, err := time.Parse(time.RFC3339Nano, exp.String); err != nil || now.After(et) {
				return fmt.Errorf("expired")
			}
		}
		if maxUses > 0 && uses >= maxUses {
			return fmt.Errorf("consumed")
		}
		_, err := tx.Exec(`UPDATE access_tokens SET uses=uses+1 WHERE id=?`, tokID)
		return err
	})
	if err != nil {
		return "", 0, false
	}
	return leaseRowID, tg, true
}

// tokenRow holds the durable fields of a minted visitor token. The raw
// secret is returned to the caller and never persisted.
type tokenRow struct {
	id       string
	verifier string
	created  string
	expires  any
}

// execer abstracts *sql.DB and *sql.Tx so a token row can be inserted
// inside a caller's transaction or standalone.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// prepareAccessToken mints the token secret without any database side
// effect, so rotation and lease allocation can fail before mutating state
// and can insert the verifier inside the same transaction as the other
// durable effects.
func prepareAccessToken(scope string, maxUses int, ttl time.Duration) (string, tokenRow, error) {
	tok, err := access.Mint(scope)
	if err != nil {
		return "", tokenRow{}, err
	}
	now := time.Now().UTC()
	var exp any
	if ttl > 0 {
		exp = now.Add(ttl).Format(time.RFC3339Nano)
	}
	return tok.Raw, tokenRow{
		id:       fmt.Sprintf("tok-%d", now.UnixNano()),
		verifier: tok.Verifier,
		created:  now.Format(time.RFC3339Nano),
		expires:  exp,
	}, nil
}

// insertAccessTokenRow persists a prepared token verifier through q. When
// q is a *sql.Tx owned by a broader mutation, the token commits atomically
// with it; a commit failure leaves no orphaned or tokenless state behind.
func insertAccessTokenRow(q execer, leaseID, scope string, maxUses int, row tokenRow) error {
	_, err := q.Exec(
		`INSERT INTO access_tokens(id, lease_id, verifier, scope, created_at, expires_at, max_uses) VALUES(?,?,?,?,?,?,?)`,
		row.id, leaseID, row.verifier, scope, row.created, row.expires, maxUses)
	if err != nil {
		return storeErr("storing access token", err)
	}
	return nil
}

// newAccessToken mints a scoped visitor token row; the raw secret is
// returned once to the agent over the authenticated session.
func (s *Server) newAccessToken(leaseID, scope string, maxUses int, ttl time.Duration) (string, error) {
	raw, row, err := prepareAccessToken(scope, maxUses, ttl)
	if err != nil {
		return "", err
	}
	if err := insertAccessTokenRow(s.db.SQL(), leaseID, scope, maxUses, row); err != nil {
		return "", err
	}
	return raw, nil
}

// newAccessTokenTx mints a scoped visitor token row inside tx. The caller
// must commit tx before disclosing raw; on any commit failure the caller
// reports failure and no partial credential state survives.
func (s *Server) newAccessTokenTx(tx *sql.Tx, leaseID, scope string, maxUses int, ttl time.Duration) (string, error) {
	raw, row, err := prepareAccessToken(scope, maxUses, ttl)
	if err != nil {
		return "", err
	}
	if err := insertAccessTokenRow(tx, leaseID, scope, maxUses, row); err != nil {
		return "", err
	}
	return raw, nil
}
