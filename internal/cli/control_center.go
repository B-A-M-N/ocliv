package cli

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/B-A-M-N/ocliv/internal/apperr"
	"github.com/B-A-M-N/ocliv/internal/config"
	"github.com/B-A-M-N/ocliv/internal/identity"
)

//go:embed ui/index.html
var controlCenterHTML string

//go:embed ui/app.js
var controlCenterJS string

const (
	controlCenterSessionCookie  = "ocliv_cc_session"
	controlCenterMaxBodyBytes   = 64 * 1024
	controlCenterIdleTimeout    = 2 * time.Hour
	controlCenterMaxSessionLife = 8 * time.Hour
)

type controlCenterServer struct {
	mu               sync.Mutex
	addr             string // host:port bound strictly on 127.0.0.1
	port             int
	bootstrapToken   string
	bootstrapUsed    bool
	sessionToken     string
	sessionCreatedAt time.Time
	sessionLastSeen  time.Time
	sessionRevoked   bool
	csrfToken        string
	relayURL         string
	key              *identity.KeyPair
	keyID            string
	ops              serviceOps
	auditPath        string
}

func randomToken256() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func newControlCenterServer(addr, relayURL string, k *identity.KeyPair, keyID string, ops serviceOps) (*controlCenterServer, error) {
	boot, err := randomToken256()
	if err != nil {
		return nil, err
	}
	sess, err := randomToken256()
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken256()
	if err != nil {
		return nil, err
	}
	auditPath := ""
	if dir, _, _, derr := agentFiles(); derr == nil {
		auditPath = filepath.Join(dir, "control-center-audit.jsonl")
	}
	_, portStr, _ := net.SplitHostPort(addr)
	portNum, _ := strconv.Atoi(portStr)
	return &controlCenterServer{
		addr:           addr,
		port:           portNum,
		bootstrapToken: boot,
		sessionToken:   sess,
		csrfToken:      csrf,
		relayURL:       relayURL,
		key:            k,
		keyID:          keyID,
		ops:            ops,
		auditPath:      auditPath,
	}, nil
}

func (cc *controlCenterServer) audit(action, target, outcome string) error {
	if cc.auditPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(cc.auditPath), 0o700); err != nil {
		return fmt.Errorf("audit dir: %w", err)
	}
	f, err := os.OpenFile(cc.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("audit open: %w", err)
	}
	defer f.Close()
	line, _ := json.Marshal(map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339),
		"action":  action,
		"target":  target,
		"outcome": outcome,
	})
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit write: %w", err)
	}
	return nil
}

func (cc *controlCenterServer) setSecurityHeaders(w http.ResponseWriter) {
	// Strict CSP: zero 'unsafe-inline' in script-src (OCL-014.8).
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}

func (cc *controlCenterServer) validHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	_, port, _ := net.SplitHostPort(cc.addr)
	return h == "127.0.0.1:"+port || h == "localhost:"+port
}

func (cc *controlCenterServer) validOrigin(r *http.Request) bool {
	_, port, _ := net.SplitHostPort(cc.addr)
	allowed1 := "http://127.0.0.1:" + port
	allowed2 := "http://localhost:" + port
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		return origin == allowed1 || origin == allowed2
	}
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref != "" {
		return strings.HasPrefix(ref, allowed1+"/") || strings.HasPrefix(ref, allowed2+"/") || ref == allowed1 || ref == allowed2
	}
	return false
}

func (cc *controlCenterServer) hasValidSession(r *http.Request) bool {
	c, err := r.Cookie(controlCenterSessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(c.Value), []byte(cc.sessionToken)) != 1 {
		return false
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.sessionRevoked || cc.sessionCreatedAt.IsZero() {
		return false
	}
	now := time.Now()
	if now.Sub(cc.sessionCreatedAt) > controlCenterMaxSessionLife || now.Sub(cc.sessionLastSeen) > controlCenterIdleTimeout {
		cc.sessionRevoked = true
		return false
	}
	cc.sessionLastSeen = now
	return true
}

func (cc *controlCenterServer) hasValidCSRF(r *http.Request) bool {
	got := strings.TrimSpace(r.Header.Get("X-Ocliv-CSRF"))
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(cc.csrfToken)) == 1
}

func writeCCJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (cc *controlCenterServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cc.setSecurityHeaders(w)
	if !cc.validHost(r.Host) {
		writeCCJSON(w, http.StatusForbidden, map[string]string{"error": "invalid Host header"})
		return
	}

	// Single-use bootstrap login: trades ?token=... for an HttpOnly SameSite=Strict session cookie.
	if r.URL.Path == "/auth" && r.Method == http.MethodGet {
		tok := strings.TrimSpace(r.URL.Query().Get("token"))
		cc.mu.Lock()
		ok := !cc.bootstrapUsed && tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(cc.bootstrapToken)) == 1
		if ok {
			cc.bootstrapUsed = true
			now := time.Now()
			cc.sessionCreatedAt = now
			cc.sessionLastSeen = now
			cc.sessionRevoked = false
		}
		cc.mu.Unlock()
		if !ok {
			writeCCJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or already-used bootstrap token"})
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     controlCenterSessionCookie,
			Value:    cc.sessionToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		_ = cc.audit("session_bootstrap", "operator", "ok")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Authenticated embedded JS bundle (strict script-src 'self').
	if r.URL.Path == "/app.js" && r.Method == http.MethodGet {
		if !cc.hasValidSession(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write([]byte(controlCenterJS))
		return
	}

	// Authenticated HTML shell.
	if r.URL.Path == "/" && r.Method == http.MethodGet {
		if !cc.hasValidSession(r) {
			http.Error(w, "Ocliv Control Center requires an authenticated local operator session. Launch via `ocliv ui`.", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := strings.Replace(controlCenterHTML, "</head>", fmt.Sprintf(`<meta name="ocliv-csrf" content="%s"></head>`, cc.csrfToken), 1)
		_, _ = w.Write([]byte(html))
		return
	}

	// All /api/* endpoints require an authenticated operator session.
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if !cc.hasValidSession(r) {
		writeCCJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized session"})
		return
	}
	if r.Method != http.MethodGet {
		if !cc.validOrigin(r) {
			writeCCJSON(w, http.StatusForbidden, map[string]string{"error": "invalid Origin header"})
			return
		}
		if !cc.hasValidCSRF(r) {
			writeCCJSON(w, http.StatusForbidden, map[string]string{"error": "missing or invalid CSRF token"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, controlCenterMaxBodyBytes)
	}

	cc.handleAPI(w, r)
}

func (cc *controlCenterServer) handleAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	store, err := openServices()
	if err != nil {
		writeCCJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	switch {
	case path == "/api/auth/logout" && r.Method == http.MethodPost:
		cc.mu.Lock()
		cc.sessionRevoked = true
		cc.mu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     controlCenterSessionCookie,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		_ = cc.audit("session_logout", "operator", "ok")
		writeCCJSON(w, http.StatusOK, map[string]any{"ok": true})
		return

	case path == "/api/setup/update-check" && r.Method == http.MethodGet:
		bi := GetBuildInfo()
		msg := fmt.Sprintf("Installed: v%s (%s, schema V%d). Run `ocliv update --check` to verify signed releases from your relay.", bi.Version, bi.BuildCommit, bi.StoreSchemaVersion)
		writeCCJSON(w, http.StatusOK, map[string]any{"ok": true, "installed": bi, "message": msg})
		return

	case path == "/api/status" && r.Method == http.MethodGet:
		relayReachable := false
		if cc.key != nil {
			if _, _, perr := fetchRelayPublications(cc.relayURL, cc.key, cc.keyID, cc.ops); perr == nil {
				relayReachable = true
			}
		}
		writeCCJSON(w, http.StatusOK, map[string]any{
			"relay_url":       cc.relayURL,
			"key_id":          cc.keyID,
			"enrolled":        cc.key != nil,
			"relay_reachable": relayReachable,
			"version":         buildVersionInfo(),
		})
		return

	case path == "/api/services" && r.Method == http.MethodGet:
		svcs, err := store.List()
		if err != nil {
			writeCCJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out := make([]map[string]any, 0, len(svcs))
		for _, rec := range svcs {
			rk, rKeyID := cc.key, cc.keyID
			if rec.Profile != "" && rec.Profile != config.ActiveProfile() {
				if pk, pkID, kerr := loadKeyForProfile(rec.Profile); kerr == nil {
					rk, rKeyID = pk, pkID
				}
			}
			rep := inspectServiceStatus(rec, rk, rKeyID, cc.ops)
			out = append(out, safeStatusReport(rep))
		}
		writeCCJSON(w, http.StatusOK, map[string]any{"services": out})
		return

	case path == "/api/services" && r.Method == http.MethodPost:
		var body struct {
			Name           string `json:"name"`
			Port           int    `json:"port"`
			Path           string `json:"path"`
			Type           string `json:"type"`
			Authentication string `json:"authentication"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if err := validateMCPServiceName(body.Name); err != nil {
			writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if body.Port < 1 || body.Port > 65535 {
			writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": "port must be 1..65535"})
			return
		}
		if cc.port > 0 && body.Port == cc.port {
			writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": "refusing to publish the local Ocliv Control Center port"})
			return
		}
		if body.Type == "" {
			body.Type = "mcp"
		}
		if body.Path == "" {
			body.Path = "/mcp"
		}
		if body.Authentication == "" {
			body.Authentication = "ocliv-managed"
		}
		_, _, _, regErr := registerHostedService(serviceAddRequest{
			Name:        body.Name,
			Type:        body.Type,
			LocalURL:    fmt.Sprintf("http://127.0.0.1:%d%s", body.Port, body.Path),
			Auth:        body.Authentication,
			Profile:     config.ActiveProfile(),
			BackendMode: config.BackendAttached,
		}, cc.ops)
		if regErr != nil {
			cc.audit("service_add", body.Name, "error")
			writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": regErr.Error()})
			return
		}
		out, _, startErr := startHostedService(serviceStartRequest{Name: body.Name}, cc.ops)
		confirmed := startErr == nil && out.Status.State == ServiceStateServing && out.Status.Health == HealthReady
		cc.audit("service_add", body.Name, fmt.Sprintf("confirmed=%v", confirmed))
		writeCCJSON(w, http.StatusOK, map[string]any{
			"confirmed":      confirmed,
			"status":         out.Status.State,
			"public_url":     out.Status.PublicURL,
			"publication_id": out.Status.PublicationID,
			"detail":         sanitizeMCPError(startErr),
		})
		return

	case path == "/api/agents/permissions" && r.Method == http.MethodGet:
		pol, err := loadAgentPermissionsPolicy()
		if err != nil {
			writeCCJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeCCJSON(w, http.StatusOK, pol)
		return

	case path == "/api/agents/permissions" && r.Method == http.MethodPut:
		var env struct {
			ExpectedRevision *int64                  `json:"expected_revision"`
			Policy           *AgentPermissionsPolicy `json:"policy"`
		}
		rawBytes := make([]byte, 0, 1024)
		var direct AgentPermissionsPolicy
		dec := json.NewDecoder(r.Body)
		var rawDoc json.RawMessage
		if err := dec.Decode(&rawDoc); err != nil {
			writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid permissions payload"})
			return
		}
		_ = rawBytes
		expRev := int64(-1)
		if json.Unmarshal(rawDoc, &env) == nil && env.Policy != nil {
			direct = *env.Policy
			if env.ExpectedRevision != nil {
				expRev = *env.ExpectedRevision
			}
		} else if err := json.Unmarshal(rawDoc, &direct); err != nil {
			writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid permissions payload"})
			return
		}
		if aerr := cc.audit("permissions_save", "agent-permissions.json", "attempt"); aerr != nil {
			writeCCJSON(w, http.StatusInternalServerError, map[string]string{"error": "audit log write failed: " + aerr.Error()})
			return
		}
		saved, serr := saveAgentPermissionsPolicyCAS(direct, expRev)
		if errors.Is(serr, ErrPolicyConflict) {
			writeCCJSON(w, http.StatusConflict, map[string]string{"error": serr.Error()})
			return
		}
		if serr != nil {
			writeCCJSON(w, http.StatusInternalServerError, map[string]string{"error": serr.Error()})
			return
		}
		writeCCJSON(w, http.StatusOK, map[string]any{"ok": true, "policy": saved})
		return

	case path == "/api/agents/requests" && r.Method == http.MethodGet:
		reqs, err := listOperatorApprovalRequests()
		if err != nil {
			writeCCJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeCCJSON(w, http.StatusOK, map[string]any{"requests": reqs})
		return

	case strings.HasPrefix(path, "/api/agents/requests/") && strings.HasSuffix(path, "/decide") && r.Method == http.MethodPost:
		reqID := strings.TrimSuffix(strings.TrimPrefix(path, "/api/agents/requests/"), "/decide")
		var body struct {
			Decision string `json:"decision"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		updated, err := decideOperatorApprovalRequest(reqID, body.Decision)
		if err != nil {
			writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		cc.audit("approval_request_"+body.Decision, reqID, updated.Status)
		writeCCJSON(w, http.StatusOK, map[string]any{"ok": true, "request": updated})
		return

	case path == "/api/setup/install-shortcut" && r.Method == http.MethodPost:
		dest, err := installDesktopShortcut()
		if err != nil {
			writeCCJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		cc.audit("install_shortcut", dest, "ok")
		writeCCJSON(w, http.StatusOK, map[string]any{"ok": true, "path": dest})
		return
	}

	// Per-service operator routes: /api/services/{name}/{action}
	if strings.HasPrefix(path, "/api/services/") {
		rest := strings.TrimPrefix(path, "/api/services/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		svcName, action := parts[0], parts[1]
		if err := validateMCPServiceName(svcName); err != nil {
			writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		rec, ok, err := store.Get(svcName)
		if err != nil || !ok {
			writeCCJSON(w, http.StatusNotFound, map[string]string{"error": "unknown service"})
			return
		}
		rURL := rec.RelayURL
		if rURL == "" {
			rURL = cc.relayURL
		}
		switch {
		case action == "enable" && r.Method == http.MethodPost:
			out, _, serr := startHostedService(serviceStartRequest{Name: rec.Name}, cc.ops)
			confirmed := serr == nil && out.Status.State == ServiceStateServing && out.Status.Health == HealthReady
			cc.audit("service_enable", rec.Name, fmt.Sprintf("confirmed=%v", confirmed))
			writeCCJSON(w, http.StatusOK, map[string]any{"confirmed": confirmed, "status": out.Status.State, "public_url": out.Status.PublicURL, "detail": sanitizeMCPError(serr)})
			return

		case action == "disable" && r.Method == http.MethodPost:
			res := stopServiceAuthoritatively(store, rec, cc.key, cc.keyID, cc.ops)
			confirmed := res.Stopped && res.RemoteDisabled
			cc.audit("service_disable", rec.Name, fmt.Sprintf("confirmed=%v", confirmed))
			writeCCJSON(w, http.StatusOK, map[string]any{
				"confirmed":             confirmed,
				"status":                res.State,
				"public_access_blocked": res.RemoteDisabled,
				"url_retained":          res.RetainedURL != "",
				"detail":                res.Detail,
			})
			return

		case action == "reconcile" && r.Method == http.MethodPost:
			rep, rerr := reconcileServiceOnce(store, rec.Name, cc.key, cc.keyID, cc.ops, time.Now())
			confirmed := rerr == nil && rep.Health == HealthReady
			cc.audit("service_reconcile", rec.Name, fmt.Sprintf("confirmed=%v", confirmed))
			writeCCJSON(w, http.StatusOK, map[string]any{"confirmed": confirmed, "status": rep.State, "detail": sanitizeMCPError(rerr)})
			return

		case action == "remove" && r.Method == http.MethodPost:
			pubID, remErr := removeServiceAuthoritatively(store, rec, cc.key, cc.keyID, cc.ops)
			confirmed := remErr == nil
			cc.audit("service_remove", rec.Name, fmt.Sprintf("confirmed=%v", confirmed))
			writeCCJSON(w, http.StatusOK, map[string]any{"confirmed": confirmed, "publication_id": pubID, "detail": sanitizeMCPError(remErr)})
			return

		case action == "pending" && r.Method == http.MethodGet:
			pubID, _, found, rerr := resolveRelayPublication(rURL, cc.key, cc.keyID, rec, cc.ops)
			if rerr != nil || !found {
				writeCCJSON(w, http.StatusOK, map[string]any{"pending": []any{}, "pending_transactions": []any{}})
				return
			}
			st, body, cerr := cc.ops.mgmtCall(rURL, cc.key, cc.keyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/authz/pending")
			if cerr != nil || st != http.StatusOK {
				writeCCJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to query pending approvals"})
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write(body)
			return

		case action == "clients" && r.Method == http.MethodGet:
			pubID, _, found, rerr := resolveRelayPublication(rURL, cc.key, cc.keyID, rec, cc.ops)
			if rerr != nil || !found {
				writeCCJSON(w, http.StatusOK, map[string]any{"clients": []any{}, "detail": "No active publication found."})
				return
			}
			st, body, cerr := cc.ops.mgmtCall(rURL, cc.key, cc.keyID, http.MethodGet, "/v1/agent/mcp-routes/"+pubID+"/authz/clients")
			if cerr != nil || st != http.StatusOK {
				writeCCJSON(w, http.StatusOK, map[string]any{"clients": []any{}, "detail": fmt.Sprintf("Authoritative client inventory unavailable (relay HTTP %d).", st)})
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write(body)
			return

		case action == "decide-tx" && r.Method == http.MethodPost:
			var body struct {
				Challenge string `json:"challenge"`
				Decision  string `json:"decision"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
				return
			}
			if err := validateMCPSafeID(body.Challenge, "challenge"); err != nil || (body.Decision != "approve" && body.Decision != "deny") {
				writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid challenge or decision"})
				return
			}
			pubID, _, found, rerr := resolveRelayPublication(rURL, cc.key, cc.keyID, rec, cc.ops)
			if rerr != nil || !found {
				writeCCJSON(w, http.StatusNotFound, map[string]string{"error": "no publication found"})
				return
			}
			st, respBody, cerr := cc.ops.mgmtCall(rURL, cc.key, cc.keyID, http.MethodPost, "/v1/agent/mcp-routes/"+pubID+"/authz/consents/"+body.Challenge+"/"+body.Decision)
			if cerr != nil || (st != http.StatusOK && st != http.StatusCreated) {
				writeCCJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("relay returned HTTP %d", st)})
				return
			}
			cc.audit("visitor_tx_"+body.Decision, rec.Name, "ok")
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write(respBody)
			return

		case action == "revoke-client" && r.Method == http.MethodPost:
			var body struct {
				ClientID string `json:"client_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || validateMCPSafeID(body.ClientID, "client_id") != nil {
				writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid client_id"})
				return
			}
			pubID, _, found, rerr := resolveRelayPublication(rURL, cc.key, cc.keyID, rec, cc.ops)
			if rerr != nil || !found {
				writeCCJSON(w, http.StatusNotFound, map[string]string{"error": "no publication found"})
				return
			}
			st, _, cerr := cc.ops.mgmtCall(rURL, cc.key, cc.keyID, http.MethodPost, "/v1/agent/mcp-routes/"+pubID+"/authz/revoke/"+body.ClientID)
			if cerr != nil || st != http.StatusOK {
				writeCCJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("revoke failed (HTTP %d)", st)})
				return
			}
			cc.audit("revoke_client", rec.Name+"/"+body.ClientID, "ok")
			writeCCJSON(w, http.StatusOK, map[string]any{"ok": true, "confirmed": true})
			return

		case action == "trust" && r.Method == http.MethodPost:
			var body struct {
				Preset      string `json:"preset"`
				RedirectURI string `json:"redirect_uri"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
				return
			}
			pubID, _, found, rerr := resolveRelayPublication(rURL, cc.key, cc.keyID, rec, cc.ops)
			if rerr != nil || !found {
				writeCCJSON(w, http.StatusNotFound, map[string]string{"error": "no publication found"})
				return
			}
			var redirects []string
			if body.RedirectURI != "" {
				redirects = []string{body.RedirectURI}
			}
			polRes, status, _, perr := applyTrustPolicyToRoute(rURL, cc.key, cc.keyID, pubID, body.Preset, redirects, cc.ops)
			if perr != nil {
				writeCCJSON(w, http.StatusBadRequest, map[string]string{"error": perr.Error()})
				return
			}
			cc.audit("trust_policy_add", rec.Name, status)
			writeCCJSON(w, http.StatusOK, map[string]any{"ok": true, "status": status, "policy": polRes})
			return

		case action == "connect-google" && r.Method == http.MethodPost:
			// Operator-only confidential client provisioning for Gemini/Google.
			// Never exposed through agent-visible MCP tools (OCL-014.5).
			pubID, pubURL, found, rerr := resolveRelayPublication(rURL, cc.key, cc.keyID, rec, cc.ops)
			if rerr != nil || !found {
				writeCCJSON(w, http.StatusNotFound, map[string]string{"error": "no active publication found"})
				return
			}
			reqPayload, _ := json.Marshal(map[string]any{
				"name":          "Google (gemini)",
				"redirect_uris": []string{"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp"},
				"confidential":  true,
				"approve":       true,
			})
			st, respBody, cerr := cc.ops.callMgmtBody(rURL, cc.key, cc.keyID, http.MethodPost, "/v1/agent/mcp-routes/"+pubID+"/authz/register", reqPayload)
			if cerr != nil || (st != http.StatusOK && st != http.StatusCreated) {
				writeCCJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("relay registration failed (HTTP %d)", st)})
				return
			}
			var regResp struct {
				ClientID     string `json:"client_id"`
				ClientSecret string `json:"client_secret"`
			}
			_ = json.Unmarshal(respBody, &regResp)
			_ = cc.audit("connect_google", rec.Name, "ok")
			writeCCJSON(w, http.StatusOK, map[string]any{
				"ok":            true,
				"url":           pubURL,
				"client_id":     regResp.ClientID,
				"client_secret": regResp.ClientSecret,
				"detail":        "Save this one-time secret in Gemini now; it is never shown to MCP agents.",
			})
			return

		case action == "verify" && r.Method == http.MethodPost:
			rep := inspectServiceStatus(rec, cc.key, cc.keyID, cc.ops)
			entry, _ := resolveCatalogEntry(rec.Name, rec.Profile, cc.ops)
			endpointStage, oauthStage := "FAIL", "UNKNOWN"
			if entry.URL != "" {
				d := runReadOnlyDiscoveryCheck(&http.Client{Timeout: 8 * time.Second}, entry.URL)
				endpointStage, oauthStage = d.Transport, d.Discovery
			}
			authMCP, extAcc := "UNKNOWN", "UNKNOWN"
			if rep.PublicVerified {
				authMCP = "PASS"
			}
			if rep.VerificationEvidence != nil && rep.VerificationEvidence.Stage == "EXTERNAL_CLIENT_VERIFIED" {
				extAcc = "PASS"
			}
			writeCCJSON(w, http.StatusOK, map[string]any{
				"ok":         endpointStage == "PASS" && oauthStage == "PASS",
				"checked_at": time.Now().UTC().Format(time.RFC3339),
				"stages": map[string]string{
					"public_endpoint_reachable":    endpointStage,
					"oauth_discovery_compatible":   oauthStage,
					"authenticated_mcp_handshake":  authMCP,
					"events_advertised":            "UNKNOWN",
					"events_subscription_verified": "UNKNOWN",
					"callback_delivery_verified":   "UNKNOWN",
					"external_client_acceptance":   extAcc,
				},
			})
			return
		}
	}
	http.NotFound(w, r)
}

func installDesktopShortcut() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	exe, err := os.Executable()
	if err != nil {
		exe = "ocliv"
	}
	dir := filepath.Join(home, ".local", "share", "applications")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, "ocliv-control-center.desktop")
	content := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=Ocliv Control Center
GenericName=Local MCP & Tunnel Operator Interface
Comment=Manage Ocliv services, approve AI connections, and configure agent permissions
Exec=%s ui
Terminal=false
Categories=Network;Utility;Development;
StartupNotify=true
`, exe)
	if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
		return "", err
	}
	return dest, nil
}

func cmdUI(argv []string) int {
	port := 0
	noBrowser := false
	installShortcutOnly := false
	for i := 0; i < len(argv); i++ {
		switch {
		case argv[i] == "--help" || argv[i] == "-h":
			fmt.Println("usage: ocliv ui [--port PORT] [--no-browser] [--install-shortcut]")
			return apperr.ExitOK
		case argv[i] == "--no-browser":
			noBrowser = true
		case argv[i] == "--install-shortcut":
			installShortcutOnly = true
		case argv[i] == "--port" || strings.HasPrefix(argv[i], "--port="):
			v, ok := mcpFlagValue(argv, &i, "port")
			if !ok {
				return apperr.ExitCLIValidation
			}
			p, err := strconv.Atoi(v)
			if err != nil || p < 0 || p > 65535 {
				fmt.Fprintf(os.Stderr, "invalid --port %q\n", v)
				return apperr.ExitCLIValidation
			}
			port = p
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", argv[i])
			return apperr.ExitCLIValidation
		}
	}
	if installShortcutOnly {
		dest, err := installDesktopShortcut()
		if err != nil {
			fmt.Fprintf(os.Stderr, "install-shortcut failed: %v\n", err)
			return apperr.ExitInternal
		}
		fmt.Printf("Installed Ocliv Control Center desktop shortcut: %s\n", dest)
		return apperr.ExitOK
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ocliv ui: listen loopback failed: %v\n", err)
		return apperr.ExitInternal
	}
	defer ln.Close()

	k, keyID, _ := loadKey()
	relayURL := agentRelayURL()
	cc, err := newControlCenterServer(ln.Addr().String(), relayURL, k, keyID, defaultServiceOps())
	if err != nil {
		fmt.Fprintf(os.Stderr, "ocliv ui: %v\n", err)
		return apperr.ExitInternal
	}
	srv := &http.Server{
		Handler:           cc,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	launchURL := fmt.Sprintf("http://%s/auth?token=%s", ln.Addr().String(), cc.bootstrapToken)
	fmt.Printf("Ocliv Control Center listening on http://%s (loopback-only)\n", ln.Addr().String())
	if !noBrowser {
		_ = exec.Command("xdg-open", launchURL).Start()
	} else {
		fmt.Printf("Open in browser (single-use login link): %s\n", launchURL)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "ocliv ui: %v\n", err)
		return apperr.ExitInternal
	}
	return apperr.ExitOK
}
