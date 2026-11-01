// MCP route handlers (relay side): list, create, and delete the path
// routes bound to an owned lease. Called only from the signed
// agent-management adapter after agentLeaseAuth; every mutation here is
// a durable route operation, never a visitor-auth bypass.
package relay

import (
	"net/http"
	"time"

	"ocliv/internal/lease"
)

// serveMCPRouteList reports the lease's path routes (P1 `mcp doctor`).
// URLs are built from the relay's current external host: an empty host
// means route ingress is not configured, and listed IDs have no URL.
func (s *Server) serveMCPRouteList(w http.ResponseWriter, leaseID string) {
	rows, err := s.db.SQL().Query(
		`SELECT route_id, profile, created_at FROM mcp_routes WHERE lease_id=? ORDER BY created_at`, leaseID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type routeInfo struct {
		RouteID   string `json:"route_id"`
		Auth      string `json:"auth"`
		URL       string `json:"url"`
		CreatedAt string `json:"created_at"`
	}
	out := []routeInfo{}
	for rows.Next() {
		var id, profile, created string
		if err := rows.Scan(&id, &profile, &created); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		url := ""
		if s.mcpHost != "" {
			url = "https://" + s.mcpHost + "/r/" + id + "/mcp"
		}
		out = append(out, routeInfo{RouteID: id, Auth: profile, URL: url, CreatedAt: created})
	}
	writeJSON(w, http.StatusOK, map[string]any{"lease_id": leaseID, "routes": out})
}

// serveMCPRouteMutation creates (POST) or deletes (DELETE) one path
// route. Creation is idempotent per (lease, profile, host): republishing
// returns the same stable route ID instead of minting a second route.
func (s *Server) serveMCPRouteMutation(w http.ResponseWriter, r *http.Request, tenant, leaseID, rest string) {
	var hostname, mode, state string
	if err := s.db.SQL().QueryRow(`SELECT hostname, access_mode, status FROM leases WHERE id=?`,
		leaseID).Scan(&hostname, &mode, &state); err != nil {
		http.Error(w, "unknown lease", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodPost:
		profile, ok := parseIngressProfile(rest)
		if !ok {
			http.Error(w, "unknown ingress profile", http.StatusBadRequest)
			return
		}
		if s.mcpHost == "" {
			http.Error(w, "path-route ingress not configured on this relay", http.StatusConflict)
			return
		}
		if state != lease.StateActive {
			http.Error(w, "lease not active", http.StatusConflict)
			return
		}
		// Modes are born at allocation (P1 `mcp serve --auth`), never
		// flipped in place: changing policy under live streams would
		// either strand the agent (resume denies the mismatch) or
		// silently re-authorize existing streams. Start the tunnel
		// with the matching mode instead.
		targetMode := AccessModeMCPUpstreamOAuth
		if profile == IngressMCPAnonymousFixture {
			targetMode = AccessModeMCPAnonymousFixture
		}
		if mode != targetMode {
			http.Error(w, "lease mode "+mode+" does not support MCP routes; start the tunnel with the matching --auth mode", http.StatusConflict)
			return
		}
		// Idempotent publication (P1-4): the UNIQUE(lease_id,
		// external_host, profile) constraint makes concurrent creates
		// converge. The loser of the INSERT race re-reads the winner's
		// row; the second attempt also covers a delete racing create.
		// Test-only barrier (audit P1): a test may revoke the lease
		// here to land exactly in the check-to-insert window and prove
		// the atomic EXISTS predicate denies the mint. Nil in
		// production.
		if s.routeCreateHold != nil {
			s.routeCreateHold()
		}
		for attempt := 0; attempt < 2; attempt++ {
			var existing string
			err := s.db.SQL().QueryRow(
				`SELECT route_id FROM mcp_routes WHERE lease_id=? AND profile=? AND external_host=?`,
				leaseID, rest, s.mcpHost).Scan(&existing)
			if err == nil {
				s.db.Audit("agent", tenant, leaseID, "mcp-route", "ok", "republished existing route")
				writeJSON(w, http.StatusOK, map[string]string{
					"route_id": existing,
					"url":      "https://" + s.mcpHost + "/r/" + existing + "/mcp",
					"auth":     rest,
				})
				return
			}
			routeID, err := MintRouteID()
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			// The ACTIVE predicate is enforced atomically in the
			// INSERT itself: a close/revoke racing the pre-check
			// above must not mint a row for a dead lease (audit
			// P1). The EXISTS clause and the insert commit as one
			// statement; a post-revoke attempt inserts zero rows
			// and falls through to the status re-check below.
			_, err = s.db.SQL().Exec(
				`INSERT INTO mcp_routes(route_id, lease_id, external_host, profile, target_path, created_at)
				 SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM leases WHERE id=? AND status='ACTIVE')
				 ON CONFLICT(lease_id, external_host, profile) DO NOTHING`,
				routeID, leaseID, s.mcpHost, rest, "/mcp",
				time.Now().UTC().Format(time.RFC3339Nano), leaseID)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			var won string
			if err := s.db.SQL().QueryRow(
				`SELECT route_id FROM mcp_routes WHERE lease_id=? AND profile=? AND external_host=?`,
				leaseID, rest, s.mcpHost).Scan(&won); err == nil {
				s.db.Audit("agent", tenant, leaseID, "mcp-route", "ok", "route "+won+" bound")
				writeJSON(w, http.StatusOK, map[string]string{
					"route_id": won,
					"url":      "https://" + s.mcpHost + "/r/" + won + "/mcp",
					"auth":     rest,
				})
				return
			}
		}
		// No row won: either a transient race (retries exhausted) or
		// the lease died mid-create. Re-read status so a revoke/close
		// racing admission reports 409, not 500.
		var stNow string
		if err := s.db.SQL().QueryRow(`SELECT status FROM leases WHERE id=?`, leaseID).Scan(&stNow); err != nil || stNow != lease.StateActive {
			http.Error(w, "lease not active", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
	case http.MethodDelete:
		if !validRouteID(rest) {
			http.Error(w, "unknown route", http.StatusNotFound)
			return
		}
		res, err := s.db.SQL().Exec(`DELETE FROM mcp_routes WHERE route_id=? AND lease_id=?`, rest, leaseID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if n, _ := res.RowsAffected(); n != 1 {
			http.Error(w, "unknown route", http.StatusNotFound)
			return
		}
		s.db.Audit("agent", tenant, leaseID, "mcp-route-delete", "ok", "route "+rest+" removed")
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
