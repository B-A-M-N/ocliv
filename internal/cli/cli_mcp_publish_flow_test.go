package cli

// End-to-end publish lifecycle tests (god-object item 1 acceptance).
// These drive runMCPPublish against an in-process relay and assert the
// cleanup contract behaviorally: registration failure propagates
// closeTunnel's adjusted exit with the lease closed (not abandoned), and
// a full publish removes its route and closes its lease on shutdown.
// The three post-attachment error paths return closeTunnel's value
// directly, so a future refactor that discards the receipt fails these.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
	"ocliv/internal/relay"
	"ocliv/internal/store"
)

func publishFlowRelay(t *testing.T, mcpHost string) (*store.DB, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ocliv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv, err := relay.New(relay.Options{
		DB: db, Namespace: "t.example.test",
		// The CLI runner presents the dial address as Host (no
		// Caddy in tests), so the relay authority is the loopback
		// address itself; canonicalHost strips the port.
		RelayHost: "127.0.0.1", MCPExternalHost: mcpHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	return db, "http://" + ln.Addr().String()
}

func publishFlowKey(t *testing.T, home, relayURL string, db *store.DB) (*identity.KeyPair, string, error) {
	t.Helper()
	t.Setenv("HOME", home)
	dir, err := config.DataDir()
	if err != nil {
		return nil, "", err
	}
	k, err := identity.Generate()
	if err != nil {
		return nil, "", err
	}
	if err := k.Save(filepath.Join(dir, config.AgentKeyFile)); err != nil {
		return nil, "", err
	}
	code, err := relay.IssueEnrollmentCode(db, "tenant-test", time.Hour, "test")
	if err != nil {
		return nil, "", err
	}
	body, _ := json.Marshal(map[string]string{
		"code":       code,
		"public_key": base64.StdEncoding.EncodeToString(k.Public()),
	})
	req, err := http.NewRequest("POST", relayURL+"/v1/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("enroll status %d", resp.StatusCode)
	}
	keyID := "key-" + string(k.ID())
	return k, keyID, nil
}

func publishFlowEnroll(t *testing.T, home, relayURL string, db *store.DB) {
	t.Helper()
	if _, _, err := publishFlowKey(t, home, relayURL, db); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCLIV_RELAY_URL", relayURL)
}

// flowLeaseID returns the lease ID recorded for a hostname.
func flowLeaseID(t *testing.T, db *store.DB, hostname string) string {
	t.Helper()
	var id string
	if err := db.SQL().QueryRow(`SELECT id FROM leases WHERE hostname=?`, hostname).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// publishFlowFixture is a minimal MCP-speaking loopback fixture: GET /
// answers 200 for ProbeLocal, and POST answers JSON-RPC initialize,
// notifications/initialized, and tools/list with id-echoed replies. It
// keeps the publish flow tests hermetic without importing the MCP stack,
// at protocol fidelity (not a dumb 200 socket).
func publishFlowFixture(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				serveFlowMCP(c)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

// serveFlowMCP answers one HTTP request on c: GET with 200, POST with a
// minimal JSON-RPC dispatch sufficient for the doctor probe
// (initialize, notifications/initialized, tools/list).
func serveFlowMCP(c net.Conn) {
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	head := strings.Fields(line)
	body := []byte{}
	if len(head) > 0 && head[0] == "POST" {
		bodyLen := 0
		for {
			h, err := br.ReadString('\n')
			if err != nil || h == "\r\n" {
				break
			}
			if n, ok := strings.CutPrefix(strings.ToLower(h), "content-length:"); ok {
				fmt.Sscanf(strings.TrimSpace(n), "%d", &bodyLen)
			}
		}
		if bodyLen > 0 && bodyLen <= 1<<20 {
			body = make([]byte, bodyLen)
			if _, err := io.ReadFull(br, body); err != nil {
				return
			}
		}
	}
	reply := "ok"
	if len(head) > 0 && head[0] == "POST" {
		var env struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(body, &env)
		id := "1"
		if len(env.ID) > 0 {
			id = string(env.ID)
		}
		switch env.Method {
		case "initialize":
			reply = `{"jsonrpc":"2.0","id":` + id + `,"result":{"protocolVersion":"2024-11-05"}}`
		case "tools/list":
			reply = `{"jsonrpc":"2.0","id":` + id + `,"result":{"tools":[]}}`
		default:
			reply = `{}` // notifications/initialized: 200, no claim
		}
	}
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(reply), reply)
}

// publishDumbFixture is the pre-protocol-check negative control: a plain
// HTTP listener that answers 200 to everything but speaks no MCP. A
// publish against it must fail closed in preflight, before any tunnel
// or route exists.
func publishDumbFixture(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

func routeRowCount(t *testing.T, db *store.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM mcp_routes`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func leaseStatus(t *testing.T, db *store.DB, hostname string) string {
	t.Helper()
	var st string
	if err := db.SQL().QueryRow(`SELECT status FROM leases WHERE hostname=?`, hostname).Scan(&st); err != nil {
		t.Fatalf("lease lookup: %v", err)
	}
	return st
}

// TestMCPPublishFullCycleCleansUpRouteAndLease: a published route is
// removed and its owning lease closed on SIGINT shutdown, and the exit
// is clean when both remote revocations confirm.
func TestMCPPublishFullCycleCleansUpRouteAndLease(t *testing.T) {
	home := t.TempDir()
	db, relayURL := publishFlowRelay(t, "mcp.example.test")
	publishFlowEnroll(t, home, relayURL, db)
	port, closeFixture := publishFlowFixture(t)
	defer closeFixture()

	argv := []string{"--local", fmt.Sprintf("http://127.0.0.1:%d/mcp", port),
		"--auth", "upstream-oauth", "--name", "flowtest", "--ttl", "30m"}
	done := make(chan int, 1)
	go func() { done <- runMCPPublish(argv, false) }()

	deadline := time.Now().Add(25 * time.Second)
	for routeRowCount(t, db) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("route was never registered")
		}
		time.Sleep(200 * time.Millisecond)
	}

	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := self.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != apperr.ExitOK {
			t.Fatalf("shutdown exit=%d, want clean 0", code)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("publish did not shut down after SIGINT")
	}
	// The DELETE targets the route-owning lease: no orphan rows, no
	// abandoned ACTIVE lease.
	if n := routeRowCount(t, db); n != 0 {
		t.Fatalf("route rows after shutdown: %d, want 0", n)
	}
	if st := leaseStatus(t, db, "flowtest.t.example.test"); st != "CLOSED" {
		t.Fatalf("lease status %q, want CLOSED", st)
	}
}

// TestMCPPublishRejectsNonMCPServer: a plain HTTP server that answers 200
// but speaks no MCP must fail closed in preflight (P1), before any tunnel
// attaches or any route is registered.
func TestMCPPublishRejectsNonMCPServer(t *testing.T) {
	home := t.TempDir()
	db, relayURL := publishFlowRelay(t, "mcp.example.test")
	publishFlowEnroll(t, home, relayURL, db)
	port, closeDumb := publishDumbFixture(t)
	defer closeDumb()

	argv := []string{"--local", fmt.Sprintf("http://127.0.0.1:%d/mcp", port),
		"--auth", "upstream-oauth", "--name", "flownonmcp", "--ttl", "30m"}
	done := make(chan int, 1)
	go func() { done <- runMCPPublish(argv, false) }()
	select {
	case code := <-done:
		if code != apperr.ExitLocalTarget {
			t.Fatalf("exit=%d, want ExitLocalTarget for non-MCP server", code)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("publish did not fail closed on non-MCP server")
	}
	if n := routeRowCount(t, db); n != 0 {
		t.Fatalf("route rows after preflight rejection: %d, want 0", n)
	}
}

// TestMCPPublishRouteFailureClosesLeaseAndPropagatesExit: when route
// registration fails (no path-route ingress configured), the publish
// fails with closeTunnel's adjusted exit AND the lease is closed —
// cleanup is attempted on every post-attachment exit, never skipped.
func TestMCPPublishRouteFailureClosesLeaseAndPropagatesExit(t *testing.T) {
	home := t.TempDir()
	db, relayURL := publishFlowRelay(t, "") // no MCPExternalHost: registration 409s
	publishFlowEnroll(t, home, relayURL, db)
	port, closeFixture := publishFlowFixture(t)
	defer closeFixture()

	argv := []string{"--local", fmt.Sprintf("http://127.0.0.1:%d/mcp", port),
		"--auth", "upstream-oauth", "--name", "flowfail", "--ttl", "30m"}
	done := make(chan int, 1)
	go func() { done <- runMCPPublish(argv, false) }()
	select {
	case code := <-done:
		// closeTunnel(ready, a, ExitAuth) with a confirmed lease close
		// keeps the auth base: the failure is auth/policy, and the
		// receipt records the confirmed close. The assertion that
		// matters is that cleanup ran (lease CLOSED, no route) and the
		// exit is the adjusted receipt, not a constant that skips it.
		if code != apperr.ExitAuth {
			t.Fatalf("exit=%d, want ExitAuth receipt", code)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("publish did not return after registration failure")
	}
	if n := routeRowCount(t, db); n != 0 {
		t.Fatalf("route rows after failed registration: %d", n)
	}
	if st := leaseStatus(t, db, "flowfail.t.example.test"); st != "CLOSED" {
		t.Fatalf("lease status %q after failed registration, want CLOSED (cleanup skipped?)", st)
	}
}

// TestMCPPublishLeaseCloseFailurePropagates: revoking the agent key
// mid-publish makes both remote cleanup calls fail closed (403). The
// shutdown must report an explicit nonzero exit and must not pretend the
// remote route or lease is gone: the route row survives and the lease is
// not CLOSED.
func TestMCPPublishLeaseCloseFailurePropagates(t *testing.T) {
	home := t.TempDir()
	db, relayURL := publishFlowRelay(t, "mcp.example.test")
	publishFlowEnroll(t, home, relayURL, db)
	port, closeFixture := publishFlowFixture(t)
	defer closeFixture()

	argv := []string{"--local", fmt.Sprintf("http://127.0.0.1:%d/mcp", port),
		"--auth", "upstream-oauth", "--name", "flowclose", "--ttl", "30m"}
	done := make(chan int, 1)
	go func() { done <- runMCPPublish(argv, false) }()

	deadline := time.Now().Add(25 * time.Second)
	for routeRowCount(t, db) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("route was never registered")
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Break remote cleanup authority out from under the shutdown path.
	if _, err := db.SQL().Exec(`UPDATE agent_keys SET status='revoked'`); err != nil {
		t.Fatal(err)
	}
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := self.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code == apperr.ExitOK {
			t.Fatal("shutdown claimed clean exit with unconfirmed remote cleanup")
		}
	case <-time.After(45 * time.Second):
		t.Fatal("publish did not shut down after SIGINT")
	}
	// Nothing was deregistered: the failure is visible in durable state.
	if n := routeRowCount(t, db); n != 1 {
		t.Fatalf("route rows after failed cleanup: %d, want 1", n)
	}
	if st := leaseStatus(t, db, "flowclose.t.example.test"); st == "CLOSED" {
		t.Fatal("lease reads CLOSED although remote close was refused")
	}
}

// TestMCPPublishRouteDeleteFailurePropagates: deleting the route
// out-of-band before shutdown makes the shutdown DELETE miss (404) while
// the lease close still confirms. The exit must be nonzero (unconfirmed
// route revocation) even though the lease closed cleanly.
func TestMCPPublishRouteDeleteFailurePropagates(t *testing.T) {
	home := t.TempDir()
	db, relayURL := publishFlowRelay(t, "mcp.example.test")
	k, keyID, err := publishFlowKey(t, home, relayURL, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCLIV_RELAY_URL", relayURL)
	port, closeFixture := publishFlowFixture(t)
	defer closeFixture()

	argv := []string{"--local", fmt.Sprintf("http://127.0.0.1:%d/mcp", port),
		"--auth", "upstream-oauth", "--name", "flowroute", "--ttl", "30m"}
	done := make(chan int, 1)
	go func() { done <- runMCPPublish(argv, false) }()

	deadline := time.Now().Add(25 * time.Second)
	routeID := ""
	for routeID == "" {
		if time.Now().After(deadline) {
			t.Fatal("route was never registered")
		}
		time.Sleep(200 * time.Millisecond)
		_ = db.SQL().QueryRow(`SELECT route_id FROM mcp_routes`).Scan(&routeID)
	}
	// Remove the route behind the publisher's back: the shutdown DELETE
	// will 404 while the lease close confirms.
	status, _ := mgmtCall(relayURL, k, keyID, "DELETE", "/v1/agent/lease/"+flowLeaseID(t, db, "flowroute.t.example.test")+"/mcp-route/"+routeID)
	if status != http.StatusOK {
		t.Fatalf("out-of-band route delete: want 200 got %d", status)
	}
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := self.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != apperr.ExitInternal {
			t.Fatalf("exit=%d, want ExitInternal for unconfirmed route revocation", code)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("publish did not shut down after SIGINT")
	}
	if st := leaseStatus(t, db, "flowroute.t.example.test"); st != "CLOSED" {
		t.Fatalf("lease status %q, want CLOSED (lease close confirmed)", st)
	}
	if n := routeRowCount(t, db); n != 0 {
		t.Fatalf("route rows after shutdown: %d", n)
	}
}
