package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"ocliv/internal/agent"
	"ocliv/internal/config"
)

// TestAgentExitsOnTerminalDeny: once the lease is terminally denied
// (expired here), the agent must stop with a permanent error instead of
// retrying forever (F09).
func TestAgentExitsOnTerminalDeny(t *testing.T) {
	app := startLocalApp(t)
	defer app.srv.Close()
	h := newHarness(t)
	defer h.db.Close()
	defer h.relaySrv.Close()
	h.startAgentOpts(t, app.Port, config.Agent{TTLSeconds: 2})

	// The primary agent holds the lease; kill it so the TTL can lapse with
	// no session, then a fresh image must fail permanently on resume.
	h.cancel()
	time.Sleep(3 * time.Second)

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	cfg2 := config.Agent{RelayURL: h.relaySrv.URL, Port: app.Port, DataDir: h.agentDir}
	rn2 := &agent.Runner{Cfg: cfg2, Key: h.agentKey, KeyID: h.keyID,
		Target: "127.0.0.1:1", HandshakeTransport: h.handshakeTransport()}
	done := make(chan error, 1)
	go func() { done <- rn2.Run(ctx2) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "denied") {
			t.Fatalf("terminal deny: Run returned %v, want permanent denied error", err)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("agent retried a terminally denied lease instead of exiting")
	}
}
