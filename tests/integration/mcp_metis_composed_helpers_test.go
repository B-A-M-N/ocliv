package integration

// Composed-test helpers for the real-Metis vertical: launch a real Metis
// MCP HTTP server as a subprocess and mint real RS256 bearer tokens with
// the committed tests/staging/metis-idp scaffold. No JWT/JWKS logic is
// reimplemented here. Test-only; nothing is product code.

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// metisIssuer must equal METIS_MCP_ISSUER exactly (Metis checks the
	// token's iss against it).
	metisIssuer = "https://idp.example/oauth"
	// metisTestScope carries every scope Metis grants for the
	// admin,tasks,message capability set (nothing implies another).
	metisTestScope = "metis:message metis:provision metis:input metis:stop"
	// metisProtoVerOK is an MCP-Protocol-Version Metis accepts; the
	// 2025-06-18 value is rejected with HTTP 400.
	metisProtoVerOK = "2024-11-05"
)

// metisBinPath resolves the Metis binary from OCLIV_METIS_BIN. Without a
// Metis checkout the test skips cleanly — mirroring Metis's own
// METIS_OCLIV_BIN gate — so the default Ocliv gate stays green.
func metisBinPath(t *testing.T) string {
	t.Helper()
	bin := strings.TrimSpace(os.Getenv("OCLIV_METIS_BIN"))
	if bin == "" {
		t.Skip("OCLIV_METIS_BIN not set: Metis checkout absent")
	}
	st, err := os.Stat(bin)
	if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		t.Skipf("OCLIV_METIS_BIN=%q is not an executable file: Metis checkout absent", bin)
	}
	return bin
}

// metisRepoRoot walks up from the test working directory to the module
// root (the integration tests live two levels down).
func metisRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above tests/integration")
		}
		dir = parent
	}
}

// metisBuildIDP compiles the committed tests/staging/metis-idp scaffold
// (stdlib-only) and returns the binary path. Tokens are minted only
// through this tool; the test never signs a JWT itself.
func metisBuildIDP(t *testing.T, dir string) string {
	t.Helper()
	out := filepath.Join(dir, "metis-idp")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, "./tests/staging/metis-idp")
	cmd.Dir = metisRepoRoot(t)
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build tests/staging/metis-idp: %v\n%s", err, raw)
	}
	return out
}

// metisIDPGenKey runs `metis-idp genkey`, producing DIR/key.pem (0600) and
// DIR/jwks.json (0600). Returns the private-key path; the JWKS path is
// what METIS_MCP_JWKS_FILE points at.
func metisIDPGenKey(t *testing.T, idpBin, dir string) (keyPEM, jwks string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(idpBin, "genkey", "-dir", dir).Output()
	if err != nil {
		t.Fatalf("metis-idp genkey: %v", err)
	}
	jwks = strings.TrimSpace(string(raw))
	keyPEM = filepath.Join(dir, "key.pem")
	if jwks == "" {
		t.Fatal("metis-idp genkey printed no jwks path")
	}
	if _, err := os.Stat(keyPEM); err != nil {
		t.Fatalf("metis-idp genkey wrote no key.pem: %v", err)
	}
	return keyPEM, jwks
}

// metisIDPToken mints one RS256 JWT via the committed scaffold. The token
// is returned to the caller only and is never logged: the idp prints it on
// stdout, which is captured into the return value; error paths carry only
// the idp's stderr.
func metisIDPToken(t *testing.T, idpBin, keyPEM, iss, aud, scope string, expSecs int) string {
	t.Helper()
	raw, err := exec.Command(idpBin, "token", "-privkey", keyPEM,
		"-iss", iss, "-aud", aud, "-scope", scope,
		"-exp", fmt.Sprintf("%d", expSecs)).Output()
	if err != nil {
		t.Fatalf("metis-idp token: %v", err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		t.Fatal("metis-idp token: empty output")
	}
	return tok
}

// metisServer is a running real Metis MCP HTTP transport process.
type metisServer struct {
	t            *testing.T
	port         int
	resourceFile string
	logMu        sync.Mutex
	logBuf       bytes.Buffer
	cmd          *exec.Cmd
	exited       chan struct{}
}

func (m *metisServer) url() string { return fmt.Sprintf("http://127.0.0.1:%d/mcp", m.port) }

// metisLogWriter funnels Metis's process output through a mutex so the
// test goroutine can snapshot it even while the process is running.
type metisLogWriter struct{ m *metisServer }

func (w metisLogWriter) Write(p []byte) (int, error) {
	w.m.logMu.Lock()
	w.m.logBuf.Write(p)
	w.m.logMu.Unlock()
	return len(p), nil
}

func (m *metisServer) logSnapshot() string {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	out := m.logBuf.String()
	if len(out) > 4096 {
		out = out[len(out)-4096:]
	}
	return out
}

// metisStartServer launches the real Metis binary (`mcp serve-http`) on a
// fresh loopback port with the required environment, binding its resource
// to a resource file that is deliberately NOT written yet: Metis starts
// before Ocliv allocates the route, and the handoff (writing the route
// URL) happens per-request re-read afterwards. The process is always
// stopped on cleanup.
func metisStartServer(t *testing.T, bin, jwksFile, stateDir, handoffDir string) *metisServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(handoffDir, 0o700); err != nil {
		t.Fatal(err)
	}
	m := &metisServer{
		t:            t,
		port:         port,
		resourceFile: filepath.Join(handoffDir, "resource.url"),
		exited:       make(chan struct{}),
	}
	cmd := exec.Command(bin, "mcp", "serve-http", "--listen", fmt.Sprintf("127.0.0.1:%d", port))
	// Scrub any inherited METIS_* variables so the subprocess sees
	// exactly the environment this test intends.
	env := make([]string, 0, len(os.Environ())+5)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "METIS_") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env,
		"METIS_MCP_ISSUER="+metisIssuer,
		"METIS_MCP_JWKS_FILE="+jwksFile,
		"METIS_MCP_RESOURCE_FILE="+m.resourceFile,
		"METIS_STATE="+stateDir,
		"METIS_MCP_REMOTE_CAPABILITIES=admin,tasks,message",
	)
	w := metisLogWriter{m}
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		t.Fatalf("start metis %s: %v", bin, err)
	}
	m.cmd = cmd
	go func() {
		_ = cmd.Wait()
		close(m.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-m.exited:
		case <-time.After(5 * time.Second):
		}
	})
	return m
}

// writeResource performs the Ocliv->Metis handoff: the resource file holds
// the exact public route URL. It is written 0600 inside a 0700 directory —
// Metis refuses to honor a group/world-writable binding — and Metis
// re-reads it per request, so it may be written after route allocation.
func (m *metisServer) writeResource(t *testing.T, resourceURL string) {
	t.Helper()
	if err := os.WriteFile(m.resourceFile, []byte(resourceURL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// waitReady polls Metis until it answers HTTP on /mcp at all (a bare
// tools/list without a bearer yields 401 once serving). Bounded timeout;
// a dead process fails immediately with its captured output.
func (m *metisServer) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	client := &http.Client{Timeout: 3 * time.Second}
	for {
		select {
		case <-m.exited:
			t.Fatalf("metis exited before readiness:\n%s", m.logSnapshot())
		default:
		}
		resp, err := client.Post(m.url(), "application/json",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("metis not ready on %s within 15s: %v\n%s", m.url(), err, m.logSnapshot())
		}
		time.Sleep(100 * time.Millisecond)
	}
}
