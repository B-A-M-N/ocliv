package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/identity"
)

// manageCall feeds one JSON-RPC request to the local management loop and
// returns the decoded response envelopes (notifications yield none).
func manageCall(t *testing.T, req string) []map[string]any {
	t.Helper()
	// Isolate from any real enrollment in the operator's home: the tool
	// surface must be provable without credentials.
	t.Setenv("HOME", t.TempDir())
	var out strings.Builder
	if code := runMCPManage(strings.NewReader(req), &out); code != 0 {
		t.Fatalf("manage exit=%d", code)
	}
	var resps []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("non-JSON response line: %q", line)
		}
		resps = append(resps, m)
	}
	return resps
}

// TestManageToolSurfaceClosed (M12): tools/list exposes exactly the three
// narrowly scoped tunnel-management tools. There is no shell, exec,
// command, or run tool, and no request can add one — the set is a package
// constant, not caller input.
func TestManageToolSurfaceClosed(t *testing.T) {
	resps := manageCall(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	res, ok := resps[0]["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", resps[0])
	}
	tools, ok := res["tools"].([]any)
	if !ok {
		t.Fatalf("no tools: %v", res)
	}
	if len(tools) != len(manageTools) {
		t.Fatalf("tools=%v, want exactly %v", tools, manageTools)
	}
	seen := map[string]bool{}
	for _, tl := range tools {
		name, _ := tl.(map[string]any)["name"].(string)
		seen[name] = true
		for _, banned := range []string{"exec", "shell", "command", "run", "eval", "system"} {
			if strings.Contains(strings.ToLower(name), banned) {
				t.Fatalf("management tool %q looks like remote execution", name)
			}
		}
	}
	for _, want := range manageTools {
		if !seen[want] {
			t.Fatalf("missing management tool %q in %v", want, seen)
		}
	}
}

// enrollHome writes a fresh agent key into a temp HOME so the management
// loop runs as enrolled (without any relay contact).
func enrollHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	k, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".config", "ocliv")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := k.Save(filepath.Join(dir, config.AgentKeyFile)); err != nil {
		t.Fatal(err)
	}
	return home
}

// TestManageUnknownToolRejected: tools/call with any other name is
// method-not-found, never dispatched — even when enrolled, so the
// rejection proves name validation rather than missing credentials.
func TestManageUnknownToolRejected(t *testing.T) {
	enrollHome(t)
	var out strings.Builder
	req := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{"cmd":"id"}}}` + "\n"
	if code := runMCPManage(strings.NewReader(req), &out); code != 0 {
		t.Fatalf("manage exit=%d", code)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("non-JSON response: %q", out.String())
	}
	resps := []map[string]any{resp}
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	errObj, ok := resps[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("exec tool was not rejected: %v", resps[0])
	}
	if code, _ := errObj["code"].(float64); code != -32601 {
		t.Fatalf("error code=%v, want -32601", errObj["code"])
	}
}

// TestManageUnknownMethodRejected: only initialize/tools/list/tools/call
// exist; everything else is method-not-found.
func TestManageUnknownMethodRejected(t *testing.T) {
	resps := manageCall(t, `{"jsonrpc":"2.0","id":3,"method":"tools/execute"}`+"\n")
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	if _, ok := resps[0]["error"]; !ok {
		t.Fatalf("unknown method was not rejected: %v", resps[0])
	}
}

// TestManageParseError: garbage input is a -32700, never a dispatch.
func TestManageParseError(t *testing.T) {
	resps := manageCall(t, `this is not json`+"\n")
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	errObj, ok := resps[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("parse error not reported: %v", resps[0])
	}
	if code, _ := errObj["code"].(float64); code != -32700 {
		t.Fatalf("error code=%v, want -32700", errObj["code"])
	}
}

// TestManageNotificationSilent: notifications get no response.
func TestManageNotificationSilent(t *testing.T) {
	resps := manageCall(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n")
	if len(resps) != 0 {
		t.Fatalf("notification drew %d responses: %v", len(resps), resps)
	}
}

// TestManageStatusRequiresEnrollment: without a local key the management
// loop reports not-enrolled instead of touching the relay.
func TestManageStatusRequiresEnrollment(t *testing.T) {
	resps := manageCall(t, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ocliv_status","arguments":{}}}`+"\n")
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	errObj, ok := resps[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("unenrolled status call succeeded: %v", resps[0])
	}
	if code, _ := errObj["code"].(float64); code != -32000 {
		t.Fatalf("error code=%v, want -32000", errObj["code"])
	}
}

// TestManageExposeValidation: expose without a command, or with an
// unresolvable command, fails before spawning anything.
func TestManageExposeValidation(t *testing.T) {
	if code := cmdMCPExpose(nil); code == 0 {
		t.Fatal("expose without command succeeded")
	}
	if code := cmdMCPExpose([]string{"--", "definitely-not-a-real-binary-xyz"}); code == 0 {
		t.Fatal("expose with unresolvable command succeeded")
	}
}

// P2-H: `ocliv mcp 3000` rewrites to the equivalent publish argv with
// authentication pinned to upstream-oauth; non-ports stay errors.
func TestMCPPortAliasArgs(t *testing.T) {
	pub, ok := mcpPortAliasArgs([]string{"3000", "--name", "mytools"})
	if !ok {
		t.Fatal("port alias not recognized")
	}
	cfg, code := parseMCPPublish(pub, false)
	if code != apperr.ExitOK {
		t.Fatalf("alias argv rejected by publish parser: %v", pub)
	}
	if cfg.localURL != "http://127.0.0.1:3000/mcp" || cfg.auth != "upstream-oauth" || cfg.name != "mytools" {
		t.Fatalf("alias misparsed: %+v", cfg)
	}
	for _, bad := range [][]string{nil, {}, {"bogus"}, {"0"}, {"70000"}, {"--name"}} {
		if _, ok := mcpPortAliasArgs(bad); ok {
			t.Fatalf("alias accepted %v", bad)
		}
	}
}
