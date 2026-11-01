// Command mcp-auth-fixture is the authenticated staging MCP server for
// Ocliv publication qualification (Gates 1-3). It serves exactly /mcp
// plus the server-root RFC 9728 metadata path on loopback, behind a
// static test bearer token. No shell, no filesystem beyond an optional
// token/binding file, one read-only tool ("ping").
//
// Contract with the publisher (see internal/cli/cli_mcp_publish.go):
//   - metadata "resource" MUST equal the published public route URL.
//     The expected URL arrives via MCP_RESOURCE_URL or MCP_RESOURCE_FILE
//     (the publisher-owned binding handoff); default is the local URL,
//     which fails strict discovery closed (correct: unbound fixture
//     must not verify).
//   - every /mcp POST requires Authorization: Bearer <token>; anything
//     else gets HTTP 401 + WWW-Authenticate challenge, no tool runs.
//   - the token is re-read from MCP_TOKEN_FILE per request when set, so
//     revocation/rotation tests take effect without restarting the
//     fixture. MCP_AUTH_TOKEN is the static alternative; exactly one of
//     the two is required at startup (fail closed, no anonymous mode).
package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

var supportedVersions = map[string]bool{
	"2024-11-05": true,
	"2025-06-18": true,
	"2026-07-28": true,
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func result(id any, r any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": r}
}

func rpcErr(id any, code int, msg string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": msg}}
}

type fixture struct {
	resource     string
	resourceFile string
	authToken    string
	tokenFile    string
}

// currentResource re-reads the publisher-owned binding file on every
// metadata request, so the fixture advertises the public route URL the
// moment the publisher writes it — no restart, no stale URL. A missing
// or unreadable file falls back to the startup value (local URL), which
// fails strict discovery closed.
func (f *fixture) currentResource() string {
	if f.resourceFile == "" {
		return f.resource
	}
	raw, err := os.ReadFile(f.resourceFile)
	if err != nil {
		return f.resource
	}
	if u := strings.TrimSpace(string(raw)); u != "" {
		return u
	}
	return f.resource
}

func (f *fixture) currentToken() string {
	if f.tokenFile != "" {
		raw, err := os.ReadFile(f.tokenFile)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(raw))
	}
	return f.authToken
}

func (f *fixture) challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate",
		`Bearer resource_metadata="`+f.resource+`", error="invalid_token", error_description="valid bearer token required"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (f *fixture) authorized(r *http.Request) bool {
	want := f.currentToken()
	if want == "" {
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if r.Header.Get("Authorization") == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (f *fixture) serveMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !f.authorized(r) {
		f.challenge(w)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var in rpcReq
	if err := json.Unmarshal(body, &in); err != nil || in.JSONRPC != "2.0" {
		writeJSON(w, rpcErr(nil, -32700, "parse error"))
		return
	}
	if in.ID == nil {
		fmt.Printf("auth-fixture: notification %s accepted\n", in.Method)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	fmt.Printf("auth-fixture: method=%s id=%v\n", in.Method, in.ID)
	switch in.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(in.Params, &p)
		if !supportedVersions[p.ProtocolVersion] {
			writeJSON(w, rpcErr(in.ID, -32602,
				fmt.Sprintf("unsupported protocol version %q", p.ProtocolVersion)))
			return
		}
		writeJSON(w, result(in.ID, map[string]any{
			"protocolVersion": p.ProtocolVersion,
			"capabilities":    map[string]any{},
			"serverInfo":      map[string]any{"name": "ocliv-auth-fixture", "version": "1"},
		}))
	case "tools/list":
		writeJSON(w, result(in.ID, map[string]any{
			"tools": []any{map[string]any{
				"name":        "ping",
				"description": "authenticated read-only smoke probe",
				"annotations": map[string]any{"readOnlyHint": true},
				"inputSchema": map[string]any{
					"type":                 "object",
					"properties":           map[string]any{},
					"additionalProperties": false,
				},
			}},
		}))
	case "tools/call":
		var p rpcCallParams
		if err := json.Unmarshal(in.Params, &p); err != nil {
			writeJSON(w, rpcErr(in.ID, -32602, "invalid params"))
			return
		}
		if p.Name != "ping" {
			writeJSON(w, rpcErr(in.ID, -32602, fmt.Sprintf("unknown tool %q", p.Name)))
			return
		}
		if len(p.Arguments) != 0 {
			writeJSON(w, rpcErr(in.ID, -32602, "ping takes no arguments"))
			return
		}
		writeJSON(w, result(in.ID, map[string]any{
			"content": []any{map[string]any{
				"type": "text",
				"text": "pong:ocliv-auth-fixture-1",
			}},
		}))
	case "ping":
		writeJSON(w, result(in.ID, map[string]any{}))
	default:
		writeJSON(w, rpcErr(in.ID, -32601, "method not found"))
	}
}

func newMux(f *fixture) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", f.serveMCP)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", f.serveMetadata)
	return mux
}

func (f *fixture) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{
		"resource":                 f.currentResource(),
		"authorization_servers":    []string{os.Getenv("MCP_AUTH_SERVER")},
		"bearer_methods_supported": []string{"header"},
	})
}

func resolveResource(localAddr string) string {
	if u := strings.TrimSpace(os.Getenv("MCP_RESOURCE_URL")); u != "" {
		return u
	}
	if p := strings.TrimSpace(os.Getenv("MCP_RESOURCE_FILE")); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			if !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "auth-fixture: cannot read MCP_RESOURCE_FILE: %v\n", err)
				os.Exit(2)
			}
			// Missing binding file at startup is the normal boot
			// order: the publisher writes it after route registration
			// and currentResource() picks it up live. Warn loudly;
			// strict discovery still fails closed until bound.
			fmt.Fprintf(os.Stderr, "auth-fixture: MCP_RESOURCE_FILE %s not present yet; advertising local URL until bound\n", p)
		} else if u := strings.TrimSpace(string(raw)); u != "" {
			return u
		}
	}
	return "http://" + localAddr + "/mcp"
}

func main() {
	port := flag.String("port", "18766", "loopback port to listen on")
	flag.Parse()

	token, tokenFile := strings.TrimSpace(os.Getenv("MCP_AUTH_TOKEN")), strings.TrimSpace(os.Getenv("MCP_TOKEN_FILE"))
	if (token == "") == (tokenFile == "") {
		fmt.Fprintln(os.Stderr, "auth-fixture: set exactly one of MCP_AUTH_TOKEN or MCP_TOKEN_FILE (fail closed, no anonymous mode)")
		os.Exit(2)
	}

	addr := "127.0.0.1:" + *port
	f := &fixture{authToken: token, tokenFile: tokenFile,
		resourceFile: strings.TrimSpace(os.Getenv("MCP_RESOURCE_FILE"))}
	f.resource = resolveResource(addr)

	mux := newMux(f)
	fmt.Println("auth-fixture listening on " + addr + " resource=" + f.resource)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "auth-fixture: "+err.Error())
		os.Exit(1)
	}
}
