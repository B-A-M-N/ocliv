// Command mcp-smoke-fixture is a throwaway-safe, read-only MCP server
// for live smoke tests (Funnel edge, tailnet staging). It serves exactly
// /mcp on loopback: initialize, tools/list, and tools/call (ping only).
// No state, no secrets, no filesystem access, no write tools. Tracked in
// the repo so every machine running the smoke test uses the same fixture.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
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

func main() {
	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var in rpcReq
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, rpcErr(nil, -32700, "parse error"))
			return
		}
		if in.ID == nil {
			fmt.Printf("fixture: notification %s accepted\n", in.Method)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		fmt.Printf("fixture: method=%s id=%v\n", in.Method, in.ID)
		switch in.Method {
		case "initialize":
			writeJSON(w, result(in.ID, map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{},
				"serverInfo":      map[string]any{"name": "ocliv-smoke-fixture", "version": "1"},
			}))
		case "tools/list":
			writeJSON(w, result(in.ID, map[string]any{
				"tools": []any{map[string]any{
					"name":        "ping",
					"description": "read-only smoke probe",
					"inputSchema": map[string]any{"type": "object"},
				}},
			}))
		case "tools/call":
			writeJSON(w, result(in.ID, map[string]any{
				"content": []any{map[string]any{
					"type": "text",
					"text": "pong:ocliv-funnel-smoke-1",
				}},
			}))
		default:
			writeJSON(w, rpcErr(in.ID, -32601, "method not found"))
		}
	})
	port := "18765"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	fmt.Println("fixture listening on 127.0.0.1:" + port)
	_ = http.ListenAndServe("127.0.0.1:"+port, nil)
}
