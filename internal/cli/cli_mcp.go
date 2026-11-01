package cli

// Local MCP commands: `ocliv mcp expose` adapts an operator-selected stdio
// MCP server to loopback HTTP for the ordinary tunnel path (V1.1, M07/M08),
// and `ocliv mcp manage` offers narrowly scoped tunnel-management tools
// over local stdio only (M12). Neither command listens on the network for
// management: expose serves the adapted MCP on loopback, manage speaks
// only stdin/stdout. Remote clients can reach neither command's selection
// surface — process choice is local argv, management tools are local
// stdio — so there is no remote management listener to attack.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/config"
	"ocliv/internal/mcp"
)

// manageTools is the complete tool surface of `ocliv mcp manage`. It is a
// closed set by construction: no shell, exec, or command tool exists and
// none can be added by a caller (M12).
var manageTools = []string{"ocliv_status", "ocliv_share", "ocliv_revoke"}

func cmdMCP(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv mcp expose|manage|publish|serve|doctor ...")
		return apperr.ExitCLIValidation
	}
	switch argv[0] {
	case "expose":
		return cmdMCPExpose(argv[1:])
	case "manage":
		return cmdMCPManage(argv[1:])
	case "publish":
		return cmdMCPPublish(argv[1:])
	case "serve":
		return cmdMCPServe(argv[1:])
	case "doctor":
		return cmdMCPDoctor(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown mcp command %q\n", argv[0])
		return apperr.ExitCLIValidation
	}
}

// agentRelayURL resolves the enrolled relay URL with the same precedence
// as the access commands: explicit environment override, then the stored
// enrollment, then the compiled default.
func agentRelayURL() string {
	relayURL := config.DefaultRelayURL
	if _, _, cfgPath, err := agentFiles(); err == nil {
		if vals, _ := config.LoadAgentFile(cfgPath); vals["relay_url"] != "" {
			relayURL = vals["relay_url"]
		}
	}
	if v := config.EnvRelay(); v != "" {
		relayURL = v
	}
	return relayURL
}

func cmdMCPExpose(argv []string) int {
	var opts mcp.Options
	var rest []string
	seenDashDash := false
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !seenDashDash && a == "--" {
			seenDashDash = true
			rest = argv[i+1:]
			break
		}
		if !seenDashDash && strings.HasPrefix(a, "--dir=") {
			opts.Dir = strings.TrimPrefix(a, "--dir=")
		} else if !seenDashDash && strings.HasPrefix(a, "--env=") {
			opts.Env = append(opts.Env, strings.TrimPrefix(a, "--env="))
		} else if !seenDashDash && strings.HasPrefix(a, "--max-body=") {
			n, err := strconv.ParseInt(strings.TrimPrefix(a, "--max-body="), 10, 64)
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "invalid --max-body %q\n", a)
				return apperr.ExitCLIValidation
			}
			opts.MaxBodyBytes = n
		} else if !seenDashDash && strings.HasPrefix(a, "--max-concurrent=") {
			n, err := strconv.Atoi(strings.TrimPrefix(a, "--max-concurrent="))
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "invalid --max-concurrent %q\n", a)
				return apperr.ExitCLIValidation
			}
			opts.MaxConcurrent = n
		} else if !seenDashDash && strings.HasPrefix(a, "--timeout=") {
			d, err := time.ParseDuration(strings.TrimPrefix(a, "--timeout="))
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "invalid --timeout %q\n", a)
				return apperr.ExitCLIValidation
			}
			opts.Timeout = d
		} else if !seenDashDash && strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
			return apperr.ExitCLIValidation
		} else {
			rest = argv[i:]
			break
		}
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv mcp expose [--dir D] [--env K=V]... -- COMMAND [ARGS...]")
		return apperr.ExitCLIValidation
	}
	opts.Command = rest[0]
	opts.Args = rest[1:]

	a, err := mcp.New(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp expose: %v\n", err)
		return apperr.ExitCLIValidation
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "mcp expose: %v\n", err)
		return apperr.ExitAuth
	}
	defer a.Close()
	host, port, _ := net.SplitHostPort(a.Addr().String())
	fmt.Printf("MCP stdio adapter: %s %v on http://%s:%s (loopback only)\n", opts.Command, opts.Args, host, port)
	fmt.Printf("Expose it with: ocliv <PORT> (point the tunnel at 127.0.0.1:%s)\n", port)
	<-ctx.Done()
	return apperr.ExitOK
}

// jsonRPC is the minimal envelope `ocliv mcp manage` speaks over stdio.
type jsonRPC struct {
	Version string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func rpcResult(out io.Writer, id any, result any) {
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	fmt.Fprintln(out, string(raw))
}

func rpcError(out io.Writer, id any, code int, message string) {
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": message}})
	fmt.Fprintln(out, string(raw))
}

func cmdMCPManage(argv []string) int {
	if len(argv) != 0 {
		fmt.Fprintln(os.Stderr, "usage: ocliv mcp manage (reads JSON-RPC on stdin)")
		return apperr.ExitCLIValidation
	}
	return runMCPManage(os.Stdin, os.Stdout)
}

// runMCPManage serves the fixed management tool set over caller-supplied
// stdio streams. Split from cmdMCPManage for testing; production passes
// the real process stdio. There is deliberately no network listener here.
func runMCPManage(in io.Reader, out io.Writer) int {
	k, keyID, err := loadKey()
	enrolled := err == nil
	relayURL := agentRelayURL()
	dir, _, _, _ := agentFiles()

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req jsonRPC
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			rpcError(out, nil, -32700, "parse error")
			continue
		}
		if strings.HasPrefix(req.Method, "notifications/") {
			continue // no response for notifications
		}
		switch req.Method {
		case "initialize":
			rpcResult(out, req.ID, map[string]any{
				"protocolVersion": "2026-07-28",
				"serverInfo":      map[string]any{"name": "ocliv-manage", "version": "1.0.0"},
			})
		case "tools/list":
			tools := make([]any, 0, len(manageTools))
			for _, name := range manageTools {
				tools = append(tools, map[string]any{"name": name})
			}
			rpcResult(out, req.ID, map[string]any{"tools": tools})
		case "tools/call":
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &p); err != nil {
				rpcError(out, req.ID, -32602, "invalid params")
				continue
			}
			if !enrolled {
				rpcError(out, req.ID, -32000, "not enrolled: run `ocliv login` first")
				continue
			}
			leaseID := lastLeaseID(dir)
			switch p.Name {
			case "ocliv_status":
				st := map[string]any{"lease_id": leaseID, "relay_url": relayURL}
				if leaseID == "" {
					st["route"] = "no active lease"
				}
				rpcResult(out, req.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": fmt.Sprintf("%v", st)}}})
			case "ocliv_share", "ocliv_revoke":
				if leaseID == "" {
					rpcError(out, req.ID, -32000, "no active lease; start a tunnel first")
					continue
				}
				action := strings.TrimPrefix(p.Name, "ocliv_")
				code, body := mgmtCall(relayURL, k, keyID, "POST", "/v1/agent/lease/"+leaseID+"/"+action)
				if code != 200 {
					rpcError(out, req.ID, -32000, fmt.Sprintf("%s failed (relay status %d)", action, code))
					continue
				}
				rpcResult(out, req.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": string(body)}}})
			default:
				rpcError(out, req.ID, -32601, fmt.Sprintf("unknown tool %q", p.Name))
			}
		default:
			rpcError(out, req.ID, -32601, fmt.Sprintf("unknown method %q", req.Method))
		}
	}
	return apperr.ExitOK
}
