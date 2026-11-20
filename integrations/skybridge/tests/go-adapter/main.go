package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ocliv/internal/mcp"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	script := `while IFS= read -r req; do
id=$(printf '%s' "$req" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
case "$req" in
  *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":"%s","result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}\n' "$id" ;;
  *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":"%s","result":{"tools":[{"name":"ping"}]}}\n' "$id" ;;
  *'"method":"tools/call"'*) printf '{"jsonrpc":"2.0","id":"%s","result":{"content":[{"type":"text","text":"pong:adapter-fixture"}]}}\n' "$id" ;;
esac
done`
	a, err := mcp.New(mcp.Options{Command: "sh", Args: []string{"-c", script}, Timeout: 15 * time.Second,
		MultiClientSessions: true, MaxSessions: 4, SessionIdleTimeout: time.Minute})
	if err != nil {
		fmt.Fprintln(os.Stderr, "adapter init failed")
		os.Exit(1)
	}
	if err := a.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "adapter start failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("LISTEN http://%s/mcp\n", a.Addr().String())
	<-ctx.Done()
	_ = a.Close()
}
