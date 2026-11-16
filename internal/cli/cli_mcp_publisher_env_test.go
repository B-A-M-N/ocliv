package cli

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestShippedPublisherEnvExamplesMatchCLIPublishContract(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	for _, path := range []string{
		"packaging/systemd/ocliv-mcp-publisher.env.example",
		"packaging/mcp/config/publisher.env.example",
	} {
		t.Run(path, func(t *testing.T) {
			f, err := os.Open(filepath.Join(root, path))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			values := map[string]string{}
			scan := bufio.NewScanner(f)
			for scan.Scan() {
				line := strings.TrimSpace(scan.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				key, value, found := strings.Cut(line, "=")
				if found {
					values[key] = strings.Trim(value, "\"'")
				}
			}
			if err := scan.Err(); err != nil {
				t.Fatal(err)
			}
			if values["OCLIV_LOCAL_URL"] == "" {
				values["OCLIV_LOCAL_URL"] = "http://127.0.0.1:8765/mcp"
			}
			if values["OCLIV_AUTH"] == "" {
				t.Fatal("example must select an explicit auth mode")
			}
			args := []string{"--local", values["OCLIV_LOCAL_URL"], "--auth", values["OCLIV_AUTH"]}
			if values["OCLIV_NAME"] != "" {
				args = append(args, "--name", values["OCLIV_NAME"])
			}
			if values["OCLIV_TTL"] != "" {
				args = append(args, "--ttl", values["OCLIV_TTL"])
			}
			if values["OCLIV_STRICT"] != "" {
				args = append(args, "--strict-discovery")
			}
			if values["OCLIV_RESOURCE_FILE"] != "" {
				args = append(args, "--resource-file", values["OCLIV_RESOURCE_FILE"])
			}
			if _, code := parseMCPPublish(args, false); code != 0 {
				t.Fatalf("shipped env example generated rejected CLI args: %v", args)
			}
		})
	}
}
