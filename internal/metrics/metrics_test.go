package metrics

import (
	"strings"
	"testing"
)

// Snapshot stays bounded-cardinality: fixed line set, no label braces.
func TestSnapshotBounded(t *testing.T) {
	Global.HTTPRequests.Add(3)
	out := Snapshot()
	if !strings.HasPrefix(out, "# Ocliv relay metrics") {
		t.Fatal("snapshot missing header")
	}
	if strings.Contains(out, "{") {
		t.Fatal("snapshot carries labels; cardinality unbounded")
	}
	if !strings.Contains(out, "ocliv_http_requests_total 3\n") {
		t.Fatalf("counter missing:\n%s", out)
	}
	lines := strings.Count(out, "\n")
	if lines < 10 || lines > 30 {
		t.Fatalf("snapshot line count %d outside fixed range", lines)
	}
}
