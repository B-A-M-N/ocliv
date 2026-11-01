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

// Inflight and active-session gauges must be observable, not just
// tracked in memory: an operator cannot see saturation otherwise
// (Domain E availability signal). Same bounded rules: fixed lines, no
// labels.
func TestSnapshotExportsSaturationGauges(t *testing.T) {
	Global.HTTPInflight.Store(2)
	Global.WSActive.Store(1)
	Global.UpstreamDials.Add(5)
	out := Snapshot()
	for _, want := range []string{"ocliv_http_inflight 2\n", "ocliv_ws_active 1\n", "ocliv_upstream_dials_total 5\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("snapshot missing %q:\n%s", want, out)
		}
	}
}

// A gauge driven negative by an inc/dec pairing bug must render 0,
// never wrap to a huge counter that hides the defect.
func TestSnapshotClampsNegativeGauge(t *testing.T) {
	Global.HTTPInflight.Store(-3)
	out := Snapshot()
	Global.HTTPInflight.Store(0)
	if !strings.Contains(out, "ocliv_http_inflight 0\n") {
		t.Fatalf("negative gauge not clamped:\n%s", out)
	}
}

// Abuse-relevant counters must be observable, not just tracked in
// memory (Domain E: reconnect attempts detect flapping; auth failures
// and fencing rejections reveal credential attacks). Same bounded
// rules: fixed lines, no labels.
func TestSnapshotExportsAbuseCounters(t *testing.T) {
	Global.SessionReconnects.Add(4)
	Global.VisitorAuthFails.Add(1)
	Global.FencingRejects.Add(1)
	out := Snapshot()
	for _, want := range []string{"ocliv_session_reconnect_total 4\n", "ocliv_visitor_auth_failures_total 1\n", "ocliv_lease_fencing_rejections_total 1\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("snapshot missing %q:\n%s", want, out)
		}
	}
}
