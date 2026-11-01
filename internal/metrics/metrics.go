// Package metrics provides structured logging and bounded operational
// metrics. Logs never carry bodies, secrets, cookies, or full URLs (H03).
// Metric labels are bounded: no hostname, token, IP, or user id labels (G08).
package metrics

import (
	"log/slog"
	"os"
	"sync/atomic"
)

// Counters is the bounded process-wide metric set (spec 7).
type Counters struct {
	HTTPRequests        atomic.Uint64
	HTTPInflight        atomic.Int64
	VisitorAuthFails    atomic.Uint64
	UpstreamDials       atomic.Uint64
	SessionReconnects   atomic.Uint64
	FencingRejects      atomic.Uint64
	CapacityRejects     atomic.Uint64
	PreAuthRejects      atomic.Uint64
	MCPAdmissionRejects atomic.Uint64
	NonceEntries        atomic.Int64
	ThrottleKeys        atomic.Int64
	WSActive            atomic.Int64
	WSClosed            atomic.Uint64
	BytesUp             atomic.Uint64
	BytesDown           atomic.Uint64
}

// Global is the process metric set.
var Global Counters

// Log is the process structured logger (slog, text to stderr).
var Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

// Snapshot renders the bounded Prometheus exposition (internal only, H01).
func Snapshot() string {
	g := &Global
	out := "# Ocliv relay metrics (bounded cardinality)\n"
	f := func(name string, v uint64) string {
		return name + " " + itoa(v) + "\n"
	}
	out += f("ocliv_http_requests_total", g.HTTPRequests.Load())
	out += "ocliv_http_inflight " + itoa64(g.HTTPInflight.Load()) + "\n"
	out += f("ocliv_visitor_auth_failures_total", g.VisitorAuthFails.Load())
	out += f("ocliv_session_reconnect_total", g.SessionReconnects.Load())
	out += f("ocliv_lease_fencing_rejections_total", g.FencingRejects.Load())
	out += f("ocliv_capacity_rejections_total", g.CapacityRejects.Load())
	out += f("ocliv_preauth_rejections_total", g.PreAuthRejects.Load())
	out += f("ocliv_mcp_admission_rejections_total", g.MCPAdmissionRejects.Load())
	out += f("ocliv_upstream_dials_total", g.UpstreamDials.Load())
	out += "ocliv_nonce_entries " + itoa64(g.NonceEntries.Load()) + "\n"
	out += "ocliv_throttle_keys " + itoa64(g.ThrottleKeys.Load()) + "\n"
	out += "ocliv_ws_active " + itoa64(g.WSActive.Load()) + "\n"
	out += f("ocliv_ws_closed_total", g.WSClosed.Load())
	out += f("ocliv_stream_bytes_up", g.BytesUp.Load())
	out += f("ocliv_stream_bytes_down", g.BytesDown.Load())
	return out
}

// itoa64 renders a gauge, clamping a negative (inc/dec pairing bug) to
// zero rather than wrapping to a huge counter that hides the defect.
func itoa64(v int64) string {
	if v < 0 {
		return "0"
	}
	return itoa(uint64(v))
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [24]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
