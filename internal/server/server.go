// Package server exposes internal-only health and metrics endpoints.
// These bind to loopback or a Unix socket only (H01); never to the public
// wildcard route.
package server

import (
	"net/http"

	"ocliv/internal/metrics"
)

// Health holds readiness probes.
type Health struct {
	// Ready reports whether the relay can accept tunnel sessions: SQLite
	// writable, route registry initialized, capacity available.
	Ready func() bool
}

// Handler returns the internal mux.
func (h *Health) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		if h.Ready != nil && !h.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(metrics.Snapshot()))
	})
	return mux
}
