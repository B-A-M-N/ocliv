// Package server exposes internal-only health and metrics endpoints.
// These bind to loopback or a Unix socket only (H01); never to the public
// wildcard route.
package server

import (
	"encoding/json"
	"net/http"

	"ocliv/internal/metrics"
)

// Health holds readiness and capacity status probes.
type Health struct {
	// Ready reports whether the relay process and store are healthy.
	Ready func() bool
	// Status optionally returns a structured JSON snapshot separating
	// process readiness, session admission availability, and data-plane saturation.
	Status func() any
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
	mux.HandleFunc("/health/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		var payload any = map[string]any{"process_ready": h.Ready == nil || h.Ready()}
		if h.Status != nil {
			payload = h.Status()
		}
		_ = json.NewEncoder(w).Encode(payload)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(metrics.Snapshot()))
	})
	return mux
}
