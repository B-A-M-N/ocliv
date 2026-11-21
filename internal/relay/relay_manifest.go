package relay

import "net/http"

// handleReleaseManifest serves the operator-supplied release manifest at
// GET /.well-known/ocliv-release-manifest.json. Used by `ocliv install`
// to discover the latest release artifact and its SHA256 digest.
// No authentication required: the manifest is public information.
func (s *Server) handleReleaseManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(s.releaseManifestJSON) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(s.releaseManifestJSON)
	}
}

// handleReleaseManifestSig serves the Ed25519 signature of the release manifest at
// GET /.well-known/ocliv-release-manifest.json.sig
// No authentication required: the signature is only useful alongside the manifest.
func (s *Server) handleReleaseManifestSig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(s.releaseManifestSig) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(s.releaseManifestSig)
	}
}
