package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleReleaseArtifact serves release artifacts declared in the release manifest.
// GET /.well-known/ocliv-artifacts/{name} — GET and HEAD only.
// Security: only artifacts explicitly declared in the manifest are served;
// the name is validated against an allowlist to prevent path traversal.
func (s *Server) handleReleaseArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.releaseArtifactDir == "" || len(s.releaseManifestJSON) == 0 {
		http.NotFound(w, r)
		return
	}

	// Extract artifact name from URL path.
	name := strings.TrimPrefix(r.URL.Path, "/.well-known/ocliv-artifacts/")
	name = strings.TrimPrefix(name, "/")

	if !isValidArtifactName(name) {
		http.NotFound(w, r)
		return
	}

	// Parse manifest to find the artifact entry. Only declared artifacts are served.
	var manifest struct {
		Artifacts map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(s.releaseManifestJSON, &manifest); err != nil {
		http.Error(w, "manifest unavailable", http.StatusInternalServerError)
		return
	}
	entry, ok := manifest.Artifacts[name]
	if !ok || entry.SHA256 == "" {
		// Artifact not declared in manifest — refuse, even if the file exists on disk.
		http.NotFound(w, r)
		return
	}

	// Resolve the path and confirm it is a regular file (no symlinks).
	cleanPath := filepath.Join(s.releaseArtifactDir, name)
	// Extra guard: reject paths that escaped the directory after filepath.Join.
	dirWithSep := filepath.Clean(s.releaseArtifactDir) + string(filepath.Separator)
	if !strings.HasPrefix(cleanPath, dirWithSep) {
		http.NotFound(w, r)
		return
	}

	fi, err := os.Lstat(cleanPath)
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		http.Error(w, "artifact unavailable", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", `"`+entry.SHA256+`"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))

	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// isValidArtifactName reports whether name is a safe artifact identifier.
// Accepts only lowercase alphanumeric + hyphens starting with "ocliv-".
// Rejects path separators, dots, percent-encoding, and hidden-file prefixes.
func isValidArtifactName(name string) bool {
	if name == "" {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") ||
		strings.Contains(name, "..") || strings.HasPrefix(name, ".") ||
		strings.Contains(name, "%") {
		return false
	}
	if !strings.HasPrefix(name, "ocliv-") {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}
