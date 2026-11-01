// Status surfaces the recorded probe contract (Domain A) so an operator
// can see why a tunnel reports local-target-unreachable: the path and
// expected status come from the lease record, never from a fresh guess.
package cli

import (
	"strings"
	"testing"

	"ocliv/internal/protocol"
)

func TestRenderStatusShowsProbeContract(t *testing.T) {
	local := map[string]any{
		"lease_id": "lse-1", "url": "https://x", "access_mode": "protected",
		"port": 3000, "probe_path": "/healthz", "probe_status": 200,
	}
	out, _ := renderStatus(local, nil, nil, false)
	if !strings.Contains(out, "/healthz") || !strings.Contains(out, "200") {
		t.Fatalf("status hides probe contract:\n%s", out)
	}
	def, _ := renderStatus(map[string]any{
		"lease_id": "lse-1", "url": "https://x", "access_mode": "protected",
		"port": 3000,
	}, nil, nil, false)
	if !strings.Contains(def, "Probe:") || !strings.Contains(def, "any status") {
		t.Fatalf("status hides default probe contract:\n%s", def)
	}
	js, _ := renderStatus(local, nil, nil, true)
	if !strings.Contains(js, `"probe_path":"/healthz"`) || !strings.Contains(js, `"probe_status":200`) {
		t.Fatalf("json status hides probe contract:\n%s", js)
	}
}

// Doctor flag resolution (Domain A verify-stage): explicit flags
// override the recorded contract after the same edge validation the
// tunnel applies; anything else falls back to the record.
func TestResolveDoctorProbe(t *testing.T) {
	p, s, err := resolveDoctorProbe("/healthz", 200, "", "")
	if err != nil || p != "/healthz" || s != 200 {
		t.Fatalf("record fallback wrong: %q %d %v", p, s, err)
	}
	p, s, err = resolveDoctorProbe("/healthz", 200, "/readyz", "204")
	if err != nil || p != "/readyz" || s != 204 {
		t.Fatalf("flag override wrong: %q %d %v", p, s, err)
	}
	if _, _, err = resolveDoctorProbe("", 0, "http://x/", ""); err == nil {
		t.Fatal("absolute probe path accepted")
	}
	if _, _, err = resolveDoctorProbe("", 0, "", "99"); err == nil {
		t.Fatal("out-of-range probe status accepted")
	}
}

// `ocliv version` must report the single-source protocol constants, so
// a wire bump cannot leave the CLI advertising a stale version.
func TestVersionStringTracksProtocolConstants(t *testing.T) {
	s := versionString()
	for _, want := range []string{BinaryVersion, protocol.Version, protocol.MinVersion, protocol.MaxVersion} {
		if !strings.Contains(s, want) {
			t.Fatalf("version string %q missing %q", s, want)
		}
	}
	if strings.Count(s, "ocliv/") < 3 {
		t.Fatalf("version string hides the protocol range: %q", s)
	}
}
