package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpstreamAuthQualificationRequiresMissingAndInvalidRejection(t *testing.T) {
	for _, tc := range []struct {
		name          string
		rejectMissing bool
		rejectInvalid bool
		wantEnforced  bool
	}{
		{name: "rejects missing and invalid bearer", rejectMissing: true, rejectInvalid: true, wantEnforced: true},
		{name: "accepts missing bearer", rejectMissing: false, rejectInvalid: true, wantEnforced: false},
		{name: "accepts invalid bearer", rejectMissing: true, rejectInvalid: false, wantEnforced: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if (auth == "" && tc.rejectMissing) ||
					(strings.HasPrefix(auth, "Bearer ocliv-invalid-") && tc.rejectInvalid) {
					w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
			}))
			defer srv.Close()
			target := probeTarget(srv)
			got := verifyUpstreamAuthEnforcement(target)
			if got != tc.wantEnforced {
				t.Fatalf("authorization enforcement=%v, want %v", got, tc.wantEnforced)
			}
			out := runMCPProbeWithBearer(target, "mcp_upstream_oauth", "valid-upstream-token")
			if !out.Verified {
				t.Fatalf("valid local bearer did not verify tools/list: %+v", out)
			}
			out.AuthEnforced = got
			if publishLocalProbeOK(out, "upstream-oauth", false) != tc.wantEnforced {
				t.Fatalf("publish gate did not preserve auth evidence: %+v", out)
			}
			if publishLocalProbeOK(out, "upstream-oauth", true) != true {
				t.Fatalf("explicit acceptance should allow only the verified protocol result: %+v", out)
			}
		})
	}
}

func TestUpstreamAuthAcceptanceCannotWaiveProtocolVerification(t *testing.T) {
	out := mcpProbeOutcome{Auth: "AUTH_REQUIRED", Verified: false}
	if publishLocalProbeOK(out, "upstream-oauth", true) {
		t.Fatal("explicit acceptance of unverified auth must not waive MCP protocol verification")
	}
}
