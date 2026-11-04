package install_test

// Regression: systemd-analyze verify rejects unit filenames with extra
// suffixes ("Invalid argument"), so the staged unit MUST be validated
// under its proper unit name (ocliv-relay.service) inside a staging
// directory — never as ocliv-relay.service.new.$$. Found live on a
// clean host during qualification: upgrades failed with
// "staged unit failed systemd-analyze verify" though the unit itself
// was valid. This test pins the staging layout textually (the shimmed
// hermetic drills above cannot see the real filename validation).

import (
	"os"
	"strings"
	"testing"
)

func TestStagedUnitUsesProperUnitName(t *testing.T) {
	raw, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if !strings.Contains(src, "STAGE_DIR=") || !strings.Contains(src, "STAGED_UNIT=\"$STAGE_DIR/ocliv-relay.service\"") {
		t.Fatal("installer must stage the unit under its proper name for systemd-analyze verify")
	}
	for _, bad := range []string{`STAGED_UNIT="$UNIT_FILE.new`, `STAGED_UNIT="$UNIT_FILE".new`} {
		if strings.Contains(src, bad) {
			t.Fatalf("suffixed staged unit name %q: systemd-analyze verify rejects it", bad)
		}
	}
}
