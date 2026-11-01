package setup

// Oracle Always Free adapter contract (Slice 5): when the local host
// has no direct inbound path, an optional provider adapter can host
// the relay instead. The adapter NEVER creates billable resources
// silently: Check verifies the operator's own authorized tooling,
// Plan prints the exact free-tier shape and its no-guarantee bounds,
// and Create runs only with explicit --confirm-create. Without the
// operator's cloud account, every live step reports BLOCKED with the
// exact prerequisite — never a fabricated success.

import (
	"context"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	binaries map[string]bool
	files    map[string]bool
	ran      [][]string
	fail     bool
}

func (f *fakeRunner) lookPath(bin string) bool    { return f.binaries[bin] }
func (f *fakeRunner) fileExists(path string) bool { return f.files[path] }
func (f *fakeRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	f.ran = append(f.ran, append([]string{name}, args...))
	if f.fail {
		return "", errFakeRun
	}
	return "ocid1.instance.fake", nil
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

const errFakeRun = fakeErr("fake run failure")

func TestOracleCheckRequiresCLIAndConfig(t *testing.T) {
	a := OracleAdapter{Runner: &fakeRunner{}}
	if _, ok := a.Check(context.Background()); ok {
		t.Fatal("check passed without oci CLI or config")
	}
	okRunner := &fakeRunner{
		binaries: map[string]bool{"oci": true},
		files:    map[string]bool{"/home/u/.oci/config": true},
	}
	a2 := OracleAdapter{Runner: okRunner, ConfigFile: "/home/u/.oci/config"}
	msg, ok := a2.Check(context.Background())
	if !ok || msg == "" {
		t.Fatalf("check failed with CLI+config present: ok=%v msg=%q", ok, msg)
	}
}

func TestOraclePlanStatesFreeTierBounds(t *testing.T) {
	a := OracleAdapter{}
	plan := a.Plan()
	for _, want := range []string{"A1.Flex", "Always Free", "no guarantee", "approve"} {
		found := false
		for _, line := range strings.Split(strings.ToLower(plan), "\n") {
			if strings.Contains(line, strings.ToLower(want)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("plan omits %q:\n%s", want, plan)
		}
	}
}

func TestOracleCreateNeedsExplicitConfirm(t *testing.T) {
	r := &fakeRunner{binaries: map[string]bool{"oci": true}}
	a := OracleAdapter{Runner: r, Compartment: "ocid1.compartment.fake", Zone: "AD-1"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Create(ctx, false); err == nil {
		t.Fatal("create ran without explicit confirmation")
	}
	if len(r.ran) != 0 {
		t.Fatalf("unconfirmed create executed %d commands", len(r.ran))
	}
	if err := a.Create(ctx, true); err != nil {
		t.Fatalf("confirmed create failed: %v", err)
	}
	if len(r.ran) != 1 || r.ran[0][0] != "oci" {
		t.Fatalf("confirmed create ran %v, want one oci launch", r.ran)
	}
}

func TestOracleCreateRefusesWithoutScope(t *testing.T) {
	r := &fakeRunner{binaries: map[string]bool{"oci": true}}
	a := OracleAdapter{Runner: r}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Create(ctx, true); err == nil {
		t.Fatal("confirmed create ran without compartment/zone")
	}
	if len(r.ran) != 0 {
		t.Fatalf("unscoped create executed %d commands", len(r.ran))
	}
}
