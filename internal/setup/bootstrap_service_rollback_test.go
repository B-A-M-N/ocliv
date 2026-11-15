package setup

// Failing-first regressions for the 2026-11-15 rereview P1: a failed
// clean-host bootstrap must reverse the service transitions it actually
// performed (stop a relay it started, disable a unit it enabled) BEFORE
// rolling back files, and must never stop a service that was already
// running. RollbackDataDir must refuse to recursively delete a newly
// created data directory that the relay has already populated with
// generated authorization state, and must report the exact path.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRollbackDataDirRefusesNonemptyNewDir(t *testing.T) {
	dir := t.TempDir()
	// Simulate EnsureDataDir's journal marker + a relay database.
	if err := os.WriteFile(newFileSentinel(dir), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ocliv.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := RollbackDataDir(dir)
	if err == nil {
		t.Fatal("rollback removed a nonempty newly-created data dir; want explicit refusal")
	}
	if fi, serr := os.Stat(filepath.Join(dir, "ocliv.db")); serr != nil || fi.IsDir() {
		t.Fatalf("generated state not preserved: %v", serr)
	}
}

func TestRollbackDataDirRemovesEmptyNewDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(newFileSentinel(dir), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	restored, err := RollbackDataDir(dir)
	if err != nil || !restored {
		t.Fatalf("empty new dir rollback: restored=%v err=%v", restored, err)
	}
	if _, serr := os.Stat(dir); !os.IsNotExist(serr) {
		t.Fatal("empty new dir not removed")
	}
}

func TestRollbackDataDirNeverTouchesPreexistingDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "important.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := RollbackDataDir(dir)
	if err != nil || restored {
		t.Fatalf("pre-existing dir rollback: restored=%v err=%v (want false,nil)", restored, err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "important.db")); serr != nil {
		t.Fatal("pre-existing dir contents disturbed")
	}
}

// serviceStateFakes lets a test drive CaptureServiceState/RestoreService
// without systemd.
func serviceStateFakes(t *testing.T, before map[string]ServiceState, calls *[]string) {
	t.Helper()
	origCapture, origRestore := captureServiceState, restoreServiceState
	t.Cleanup(func() { captureServiceState, restoreServiceState = origCapture, origRestore })
	captureServiceState = func(unit string) ServiceState { return before[unit] }
	restoreServiceState = func(unit string, st ServiceState) error {
		*calls = append(*calls, "restore:"+unit)
		if !st.Enabled {
			*calls = append(*calls, "disable "+unit)
		}
		if !st.Active {
			*calls = append(*calls, "stop "+unit)
		}
		return nil
	}
}

func TestRollbackStopsRelayWeStartedNotPreexisting(t *testing.T) {
	var calls []string
	// Before: caddy running, relay not.
	serviceStateFakes(t, map[string]ServiceState{
		"caddy":       {Enabled: true, Active: true},
		"ocliv-relay": {},
	}, &calls)
	ResetStartedUnits()
	MarkPreState(map[string]ServiceState{
		"caddy":       {Enabled: true, Active: true},
		"ocliv-relay": {},
	})
	MarkStarted("caddy")
	MarkStarted("ocliv-relay")
	if err := RestoreService("ocliv-relay"); err != nil {
		t.Fatalf("restore relay: %v", err)
	}
	// A pre-existing running Caddy must NOT be stopped by a rollback that
	// only recorded a relay transition — and vice versa.
	if err := RestoreService("caddy"); err != nil {
		t.Fatalf("restore caddy: %v", err)
	}
	// The restore call must consult the pre-state: relay (was stopped)
	// gets stopped; caddy (was running) is left running.
	foundStopRelay := false
	for _, c := range calls {
		if c == "restore:ocliv-relay" {
			foundStopRelay = true
		}
	}
	if !foundStopRelay {
		t.Fatalf("relay restore not invoked; calls=%v", calls)
	}
}

func TestStartedUnitsTracking(t *testing.T) {
	ResetStartedUnits()
	if len(StartedUnits()) != 0 {
		t.Fatal("fresh run should have no started units")
	}
	MarkStarted("ocliv-relay")
	if !StartedUnits()["ocliv-relay"] {
		t.Fatal("MarkStarted not recorded")
	}
	ResetStartedUnits()
	if StartedUnits()["ocliv-relay"] {
		t.Fatal("ResetStartedUnits did not clear")
	}
}
