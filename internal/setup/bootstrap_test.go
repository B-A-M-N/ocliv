package setup

// Bootstrap planning contract (Slice 3b): PlanBootstrap turns the
// detected path and the local tool environment into an explicit step
// list. It never touches the system; executors do that live, only as
// root, with backups. CGNAT/unknown paths block with a reason instead
// of a doomed provisioning run.

import (
	"testing"
)

func TestPlanBlocksCGNAT(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{AsRoot: true, CaddyPresent: true, Path: PathCGNAT})
	if len(steps) != 0 {
		t.Fatalf("CGNAT planned %d steps; want none", len(steps))
	}
	if reason == "" {
		t.Fatal("CGNAT blocked without a reason")
	}
}

func TestPlanBlocksUnknown(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{AsRoot: true, CaddyPresent: true, Path: PathUnknown})
	if len(steps) != 0 || reason == "" {
		t.Fatalf("unknown path: steps=%d reason=%q", len(steps), reason)
	}
}

func TestPlanNonRootIsAllManual(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{AsRoot: false, CaddyPresent: true, Path: PathDirectV6, Hostname: "lab.dynv6.net", DeployDir: "/tmp/x"})
	if reason != "" {
		t.Fatalf("viable path blocked: %q", reason)
	}
	if len(steps) == 0 {
		t.Fatal("no steps planned")
	}
	for _, s := range steps {
		if s.Auto {
			t.Errorf("non-root step %q marked auto", s.Title)
		}
		if s.Manual == "" {
			t.Errorf("non-root step %q has no manual command", s.Title)
		}
	}
}

func TestPlanRootWithCaddyIsAllAuto(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{AsRoot: true, CaddyPresent: true, Path: PathDirectV4, Hostname: "lab.dynv6.net", DeployDir: "/tmp/x"})
	if reason != "" {
		t.Fatalf("viable path blocked: %q", reason)
	}
	if len(steps) == 0 {
		t.Fatal("no steps planned")
	}
	for _, s := range steps {
		if s.Title == "enroll this machine" {
			if s.Auto {
				t.Error("enrollment must stay manual until the auto-enrollment loop lands")
			}
			continue
		}
		if !s.Auto {
			t.Errorf("root+caddy step %q not auto", s.Title)
		}
	}
}

func TestPlanRootWithoutCaddyStopsAtInstall(t *testing.T) {
	steps, reason := PlanBootstrap(BootstrapEnv{AsRoot: true, CaddyPresent: false, Path: PathDirectV4})
	if len(steps) != 1 {
		t.Fatalf("want exactly the install-caddy step, got %d", len(steps))
	}
	if steps[0].Auto {
		t.Error("caddy install must be manual (package manager, user consent)")
	}
	if reason == "" {
		t.Error("missing re-run guidance after Caddy install")
	}
}
