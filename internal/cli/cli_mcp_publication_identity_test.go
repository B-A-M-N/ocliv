package cli

// P1: a bare `ocliv mcp PORT` must have a DURABLE publication identity.
//
// The alias is the one-command publishing path the product leads with, and
// it minted a random publication name on every run. Two consequences, both
// observed live:
//
//   - the public URL changed on every restart, so the endpoint an operator
//     handed to a client was not durable;
//   - each run created a SECOND publication row under the same owner,
//     leaving orphaned routes behind.
//
// The durable identity must be derived from the SERVICE (the local target
// it publishes), not from the moment it was published: the same configured
// service must map to the same publication name every time.
//
// Requirements this pins:
//   - the same local target always yields the same publication name;
//   - two different local targets never collide;
//   - the name is a valid DNS label (the relay mints a hostname from it);
//   - an EXPLICIT --name still wins (the operator's choice is never
//     overridden);
//   - an operator can still ask for a FRESH publication (a new identity)
//     even when the service already has one.
import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	"ocliv/internal/lease"
)

// TestDefaultPublicationNameIsStable pins the core property: the same
// service maps to the same name, every time.
func TestDefaultPublicationNameIsStable(t *testing.T) {
	first := defaultPublicationName(8765, "http://127.0.0.1:8765/mcp", "ocliv-managed")
	for i := 0; i < 5; i++ {
		again := defaultPublicationName(8765, "http://127.0.0.1:8765/mcp", "ocliv-managed")
		if again != first {
			t.Fatalf("publication name is not stable: %q then %q", first, again)
		}
	}
}

// TestDefaultPublicationNameDistinguishesTargets pins that two services
// never share an identity.
func TestDefaultPublicationNameDistinguishesTargets(t *testing.T) {
	a := defaultPublicationName(8765, "http://127.0.0.1:8765/mcp", "ocliv-managed")
	b := defaultPublicationName(8766, "http://127.0.0.1:8766/mcp", "ocliv-managed")
	if a == b {
		t.Fatalf("two different local targets share the publication name %q", a)
	}
	// The auth profile is part of the service identity too: the same
	// local server published under a different profile is a different
	// publication.
	c := defaultPublicationName(8765, "http://127.0.0.1:8765/mcp", "upstream-oauth")
	if a == c {
		t.Fatalf("the same target under two auth profiles shares the name %q", a)
	}
}

// TestDefaultPublicationNameIsValidLabel pins that the relay can mint a
// hostname from it: lowercase alphanumerics and hyphens, no leading or
// trailing hyphen, within the 63-character label limit.
func TestDefaultPublicationNameIsValidLabel(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1:8765/mcp",
		"http://127.0.0.1:1/mcp",
		"http://[::1]:8765/mcp",
		"http://127.0.0.1:65535/mcp",
	} {
		for _, profile := range []string{"ocliv-managed", "upstream-oauth"} {
			name := defaultPublicationName(portOf(target), target, profile)
			if err := lease.ValidateLabel(name); err != nil {
				t.Fatalf("name %q for %s/%s is not a valid label: %v", name, target, profile, err)
			}
			if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
				t.Fatalf("name %q has a leading or trailing hyphen", name)
			}
		}
	}
}

// TestDefaultPublicationNameSeparatesStdioServices pins that a stdio-backed
// service (no local URL at all) still gets its own identity: the adapter
// port is what distinguishes one run from another.
func TestDefaultPublicationNameSeparatesStdioServices(t *testing.T) {
	a := defaultPublicationName(45123, "", "ocliv-managed")
	b := defaultPublicationName(45124, "", "ocliv-managed")
	if a == b {
		t.Fatalf("two stdio services on different adapter ports share the name %q", a)
	}
	if err := lease.ValidateLabel(a); err != nil {
		t.Fatalf("stdio name %q is not a valid label: %v", a, err)
	}
}

// portOf extracts the port from a test target.
func portOf(target string) int {
	u, err := url.Parse(target)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(u.Port())
	return n
}

// TestExplicitNameWinsOverDefault pins that the operator's explicit choice
// is never overridden by the derived default.
func TestExplicitNameWinsOverDefault(t *testing.T) {
	pub, ok := mcpPortAliasArgs([]string{"3000", "--name", "mytools"})
	if !ok {
		t.Fatal("port alias not recognized")
	}
	cfg, code := parseMCPPublish(pub, false)
	if code != 0 {
		t.Fatalf("alias argv rejected by publish parser: %v", pub)
	}
	if cfg.name != "mytools" {
		t.Fatalf("explicit --name was overridden: %q", cfg.name)
	}
}

// TestFreshPublicationRequestIsHonored pins that an operator can still
// ask for a NEW identity for a service that already has one, without
// unpublishing first.
func TestFreshPublicationRequestIsHonored(t *testing.T) {
	pub, ok := mcpPortAliasArgs([]string{"3000", "--fresh-publication"})
	if !ok {
		t.Fatal("port alias with --fresh-publication not recognized")
	}
	cfg, code := parseMCPPublish(pub, false)
	if code != 0 {
		t.Fatalf("alias argv rejected by publish parser: %v", pub)
	}
	if !cfg.freshPublication {
		t.Fatal("--fresh-publication did not reach the publish config")
	}
	// The default name is still derived; the fresh request is an
	// explicit overlay on top of it, not a replacement for it.
	if cfg.name != "" {
		t.Fatalf("--fresh-publication invented its own name %q instead of deriving one", cfg.name)
	}
}
