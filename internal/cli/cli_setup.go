package cli

// `ocliv setup`: automated detection and bootstrapping of a self-hosted
// public relay. Slice 1 is detection-only: it classifies the host's
// inbound prospects (direct, NAT, CGNAT, unknown) and prints the
// concrete next steps. It changes nothing: no DNS updates, no router
// changes, no services, no credentials.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"ocliv/internal/apperr"
	"ocliv/internal/setup"
)

// Default echo endpoints observe the egress address per family. They
// are diagnostics-only (best effort, 8s each inside the 30s budget),
// receive no credentials, and can be overridden or disabled with empty
// --echo-v4/--echo-v6 values.
const (
	defaultEchoV4 = "https://api4.ipify.org"
	defaultEchoV6 = "https://api6.ipify.org"
)

func cmdSetup(argv []string) int {
	auto := true
	check := false
	jsonOut := false
	echoV4, echoV6 := defaultEchoV4, defaultEchoV6
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--auto":
			auto = true
		case a == "--check":
			check = true
			auto = false
		case a == "--json":
			jsonOut = true
		case strings.HasPrefix(a, "--echo-v4="):
			echoV4 = strings.TrimPrefix(a, "--echo-v4=")
		case a == "--echo-v4" && i+1 < len(argv):
			i++
			echoV4 = argv[i]
		case strings.HasPrefix(a, "--echo-v6="):
			echoV6 = strings.TrimPrefix(a, "--echo-v6=")
		case a == "--echo-v6" && i+1 < len(argv):
			i++
			echoV6 = argv[i]
		default:
			fmt.Fprintf(os.Stderr, "unknown setup flag %q; see `ocliv help`\n", a)
			return apperr.ExitCLIValidation
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d := setup.Gather(ctx, echoV4, echoV6)
	if jsonOut {
		raw, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return apperr.ExitInternal
		}
		fmt.Println(string(raw))
		return apperr.ExitOK
	}
	printSetupReport(d)
	if check || !auto {
		return apperr.ExitOK
	}
	printSetupNext(d)
	return apperr.ExitOK
}

func printSetupReport(d setup.Detection) {
	fmt.Printf("path: %s\n", d.Path)
	fmt.Printf("egress v4: %s  egress v6: %s\n", nonEmpty(d.EgressV4), nonEmpty(d.EgressV6))
	fmt.Printf("local v4: %s\n", strings.Join(d.LocalV4, ", "))
	fmt.Printf("local v6: %s\n", strings.Join(d.LocalV6, ", "))
	fmt.Printf("cgnat v4: %v  direct v4: %v  direct v6: %v\n", d.CGNATv4, d.DirectV4, d.DirectV6)
	fmt.Printf("inbound: UNKNOWN (outbound echo does not prove inbound reachability)\n")
	for _, n := range d.Notes {
		fmt.Printf("- %s\n", n)
	}
}

// printSetupNext gives the concrete next steps for the detected path.
// These are manual until provisioning slices automate them; each step
// names the exact permission or account action the operator must take.
func printSetupNext(d setup.Detection) {
	fmt.Printf("\nnext:\n")
	switch d.Path {
	case setup.PathDirectV6, setup.PathDirectV4:
		fam := "IPv6"
		if d.Path == setup.PathDirectV4 {
			fam = "IPv4"
		}
		fmt.Printf("- Pick a free DNS name (e.g. a dynv6 hostname) and point it at this host's public %s address.\n", fam)
		fmt.Printf("- Allow TCP 80/443 inbound in the host firewall; this host can serve directly (relay stays on 127.0.0.1, Caddy terminates TLS).\n")
		fmt.Printf("- Re-run `ocliv setup --auto` once DNS resolves here; provisioning continues from the stored detection.\n")
	case setup.PathNATV4:
		fmt.Printf("- In the router admin page, forward TCP 80 and 443 to this host (%s).\n", firstOr(d.LocalV4, "its LAN address"))
		fmt.Printf("- Pick a free DNS name (e.g. dynv6) pointing at the router's public IPv4; keep it updated if the address changes.\n")
		fmt.Printf("- Re-run `ocliv setup --auto` after the forward is in place.\n")
	case setup.PathCGNAT:
		fmt.Printf("- No direct IPv4 inbound path exists (carrier-grade NAT): port forwarding cannot work.\n")
		if d.DirectV6 || d.EgressV6 != "" {
			fmt.Printf("- IPv6 egress was observed: if the address is stable and globally reachable, serve over IPv6 (see the direct path above).\n")
		}
		fmt.Printf("- Otherwise a provider-hosted relay is required; that adapter is not implemented yet.\n")
	default:
		fmt.Printf("- Egress could not be observed: check network connectivity, then re-run `ocliv setup --check`.\n")
	}
}

func nonEmpty(s string) string {
	if s == "" {
		return "(unobserved)"
	}
	return s
}

func firstOr(ss []string, fallback string) string {
	if len(ss) > 0 {
		return ss[0]
	}
	return fallback
}
