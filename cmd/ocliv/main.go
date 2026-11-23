// Command ocliv is the single Ocliv executable: agent, relay, diagnostics.
package main

import (
	"os"

	"github.com/B-A-M-N/ocliv/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
