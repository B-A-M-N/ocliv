// Command ocliv is the single Ocliv executable: agent, relay, diagnostics.
package main

import (
	"os"

	"ocliv/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
