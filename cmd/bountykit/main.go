// Command bountykit builds deterministic context packs for bug bounty work.
//
// It covers the mechanical phases (scope intake, recon, mapping prep) and
// hands the result to an agent as a ZIP that mirrors a Kairos workspace.
package main

import (
	"os"

	"github.com/hourx/bountykit/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
