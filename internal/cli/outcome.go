package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// cmdOutcome records what a target turned out to be — the return path of the
// loop. `kai next` drops targets that are already classified and lifts the ones
// that paid off, so recording an outcome is what keeps the queue honest.
func cmdOutcome(args []string) int {
	if len(args) < 1 {
		return fail(errors.New("usage: kai outcome <program> --status negation|informational|finding|reported|paid [--class C] [--note T] <target...>"))
	}
	name := args[0]
	fs := flag.NewFlagSet("outcome", flag.ContinueOnError)
	status := fs.String("status", "", "negation|informational|finding|reported|paid")
	class := fs.String("class", "", "hypothesis class, e.g. IDOR/BOLA")
	note := fs.String("note", "", "one line of evidence")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	target := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if *status == "" || target == "" {
		return fail(errors.New("usage: kai outcome <program> --status S [--class C] [--note T] <target...>"))
	}
	if !outcome.Valid(*status) {
		return fail(fmt.Errorf("unknown status %q — one of: %s", *status, strings.Join(outcome.Statuses, ", ")))
	}
	p, err := workspace.Open(name)
	if err != nil {
		return fail(err)
	}
	rec := outcome.Record{Target: target, Status: *status, Class: *class, Note: *note}
	if err := outcome.Append(p.Dir, rec); err != nil {
		return fail(err)
	}
	// Read the log back: the next `kai next` depends on this line existing, and
	// a successful write is not the same thing as a readable record.
	tbl, err := outcome.Load(p.Dir)
	if err != nil {
		return fail(err)
	}
	if got, ok := tbl.Last(target); !ok || got.Status != rec.Status {
		return fail(fmt.Errorf("record written but not readable back at %s", outcome.Path(p.Dir)))
	}
	fmt.Printf("recorded %s %s — %d target(s) in history\n", rec.Status, target, tbl.Len())
	return 0
}
