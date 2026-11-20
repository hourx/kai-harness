package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hourx/kai-harness/pkg/hypothesis"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// cmdPlan turns the ranked queue into an engagement plan grouped by what each
// hypothesis needs before it can be attempted. Pure data in, pure data out: no
// request is sent and nothing is decided on the operator's behalf.
func cmdPlan(args []string) int {
	pos, rest := split(args, map[string]bool{"out": true})
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", "", "write plan.md to this file instead of <program>/plan.md")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai plan <program> [--out file]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	queue, err := surface.LoadPlan(p.Dir)
	if err != nil {
		return fail(err)
	}
	if len(queue.Items) == 0 {
		return fail(fmt.Errorf("no ranked queue yet — run: kai map %s && kai next %s", p.Name, p.Name))
	}

	plan := hypothesis.Build(queue)
	jsonPath, mdPath, err := hypothesis.Write(p.Dir, plan)
	if err != nil {
		return fail(err)
	}
	if *out != "" {
		dest := *out
		if abs, err := filepath.Abs(dest); err == nil {
			dest = abs
		}
		if err := os.WriteFile(dest, []byte(plan.Markdown()), 0o600); err != nil {
			return fail(err)
		}
		mdPath = dest
	}

	fmt.Printf("%s: %d step(s) in %d wave(s) from %d queue item(s)\n", p.Name, len(plan.Steps), len(plan.Waves), len(queue.Items))
	for _, w := range plan.Waves {
		fmt.Printf("  wave %d — %s: %d step(s)\n", w.N, w.Name, w.Count)
	}
	show := 3
	if len(plan.Steps) < show {
		show = len(plan.Steps)
	}
	for _, s := range plan.Steps[:show] {
		fmt.Printf("  #%d [%s] %s — %s (score %d)\n", s.Rank, s.Needs, s.Class, s.Target, s.Score)
	}
	fmt.Printf("wrote %s\nwrote %s\n", jsonPath, mdPath)
	return 0
}
