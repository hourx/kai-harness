package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/hourx/kai-harness/pkg/planner"
	"github.com/hourx/kai-harness/pkg/scope"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// cmdDecide runs the LLM seam. It assembles a brief from the workspace, asks the
// configured proposer for a plan, validates every step against the scope gate,
// and writes the result as an artifact. It opens no socket to a target: the plan
// is a decision, and running the steps is a separate, operator-authorized act.
//
// With no endpoint configured — or with the kill switch thrown — the
// deterministic proposer still produces the same artifact from the ranked
// queue, so this command is useful on a box with no model at all.
func cmdDecide(args []string) int {
	pos, rest := split(args, map[string]bool{"limit": true, "archetype": true, "out": true})
	fs := flag.NewFlagSet("decide", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	limit := fs.Int("limit", 0, "cap how many steps the proposer may offer (default: the config's max_steps)")
	asJSON := fs.Bool("json", false, "print the plan as JSON")
	det := fs.Bool("deterministic", false, "skip the model even if one is configured")
	dryRun := fs.Bool("dry-run", false, "print the plan without writing state/proposal.json")
	archetype := fs.String("archetype", "", "override the program's archetype for this run")
	out := fs.String("out", "", "write the plan JSON to this file as well")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai decide <program> [--json] [--limit N] [--deterministic] [--dry-run] [--archetype NAME] [--out file]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}

	cfg := planner.LoadConfig(p.Dir)
	notes := make([]string, 0, 4)
	if !cfg.Enabled && !*det {
		notes = append(notes, "planner is off: "+cfg.Reason)
	}

	stepLimit := cfg.MaxSteps
	if *limit > 0 {
		stepLimit = *limit
	}

	brief, briefNotes, err := planner.BuildBrief(p, *archetype, stepLimit)
	if err != nil {
		return fail(err)
	}
	notes = append(notes, briefNotes...)

	gate, err := scope.LoadGate(p.Dir)
	if err != nil {
		return fail(err)
	}

	now := time.Now().UTC()
	proposer, budgetNote := pickProposer(cfg, *det, p.Dir, now)
	if budgetNote != "" {
		notes = append(notes, budgetNote)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	budget := planner.Budget{MaxSteps: stepLimit, MaxTokens: cfg.MaxTokens}
	plan := planner.Run(ctx, brief, proposer, gate, budget, now)
	plan.Notes = append(notes, plan.Notes...)

	// Spend is recorded only when a model actually answered, and only on a real
	// run: a dry run must not consume the day's budget.
	if !*dryRun && plan.Budget.TokensUsed > 0 {
		if err := planner.RecordUsage(p.Dir, now, plan.Budget.TokensUsed); err != nil {
			fmt.Fprintf(os.Stderr, "kai: could not record the planner spend: %v\n", err)
		}
	}

	if *out != "" {
		b, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return fail(err)
		}
		if err := os.WriteFile(*out, append(b, '\n'), 0o600); err != nil {
			return fail(err)
		}
	}

	if *asJSON {
		b, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return fail(err)
		}
		fmt.Println(string(b))
	} else {
		renderPlan(plan)
	}

	if *dryRun {
		fmt.Fprintln(os.Stderr, "dry-run: nothing written")
		return 0
	}
	jsonPath, mdPath, err := planner.Write(p.Dir, plan)
	if err != nil {
		return fail(err)
	}
	// Progress lines go to stderr: stdout stays machine-readable for --json.
	fmt.Fprintf(os.Stderr, "wrote %s\nwrote %s\n", jsonPath, mdPath)
	return 0
}

// pickProposer decides who answers, and says why when it is not the model. The
// budget is checked here, before a request is sent, because a day's allowance is
// a hard stop and not a warning.
func pickProposer(cfg planner.Config, forceDeterministic bool, pDir string, now time.Time) (planner.Proposer, string) {
	if forceDeterministic {
		return nil, "--deterministic was set — the ranked queue is proposed as-is"
	}
	if !cfg.Enabled {
		return nil, ""
	}
	if cfg.MaxTokens > 0 {
		used, calls := planner.UsageToday(pDir, now)
		if used >= cfg.MaxTokens {
			return nil, fmt.Sprintf("the day's token budget is spent (%d/%d over %d call(s)) — using the deterministic proposer", used, cfg.MaxTokens, calls)
		}
	}
	return cfg.Proposer(), ""
}

// renderPlan prints a compact, human-readable summary. The steps come after the
// counts, and the dropped list last: what was refused is the part that explains
// the plan's shape.
func renderPlan(p planner.Plan) {
	who := p.Proposer
	if p.Fallback {
		who += " (fallback)"
	} else if p.Model != "" {
		who += " · " + p.Model
	}
	fmt.Printf("%s: %d step(s), %d dropped — proposer %s\n", p.Program, p.Budget.StepsKept, p.Budget.StepsDropped, who)
	if p.Budget.TokensUsed > 0 || p.Budget.MaxTokens > 0 {
		fmt.Printf("budget   %d/%d steps, %d/%d tokens today\n", p.Budget.StepsKept, p.Budget.MaxSteps, p.Budget.TokensUsed, p.Budget.MaxTokens)
	}
	for _, n := range p.Notes {
		fmt.Printf("note     %s\n", n)
	}
	if len(p.Steps) == 0 {
		fmt.Println("nothing passed validation")
	} else {
		for i, s := range p.Steps {
			fmt.Printf("  #%d [%s] %s — %s\n", i+1, s.Action, s.Class, s.Target)
		}
	}
	for _, d := range p.Dropped {
		fmt.Printf("  dropped  %s — %s\n", d.Target, d.Reason)
	}
}
