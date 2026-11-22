package planner

import (
	"context"
	"strings"
)

// Deterministic is the proposer that needs no model. It walks the ranked queue in
// order and proposes each hypothesis as a read-only step, carrying the queue's
// own oracle and reasons. It is the floor the seam stands on: with it, kai prints
// the same plan it always has, so switching the LLM on changes the suggestions
// and never the shape of the artifact.
type Deterministic struct{}

// Name identifies the proposer in the artifact.
func (Deterministic) Name() string { return "deterministic" }

// Propose turns the queue into steps. It is pure: no clock, no disk, no network,
// so two runs over one brief are byte-identical.
func (Deterministic) Propose(ctx context.Context, b Brief) ([]Step, Usage, error) {
	if err := ctx.Err(); err != nil {
		return nil, Usage{}, err
	}
	steps := make([]Step, 0, len(b.Queue))
	for _, it := range b.Queue {
		steps = append(steps, Step{
			Target:    it.Target,
			Class:     it.Class,
			Action:    ReadOnly,
			Expected:  it.Probe,
			Rationale: strings.Join(it.Why, "; "),
			Source:    "deterministic",
		})
	}
	return steps, Usage{}, nil
}
