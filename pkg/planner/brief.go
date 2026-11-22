package planner

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/hourx/kai-harness/pkg/model"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/pattern"
	"github.com/hourx/kai-harness/pkg/scope"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// maxOutcomeLines caps how much outcome history rides in a brief. The proposer
// needs the recent shape of the program, not its whole life.
const maxOutcomeLines = 40

// Item is one row of the ranked queue as the proposer sees it. It is a copy of a
// surface hypothesis, not the hypothesis itself, so a brief can be serialized
// into a prompt without dragging the queue's internals along.
type Item struct {
	Target string   `json:"target"`
	Class  string   `json:"class"`
	Score  int      `json:"score"`
	Probe  string   `json:"probe,omitempty"`
	Why    []string `json:"why,omitempty"`
}

// Brief is everything a proposer is given. It is assembled from artifacts the
// kernel has already written — the queue, the model, the scope, the outcome log
// — never from a live view of a target. That is what keeps a proposal
// reproducible: the same workspace always yields the same brief.
type Brief struct {
	Program    string   `json:"program"`
	Archetype  string   `json:"archetype,omitempty"`
	Scope      []string `json:"scope"`
	OutOfScope []string `json:"out_of_scope,omitempty"`
	// Hosts are the in-scope rules that name a host, listed so a proposer can
	// write a full target instead of a bare path when it knows which host it
	// means. The host list is the only thing a proposal may name.
	Hosts    []string `json:"hosts,omitempty"`
	Queue    []Item   `json:"queue"`
	Patterns []string `json:"patterns,omitempty"`
	Outcomes []string `json:"outcomes,omitempty"`
	Gaps     []string `json:"gaps,omitempty"`
	Limit    int      `json:"limit"`
}

// BuildBrief assembles the proposer's input. It reads only the workspace and
// opens no sockets. A missing artifact is a note, not an error, except a scope
// that will not parse — a plan built on an unknown scope would be unsound, so
// that one stops the run.
func BuildBrief(p *workspace.Program, archetypeOverride string, limit int) (Brief, []string, error) {
	var notes []string
	b := Brief{Program: p.Name, Limit: limit}

	in, err := scope.Load(filepath.Join(p.Dir, "scope.txt"))
	if err != nil {
		return Brief{}, nil, fmt.Errorf("reading scope: %w", err)
	}
	b.Scope = in
	if len(in) == 0 {
		return Brief{}, nil, errors.New("the scope is empty — a plan cannot be validated against it; add scope rules first")
	}
	out, err := scope.Load(filepath.Join(p.Dir, "out-of-scope.txt"))
	if err != nil {
		return Brief{}, nil, fmt.Errorf("reading out-of-scope: %w", err)
	}
	b.OutOfScope = out

	// The in-scope rules that name a host are the whole address space a proposal
	// may point at. Rules that do not parse as a host (a bare path, a stray
	// word) are still scope, but they cannot be offered as a target.
	for _, r := range in {
		if _, err := scope.Parse(r); err == nil {
			b.Hosts = append(b.Hosts, r)
		}
	}
	if len(b.Hosts) == 0 {
		notes = append(notes, "the scope names no host — every step must name its own host to be validated")
	}

	q, err := surface.LoadPlan(p.Dir)
	if err != nil {
		return Brief{}, nil, fmt.Errorf("reading the ranked queue: %w", err)
	}
	if len(q.Items) == 0 {
		notes = append(notes, "the ranked queue is empty — run `kai map` then `kai next` to build one")
	}
	for _, h := range q.Items {
		b.Queue = append(b.Queue, Item{Target: h.Target, Class: h.Class, Score: h.Score, Probe: h.Probe, Why: h.Why})
	}

	if m, err := model.Load(p.Dir); err == nil {
		b.Archetype = m.Archetype
		b.Gaps = m.Gaps
	} else {
		notes = append(notes, "no program model yet — run `kai model` for a sharper plan")
	}
	if archetypeOverride != "" {
		b.Archetype = archetypeOverride
	}

	lib := pattern.Public()
	if a, ok, err := pattern.WorkspaceAdapter(p.Dir); err == nil && ok {
		if widened, warns, err := pattern.LoadAdapters(lib, a); err == nil {
			lib = widened
			notes = append(notes, warns...)
		} else {
			notes = append(notes, "workspace patterns were not loaded: "+err.Error())
		}
	}
	for _, pat := range lib.For(b.Archetype) {
		b.Patterns = append(b.Patterns, fmt.Sprintf("%s (confidence %.2f)", pat.Key.String(), pat.Confidence))
	}

	if tbl, err := outcome.Load(p.Dir); err == nil {
		recs := tbl.Records()
		// Keep the newest lines: the proposer reasons about what just happened.
		sort.SliceStable(recs, func(i, j int) bool { return recs[i].Time().After(recs[j].Time()) })
		if len(recs) > maxOutcomeLines {
			recs = recs[:maxOutcomeLines]
			notes = append(notes, fmt.Sprintf("the brief carries the %d most recent outcomes only", maxOutcomeLines))
		}
		for _, r := range recs {
			line := r.Target + " → " + r.Status
			if r.Class != "" {
				line += " (" + r.Class + ")"
			}
			b.Outcomes = append(b.Outcomes, line)
		}
	}
	return b, notes, nil
}
