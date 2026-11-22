// Package planner is kai's LLM seam. It sits at an edge of the system, never in
// the kernel: it reads a workspace's own artifacts, asks a proposer for a plan,
// validates every proposed step against the scope gate and the action-class
// policy, and writes the result as a recorded artifact. It never opens a socket
// to a target and it never executes a step — the kernel does that, from the plan
// on disk.
//
// The seam degrades toward the artifact, never toward an error. With no endpoint
// configured, with the kill switch thrown, or with the model unreachable, the
// deterministic proposer turns the ranked queue into the same Plan shape, so a
// run is reproducible and useful with the model switched off entirely.
package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/scope"
)

// ActionClass is what a step is allowed to do. The policy is fixed and lives
// here, not in the proposer's output: a proposal cannot promote itself, and the
// validator — not the model — has the last word on what may run unattended.
type ActionClass string

const (
	// ReadOnly asks a target for data and changes nothing observable. It is the
	// only class that may run unattended.
	ReadOnly ActionClass = "read-only"
	// StateChanging writes: a POST/PUT/DELETE, a new account, an order. It stays
	// in the plan only to be run once the operator says so, every time.
	StateChanging ActionClass = "state-changing"
	// Destructive is refused on sight. It is a class rather than an error so the
	// refusal can say why in the dropped list.
	Destructive ActionClass = "destructive"
)

// Known reports whether c is a class the policy understands.
func (c ActionClass) Known() bool {
	switch c {
	case ReadOnly, StateChanging, Destructive:
		return true
	}
	return false
}

// Step is one proposed action: a target, what it would do, and what a positive
// result looks like. Expected is the oracle — the observation that would make
// the step worth reporting — written down before anything is run.
type Step struct {
	Target    string      `json:"target"`
	Class     string      `json:"class"`
	Action    ActionClass `json:"action"`
	Pattern   string      `json:"pattern,omitempty"`
	Expected  string      `json:"expected_oracle"`
	Rationale string      `json:"rationale,omitempty"`
	Source    string      `json:"source"`
}

// Drop is a proposal the validator refused, kept so a refusal is visible in the
// artifact rather than silent.
type Drop struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
}

// Budget is what the planner was allowed to spend and what it spent.
type Budget struct {
	MaxSteps     int `json:"max_steps"`
	MaxTokens    int `json:"max_tokens_per_day"`
	TokensUsed   int `json:"tokens_used_today"`
	StepsKept    int `json:"steps_kept"`
	StepsDropped int `json:"steps_dropped"`
}

// Plan is the artifact the seam produces. It is the recorded decision: with the
// model disabled the same file can be replayed, because the queue it came from
// is deterministic.
type Plan struct {
	Program   string   `json:"program"`
	Proposer  string   `json:"proposer"`
	Model     string   `json:"model,omitempty"`
	Generated string   `json:"generated"`
	Fallback  bool     `json:"fallback"`
	Steps     []Step   `json:"steps"`
	Dropped   []Drop   `json:"dropped,omitempty"`
	Budget    Budget   `json:"budget"`
	Notes     []string `json:"notes,omitempty"`
}

// Usage is what a proposer spent, so a day's token budget can be tracked.
type Usage struct {
	Model  string `json:"model,omitempty"`
	Tokens int    `json:"tokens"`
}

// Proposer turns a brief into proposed steps. The interface says nothing about
// the network: a stub that returns fixed steps is a proposer too, which is how
// the seam is tested without a model.
type Proposer interface {
	Name() string
	Propose(ctx context.Context, b Brief) ([]Step, Usage, error)
}

// Validate is the kernel's say over the proposer's output. It parses every
// proposed target, asks the scope gate, and applies the action policy. It can
// only ever remove a step: a target the scope does not mention is dropped, never
// "repaired" into something that might be in scope. Order is preserved so the
// proposer's ranking survives.
//
// Two target shapes are accepted, because the kernel's own queue uses the second
// one: a full host ("api.example.com/orders") is checked against the gate, and a
// method-plus-path ("GET /orders") is a path on the program's surface whose host
// is implied. A path-only step is kept only when the scope names at least one
// host to attach it to, and it is marked so the host is chosen deliberately
// rather than by the proposer.
func Validate(steps []Step, g scope.Gate, maxSteps int) ([]Step, []Drop) {
	kept := make([]Step, 0, len(steps))
	var dropped []Drop
	for _, s := range steps {
		t := strings.TrimSpace(s.Target)
		if t == "" {
			dropped = append(dropped, Drop{s.Target, "no target"})
			continue
		}
		if !s.Action.Known() {
			dropped = append(dropped, Drop{s.Target, fmt.Sprintf("action %q is not one of read-only/state-changing/destructive", string(s.Action))})
			continue
		}
		if s.Action == Destructive {
			dropped = append(dropped, Drop{s.Target, "a destructive action is never taken"})
			continue
		}
		pathOnly := false
		if _, _, ok := methodPath(t); ok {
			pathOnly = true
			if !hasHostRule(g) {
				dropped = append(dropped, Drop{s.Target, "path-only target, and the scope names no host to attach it to"})
				continue
			}
		} else if target, err := scope.Parse(t); err != nil {
			dropped = append(dropped, Drop{s.Target, "target does not parse: " + err.Error()})
			continue
		} else if ok, reason := g.Check(target); !ok {
			dropped = append(dropped, Drop{s.Target, "out of scope: " + reason})
			continue
		}
		if maxSteps > 0 && len(kept) >= maxSteps {
			dropped = append(dropped, Drop{s.Target, fmt.Sprintf("over the step budget of %d", maxSteps)})
			continue
		}
		if s.Action == StateChanging {
			s.Rationale = strings.TrimSpace(s.Rationale + " [needs the operator's word: state-changing]")
		}
		if pathOnly {
			s.Rationale = strings.TrimSpace(s.Rationale + " [path-only target: attach an in-scope host before sending]")
		}
		if s.Expected == "" {
			s.Expected = "state what a positive result would look like before running this"
		}
		kept = append(kept, s)
	}
	return kept, dropped
}

// httpMethods is the set a queue target may lead with.
var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
	"HEAD": true, "OPTIONS": true, "TRACE": true,
}

// methodPath recognises the queue's target shape: an optional HTTP method
// followed by an absolute path. "/orders" and "GET /orders/{id}" both match; a
// host always wins, so "api.example.com/orders" is left to the scope gate.
func methodPath(raw string) (method, path string, ok bool) {
	s := strings.TrimSpace(raw)
	if f := strings.Fields(s); len(f) == 2 && httpMethods[strings.ToUpper(f[0])] && strings.HasPrefix(f[1], "/") {
		return strings.ToUpper(f[0]), f[1], true
	}
	if strings.HasPrefix(s, "/") {
		return "", s, true
	}
	return "", "", false
}

// hasHostRule reports whether the scope names at least one host, which is what a
// path-only target needs before it can be sent anywhere.
func hasHostRule(g scope.Gate) bool {
	for _, r := range g.In {
		if _, err := scope.Parse(r); err == nil {
			return true
		}
	}
	return false
}

// Run is the whole seam in one call: propose, then validate, then assemble the
// artifact. A nil proposer, or a proposer that fails, falls back to the
// deterministic one and records why — the model's absence is a note, not an
// error, because a complete plan must survive it.
func Run(ctx context.Context, b Brief, p Proposer, g scope.Gate, budget Budget, now time.Time) Plan {
	steps, usage, notes := proposeWith(ctx, b, p)

	// Every step must be attributable, even when a proposer forgot to name
	// itself. The artifact is the record of who suggested what.
	name := proposerName(p)
	for i := range steps {
		if strings.TrimSpace(steps[i].Source) == "" {
			if usage.Model != "" {
				steps[i].Source = "llm:" + usage.Model
			} else {
				steps[i].Source = name
			}
		}
	}

	if b.Limit > 0 && len(steps) > b.Limit {
		steps = steps[:b.Limit]
		notes = append(notes, fmt.Sprintf("proposer offered more than the %d-step limit; the tail was cut before validation", b.Limit))
	}
	kept, dropped := Validate(steps, g, budget.MaxSteps)
	sort.SliceStable(dropped, func(i, j int) bool { return dropped[i].Target < dropped[j].Target })

	plan := Plan{
		Program:   b.Program,
		Proposer:  name,
		Model:     usage.Model,
		Generated: now.UTC().Format(time.RFC3339),
		Fallback:  usage.Model == "",
		Steps:     kept,
		Dropped:   dropped,
		Budget: Budget{
			MaxSteps:     budget.MaxSteps,
			MaxTokens:    budget.MaxTokens,
			TokensUsed:   usage.Tokens,
			StepsKept:    len(kept),
			StepsDropped: len(dropped),
		},
		Notes: notes,
	}
	if plan.Steps == nil {
		plan.Steps = []Step{}
	}
	return plan
}

// proposeWith tries the configured proposer first and the deterministic one
// second. It returns the notes that explain a fallback.
func proposeWith(ctx context.Context, b Brief, p Proposer) ([]Step, Usage, []string) {
	det := Deterministic{}
	if p == nil {
		steps, usage, err := det.Propose(ctx, b)
		if err != nil {
			return nil, Usage{}, []string{"deterministic proposer failed: " + err.Error()}
		}
		return steps, usage, []string{"no planner endpoint is configured — the ranked queue was proposed as-is"}
	}
	steps, usage, err := p.Propose(ctx, b)
	if err != nil {
		fsteps, fusage, ferr := det.Propose(ctx, b)
		if ferr != nil {
			return nil, Usage{}, []string{fmt.Sprintf("proposer %s failed (%v) and the deterministic fallback failed too (%v)", p.Name(), err, ferr)}
		}
		return fsteps, fusage, []string{fmt.Sprintf("proposer %s failed: %v — fell back to the deterministic proposer", p.Name(), err)}
	}
	return steps, usage, nil
}

// proposerName names who actually answered, not who was asked.
func proposerName(p Proposer) string {
	if p == nil {
		return Deterministic{}.Name()
	}
	return p.Name()
}

// Path is where the proposal artifact lives.
func Path(pDir string) string { return filepath.Join(pDir, "state", "proposal.json") }

// Write records the plan. The artifact is owner-only: it names targets, and it
// is the decision of record for whoever runs the steps.
func Write(pDir string, p Plan) (jsonPath, mdPath string, err error) {
	if err := os.MkdirAll(filepath.Join(pDir, "state"), 0o700); err != nil {
		return "", "", err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", "", err
	}
	b = append(b, '\n')
	jsonPath = Path(pDir)
	if err := os.WriteFile(jsonPath, b, 0o600); err != nil {
		return "", "", err
	}
	mdPath = filepath.Join(pDir, "state", "proposal.md")
	if err := os.WriteFile(mdPath, []byte(p.Markdown()), 0o600); err != nil {
		return "", "", err
	}
	return jsonPath, mdPath, nil
}

// Markdown renders the plan for a human. The dropped list comes before the
// steps: what was refused is the part a reader has to check.
func (p Plan) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Proposal — %s\n\n", p.Program)
	fmt.Fprintf(&b, "- Proposer: %s", p.Proposer)
	if p.Model != "" {
		fmt.Fprintf(&b, " (model %s)", p.Model)
	}
	if p.Fallback {
		fmt.Fprintf(&b, " (deterministic fallback)")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- Generated: %s\n", p.Generated)
	fmt.Fprintf(&b, "- Steps: %d kept, %d dropped\n", p.Budget.StepsKept, p.Budget.StepsDropped)
	fmt.Fprintf(&b, "- Budget: %d/%d steps, %d/%d tokens today\n", p.Budget.StepsKept, p.Budget.MaxSteps, p.Budget.TokensUsed, p.Budget.MaxTokens)
	if len(p.Notes) > 0 {
		b.WriteString("\n")
		for _, n := range p.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
	}
	if len(p.Dropped) > 0 {
		fmt.Fprintf(&b, "\n## Dropped before running\n\n")
		for _, d := range p.Dropped {
			fmt.Fprintf(&b, "- `%s` — %s\n", d.Target, d.Reason)
		}
	}
	fmt.Fprintf(&b, "\n## Steps\n\n")
	if len(p.Steps) == 0 {
		b.WriteString("Nothing passed validation. Add scope rules or run `kai next` to build a queue.\n")
		return b.String()
	}
	for i, s := range p.Steps {
		fmt.Fprintf(&b, "%d. **%s** `%s` — %s\n", i+1, s.Action, s.Target, s.Class)
		fmt.Fprintf(&b, "   - oracle: %s\n", s.Expected)
		if s.Pattern != "" {
			fmt.Fprintf(&b, "   - pattern: %s\n", s.Pattern)
		}
		if s.Rationale != "" {
			fmt.Fprintf(&b, "   - why: %s\n", s.Rationale)
		}
		fmt.Fprintf(&b, "   - source: %s\n", s.Source)
	}
	return b.String()
}
