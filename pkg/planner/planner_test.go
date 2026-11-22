package planner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/pkg/scope"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func testGate(t *testing.T, in, out []string) scope.Gate {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "scope.txt"), strings.Join(in, "\n")+"\n")
	if len(out) > 0 {
		writeFile(t, filepath.Join(dir, "out-of-scope.txt"), strings.Join(out, "\n")+"\n")
	}
	g, err := scope.LoadGate(dir)
	if err != nil {
		t.Fatalf("LoadGate: %v", err)
	}
	return g
}

func TestValidateKeepsOnlyWhatTheScopeAllows(t *testing.T) {
	g := testGate(t,
		[]string{"*.shop.example", "shop.example"},
		[]string{"internal.shop.example"},
	)
	steps := []Step{
		{Target: "api.shop.example/orders", Class: "IDOR/BOLA", Action: ReadOnly, Expected: "x"},
		{Target: "https://evil.example/login", Class: "auth-bypass/ATO", Action: ReadOnly, Expected: "x"},
		{Target: "internal.shop.example/admin", Class: "access-control", Action: ReadOnly, Expected: "x"},
		{Target: "api.shop.example/orders", Class: "business-logic", Action: Destructive, Expected: "x"},
		{Target: "api.shop.example/orders", Class: "business-logic", Action: ActionClass("teleport"), Expected: "x"},
		{Target: "", Class: "graphql", Action: ReadOnly, Expected: "x"},
		{Target: "api.shop.example/checkout", Class: "business-logic", Action: StateChanging, Expected: "order total should not change"},
	}
	kept, dropped := Validate(steps, g, 12)
	if len(kept) != 2 {
		t.Fatalf("want 2 kept, got %d: %+v", len(kept), kept)
	}
	if len(dropped) != 5 {
		t.Fatalf("want 5 dropped, got %d: %+v", len(dropped), dropped)
	}
	for _, d := range dropped {
		if !strings.Contains(d.Reason, "") { // reasons must never be empty
			t.Fatal("empty drop reason")
		}
		switch d.Target {
		case "https://evil.example/login":
			if !strings.Contains(d.Reason, "out of scope") {
				t.Errorf("foreign host reason = %q", d.Reason)
			}
		case "internal.shop.example/admin":
			if !strings.Contains(d.Reason, "out of scope") {
				t.Errorf("out-of-scope rule reason = %q", d.Reason)
			}
		case "api.shop.example/orders":
			if strings.Contains(d.Reason, "teleport") || strings.Contains(d.Reason, "never taken") {
				continue
			}
			t.Errorf("unexpected reason for dup target: %q", d.Reason)
		}
	}
	if !strings.Contains(kept[1].Rationale, "needs the operator's word") {
		t.Errorf("state-changing step was not flagged: %q", kept[1].Rationale)
	}
	// A kept step with no oracle must get a placeholder, never stay blank.
	for _, k := range kept {
		if k.Expected == "" {
			t.Errorf("kept step %q has an empty oracle", k.Target)
		}
	}
}

func TestValidateEnforcesStepBudget(t *testing.T) {
	g := testGate(t, []string{"a.example"}, nil)
	steps := []Step{
		{Target: "a.example/1", Action: ReadOnly, Expected: "x"},
		{Target: "a.example/2", Action: ReadOnly, Expected: "x"},
		{Target: "a.example/3", Action: ReadOnly, Expected: "x"},
	}
	kept, dropped := Validate(steps, g, 2)
	if len(kept) != 2 || len(dropped) != 1 {
		t.Fatalf("budget not enforced: kept=%d dropped=%d", len(kept), len(dropped))
	}
	if !strings.Contains(dropped[0].Reason, "step budget") {
		t.Errorf("budget reason = %q", dropped[0].Reason)
	}
}

func TestRunFallsBackWithNoProposer(t *testing.T) {
	g := testGate(t, []string{"*.shop.example"}, nil)
	b := Brief{Program: "shop", Limit: 5, Queue: []Item{
		{Target: "api.shop.example/orders", Class: "IDOR/BOLA", Score: 40, Probe: "fetch as two users", Why: []string{"object id in path"}},
	}}
	p := Run(context.Background(), b, nil, g, Budget{MaxSteps: 12}, time.Unix(0, 0))
	if !p.Fallback {
		t.Error("a nil proposer must mark the plan as a fallback")
	}
	if p.Budget.StepsKept != 1 || p.Steps[0].Action != ReadOnly {
		t.Fatalf("deterministic step not produced: %+v", p.Steps)
	}
	if p.Steps[0].Expected != "fetch as two users" {
		t.Errorf("oracle not carried from the queue: %q", p.Steps[0].Expected)
	}
	if len(p.Notes) == 0 {
		t.Error("a fallback must say why")
	}
}

type errProposer struct{}

func (errProposer) Name() string { return "boom" }
func (errProposer) Propose(context.Context, Brief) ([]Step, Usage, error) {
	return nil, Usage{}, errors.New("endpoint down")
}

func TestRunFallsBackWhenTheProposerFails(t *testing.T) {
	g := testGate(t, []string{"*.shop.example"}, nil)
	b := Brief{Program: "shop", Queue: []Item{{Target: "api.shop.example/x", Class: "graphql"}}}
	p := Run(context.Background(), b, errProposer{}, g, Budget{MaxSteps: 12}, time.Unix(0, 0))
	if !p.Fallback || len(p.Steps) != 1 {
		t.Fatalf("failed proposer did not fall back: fallback=%v steps=%d", p.Fallback, len(p.Steps))
	}
	if !strings.Contains(strings.Join(p.Notes, " "), "endpoint down") {
		t.Errorf("note must name the failure: %v", p.Notes)
	}
}

type stubProposer struct{}

func (stubProposer) Name() string { return "stub" }
func (stubProposer) Propose(context.Context, Brief) ([]Step, Usage, error) {
	return []Step{
		{Target: "evil.example/z", Class: "x", Action: ReadOnly, Expected: "never"},
		{Target: "api.shop.example/ok", Class: "graphql", Action: ReadOnly, Expected: "introspection on"},
	}, Usage{Model: "stub-1", Tokens: 321}, nil
}

func TestRunValidatesWhatTheProposerWrote(t *testing.T) {
	g := testGate(t, []string{"*.shop.example"}, nil)
	p := Run(context.Background(), Brief{Program: "shop"}, stubProposer{}, g, Budget{MaxSteps: 12, MaxTokens: 1000}, time.Unix(0, 0))
	if p.Fallback {
		t.Error("a working proposer must not be marked fallback")
	}
	if p.Model != "stub-1" || p.Budget.TokensUsed != 321 {
		t.Errorf("proposer identity/usage lost: model=%q tokens=%d", p.Model, p.Budget.TokensUsed)
	}
	if len(p.Steps) != 1 || p.Steps[0].Target != "api.shop.example/ok" {
		t.Fatalf("validator kept the wrong step: %+v", p.Steps)
	}
	if len(p.Dropped) != 1 || p.Dropped[0].Target != "evil.example/z" {
		t.Fatalf("validator did not drop the foreign host: %+v", p.Dropped)
	}
	if p.Steps[0].Source != "llm:stub-1" {
		t.Errorf("source not recorded: %q", p.Steps[0].Source)
	}
}

func TestWriteIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	p := Plan{Program: "shop", Proposer: "llm", Steps: []Step{{Target: "a.example", Action: ReadOnly}}}
	jp, mp, err := Write(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{jp, mp} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", path, fi.Mode().Perm())
		}
	}
	var back Plan
	b, _ := os.ReadFile(jp)
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Program != "shop" || len(back.Steps) != 1 {
		t.Errorf("round trip lost data: %+v", back)
	}
}

func TestMarkdownShowsDroppedBeforeSteps(t *testing.T) {
	p := Plan{Program: "shop", Proposer: "llm", Steps: []Step{{Target: "a.example", Class: "graphql", Action: ReadOnly, Expected: "x"}}, Dropped: []Drop{{Target: "z.example", Reason: "out of scope: not listed"}}}
	md := p.Markdown()
	if strings.Index(md, "Dropped") > strings.Index(md, "## Steps") {
		t.Error("the dropped list must come before the steps")
	}
	if !strings.Contains(md, "out of scope: not listed") {
		t.Error("drop reasons must survive into the artifact")
	}
}
