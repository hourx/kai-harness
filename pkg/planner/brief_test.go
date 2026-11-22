package planner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hourx/kai-harness/pkg/archetype"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/workspace"
)

func seedProgram(t *testing.T) *workspace.Program {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "scope.txt"), "*.shop.example\nshop.example\n")
	writeFile(t, filepath.Join(dir, "out-of-scope.txt"), "internal.shop.example\n")

	plan := surface.Plan{
		Program: "shop",
		Items: []surface.Hypothesis{
			{Target: "api.shop.example/orders/{id}", Class: "IDOR/BOLA", Score: 42, Probe: "fetch as two users", Why: []string{"object id in path"}},
			{Target: "api.shop.example/graphql", Class: "graphql", Score: 30, Probe: "introspection", Why: []string{"graphql endpoint"}},
		},
	}
	b, _ := json.MarshalIndent(plan, "", "  ")
	writeFile(t, filepath.Join(dir, "next.json"), string(b))

	writeFile(t, filepath.Join(dir, "state", "model.json"),
		`{"program":"shop","archetype":"api","gaps":["no pattern for coupon stacking"]}`)

	var lines []string
	for i, r := range []outcome.Record{
		{TS: "2026-11-20T10:00:00Z", Target: "api.shop.example/old", Status: "no-finding", Class: "graphql"},
		{TS: "2026-11-21T10:00:00Z", Target: "api.shop.example/new", Status: "confirmed", Class: "IDOR/BOLA"},
	} {
		_ = i
		rb, _ := json.Marshal(r)
		lines = append(lines, string(rb))
	}
	writeFile(t, filepath.Join(dir, "state", "outcomes.jsonl"), strings.Join(lines, "\n")+"\n")

	return &workspace.Program{Name: "shop", Dir: dir}
}

func TestBuildBriefReadsTheWorkspace(t *testing.T) {
	p := seedProgram(t)
	b, notes, err := BuildBrief(p, "", 5)
	if err != nil {
		t.Fatal(err)
	}
	if b.Program != "shop" || b.Limit != 5 {
		t.Errorf("brief header = %+v", b)
	}
	if len(b.Scope) != 2 || len(b.OutOfScope) != 1 {
		t.Errorf("scope not carried: in=%v out=%v", b.Scope, b.OutOfScope)
	}
	if len(b.Queue) != 2 || b.Queue[0].Score != 42 || b.Queue[0].Probe == "" {
		t.Fatalf("queue not carried: %+v", b.Queue)
	}
	if b.Archetype != "api" || len(b.Gaps) == 0 {
		t.Errorf("model not carried: archetype=%q gaps=%v", b.Archetype, b.Gaps)
	}
	if len(b.Hosts) != 2 {
		t.Errorf("in-scope hosts not listed: %v", b.Hosts)
	}
	if len(b.Patterns) == 0 {
		t.Errorf("patterns for archetype api were not listed")
	}
	// Outcomes are newest first: the proposer reasons about what just happened.
	if len(b.Outcomes) != 2 || !strings.Contains(b.Outcomes[0], "new") {
		t.Errorf("outcomes not newest-first: %v", b.Outcomes)
	}
	_ = notes
}

func TestBuildBriefArchetypeOverrideWins(t *testing.T) {
	p := seedProgram(t)
	name := archetype.Names()[0]
	b, _, err := BuildBrief(p, name, 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Archetype != name {
		t.Errorf("override ignored: got %q want %q", b.Archetype, name)
	}
}

func TestBuildBriefRefusesAnEmptyScope(t *testing.T) {
	dir := t.TempDir()
	// scope.txt exists but carries only a comment.
	writeFile(t, filepath.Join(dir, "scope.txt"), "# nothing yet\n")
	if _, _, err := BuildBrief(&workspace.Program{Name: "empty", Dir: dir}, "", 0); err == nil {
		t.Fatal("a plan built on an empty scope must be refused")
	}
}

func TestBuildBriefNotesMissingQueue(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "scope.txt"), "a.example\n")
	b, notes, err := BuildBrief(&workspace.Program{Name: "p", Dir: dir}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Queue) != 0 {
		t.Errorf("queue should be empty: %+v", b.Queue)
	}
	if !strings.Contains(strings.Join(notes, " "), "queue is empty") {
		t.Errorf("missing queue must be noted: %v", notes)
	}
}

func TestBriefIsSerializable(t *testing.T) {
	p := seedProgram(t)
	b, _, err := BuildBrief(p, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p.Dir, "next.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(b); err != nil {
		t.Fatalf("brief must serialize: %v", err)
	}
}
