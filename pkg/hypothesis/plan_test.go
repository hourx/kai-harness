package hypothesis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hourx/kai-harness/pkg/surface"
)

func queue(items ...surface.Hypothesis) surface.Plan {
	return surface.Plan{Program: "acme", Generated: "2026-01-01T00:00:00Z", Items: items}
}

func TestBuildDedupesPerClassAndOrdersWaves(t *testing.T) {
	p := Build(queue(
		surface.Hypothesis{Target: "GET /a/2", Class: "IDOR/BOLA", Score: 50},
		surface.Hypothesis{Target: "GET /docs", Class: "surface-review", Score: 30},
		surface.Hypothesis{Target: "GET /a/1", Class: "IDOR/BOLA", Score: 100},
	))
	if len(p.Steps) != 2 {
		t.Fatalf("want 2 steps (one per class), got %d", len(p.Steps))
	}
	first, second := p.Steps[0], p.Steps[1]
	if first.Class != "surface-review" || first.Wave != 1 || first.Needs != NeedNone {
		t.Fatalf("wave 1 should lead with the no-session class: %+v", first)
	}
	if second.Class != "IDOR/BOLA" || second.Wave != 3 || second.Needs != NeedTwoSessions {
		t.Fatalf("two-identity class should land in wave 3: %+v", second)
	}
	if second.Target != "GET /a/1" {
		t.Fatalf("highest-scoring path should win the class: %s", second.Target)
	}
	if len(second.Merged) != 1 || second.Merged[0] != "GET /a/2" {
		t.Fatalf("the losing path should be recorded, not dropped: %v", second.Merged)
	}
	if first.Rank != 1 || second.Rank != 2 {
		t.Fatalf("ranks not assigned in order: %d, %d", first.Rank, second.Rank)
	}
	if len(p.Waves) != 2 || p.Waves[0].N != 1 || p.Waves[1].N != 3 {
		t.Fatalf("waves: %+v", p.Waves)
	}
}

func TestUnknownClassDefaultsToSessionAndSaysSo(t *testing.T) {
	p := Build(queue(surface.Hypothesis{Target: "GET /x", Class: "quantum-thing", Score: 10}))
	if p.Steps[0].Needs != NeedSession {
		t.Fatalf("unknown class should assume a session, got %q", p.Steps[0].Needs)
	}
	if len(p.Notes) == 0 {
		t.Fatal("plan should carry its own caveats")
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	q := queue(
		surface.Hypothesis{Target: "GET /b", Class: "graphql", Score: 10},
		surface.Hypothesis{Target: "GET /a", Class: "graphql", Score: 10},
	)
	a, b := Build(q), Build(q)
	if len(a.Steps) != 1 || len(b.Steps) != 1 || a.Steps[0].Target != b.Steps[0].Target {
		t.Fatalf("equal scores must break ties the same way: %v vs %v", a.Steps, b.Steps)
	}
}

func TestWriteProducesStableArtifacts(t *testing.T) {
	dir := t.TempDir()
	p := Build(queue(surface.Hypothesis{Target: "GET /a", Class: "api-surface", Score: 40}))
	p.Generated = "2026-01-01T00:00:00Z"
	jsonPath, mdPath, err := Write(dir, p)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	firstJSON, _ := os.ReadFile(jsonPath)
	firstMD, _ := os.ReadFile(mdPath)
	if _, _, err := Write(dir, p); err != nil {
		t.Fatalf("second write: %v", err)
	}
	secondJSON, _ := os.ReadFile(jsonPath)
	secondMD, _ := os.ReadFile(mdPath)
	if string(firstJSON) != string(secondJSON) || string(firstMD) != string(secondMD) {
		t.Fatal("writing the same plan twice changed the bytes")
	}
	fi, err := os.Stat(mdPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("plan.md mode: %o", fi.Mode().Perm())
	}
	if filepath.Base(jsonPath) != "plan.json" {
		t.Fatalf("unexpected json path: %s", jsonPath)
	}
	if len(p.Steps[0].Pointer) == 0 {
		t.Fatal("every step should point at its method section")
	}
}
