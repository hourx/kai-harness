package surface

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/internal/outcome"
)

var (
	surfaceTS = time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	freshTS   = "2026-03-03T00:00:00Z" // after the surface change
	staleTS   = "2026-03-01T00:00:00Z" // before it
)

func planWith(targets ...string) *Plan {
	p := &Plan{Program: "demo"}
	for _, t := range targets {
		p.Items = append(p.Items, Hypothesis{Target: t, Class: "surface-review", Score: 100, Cluster: ClusterOf(t)})
	}
	return p
}

func scoreOf(p *Plan, target string) int {
	for _, it := range p.Items {
		if it.Target == target {
			return it.Score
		}
	}
	return -1
}

func whysOf(p *Plan, target string) []string {
	for _, it := range p.Items {
		if it.Target == target {
			return it.Why
		}
	}
	return nil
}

func anyWhyContains(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestApplyOutcomesDropsFreshNegation(t *testing.T) {
	p := planWith("GET /a", "GET /b")
	tbl := outcome.NewTable(outcome.Record{TS: freshTS, Target: "GET /a", Status: outcome.StatusNegation})
	dropped := ApplyOutcomes(p, tbl, surfaceTS)
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	if len(p.Items) != 1 || p.Items[0].Target != "GET /b" {
		t.Fatalf("items = %+v, want only GET /b", p.Items)
	}
}

func TestApplyOutcomesKeepsStaleNegationDemoted(t *testing.T) {
	p := planWith("GET /a", "GET /b")
	tbl := outcome.NewTable(outcome.Record{TS: staleTS, Target: "GET /a", Status: outcome.StatusNegation})
	if dropped := ApplyOutcomes(p, tbl, surfaceTS); dropped != 0 {
		t.Fatalf("dropped = %d, want 0: the surface changed after the probe", dropped)
	}
	if len(p.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(p.Items))
	}
	if scoreOf(p, "GET /a") >= scoreOf(p, "GET /b") {
		t.Errorf("stale negative (%d) must rank below an untested target (%d)",
			scoreOf(p, "GET /a"), scoreOf(p, "GET /b"))
	}
	if !anyWhyContains(whysOf(p, "GET /a"), "surface changed") {
		t.Errorf("why = %v, want a note that the surface changed", whysOf(p, "GET /a"))
	}
}

func TestApplyOutcomesBoostsProvenTargetAndSiblings(t *testing.T) {
	p := planWith("GET /api/orders/7", "GET /api/orders/8")
	tbl := outcome.NewTable(outcome.Record{TS: freshTS, Target: "GET /api/orders/7", Status: outcome.StatusFinding})
	ApplyOutcomes(p, tbl, surfaceTS)
	if got := scoreOf(p, "GET /api/orders/7"); got <= 100 {
		t.Errorf("proven finding score = %d, want a lift above 100", got)
	}
	if got := scoreOf(p, "GET /api/orders/8"); got <= 100 {
		t.Errorf("sibling score = %d, want a cluster lift above 100", got)
	}
	if !anyWhyContains(whysOf(p, "GET /api/orders/8"), "sibling") {
		t.Errorf("why = %v, want a sibling note", whysOf(p, "GET /api/orders/8"))
	}
	if anyWhyContains(whysOf(p, "GET /api/orders/7"), "sibling") {
		t.Errorf("why = %v, want no sibling note on the target that produced the finding", whysOf(p, "GET /api/orders/7"))
	}
}

func TestSurfaceTSIgnoresDerivedArtifacts(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-72 * time.Hour)
	store := filepath.Join(dir, "assets.json")
	if err := os.WriteFile(store, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(store, old, old); err != nil {
		t.Fatal(err)
	}
	// Derived files are rewritten by every `kai next`: they must not count as a
	// surface change, or every recorded outcome would look stale forever.
	if err := os.WriteFile(filepath.Join(dir, "map.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "next.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := outcome.SurfaceTS(dir); !got.Equal(old.UTC()) {
		t.Errorf("SurfaceTS = %v, want %v (assets.json only)", got, old.UTC())
	}
}

func TestApplyOutcomesDropsClustersWithDroppedMembers(t *testing.T) {
	p := planWith("GET /api/orders/7", "GET /api/orders/8")
	p.Clusters = []Cluster{{Key: ClusterOf("GET /api/orders/7"), Targets: []string{"GET /api/orders/7", "GET /api/orders/8"}, Count: 2}}
	p.Items[0].Variants = []string{"GET /api/orders/8"}
	tbl := outcome.NewTable(outcome.Record{TS: freshTS, Target: "GET /api/orders/8", Status: outcome.StatusInformational})
	if dropped := ApplyOutcomes(p, tbl, surfaceTS); dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	if len(p.Clusters) != 0 {
		t.Errorf("clusters = %+v, want none: one member was dropped", p.Clusters)
	}
	if len(p.Items[0].Variants) != 0 {
		t.Errorf("variants = %v, want the dropped target removed", p.Items[0].Variants)
	}
}

func TestApplyOutcomesNilTableIsNoop(t *testing.T) {
	p := planWith("GET /a")
	if dropped := ApplyOutcomes(p, nil, surfaceTS); dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}
	if got := scoreOf(p, "GET /a"); got != 100 {
		t.Errorf("score = %d, want unchanged 100", got)
	}
}

func TestApplyOutcomesUnparseableTimestampStaysInQueue(t *testing.T) {
	p := planWith("GET /a")
	tbl := outcome.NewTable(outcome.Record{TS: "not-a-time", Target: "GET /a", Status: outcome.StatusNegation})
	if dropped := ApplyOutcomes(p, tbl, surfaceTS); dropped != 0 {
		t.Fatalf("dropped = %d, want 0: a corrupt timestamp must not hide a target", dropped)
	}
	if scoreOf(p, "GET /a") >= 100 {
		t.Errorf("score = %d, want the stale penalty applied", scoreOf(p, "GET /a"))
	}
}
