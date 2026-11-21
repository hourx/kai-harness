package hypothesis

import (
	"strings"
	"testing"

	"github.com/hourx/kai-harness/pkg/surface"
)

// Two classes that share a wave and a close score, so the boost has something to
// decide; plus a second pair far apart, so it is clear what a boost may not do.
func sameWaveQueue() surface.Plan {
	return queue(
		surface.Hypothesis{Target: "GET /close", Class: "api-surface", Score: 40},
		surface.Hypothesis{Target: "GET /near", Class: "graphql", Score: 38},
	)
}

func TestBuildWithBoostTipsACloseCallAndRecordsWhy(t *testing.T) {
	plain := Build(sameWaveQueue())
	if plain.Steps[0].Class != "api-surface" {
		t.Fatalf("the plain order should follow the surface score, got %s first", plain.Steps[0].Class)
	}

	boosted := BuildWith(sameWaveQueue(), Options{Boost: func(class string) int {
		if class == "graphql" {
			return 6
		}
		return 0
	}})
	if boosted.Steps[0].Class != "graphql" {
		t.Fatalf("a real delta should tip a two-point gap, got %s first", boosted.Steps[0].Class)
	}
	if boosted.Steps[0].Boost != 6 || boosted.Steps[0].Score != 38 {
		t.Fatalf("boost must be recorded beside the score, never folded into it: %+v", boosted.Steps[0])
	}
	if boosted.Steps[1].Boost != 0 {
		t.Fatalf("an unboosted step must show no boost: %+v", boosted.Steps[1])
	}
	if !strings.Contains(strings.Join(boosted.Notes, "\n"), "pattern delta") {
		t.Fatalf("a reordered plan has to say why: %v", boosted.Notes)
	}
}

func TestABoostCannotOverturnAStrongSurfaceSignal(t *testing.T) {
	q := queue(
		surface.Hypothesis{Target: "GET /big", Class: "api-surface", Score: 90},
		surface.Hypothesis{Target: "GET /small", Class: "graphql", Score: 10},
	)
	boosted := BuildWith(q, Options{Boost: func(class string) int {
		if class == "graphql" {
			return 9 // the ceiling of a realistic delta: three yields
		}
		return 0
	}})
	if boosted.Steps[0].Class != "api-surface" {
		t.Fatalf("a pattern is a hint, not evidence: it reordered a 80-point gap (%s first)", boosted.Steps[0].Class)
	}
}

func TestBuildWithBoostNeverMovesAStepAcrossWaves(t *testing.T) {
	q := queue(
		surface.Hypothesis{Target: "GET /gql", Class: "graphql", Score: 1},
		surface.Hypothesis{Target: "GET /orders/1", Class: "IDOR/BOLA", Score: 500},
	)
	plain := Build(q)
	if plain.Steps[0].Class != "graphql" {
		t.Fatalf("precondition order should hold without a boost, got %s", plain.Steps[0].Class)
	}
	// A boost far larger than any real delta must still not overturn a precondition.
	huge := BuildWith(q, Options{Boost: func(class string) int {
		if class == "IDOR/BOLA" {
			return 500
		}
		return 0
	}})
	if huge.Steps[0].Class != "graphql" {
		t.Fatalf("a boost moved a step across a wave boundary: %s first", huge.Steps[0].Class)
	}
	if huge.Steps[0].Wave >= huge.Steps[1].Wave {
		t.Fatalf("waves out of order: %d then %d", huge.Steps[0].Wave, huge.Steps[1].Wave)
	}
}

func TestBuildWithoutOptionsIsUnchanged(t *testing.T) {
	q := sameWaveQueue()
	plain := Build(q)
	withNil := BuildWith(q, Options{})
	if len(plain.Steps) != len(withNil.Steps) {
		t.Fatalf("step counts differ: %d vs %d", len(plain.Steps), len(withNil.Steps))
	}
	for i := range plain.Steps {
		if plain.Steps[i].Target != withNil.Steps[i].Target || plain.Steps[i].Boost != 0 {
			t.Fatalf("step %d differs: %+v vs %+v", i, plain.Steps[i], withNil.Steps[i])
		}
	}
	for _, n := range withNil.Notes {
		if strings.Contains(n, "pattern delta") {
			t.Fatalf("a plan without a boost must not claim one: %v", withNil.Notes)
		}
	}
}
