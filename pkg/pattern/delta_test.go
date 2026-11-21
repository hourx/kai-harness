package pattern

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/pkg/outcome"
)

func rec(target, class, status, ts string) outcome.Record {
	return outcome.Record{TS: ts, Target: target, Class: class, Status: status}
}

func TestBuildDeltaCountsWhatTheOperatorRecorded(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	d := BuildDelta("acme", "graphql-api", []outcome.Record{
		rec("/gql", "graphql", outcome.StatusPaid, "2026-11-20T01:00:00Z"),
		rec("/gql2", "GraphQL", outcome.StatusNegation, "2026-11-20T02:00:00Z"),
		rec("/gql3", "graphql", outcome.StatusInformational, "2026-11-21T03:00:00Z"),
		rec("/x", "", outcome.StatusNegation, "2026-11-19T00:00:00Z"),
	}, now)

	if d.Schema != DeltaSchema || d.Program != "acme" || d.Archetype != "graphql-api" {
		t.Fatalf("header wrong: %+v", d)
	}
	if d.Generated != now.Format(time.RFC3339) {
		t.Fatalf("Generated = %q", d.Generated)
	}
	// Two spellings of one class must land on one key, or the delta splits and
	// each half looks weaker than it is.
	st, ok := d.Stat(Key{Archetype: "graphql-api", Family: FamilyClass, Name: "graphql"})
	if !ok {
		t.Fatalf("merged graphql key missing: %+v", d.Keys)
	}
	if st.Fired != 3 || st.Paid != 1 || st.Negation != 1 || st.Tried() != 1 {
		t.Fatalf("graphql counts = fired %d paid %d negation %d tried %d", st.Fired, st.Paid, st.Negation, st.Tried())
	}
	if st.Last != "2026-11-21T03:00:00Z" {
		t.Fatalf("Last = %q, want the newest timestamp", st.Last)
	}
	if _, ok := d.Stat(Key{Archetype: "graphql-api", Family: FamilyClass, Name: "unclassified"}); !ok {
		t.Fatalf("a record without a class must land under its own key, not vanish: %+v", d.Keys)
	}
	// Sorted, so two runs print identically.
	for i := 1; i < len(d.Keys); i++ {
		if d.Keys[i-1].Key.String() > d.Keys[i].Key.String() {
			t.Fatalf("keys are not sorted: %s before %s", d.Keys[i-1].Key, d.Keys[i].Key)
		}
	}
}

func TestBoostRanksPaidAboveTriedAboveUntouchedAboveNegated(t *testing.T) {
	now := time.Now().UTC()
	d := BuildDelta("acme", "api", []outcome.Record{
		rec("/a", "graphql", outcome.StatusPaid, "2026-11-20T01:00:00Z"),
		rec("/b", "graphql", outcome.StatusPaid, "2026-11-20T01:00:00Z"),
		rec("/c", "api-surface", outcome.StatusInformational, "2026-11-20T01:00:00Z"),
		rec("/d", "business-logic", outcome.StatusNegation, "2026-11-20T01:00:00Z"),
		rec("/e", "business-logic", outcome.StatusNegation, "2026-11-20T01:00:00Z"),
	}, now)

	paid := d.BoostClass("graphql")
	tried := d.BoostClass("api-surface")
	untouched := d.BoostClass("idor/bola")
	negated := d.BoostClass("business-logic")

	if !(paid > tried && tried > untouched && untouched > negated) {
		t.Fatalf("boost order broken: paid %d, tried %d, untouched %d, negated %d", paid, tried, untouched, negated)
	}
	if untouched != 0 {
		t.Fatalf("a class nobody touched must not be boosted, got %d", untouched)
	}
	if paid < 6 {
		t.Fatalf("two pays should be worth at least 6, got %d", paid)
	}
	// A class the delta's archetype does not cover is not boosted either.
	if got := d.Boost(Key{Archetype: "chain", Family: FamilyClass, Name: "graphql"}); got != 0 {
		t.Fatalf("boost leaked across archetypes: %d", got)
	}
}

func TestBuildDeltaWithNoRecordsIsEmptyNotAnError(t *testing.T) {
	d := BuildDelta("acme", "api", nil, time.Now().UTC())
	if len(d.Keys) != 0 {
		t.Fatalf("want no keys, got %+v", d.Keys)
	}
	// null is not an empty list: a reader that iterates the file must not crash on
	// the common case of a program with nothing recorded yet.
	if raw := string(mustJSON(t, d)); !strings.Contains(raw, `"keys":[]`) {
		t.Fatalf("an empty delta must serialise its keys as []:\n%s", raw)
	}
	if d.BoostClass("graphql") != 0 {
		t.Fatal("an empty delta must boost nothing")
	}
	if got := d.Markdown(); got == "" {
		t.Fatal("the empty delta should still explain itself")
	}
}

func TestBuildDeltaFoldsAnUnknownShapeToEveryShape(t *testing.T) {
	d := BuildDelta("acme", "not-a-shape", []outcome.Record{rec("/x", "graphql", outcome.StatusPaid, "2026-11-20T01:00:00Z")}, time.Now().UTC())
	if d.Archetype != Any {
		t.Fatalf("Archetype = %q, want %q", d.Archetype, Any)
	}
	if d.BoostClass("graphql") == 0 {
		t.Fatal("the folded key must still answer")
	}
}

func TestWriteAndLoadDeltaRoundTrip(t *testing.T) {
	dir := t.TempDir()
	d := BuildDelta("acme", "api", []outcome.Record{rec("/x", "graphql", outcome.StatusFinding, "2026-11-21T00:00:00Z")}, time.Now().UTC())
	p, err := Write(dir, d)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if filepath.Base(p) != "patterns-delta.json" {
		t.Fatalf("unexpected path %s", p)
	}
	if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("delta should be written 0600, got %v (%v)", info.Mode().Perm(), err)
	}
	got, ok, err := Load(dir)
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if got.Program != d.Program || len(got.Keys) != len(d.Keys) {
		t.Fatalf("round trip changed the delta: %+v -> %+v", d, got)
	}
	// A missing file is a fact, not a failure.
	if _, ok, err := Load(t.TempDir()); ok || err != nil {
		t.Fatalf("a missing delta must be (zero, false, nil), got ok=%v err=%v", ok, err)
	}
	if err := os.WriteFile(Path(dir), []byte("{\"schema\":\"other/1\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(dir); err == nil {
		t.Fatal("a foreign schema must be refused, not silently read")
	}
}
