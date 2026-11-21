package pattern

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shadowFixture makes a workspace dir and names the key the shadow loop's own
// gates propose against (MinFired / RaisePaid / RaiseRatio all satisfied).
func shadowFixture(t *testing.T) (string, Key) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, Key{Archetype: "graphql-api", Family: FamilyClass, Name: "graphql"}
}

// adoptForTest runs the real Adopt against the shipped library, so a change to
// the loop's gates or the library's shape fails here rather than in production.
func adoptForTest(t *testing.T, key Key, kind string, o Overrides) Overrides {
	t.Helper()
	lib := Public()
	if _, ok := lib.Lookup(key); !ok {
		t.Fatalf("shipped library has no pattern for %s — fixture is stale", key.String())
	}
	next, err := Adopt(o, lib, key, kind, 2, 4, []string{"alpha", "beta"}, "two yields across two programs", time.Now())
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	return next
}

// The bulk revert is spelled "all" on the command line. A package that reads only
// the empty string as "everything" turns the operator's word into an id that
// matches nothing: the sweep then prints a success line and changes nothing.
func TestRevertAllByLiteralName(t *testing.T) {
	_, key := shadowFixture(t)
	o := adoptForTest(t, key, "raise", Overrides{})

	if len(o.Adopted) != 1 {
		t.Fatalf("fixture did not produce one adopted lesson: %+v", o.Adopted)
	}
	if got := Reverted(o, "all"); len(got) != 1 {
		t.Fatalf(`Reverted(o, "all") = %v, want the one adopted key`, got)
	}
	after := Revert(o, "all")
	if len(after.Adopted) != 0 {
		t.Errorf(`Revert(o, "all") left %d lesson(s); the bulk sweep must drop every one`, len(after.Adopted))
	}
	if after.Nudge("graphql") != 0 {
		t.Errorf("after a full revert the class still carries a ranking nudge (%d)", after.Nudge("graphql"))
	}
}

// The empty selector is the in-package spelling of "everything"; both entry
// points must mean the same thing.
func TestRevertEverythingByEmptySelector(t *testing.T) {
	_, key := shadowFixture(t)
	o := adoptForTest(t, key, "lower", Overrides{})

	if got := len(Revert(o, "").Adopted); got != 0 {
		t.Errorf(`Revert(o, "") left %d lesson(s), want 0`, got)
	}
	if got := len(Reverted(o, "")); got != 1 {
		t.Errorf(`Reverted(o, "") = %d key(s), want 1`, got)
	}
}

// An ID must drop exactly the lesson it names and leave its siblings alone:
// reverting one engagement's lesson is not reverting all of them.
func TestRevertOneLeavesSiblings(t *testing.T) {
	_, key := shadowFixture(t)
	o := adoptForTest(t, key, "raise", Overrides{})

	second := Key{Archetype: "graphql-api", Family: FamilyClass, Name: "idor/bola"}
	if _, ok := Public().Lookup(second); !ok {
		t.Skipf("shipped library has no %s; nothing to test the sibling case with", second.String())
	}
	o = adoptForTest(t, second, "raise", o)
	if len(o.Adopted) != 2 {
		t.Fatalf("want two adopted lessons, got %d: %+v", len(o.Adopted), o.Adopted)
	}

	var target string
	for _, a := range o.Adopted {
		if a.Key == second {
			target = a.ID
		}
	}
	if target == "" {
		t.Fatalf("no adopted entry for %s in %+v", second.String(), o.Adopted)
	}
	if !o.ValidAdoptID(target) {
		t.Fatalf("Adopt wrote an ID the CLI would reject: %q", target)
	}

	kept := Revert(o, target)
	if len(kept.Adopted) != 1 {
		t.Fatalf("reverting one of two left %d, want 1", len(kept.Adopted))
	}
	if kept.Adopted[0].Key == second {
		t.Errorf("reverted the wrong lesson: %s survived, %s was dropped", kept.Adopted[0].Key.String(), second.String())
	}
}

// Adopting the same proposal twice is one lesson, not two: the CLI may be run
// again after an interrupted session without double-counting the nudge.
func TestAdoptIsIdempotentPerLesson(t *testing.T) {
	_, key := shadowFixture(t)
	o := adoptForTest(t, key, "raise", Overrides{})
	o = adoptForTest(t, key, "raise", o)

	if len(o.Adopted) != 1 || len(o.Patterns) != 1 {
		t.Fatalf("re-adopting the same ID duplicated the lesson: %d adopted, %d pattern(s)", len(o.Adopted), len(o.Patterns))
	}
	if got := o.Nudge("graphql"); got != 1 {
		t.Errorf("Nudge = %d after re-adopt, want 1", got)
	}
}
