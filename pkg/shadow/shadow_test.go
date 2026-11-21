package shadow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/pattern"
)

var now = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

func rec(target, status, class string) outcome.Record {
	return outcome.Record{Target: target, Status: status, Class: class, TS: "2026-11-21T08:00:00Z"}
}

// graphqlKey is a class the shipped library answers, so a proposal can be tested
// against a real From value instead of a hand-built library.
func graphqlKey(t *testing.T) pattern.Key {
	t.Helper()
	k := pattern.Key{Archetype: "graphql-api", Family: pattern.FamilyClass, Name: "graphql"}
	if !PatternExists(pattern.Public(), k) {
		t.Fatalf("the shipped library no longer answers %s; this fixture is stale", k.String())
	}
	return k
}

// classKeyWithHeadroom picks a class of this shape that is far enough from the
// clamp for a raise to be observable: a raise tested against a class already at
// MaxConf proves nothing, because the loop now refuses to propose it at all.
func classKeyWithHeadroom(t *testing.T) pattern.Key {
	t.Helper()
	for _, p := range pattern.Public().All() {
		if p.Key.Archetype == "graphql-api" && p.Key.Family == pattern.FamilyClass &&
			p.Confidence <= pattern.MaxConf-pattern.RaiseStep {
			return p.Key
		}
	}
	t.Fatal("no graphql-api class pattern has headroom; this fixture is stale")
	return pattern.Key{}
}

func TestOneEngagementsAfternoonIsHeldNotLearned(t *testing.T) {
	obs := []Observation{{Program: "alpha", Archetype: "graphql-api", Records: []outcome.Record{
		rec("GET /graphql/a", outcome.StatusPaid, "graphql"),
		rec("GET /graphql/b", outcome.StatusPaid, "graphql"),
		rec("GET /graphql/c", outcome.StatusPaid, "graphql"),
		rec("GET /graphql/d", outcome.StatusPaid, "graphql"),
	}}}
	r := Evaluate("alpha", "graphql-api", pattern.Public(), obs, nil, now)

	if len(r.Proposals) != 0 {
		t.Fatalf("four yields in one program became a library change: %+v", r.Proposals)
	}
	if r.Touched != 1 {
		t.Errorf("Touched = %d, want 1: the key was seen and must be counted", r.Touched)
	}
	if len(r.Held) != 1 || !strings.Contains(r.Held[0].Missing, "only 1 program") {
		t.Fatalf("the key must be reported as held, with the gate quoted: %+v", r.Held)
	}
}

func TestYieldsInTwoProgramsProposeARaise(t *testing.T) {
	lib := pattern.Public()
	k := classKeyWithHeadroom(t)
	cur, _ := lib.Lookup(k)
	obs := []Observation{
		{Program: "alpha", Archetype: "graphql-api", Records: []outcome.Record{
			rec("GET /graphql/a", outcome.StatusPaid, k.Name),
			rec("GET /graphql/b", outcome.StatusPaid, k.Name),
			rec("GET /graphql/c", outcome.StatusPaid, k.Name),
		}},
		{Program: "beta", Archetype: "graphql-api", Records: []outcome.Record{
			rec("POST /graphql", outcome.StatusFinding, k.Name),
		}},
	}
	r := Evaluate("alpha", "graphql-api", lib, obs, nil, now)

	if len(r.Proposals) != 1 {
		t.Fatalf("want exactly one proposal, got %+v", r.Proposals)
	}
	p := r.Proposals[0]
	if p.Kind != KindRaise || !p.Adoptable {
		t.Fatalf("proposal = %+v, want an adoptable raise", p)
	}
	if p.ID != KindRaise+":"+k.String() {
		t.Errorf("ID = %q, want the CLI to be able to echo it back", p.ID)
	}
	if p.From != cur.Confidence {
		t.Errorf("From = %v, want the number it starts from (%v)", p.From, cur.Confidence)
	}
	if want := clamp(cur.Confidence + pattern.RaiseStep); p.To != want {
		t.Errorf("To = %v, want %v", p.To, want)
	}
	if p.To <= p.From {
		t.Errorf("a raise that does not move up is not a raise: %+v", p)
	}
	if p.Evidence.Programs != 2 || p.Evidence.Fired != 4 || p.Evidence.Paid != 4 {
		t.Errorf("evidence must carry the whole count: %+v", p.Evidence)
	}
	if len(p.Evidence.Where) != 2 || p.Evidence.Where[0] != "alpha" || p.Evidence.Where[1] != "beta" {
		t.Errorf("Where = %v, want both programs named", p.Evidence.Where)
	}
}

func TestRepeatedClosuresProposeALower(t *testing.T) {
	lib := pattern.Public()
	obs := []Observation{
		{Program: "alpha", Archetype: "graphql-api", Records: []outcome.Record{
			rec("GET /graphql/a", outcome.StatusNegation, "graphql"),
			rec("GET /graphql/b", outcome.StatusNegation, "graphql"),
			rec("GET /graphql/c", outcome.StatusNegation, "graphql"),
			rec("GET /graphql/d", outcome.StatusInformational, "graphql"),
		}},
		{Program: "beta", Archetype: "graphql-api", Records: []outcome.Record{
			rec("POST /graphql", outcome.StatusNegation, "graphql"),
		}},
	}
	r := Evaluate("alpha", "graphql-api", lib, obs, nil, now)

	if len(r.Proposals) != 1 || r.Proposals[0].Kind != KindLower {
		t.Fatalf("want one lower proposal, got %+v", r.Proposals)
	}
	if r.Proposals[0].To >= r.Proposals[0].From {
		t.Errorf("a lower that does not move down is not a lower: %+v", r.Proposals[0])
	}
}

func TestMixedEvidenceIsHeldRatherThanGuessedAt(t *testing.T) {
	obs := []Observation{
		{Program: "alpha", Archetype: "graphql-api", Records: []outcome.Record{
			rec("a", outcome.StatusInformational, "graphql"),
			rec("b", outcome.StatusNegation, "graphql"),
			rec("c", outcome.StatusInformational, "graphql"),
		}},
		{Program: "beta", Archetype: "graphql-api", Records: []outcome.Record{
			rec("d", outcome.StatusNegation, "graphql"),
		}},
	}
	r := Evaluate("alpha", "graphql-api", pattern.Public(), obs, nil, now)

	if len(r.Proposals) != 0 {
		t.Fatalf("mixed evidence produced a proposal: %+v", r.Proposals)
	}
	if len(r.Held) != 1 || !strings.Contains(r.Held[0].Missing, "mixed") {
		t.Fatalf("want the key held as mixed: %+v", r.Held)
	}
}

// Evidence from another shape is comparable but must never be applied here: an
// `api` yield is not evidence about a `chain` class.
func TestAnotherShapesEvidenceNeverProposesAgainstThisKey(t *testing.T) {
	obs := []Observation{{Program: "gamma", Archetype: "chain", Records: []outcome.Record{
		rec("a", outcome.StatusPaid, "graphql"),
		rec("b", outcome.StatusPaid, "graphql"),
		rec("c", outcome.StatusPaid, "graphql"),
		rec("d", outcome.StatusPaid, "graphql"),
	}}}
	r := Evaluate("alpha", "graphql-api", pattern.Public(), obs, nil, now)

	if len(r.Proposals) != 0 {
		t.Fatalf("another archetype's evidence produced a proposal: %+v", r.Proposals)
	}
	if r.Touched != 0 {
		t.Errorf("Touched = %d, want 0: nothing of this shape was recorded", r.Touched)
	}
	if len(r.Held) != 1 || !strings.Contains(r.Held[0].Missing, "not this program's") {
		t.Fatalf("want the foreign archetype held and named: %+v", r.Held)
	}
}

func TestAGapIsNotAdoptable(t *testing.T) {
	entities := map[string]int{"no-such-entity-zz": 5, "barely-seen": 2}
	r := Evaluate("alpha", "graphql-api", pattern.Public(), nil, entities, now)

	if len(r.Proposals) != 1 {
		t.Fatalf("want exactly one gap (the second entity is below GapPaths), got %+v", r.Proposals)
	}
	g := r.Proposals[0]
	if g.Kind != KindGap || g.Adoptable {
		t.Fatalf("a gap must not be adoptable: %+v", g)
	}
	if !strings.Contains(g.Reason, "no pattern") {
		t.Errorf("the reason must say what writing would answer: %q", g.Reason)
	}
}

// A proposal whose application changes nothing is not a lesson: the shipped
// graphql class already sits at the ceiling, so a raise here would write a file
// that moves no number while looking like work.
func TestAClampedNoOpIsHeldNotProposed(t *testing.T) {
	lib := pattern.Public()
	k := graphqlKey(t)
	cur, _ := lib.Lookup(k)
	if cur.Confidence <= pattern.MaxConf-pattern.RaiseStep {
		t.Skipf("%s sits at %.2f, so a raise no longer clamps; this test needs a class near the ceiling", k.String(), cur.Confidence)
	}
	obs := []Observation{
		{Program: "alpha", Archetype: "graphql-api", Records: []outcome.Record{
			rec("GET /graphql/a", outcome.StatusPaid, "graphql"),
			rec("GET /graphql/b", outcome.StatusPaid, "graphql"),
			rec("GET /graphql/c", outcome.StatusPaid, "graphql"),
		}},
		{Program: "beta", Archetype: "graphql-api", Records: []outcome.Record{
			rec("POST /graphql", outcome.StatusPaid, "graphql"),
		}},
	}
	r := Evaluate("alpha", "graphql-api", lib, obs, nil, now)

	if len(r.Proposals) != 0 {
		t.Fatalf("a raise that cannot move the number was proposed: %+v", r.Proposals)
	}
	if len(r.Held) != 1 || !strings.Contains(r.Held[0].Missing, "ceiling") {
		t.Fatalf("want the key held with the ceiling named: %+v", r.Held)
	}
}

// The floor case: a corrected layer may carry a class down to MinConf, and the
// loop must read the merged number rather than the shipped one.
func TestALowerAtTheFloorIsHeldNotProposed(t *testing.T) {
	dir := t.TempDir()
	layer := filepath.Join(dir, "floor.json")
	body := `{"schema":"kai-layer/1","patterns":[{"key":{"archetype":"graphql-api","family":"class","name":"graphql"},` +
		`"class":"graphql","title":"t","why":"w","confidence":0.05,"source":"test-layer"}]}`
	if err := os.WriteFile(layer, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	lib, problems, err := pattern.LoadAdapters(pattern.Public(), pattern.FileAdapter{Path: layer})
	if err != nil || len(problems) != 0 {
		t.Fatalf("layer did not load: %v %v", err, problems)
	}

	obs := []Observation{
		{Program: "alpha", Archetype: "graphql-api", Records: []outcome.Record{
			rec("GET /graphql/a", outcome.StatusNegation, "graphql"),
			rec("GET /graphql/b", outcome.StatusNegation, "graphql"),
			rec("GET /graphql/c", outcome.StatusNegation, "graphql"),
			rec("GET /graphql/d", outcome.StatusInformational, "graphql"),
		}},
		{Program: "beta", Archetype: "graphql-api", Records: []outcome.Record{
			rec("POST /graphql", outcome.StatusNegation, "graphql"),
		}},
	}
	r := Evaluate("alpha", "graphql-api", lib, obs, nil, now)

	if len(r.Proposals) != 0 {
		t.Fatalf("a lower that cannot move the number was proposed: %+v", r.Proposals)
	}
	if len(r.Held) != 1 || !strings.Contains(r.Held[0].Missing, "floor") {
		t.Fatalf("want the key held with the floor named: %+v", r.Held)
	}
}

func TestNothingRecordedSaysSoInsteadOfGuessing(t *testing.T) {
	r := Evaluate("alpha", "graphql-api", pattern.Public(), nil, nil, now)
	md := r.Markdown()

	if len(r.Proposals) != 0 {
		t.Fatalf("a workspace with no outcomes produced %d proposal(s)", len(r.Proposals))
	}
	if !strings.Contains(md, "nothing to learn") {
		t.Errorf("the report must say there is nothing to learn yet:\n%s", md)
	}
	if !strings.Contains(md, "Nothing here has been applied") {
		t.Errorf("the report must state that nothing was applied:\n%s", md)
	}
}
