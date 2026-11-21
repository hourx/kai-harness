package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hourx/kai-harness/pkg/model"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/pattern"
)

// shadowWorkspace builds two programs of one shape whose outcomes clear every
// gate the loop has, plus a model whose entity nothing speaks about. The
// pkg/shadow tests own the gates themselves; this file owns the round trip
// through the command: propose, adopt, see it everywhere, revert.
func shadowWorkspace(t *testing.T) (home, alpha string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("KAI_HOME", home)
	for _, name := range []string{"alpha", "beta"} {
		dir := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Join(dir, "state"), 0o755); err != nil {
			t.Fatal(err)
		}
		meta := `{"name":"` + name + `","platform":"hackerone"}`
		if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(meta), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alpha = filepath.Join(home, "alpha")
	// Three distinct yields here, one in the other workspace: the loop needs four
	// recordings, and two programs, before it will re-grade a class. The class is
	// IDOR/BOLA because the shipped `graphql` class already sits at the confidence
	// ceiling, where the loop refuses to propose a raise that moves no number.
	for _, r := range []outcome.Record{
		{Target: "GET /graphql/a", Status: outcome.StatusPaid, Class: "IDOR/BOLA"},
		{Target: "GET /graphql/b", Status: outcome.StatusPaid, Class: "IDOR/BOLA"},
		{Target: "GET /graphql/c", Status: outcome.StatusPaid, Class: "IDOR/BOLA"},
	} {
		if err := outcome.Append(alpha, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := outcome.Append(filepath.Join(home, "beta"),
		outcome.Record{Target: "POST /graphql", Status: outcome.StatusFinding, Class: "IDOR/BOLA"}); err != nil {
		t.Fatal(err)
	}

	// A key is archetype-scoped and the archetype comes from the workspace that
	// recorded the outcome, so the second engagement needs its own model too: a
	// yield with no recorded shape cannot be compared with anything.
	bm := `{"program":"beta","archetype":"graphql-api","generated":"2026-11-21T00:00:00Z"}`
	if err := os.WriteFile(model.Path(filepath.Join(home, "beta")), []byte(bm), 0o600); err != nil {
		t.Fatal(err)
	}

	// A model that names an entity three observed paths address and no pattern
	// answers, so the report also carries a gap the adopt path must refuse.
	m := `{"program":"alpha","archetype":"graphql-api","generated":"2026-11-21T00:00:00Z",` +
		`"entities":[{"id":"e1","name":"widget","source":"observed"}],` +
		`"actions":[` +
		`{"id":"a1","path_or_selector":"/widget/a","source":"observed"},` +
		`{"id":"a2","path_or_selector":"/widget/b","source":"observed"},` +
		`{"id":"a3","path_or_selector":"/widget/c","source":"observed"}]}`
	if err := os.WriteFile(model.Path(alpha), []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	queue := `{"program":"alpha","items":[{"target":"GET /graphql","class":"IDOR/BOLA","score":40}]}`
	if err := os.WriteFile(filepath.Join(alpha, "next.json"), []byte(queue), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, alpha
}

const bolaRaiseID = "raise:graphql-api/class/idor/bola"

func TestShadowReportsBeforeItChangesAnything(t *testing.T) {
	_, alpha := shadowWorkspace(t)

	out, rc := runCapture(t, func() int { return cmdShadow([]string{"alpha"}) })
	if rc != 0 {
		t.Fatalf("exit %d:\n%s", rc, out)
	}
	if !strings.Contains(out, bolaRaiseID) {
		t.Errorf("the raise the evidence supports is not in the report:\n%s", out)
	}
	if !strings.Contains(out, "Nothing here has been applied") {
		t.Errorf("a read must say nothing was applied:\n%s", out)
	}
	if !strings.Contains(out, "gap:graphql-api/entity/widget") {
		t.Errorf("the named entity with no pattern is not reported as a gap:\n%s", out)
	}
	if _, err := os.Stat(pattern.OverridePath(alpha)); !os.IsNotExist(err) {
		t.Fatalf("a read wrote a layer file: %v", err)
	}
}

func TestShadowAdoptRoundTripsThroughEveryView(t *testing.T) {
	_, alpha := shadowWorkspace(t)

	out, rc := runCapture(t, func() int { return cmdShadow([]string{"alpha", "--adopt", bolaRaiseID}) })
	if rc != 0 {
		t.Fatalf("adopt exit %d:\n%s", rc, out)
	}
	if !strings.Contains(out, "adopted  "+bolaRaiseID) {
		t.Errorf("adopt did not report what it took:\n%s", out)
	}

	raw, err := os.ReadFile(pattern.OverridePath(alpha))
	if err != nil {
		t.Fatalf("adopt wrote no layer file: %v", err)
	}
	var layer pattern.Overrides
	if err := json.Unmarshal(raw, &layer); err != nil {
		t.Fatalf("layer file is not readable: %v\n%s", err, raw)
	}
	if len(layer.Adopted) != 1 || layer.Adopted[0].ID != bolaRaiseID {
		t.Fatalf("layer file does not carry the lesson: %s", raw)
	}

	// The correction must be visible where the operator reads the library, not
	// only in the file the command just wrote.
	pout, rc := runCapture(t, func() int { return cmdPatterns([]string{"alpha"}) })
	if rc != 0 {
		t.Fatalf("patterns exit %d:\n%s", rc, pout)
	}
	if !strings.Contains(pout, "adopted by the operator") {
		t.Errorf("kai patterns shows an unadopted number the plan disagrees with:\n%s", pout)
	}

	// And it must actually move the ranking, which is the only reason to adopt.
	lout, rc := runCapture(t, func() int { return cmdPlan([]string{"alpha"}) })
	if rc != 0 {
		t.Fatalf("plan exit %d:\n%s", rc, lout)
	}
	if !strings.Contains(lout, "1 adopted lesson(s)") {
		t.Errorf("the ranking did not pick up the adopted lesson:\n%s", lout)
	}

	// Revert by the bulk word: the file disappears and the library is in charge.
	rout, rc := runCapture(t, func() int { return cmdShadow([]string{"alpha", "--revert", "all"}) })
	if rc != 0 {
		t.Fatalf("revert exit %d:\n%s", rc, rout)
	}
	if !strings.Contains(rout, "reverted 1 lesson(s)") {
		t.Errorf("the bulk revert did not say what it took back:\n%s", rout)
	}
	if _, err := os.Stat(pattern.OverridePath(alpha)); !os.IsNotExist(err) {
		t.Fatalf("a full revert left the layer file behind: %v", err)
	}
}

func TestShadowAdoptRefusesAProposalTheEvidenceNoLongerSupports(t *testing.T) {
	_, alpha := shadowWorkspace(t)

	out, rc := runCapture(t, func() int {
		return cmdShadow([]string{"alpha", "--adopt", "raise:graphql-api/class/no-such-class"})
	})
	if rc == 0 {
		t.Fatalf("adopt of an unknown id reported success:\n%s", out)
	}
	if _, err := os.Stat(pattern.OverridePath(alpha)); !os.IsNotExist(err) {
		t.Fatalf("a refused adopt left a layer file: %v", err)
	}
}

func TestShadowAdoptRefusesAGap(t *testing.T) {
	_, alpha := shadowWorkspace(t)

	out, rc := runCapture(t, func() int {
		return cmdShadow([]string{"alpha", "--adopt", "gap:graphql-api/entity/widget"})
	})
	if rc == 0 {
		t.Fatalf("a gap was adopted as if it were a number:\n%s", out)
	}
	if !strings.Contains(out, "closed by writing a pattern") {
		t.Errorf("the refusal must say what a gap actually needs:\n%s", out)
	}
	if _, err := os.Stat(pattern.OverridePath(alpha)); !os.IsNotExist(err) {
		t.Fatalf("a refused gap adopt left a layer file: %v", err)
	}
}

func TestShadowRevertOnACleanWorkspaceIsNotAnError(t *testing.T) {
	shadowWorkspace(t)

	out, rc := runCapture(t, func() int { return cmdShadow([]string{"alpha", "--revert", "all"}) })
	if rc != 0 {
		t.Fatalf("exit %d:\n%s", rc, out)
	}
	if !strings.Contains(out, "nothing to revert") {
		t.Errorf("the honest answer for a clean workspace is missing:\n%s", out)
	}
}
