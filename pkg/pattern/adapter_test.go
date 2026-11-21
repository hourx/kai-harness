package pattern

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileAdapterReadsBothShapes(t *testing.T) {
	dir := t.TempDir()
	bare := write(t, dir, "bare.json", `[{"key":{"archetype":"api","family":"class","name":"surface-review"},"title":"t","confidence":0.5}]`)
	wrapped := write(t, dir, "wrapped.json", `{"schema":"layer/1","patterns":[{"key":{"archetype":"api","family":"entity","name":"account"},"class":"access-control","title":"t","confidence":0.5}]}`)

	for _, p := range []string{bare, wrapped} {
		ps, err := FileAdapter{Path: p}.Patterns()
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(p), err)
		}
		if len(ps) != 1 {
			t.Fatalf("%s: want 1 pattern, got %d", filepath.Base(p), len(ps))
		}
	}
	for name, body := range map[string]string{
		"empty.json":   "   ",
		"garbage.json": `{"nope": 1}`,
		"broken.json":  `[{"key":`,
	} {
		p := write(t, dir, name, body)
		if _, err := (FileAdapter{Path: p}).Patterns(); err == nil {
			t.Errorf("%s should not parse", name)
		}
	}
}

func TestLoadAdaptersCorrectsThePublicLayerInsteadOfDuplicatingIt(t *testing.T) {
	dir := t.TempDir()
	// Same key as a shipped pattern, with a different title and confidence.
	k := NewKey("api", FamilyClass, "idor/bola")
	if _, ok := Public().Lookup(k); !ok {
		t.Fatalf("%s should ship with the binary, or this test proves nothing", k)
	}
	write(t, dir, "01-local.json", `[{"key":{"archetype":"api","family":"class","name":"IDOR/BOLA"},"class":"IDOR/BOLA","title":"house opinion","why":"we saw it here","confidence":0.99,"source":"ops"}]`)

	adapters, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(adapters) != 1 {
		t.Fatalf("want 1 adapter, got %d", len(adapters))
	}
	lib, problems, err := LoadAdapters(Public(), adapters...)
	if err != nil {
		t.Fatalf("LoadAdapters: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if got := lib.Len(); got != Public().Len() {
		t.Fatalf("a correction must replace a pattern, not add one: %d vs %d", got, Public().Len())
	}
	got, ok := lib.Lookup(k)
	if !ok || got.Title != "house opinion" || got.Source != "ops" {
		t.Fatalf("the local layer did not win: %+v", got)
	}
}

func TestLoadAdaptersReportsBadEntriesAndKeepsTheRest(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "mixed.json", `[
		{"key":{"archetype":"api","family":"class","name":"surface-review"},"title":"good","confidence":0.5},
		{"key":{"archetype":"api","family":"class","name":"surface-review"},"title":"","confidence":0.5},
		{"key":{"archetype":"api","family":"class","name":"x"},"title":"too sure","confidence":4},
		{"key":{"archetype":"api","family":"nonsense","name":"x"},"title":"bad family","confidence":0.5},
		{"key":{"archetype":"not-a-shape","family":"class","name":"x"},"title":"bad shape","confidence":0.5},
		{"key":{"archetype":"api","family":"class","name":"x"},"title":"no class join","class":"never-produced","confidence":0.5}
	]`)
	adapters, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	lib, problems, err := LoadAdapters(Public(), adapters...)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 5 {
		t.Fatalf("want 5 problems (one per bad entry), got %d: %v", len(problems), problems)
	}
	joined := strings.Join(problems, "\n")
	for _, want := range []string{"entry 2", "entry 3", "entry 4", "entry 5", "entry 6", "confidence", "family", "archetype", "class"} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems should mention %q:\n%s", want, joined)
		}
	}
	if lib.Len() != Public().Len()+1 {
		t.Fatalf("the one good entry should have loaded: %d vs %d", lib.Len(), Public().Len()+1)
	}
}

func TestLoadDirIgnoresNonJSONAndSortsByName(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "notes.txt", "not a layer")
	write(t, dir, "b.json", `[]`)
	write(t, dir, "a.json", `[]`)
	if err := os.MkdirAll(filepath.Join(dir, "sub.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	adapters, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(adapters) != 2 || adapters[0].Name() != "a.json" || adapters[1].Name() != "b.json" {
		t.Fatalf("want a.json then b.json, got %v", adapters)
	}
}
