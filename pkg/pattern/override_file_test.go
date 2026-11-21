package pattern

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// headroom picks a shipped class pattern far enough from the clamp that a raise
// is observable. A raise tested against a pattern already at MaxConf proves
// nothing: the number would not move whether the code worked or not.
func headroom(t *testing.T, lib Library) Key {
	t.Helper()
	for _, p := range lib.All() {
		if p.Key.Family == FamilyClass && p.Confidence <= MaxConf-RaiseStep {
			return p.Key
		}
	}
	t.Fatal("no shipped class pattern has room below the clamp; the library changed shape")
	return Key{}
}

func TestAdoptMovesTheNumberAndSaysWhy(t *testing.T) {
	lib := Public()
	k := headroom(t, lib)
	base, _ := lib.Lookup(k)
	ts := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

	o, err := Adopt(Overrides{}, lib, k, "raise", 5, 5, []string{"beta", "alpha"}, "5 of 5 yielded", ts)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if len(o.Patterns) != 1 || len(o.Adopted) != 1 {
		t.Fatalf("one lesson must write exactly one pattern and one record: %+v", o)
	}
	if got, want := o.Patterns[0].Confidence, clampConf(base.Confidence+RaiseStep); got != want {
		t.Errorf("confidence = %v, want %v", got, want)
	}
	if o.Patterns[0].Source != "operator/shadow" {
		t.Errorf("Source = %q, want the layer to admit who wrote it", o.Patterns[0].Source)
	}
	if n := o.Patterns[0].Note; !strings.Contains(n, "5/5") || !strings.Contains(n, "alpha") || !strings.Contains(n, "beta") {
		t.Errorf("Note must carry both the ratio and the programs it rests on: %q", n)
	}
	a := o.Adopted[0]
	if a.ID != "raise:"+k.String() || a.Kind != "raise" || a.Boost != 1 {
		t.Errorf("adopted record = %+v", a)
	}
	if a.TS != ts.Format(time.RFC3339) {
		t.Errorf("TS = %q, want %q", a.TS, ts.Format(time.RFC3339))
	}
	if o.Schema != LayerSchema {
		t.Errorf("schema = %q, want %q", o.Schema, LayerSchema)
	}
}

func TestAdoptRefusesWhatTheLibraryDoesNotOwn(t *testing.T) {
	lib := Public()
	missing := Key{Archetype: "web-app", Family: FamilyClass, Name: "no-such-class-zz"}
	if _, err := Adopt(Overrides{}, lib, missing, "raise", 1, 1, nil, "x", time.Now()); err == nil {
		t.Error("adopt accepted a key the library does not answer")
	}
	ok := headroom(t, lib)
	if _, err := Adopt(Overrides{}, lib, ok, "sideways", 1, 1, nil, "x", time.Now()); err == nil {
		t.Error("adopt accepted an unknown kind")
	}
}

func TestSaveRemovesAnEmptyLayerAndLoadReadsAbsence(t *testing.T) {
	dir := t.TempDir()
	if _, ok, err := LoadOverrides(dir); ok || err != nil {
		t.Fatalf("a workspace with no file must read as (nothing adopted, no error); got ok=%v err=%v", ok, err)
	}

	lib := Public()
	o, err := Adopt(Overrides{}, lib, headroom(t, lib), "lower", 0, 6, []string{"alpha", "beta"}, "six closures", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	path, err := SaveOverrides(dir, o)
	if err != nil || path == "" {
		t.Fatalf("save: path=%q err=%v", path, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600 — the layer is the operator's notes", fi.Mode().Perm())
	}
	if _, ok, err := LoadOverrides(dir); !ok || err != nil {
		t.Fatalf("the file just written does not read back: ok=%v err=%v", ok, err)
	}

	if _, err := SaveOverrides(dir, Revert(o, "all")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("an empty layer must not be left on disk pretending to say something: %v", err)
	}
	if _, ok, _ := LoadOverrides(dir); ok {
		t.Error("LoadOverrides reports a layer after a full revert removed the file")
	}
}

func TestLoadRefusesABrokenLayerInsteadOfGuessing(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(OverridePath(dir), []byte(`{"schema":"kai-layer/9"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOverrides(dir); err == nil {
		t.Error("LoadOverrides accepted a layer written by a schema it does not know")
	}

	if err := os.WriteFile(OverridePath(dir), []byte(`{"schema":"kai-layer/1","patterns":[{"key":{"archetype":"web-app","family":"bogus","name":"x"},"confidence":0.5}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadOverrides(dir)
	if err == nil {
		t.Fatal("LoadOverrides accepted a pattern with an unknown family")
	}
	if !strings.Contains(err.Error(), "pattern-overrides.json") {
		t.Errorf("the error must name the file the operator has to fix: %v", err)
	}
}

// A layer file that exists but carries no patterns still counts as "adopted
// nothing" rather than an error: hand-editing the numbers away is legal.
func TestWorkspaceAdapterAbsentWithoutAFile(t *testing.T) {
	dir := t.TempDir()
	if _, ok, err := WorkspaceAdapter(dir); ok || err != nil {
		t.Fatalf("no file must mean no adapter: ok=%v err=%v", ok, err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(OverridePath(dir), []byte(`{"schema":"kai-layer/1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := WorkspaceAdapter(dir); !ok || err != nil {
		t.Fatalf("an empty layer file must still load: ok=%v err=%v", ok, err)
	}
}
