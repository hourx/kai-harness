package pattern

import (
	"strings"
	"testing"

	"github.com/hourx/kai-harness/pkg/surface"
)

func TestCanonicalFoldsSpellingsOntoOneName(t *testing.T) {
	cases := map[string]string{
		"IDOR/BOLA":            "idor/bola",
		"GraphQL":              "graphql",
		"file upload":          "file-upload",
		"file_upload":          "file-upload",
		"file--upload":         "file-upload",
		"  Auth Bypass/ATO  ":  "auth-bypass/ato",
		"access_control":       "access-control",
		"":                     "",
		"///":                  "",
		"SSTI (server side)":   "ssti-server-side",
		"broken-object-level!": "broken-object-level",
	}
	for in, want := range cases {
		if got := Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewKeyCanonicalisesEveryPart(t *testing.T) {
	k := NewKey("GraphQL_API", FamilyClass, "IDOR/BOLA")
	if k.Archetype != "graphql-api" || k.Family != FamilyClass || k.Name != "idor/bola" {
		t.Fatalf("NewKey did not canonicalise: %+v", k)
	}
	if got := NewKey("nonsense-shape", FamilyClass, "x").Archetype; got != Any {
		t.Fatalf("an unknown shape must fall back to %q, got %q", Any, got)
	}
	if got := NewKey("", FamilyEntity, "account").Archetype; got != Any {
		t.Fatalf("an empty shape must fall back to %q, got %q", Any, got)
	}
}

func TestParseKeyRoundTrips(t *testing.T) {
	k := NewKey("graphql-api", FamilyClass, "idor/bola")
	got, err := ParseKey(k.String())
	if err != nil {
		t.Fatalf("ParseKey(%q): %v", k.String(), err)
	}
	if got != k {
		t.Fatalf("round trip changed the key: %+v -> %+v", k, got)
	}
	for _, bad := range []string{"", "graphql-api", "graphql-api/class", "graphql-api/nonsense/x", "graphql-api/class/", "unknown-shape/class/x", "graphql-api/class/IDOR/BOLA"} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("ParseKey(%q) should have failed", bad)
		}
	}
}

func TestKeyValidRejectsNonCanonicalNames(t *testing.T) {
	if err := (Key{Archetype: "api", Family: FamilyClass, Name: "IDOR/BOLA"}).Valid(); err == nil {
		t.Fatal("a non-canonical name must be refused, otherwise one idea becomes two keys")
	}
	k := NewKey("api", FamilyClass, "idor/bola")
	if err := k.Valid(); err != nil {
		t.Fatalf("canonical key refused: %v", err)
	}
	if k.String() != "api/class/idor/bola" {
		t.Fatalf("String() = %q", k.String())
	}
}

func TestLabelKeepsAcronymsReadable(t *testing.T) {
	if got := Label("idor/bola"); got != "IDOR/BOLA" {
		t.Errorf("Label(idor/bola) = %q", got)
	}
	if got := Label("file-upload/ssrf"); got != "file-upload/SSRF" {
		t.Errorf("Label(file-upload/ssrf) = %q", got)
	}
	if got := Label("business-logic"); got != "business-logic" {
		t.Errorf("Label(business-logic) = %q", got)
	}
}

func TestLibraryKeepsOnePatternPerKeyAndSorts(t *testing.T) {
	a := Pattern{Key: NewKey("api", FamilyClass, "surface-review"), Class: "surface-review", Title: "first", Confidence: 0.2}
	b := Pattern{Key: NewKey("api", FamilyClass, "surface-review"), Class: "surface-review", Title: "second", Confidence: 0.9}
	c := Pattern{Key: NewKey("api", FamilyEntity, "account"), Class: "access-control", Title: "entity", Confidence: 0.5}

	lib, err := New(a, b, c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if lib.Len() != 2 {
		t.Fatalf("want 2 patterns (one per key), got %d", lib.Len())
	}
	got, ok := lib.Lookup(a.Key)
	if !ok || got.Title != "second" {
		t.Fatalf("a later pattern must replace an earlier one with the same key, got %+v", got)
	}
	all := lib.All()
	for i := 1; i < len(all); i++ {
		if all[i-1].Key.String() > all[i].Key.String() {
			t.Fatalf("All() is not sorted: %s before %s", all[i-1].Key, all[i].Key)
		}
	}
}

func TestLibraryForPrefersTheShapeThenEveryShape(t *testing.T) {
	lib := Public()
	rows := lib.For("graphql-api")
	if len(rows) == 0 {
		t.Fatal("no patterns for graphql-api")
	}
	// Three tiers in order: this shape, the shape it descends from, every shape.
	tier := func(k Key) int {
		switch k.Archetype {
		case "graphql-api":
			return 0
		case "api":
			return 1
		case Any:
			return 2
		}
		return -1
	}
	last := -1
	for i, p := range rows {
		got := tier(p.Key)
		if got < 0 {
			t.Fatalf("row %d: %s does not apply to graphql-api", i, p.Key)
		}
		if got < last {
			t.Fatalf("row %d: tier %d appears after tier %d (%s)", i, got, last, p.Key)
		}
		last = got
	}
	// A gateway is an API: the API baseline must be reachable from it.
	if _, ok := lib.Covered("graphql-api", "api-surface"); !ok {
		t.Fatal("graphql-api should inherit the api surface patterns")
	}
	if from, ok := lib.Covered("graphql-api", "api-surface"); ok && from != "inherited from `api`" {
		t.Fatalf("coverage should name the tier, got %q", from)
	}
	if _, ok := lib.Covered("graphql-api", "made-up"); ok {
		t.Fatal("an unknown class must not be reported as covered")
	}
	if got := lib.For("nonsense-shape"); len(got) == 0 {
		t.Fatal("an unclassified shape must still get the every-shape patterns")
	}
}

func TestLibraryMissingClassesNamesTheGap(t *testing.T) {
	lib := Public()
	missing := lib.MissingClasses("graphql-api", []string{"graphql", "IDOR/BOLA", "made-up-class"})
	if len(missing) != 1 || missing[0] != "made-up-class" {
		t.Fatalf("MissingClasses = %v, want [made-up-class]", missing)
	}
}

func TestPublicLibraryIsWellFormed(t *testing.T) {
	known := map[string]bool{}
	for _, c := range surface.Classes() {
		known[Canonical(c)] = true
	}
	if len(known) == 0 {
		t.Fatal("surface.Classes() returned nothing — the queue's class set is the join key")
	}
	lib := Public()
	if lib.Len() < 40 {
		t.Fatalf("the shipped layer has %d patterns; a layer this thin cannot rank anything", lib.Len())
	}
	seen := map[Key]bool{}
	for _, p := range lib.All() {
		if seen[p.Key] {
			t.Fatalf("duplicate key %s", p.Key)
		}
		seen[p.Key] = true
		if p.Confidence <= 0 || p.Confidence > 1 {
			t.Errorf("%s: confidence %.2f should be inside (0,1]", p.Key, p.Confidence)
		}
		if strings.TrimSpace(p.Why) == "" || strings.TrimSpace(p.Title) == "" {
			t.Errorf("%s: a pattern without a title and a why is a guess, not knowledge", p.Key)
		}
		if p.Source != "kai-generic/1" {
			t.Errorf("%s: unexpected source %q", p.Key, p.Source)
		}
		if strings.HasPrefix(p.Key.Name, "test-") || strings.Contains(p.Key.Name, "example") {
			t.Errorf("%s: placeholder data does not belong in the shipped layer", p.Key)
		}
	}
	// Every class the layer names must be one the queue can actually assign, or
	// the join silently does nothing.
	for _, p := range lib.All() {
		if p.Class == "" {
			continue
		}
		if !known[p.Class] {
			t.Errorf("%s feeds class %q, which the queue never produces", p.Key, p.Class)
		}
	}
	// The shapes the layer speaks about must be real shapes.
	for _, p := range lib.All() {
		if p.Key.Archetype != Any && !knownArchetype(p.Key.Archetype) {
			t.Errorf("%s: unknown archetype", p.Key)
		}
	}
	for _, class := range surface.Classes() {
		if _, ok := lib.Lookup(Key{Archetype: Any, Family: FamilyClass, Name: Canonical(class)}); ok {
			continue
		}
		found := false
		for _, arch := range []string{"api", "graphql-api", "web-app", "mobile-api", "chain", "mixed", "unknown"} {
			if _, ok := lib.Lookup(Key{Archetype: arch, Family: FamilyClass, Name: Canonical(class)}); ok {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no pattern explains class %q for any shape the queue can produce", class)
		}
	}
}

func knownArchetype(name string) bool {
	for _, p := range Public().All() {
		if p.Key.Archetype == name {
			return true
		}
	}
	return false
}
