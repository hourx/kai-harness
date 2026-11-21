package pattern

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LayerSchema tags a layer file written by kai itself.
const LayerSchema = "kai-layer/1"

// Adopted is one lesson the operator accepted. It travels beside the pattern it
// changes, because a lesson without its provenance is indistinguishable from a
// number someone typed.
type Adopted struct {
	ID    string `json:"id"`
	Key   Key    `json:"key"`
	Kind  string `json:"kind"`  // raise | lower
	Boost int    `json:"boost"` // ranking nudge: +1 raise, -1 lower
	Why   string `json:"why"`
	TS    string `json:"ts"`
}

// Overrides is the workspace-local layer: patterns the operator corrected, plus
// the adopted lessons behind each correction. One file, so adopting a proposal
// and rolling it back are the same operation on the same pointer.
type Overrides struct {
	Schema   string    `json:"schema"`
	Patterns []Pattern `json:"patterns"`
	Adopted  []Adopted `json:"adopted,omitempty"`
}

// OverridePath is where a workspace keeps its own corrections.
func OverridePath(programDir string) string {
	return filepath.Join(programDir, "state", "pattern-overrides.json")
}

// LoadOverrides reads the workspace layer. A missing file is the normal state:
// nothing has been adopted yet.
func LoadOverrides(programDir string) (Overrides, bool, error) {
	b, err := os.ReadFile(OverridePath(programDir))
	if err != nil {
		if os.IsNotExist(err) {
			return Overrides{}, false, nil
		}
		return Overrides{}, false, err
	}
	var o Overrides
	if err := json.Unmarshal(b, &o); err != nil {
		return Overrides{}, false, fmt.Errorf("pattern-overrides.json: %w", err)
	}
	if o.Schema != "" && o.Schema != LayerSchema {
		return Overrides{}, false, fmt.Errorf("pattern-overrides.json: schema %q, want %q", o.Schema, LayerSchema)
	}
	o.Schema = LayerSchema
	// A file that no longer validates is a broken layer, and a broken layer is
	// reported rather than silently ignored — see LoadAdapters.
	if _, problems, err := LoadAdapters(Library{}, FileAdapter{Path: OverridePath(programDir)}); err != nil {
		return Overrides{}, false, fmt.Errorf("pattern-overrides.json: %w", err)
	} else if len(problems) > 0 {
		return Overrides{}, false, fmt.Errorf("pattern-overrides.json: %s", strings.Join(problems, "; "))
	}
	return o, true, nil
}

// SaveOverrides writes the workspace layer, or removes it when it holds nothing.
// An empty file is not kept: an empty override and no override must behave the
// same way, or a rollback leaves a residue someone will later mistake for intent.
func SaveOverrides(programDir string, o Overrides) (string, error) {
	p := OverridePath(programDir)
	if len(o.Patterns) == 0 && len(o.Adopted) == 0 {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return "", nil
	}
	o.Schema = LayerSchema
	o.Sort()
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Join(programDir, "state"), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return "", err
	}
	return p, nil
}

// Sort keeps the file diffable: same lessons, same order.
func (o *Overrides) Sort() {
	sort.Slice(o.Patterns, func(i, j int) bool { return o.Patterns[i].Key.String() < o.Patterns[j].Key.String() })
	sort.Slice(o.Adopted, func(i, j int) bool { return o.Adopted[i].ID < o.Adopted[j].ID })
}

// Nudge is what adoption is worth in ranking: at most two points, and only for
// the class key an adopted lesson names. Adoption is a tie-breaker on top of the
// delta, never a rewrite of the surface's own evidence.
func (o Overrides) Nudge(class string) int {
	name := Canonical(class)
	if name == "" {
		return 0
	}
	sum := 0
	for _, a := range o.Adopted {
		if a.Key.Family == FamilyClass && Canonical(a.Key.Name) == name {
			sum += a.Boost
		}
	}
	if sum > 2 {
		return 2
	}
	if sum < -2 {
		return -2
	}
	return sum
}

// WorkspaceAdapter exposes the workspace layer to the merge, if it exists.
func WorkspaceAdapter(programDir string) (Adapter, bool, error) {
	p := OverridePath(programDir)
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return FileAdapter{Path: p}, true, nil
}

// Adopt turns an accepted lesson into a layer entry: the pattern it names is
// copied at the new confidence, and the lesson is recorded beside it. The key
// must already exist in the library — kai adjusts knowledge it has, it does not
// invent a pattern from a count.
func Adopt(o Overrides, lib Library, key Key, kind string, num, den int, programs []string, why string, ts time.Time) (Overrides, error) {
	if kind != "raise" && kind != "lower" {
		return Overrides{}, fmt.Errorf("adopt: unknown kind %q", kind)
	}
	base, ok := lib.Lookup(key)
	if !ok {
		return Overrides{}, fmt.Errorf("adopt: %s is not in the library — write it as a layer file first", key)
	}
	step := RaiseStep
	if kind == "lower" {
		step = LowerStep
	}
	next := base.Confidence + step
	if kind == "lower" {
		next = base.Confidence - step
	}
	next = clampConf(next)
	base.Confidence = next
	base.Source = "operator/shadow"
	base.Note = fmt.Sprintf("adopted %s: %d/%d outcomes in %d program(s) — %s",
		kind, num, den, len(programs), strings.Join(programs, ", "))

	out := o
	out.Schema = LayerSchema
	out.Patterns = replacePattern(out.Patterns, base)
	boost := 1
	if kind == "lower" {
		boost = -1
	}
	out.Adopted = replaceAdopted(out.Adopted, Adopted{
		ID:    kind + ":" + key.String(),
		Key:   key,
		Kind:  kind,
		Boost: boost,
		Why:   why,
		TS:    ts.UTC().Format(time.RFC3339),
	})
	out.Sort()
	return out, nil
}

// everything reports whether a selector means "every adopted lesson". Both the
// empty id and the literal "all" mean it: the CLI spells the bulk case "all", and
// a package that treats the operator's word as an id matching nothing would turn
// a sweep into a silent no-op that still printed a success line.
func everything(id string) bool { return id == "" || id == "all" }

// Revert drops one adopted lesson, or every one when the selector means all, and
// puts the pattern back to what the library said before.
func Revert(o Overrides, id string) Overrides {
	var keptAdopted []Adopted
	var dropped []string
	for _, a := range o.Adopted {
		if everything(id) || a.ID == id {
			dropped = append(dropped, a.Key.String())
			continue
		}
		keptAdopted = append(keptAdopted, a)
	}
	var kept []Pattern
	for _, pt := range o.Patterns {
		if contains(dropped, pt.Key.String()) {
			continue
		}
		kept = append(kept, pt)
	}
	out := o
	out.Patterns = kept
	out.Adopted = keptAdopted
	out.Sort()
	return out
}

// Reverted reports which keys a revert would restore to the library's own text.
func Reverted(o Overrides, id string) []string {
	var keys []string
	for _, a := range o.Adopted {
		if everything(id) || a.ID == id {
			keys = append(keys, a.Key.String())
		}
	}
	sort.Strings(keys)
	return keys
}

// ValidAdoptID reports whether the workspace holds this lesson.
func (o Overrides) ValidAdoptID(id string) bool {
	for _, a := range o.Adopted {
		if a.ID == id {
			return true
		}
	}
	return false
}

func replacePattern(ps []Pattern, p Pattern) []Pattern {
	for i := range ps {
		if ps[i].Key == p.Key {
			ps[i] = p
			return ps
		}
	}
	return append(ps, p)
}

func replaceAdopted(as []Adopted, a Adopted) []Adopted {
	for i := range as {
		if as[i].ID == a.ID {
			as[i] = a
			return as
		}
	}
	return append(as, a)
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func clampConf(c float64) float64 {
	if c > MaxConf {
		return MaxConf
	}
	if c < MinConf {
		return MinConf
	}
	return c
}

// The bounds a lesson may move confidence within. Small on purpose: one accepted
// proposal is an adjustment, not a rewrite.
const (
	RaiseStep = 0.10
	LowerStep = 0.15
	MaxConf   = 0.95
	MinConf   = 0.05
)
