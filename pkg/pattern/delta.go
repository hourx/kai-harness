package pattern

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/outcome"
)

// Schema tags the delta file so a future layout can be recognised rather than
// guessed at.
const DeltaSchema = "kai-patterns-delta/1"

// KeyStat is what this workspace has actually seen against one key.
type KeyStat struct {
	Key      Key    `json:"key"`
	Fired    int    `json:"fired"`    // targets recorded against the key
	Paid     int    `json:"paid"`     // records that yielded (finding, reported or paid)
	Negation int    `json:"negation"` // records the operator closed as not-a-bug
	Last     string `json:"last,omitempty"`
}

// Tried is the records that were neither a yield nor a negation — the operator
// tested the key and left it unclassified, which is weaker than a yield and
// stronger than a negation.
func (s KeyStat) Tried() int {
	if n := s.Fired - s.Paid - s.Negation; n > 0 {
		return n
	}
	return 0
}

// Delta is one program's own layer: which keys fired here, and what the operator
// recorded against them. It never leaves the workspace (§12, tier 3).
type Delta struct {
	Schema    string    `json:"schema"`
	Program   string    `json:"program"`
	Archetype string    `json:"archetype"`
	Generated string    `json:"generated"`
	Keys      []KeyStat `json:"keys"`
}

// BuildDelta derives the delta from the recorded outcomes. Only class keys are
// derived, because a class is the one thing every outcome already carries: an
// entity or action key would have to be guessed from the target string, and a
// guess written into a ranking signal is exactly the kind of quiet lie this tool
// refuses. The gap is printed by `kai patterns`, not hidden.
func BuildDelta(program, archetype string, records []outcome.Record, now time.Time) Delta {
	d := Delta{
		Schema:    DeltaSchema,
		Program:   program,
		Archetype: canonArchetype(archetype),
		Generated: now.UTC().Format(time.RFC3339),
	}
	if d.Archetype == "" {
		d.Archetype = Any
	}
	byKey := map[Key]*KeyStat{}
	for _, r := range records {
		class := Canonical(r.Class)
		if class == "" {
			class = "unclassified"
		}
		k := Key{Archetype: d.Archetype, Family: FamilyClass, Name: class}
		st, ok := byKey[k]
		if !ok {
			st = &KeyStat{Key: k}
			byKey[k] = st
		}
		st.Fired++
		switch {
		case outcome.Yields(r.Status):
			st.Paid++
		case r.Status == outcome.StatusNegation:
			st.Negation++
		}
		if ts := strings.TrimSpace(r.TS); ts > st.Last {
			st.Last = ts
		}
	}
	for _, st := range byKey {
		d.Keys = append(d.Keys, *st)
	}
	d.Sort()
	return d
}

// Sort orders the keys the way every report prints them.
func (d *Delta) Sort() {
	sort.Slice(d.Keys, func(i, j int) bool { return d.Keys[i].Key.String() < d.Keys[j].Key.String() })
}

// Stat returns the recorded counts for a key.
func (d Delta) Stat(k Key) (KeyStat, bool) {
	for _, s := range d.Keys {
		if s.Key == k {
			return s, true
		}
	}
	return KeyStat{}, false
}

// Boost is the ranking signal for one key: +3 per yield, +1 for a target that was
// tried and left unclassified, -2 per negation.
//
// It is deliberately small and linear. A pattern is a tie-breaker inside a wave —
// it must never outrank the surface's own evidence, so the numbers here stay far
// below a real endpoint score.
func (d Delta) Boost(k Key) int {
	st, ok := d.Stat(k)
	if !ok {
		return 0
	}
	return st.Paid*3 + st.Tried() - st.Negation*2
}

// BoostClass is Boost for the class key of this delta's archetype.
func (d Delta) BoostClass(class string) int {
	name := Canonical(class)
	if name == "" {
		return 0
	}
	return d.Boost(Key{Archetype: d.Archetype, Family: FamilyClass, Name: name})
}

// Path is where a delta is kept when the operator asks for it on disk.
func Path(programDir string) string {
	return filepath.Join(programDir, "state", "patterns-delta.json")
}

// Load reads a delta if one has been written. A missing file is not an error: the
// ranking is derived from outcomes on every run, and the file exists only so a
// human can read what drove the order.
func Load(programDir string) (Delta, bool, error) {
	b, err := os.ReadFile(Path(programDir))
	if err != nil {
		if os.IsNotExist(err) {
			return Delta{}, false, nil
		}
		return Delta{}, false, err
	}
	var d Delta
	if err := json.Unmarshal(b, &d); err != nil {
		return Delta{}, false, fmt.Errorf("patterns-delta.json: %w", err)
	}
	if d.Schema != DeltaSchema {
		return Delta{}, false, fmt.Errorf("patterns-delta.json: schema %q, want %q", d.Schema, DeltaSchema)
	}
	return d, true, nil
}

// Write persists the delta for inspection.
func Write(programDir string, d Delta) (string, error) {
	if d.Schema == "" {
		d.Schema = DeltaSchema
	}
	if err := os.MkdirAll(filepath.Join(programDir, "state"), 0o755); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	p := Path(programDir)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return "", err
	}
	return p, nil
}

// Markdown renders the delta as the operator's own layer, for `kai patterns`.
func (d Delta) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## This workspace's layer — archetype `%s`\n\n", d.Archetype)
	if len(d.Keys) == 0 {
		b.WriteString("No outcome recorded yet, so every class starts level: the public layer is the only signal.\n\n")
		return b.String()
	}
	b.WriteString("| class | fired | paid | negation | boost | last |\n|---|---|---|---|---|---|\n")
	for _, s := range d.Keys {
		last := s.Last
		if last == "" {
			last = "—"
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %+d | %s |\n", Label(s.Key.Name), s.Fired, s.Paid, s.Negation, d.Boost(s.Key), last)
	}
	b.WriteString("\nBoost is a tie-breaker inside a wave: +3 a yield, +1 tried and unclassified, −2 a negation. It never outranks a surface score.\n\n")
	return b.String()
}
