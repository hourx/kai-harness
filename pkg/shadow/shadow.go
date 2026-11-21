// Package shadow reads what this workspace and its neighbours recorded and
// proposes what the pattern layer should say instead — then stops.
//
// The loop is deliberately incomplete. kai proposes; the operator adopts with one
// explicit command, which writes a layer file; a rollback is that pointer
// removed. Nothing here applies itself, and no proposal can exist without evidence
// from more than one program of the same shape, because a library reshaped by a
// single engagement's bad afternoon is a library nobody can trust.
package shadow

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/pattern"
)

// Schema tags the report file.
const Schema = "kai-shadow/1"

// Kinds of proposal. Two change the library; one asks the operator to write.
const (
	// KindRaise: a class that paid here more than once, in more than one program.
	KindRaise = "raise"
	// KindLower: a class the operator closed NEGATIVE repeatedly, with nothing to
	// show for it anywhere.
	KindLower = "lower"
	// KindGap: something the model names that no pattern speaks about. Not
	// adoptable — a gap is answered by writing, not by adjusting a number.
	KindGap = "gap"
)

// Gates. Every number here exists to keep the library from being rewritten by
// noise, and each one is quoted in the report when a key fails it, so the operator
// can disagree with the threshold rather than guess at it.
const (
	MinPrograms = 2 // one program's afternoon is not evidence about the world
	MinFired    = 4 // four recordings before an idea may be re-graded
	RaisePaid   = 2 // two yields
	RaiseRatio  = 0.5
	LowerNeg    = 3 // three closures in a row
	GapPaths    = 3 // an entity addressed by three paths and no pattern is a gap
	NudgeMax    = 2 // adoption is worth at most two points (pattern.Overrides.Nudge)
)

// Observation is one program's recorded outcomes, the only input this loop takes.
type Observation struct {
	Program   string
	Archetype string
	Records   []outcome.Record
}

// Evidence is what a proposal rests on, printed in full. A proposal whose
// evidence cannot be read is an instruction.
type Evidence struct {
	Programs  int      `json:"programs"`
	Where     []string `json:"where"`
	Fired     int      `json:"fired"`
	Paid      int      `json:"paid"`
	Negation  int      `json:"negation"`
	Tried     int      `json:"tried"`
	Last      string   `json:"last,omitempty"`
	Archetype string   `json:"archetype"`
}

// Proposal is one candidate lesson, with the change it would make.
type Proposal struct {
	ID        string      `json:"id"`
	Kind      string      `json:"kind"`
	Key       pattern.Key `json:"key"`
	Class     string      `json:"class,omitempty"`
	From      float64     `json:"from,omitempty"`
	To        float64     `json:"to,omitempty"`
	Adoptable bool        `json:"adoptable"`
	Reason    string      `json:"reason"`
	Evidence  Evidence    `json:"evidence"`
}

// Held is a key that was seen and did not clear a gate. It is reported, not
// dropped: an operator who disagrees with MinPrograms should be able to see which
// keys are waiting on it.
type Held struct {
	Key      pattern.Key `json:"key"`
	Evidence Evidence    `json:"evidence"`
	Missing  string      `json:"missing"`
}

// Report is the whole loop's output.
type Report struct {
	Schema      string     `json:"schema"`
	Program     string     `json:"program"`
	Archetype   string     `json:"archetype"`
	Generated   string     `json:"generated"`
	LibrarySize int        `json:"library_size"`
	Proposals   []Proposal `json:"proposals"`
	Held        []Held     `json:"held"`
	// Touched is how many class keys had any outcome behind them at all. Zero
	// here is the honest answer for a fresh workspace, and the report says so.
	Touched int `json:"touched"`
}

// Evaluate builds the report. lib is the merged library the proposals would
// change, so a proposal can quote the confidence it starts from; gaps are read
// from the target program's model, passed as names.
func Evaluate(program, archetype string, lib pattern.Library, obs []Observation, entities map[string]int, now time.Time) Report {
	r := Report{
		Schema:      Schema,
		Program:     program,
		Archetype:   archetype,
		Generated:   now.UTC().Format(time.RFC3339),
		LibrarySize: lib.Len(),
		Proposals:   []Proposal{},
		Held:        []Held{},
	}
	arch := pattern.CanonicalArchetype(archetype)

	// Aggregate per (archetype, class): counts, plus which programs contributed.
	type bucket struct {
		key      pattern.Key
		programs map[string]bool
		fired    int
		paid     int
		negation int
		last     string
	}
	byKey := map[string]*bucket{}
	var order []string
	for _, o := range obs {
		oarch := pattern.CanonicalArchetype(o.Archetype)
		for _, rec := range o.Records {
			class := pattern.Canonical(rec.Class)
			if class == "" {
				class = "unclassified"
			}
			// A key is archetype-scoped, so evidence is only comparable inside one
			// shape. An `api` yield says nothing about a `chain` class.
			k := pattern.Key{Archetype: oarch, Family: pattern.FamilyClass, Name: class}
			id := k.String()
			b, ok := byKey[id]
			if !ok {
				b = &bucket{key: k, programs: map[string]bool{}}
				byKey[id] = b
				order = append(order, id)
			}
			b.programs[o.Program] = true
			b.fired++
			switch {
			case outcome.Yields(rec.Status):
				b.paid++
			case rec.Status == outcome.StatusNegation:
				b.negation++
			}
			if ts := strings.TrimSpace(rec.TS); ts > b.last {
				b.last = ts
			}
		}
	}
	sort.Strings(order)

	for _, id := range order {
		b := byKey[id]
		ev := Evidence{
			Programs:  len(b.programs),
			Where:     sortedKeys(b.programs),
			Fired:     b.fired,
			Paid:      b.paid,
			Negation:  b.negation,
			Tried:     maxInt(0, b.fired-b.paid-b.negation),
			Last:      b.last,
			Archetype: b.key.Archetype,
		}
		if b.key.Archetype != arch {
			// Comparable, but not this program's shape: report it as held so the
			// operator can see the loop is not blind to it, and never propose it
			// against the wrong key.
			r.Held = append(r.Held, Held{Key: b.key, Evidence: ev,
				Missing: fmt.Sprintf("recorded under archetype %s, not this program's %s", b.key.Archetype, arch)})
			continue
		}
		r.Touched++
		if !PatternExists(lib, b.key) {
			r.Held = append(r.Held, Held{Key: b.key, Evidence: ev, Missing: "no pattern for this class — write one with a layer file"})
			continue
		}
		cur, _ := lib.Lookup(b.key)

		switch {
		case ev.Programs < MinPrograms:
			r.Held = append(r.Held, Held{Key: b.key, Evidence: ev,
				Missing: fmt.Sprintf("only %d program(s) of this shape recorded it (need %d) — the workspace delta already ranks it here, the library is not changed on one engagement's word", ev.Programs, MinPrograms)})
			continue
		case ev.Fired < MinFired:
			r.Held = append(r.Held, Held{Key: b.key, Evidence: ev,
				Missing: fmt.Sprintf("%d outcome(s) recorded (need %d)", ev.Fired, MinFired)})
			continue
		}

		ratio := float64(ev.Paid) / float64(ev.Fired)
		switch {
		case ev.Paid >= RaisePaid && ratio >= RaiseRatio:
			to := clamp(cur.Confidence + pattern.RaiseStep)
			if to <= cur.Confidence {
				r.Held = append(r.Held, Held{Key: b.key, Evidence: ev,
					Missing: fmt.Sprintf("already at the confidence ceiling (%.2f): the yield is in this workspace's delta, and raising a number that cannot move would be an adoption that changes nothing", cur.Confidence)})
				continue
			}
			r.Proposals = append(r.Proposals, Proposal{
				ID: KindRaise + ":" + b.key.String(), Kind: KindRaise, Key: b.key, Class: b.key.Name,
				From: cur.Confidence, To: to, Adoptable: true,
				Reason:   fmt.Sprintf("%d of %d outcomes yielded across %d %s programs", ev.Paid, ev.Fired, ev.Programs, b.key.Archetype),
				Evidence: ev,
			})
		case ev.Paid == 0 && ev.Negation >= LowerNeg:
			to := clamp(cur.Confidence - pattern.LowerStep)
			if to >= cur.Confidence {
				r.Held = append(r.Held, Held{Key: b.key, Evidence: ev,
					Missing: fmt.Sprintf("already at the confidence floor (%.2f): a lower here would ask the shipped layer to forget a class, which is an edit to the library, not a lesson", cur.Confidence)})
				continue
			}
			r.Proposals = append(r.Proposals, Proposal{
				ID: KindLower + ":" + b.key.String(), Kind: KindLower, Key: b.key, Class: b.key.Name,
				From: cur.Confidence, To: to, Adoptable: true,
				Reason:   fmt.Sprintf("%d closures and no yield in %d outcomes across %d programs", ev.Negation, ev.Fired, ev.Programs),
				Evidence: ev,
			})
		default:
			r.Held = append(r.Held, Held{Key: b.key, Evidence: ev,
				Missing: "evidence is mixed: no yield and no run of closures"})
		}
	}

	for _, name := range sortedStringIntKeys(entities) {
		n := entities[name]
		if n < GapPaths {
			continue
		}
		k := pattern.Key{Archetype: arch, Family: pattern.FamilyEntity, Name: pattern.Canonical(name)}
		if _, ok := lib.Lookup(k); ok {
			continue
		}
		r.Proposals = append(r.Proposals, Proposal{
			ID: KindGap + ":" + k.String(), Kind: KindGap, Key: k, Adoptable: false,
			Reason: fmt.Sprintf("the model names %q and %d observed path(s) address it, with no pattern to test it", name, n),
			Evidence: Evidence{
				Archetype: arch,
				Where:     []string{program},
			},
		})
	}
	sort.Slice(r.Proposals, func(i, j int) bool {
		if r.Proposals[i].Kind != r.Proposals[j].Kind {
			return r.Proposals[i].Kind < r.Proposals[j].Kind
		}
		return r.Proposals[i].ID < r.Proposals[j].ID
	})
	return r
}

// PatternExists reports whether the merged library already answers this key.
func PatternExists(lib pattern.Library, k pattern.Key) bool {
	_, ok := lib.Lookup(k)
	return ok
}

// Markdown renders the report the way the operator reads it: proposals first,
// then what is waiting and why, then the shape of the evidence behind all of it.
func (r Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Shadow — %s\n\n", r.Program)
	fmt.Fprintf(&b, "Archetype **%s** · %d pattern(s) in the library · %d class key(s) with outcomes · %d proposal(s)\n\n",
		r.Archetype, r.LibrarySize, r.Touched, len(r.Proposals))
	b.WriteString("Nothing here has been applied. `kai shadow " + r.Program + " --adopt <id>` writes one lesson into\n`state/pattern-overrides.json`; `--revert` takes it back out.\n\n")

	if r.Touched == 0 {
		b.WriteString("No outcome recorded against any class yet, so there is nothing to learn and nothing to guess:\n")
		b.WriteString("record what you tested (`kai outcome <program> ...`) and this page fills itself.\n\n")
	}
	if len(r.Proposals) == 0 {
		b.WriteString("## No proposal cleared the gates\n\n")
	} else {
		b.WriteString("## Proposals\n\n")
		for _, p := range r.Proposals {
			fmt.Fprintf(&b, "- **%s** `%s` — %s\n", p.Kind, p.ID, p.Reason)
			if p.Adoptable {
				fmt.Fprintf(&b, "  confidence %.2f → %.2f · evidence: %d outcome(s) in %d program(s) (%s) · last %s\n",
					p.From, p.To, p.Evidence.Fired, p.Evidence.Programs, strings.Join(p.Evidence.Where, ", "), short(p.Evidence.Last))
			} else {
				b.WriteString("  not adoptable — a gap is closed by writing a pattern, not by moving a number\n")
			}
		}
		b.WriteString("\n")
	}
	if len(r.Held) > 0 {
		b.WriteString("## Seen, not yet enough\n\n")
		for _, h := range r.Held {
			fmt.Fprintf(&b, "- `%s` — %s", h.Key.String(), h.Missing)
			if h.Evidence.Fired > 0 {
				fmt.Fprintf(&b, " (%d outcome(s): %d paid, %d closed, %d unclassified)",
					h.Evidence.Fired, h.Evidence.Paid, h.Evidence.Negation, h.Evidence.Tried)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("## Gates\n\n")
	fmt.Fprintf(&b, "- a lesson needs ≥%d outcomes across ≥%d programs of the same shape\n", MinFired, MinPrograms)
	fmt.Fprintf(&b, "- raise: ≥%d yields and a ≥%.0f%% yield rate; lower: ≥%d closures and no yield anywhere\n", RaisePaid, RaiseRatio*100, LowerNeg)
	fmt.Fprintf(&b, "- a step is ±%.2f confidence, and adoption is worth at most %d ranking point(s)\n", pattern.RaiseStep, NudgeMax)
	b.WriteString("- nothing is applied without `--adopt`, and every adoption is one file you can delete\n")
	return b.String()
}

func short(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	if ts == "" {
		return "never"
	}
	return ts
}

func clamp(c float64) float64 {
	if c > pattern.MaxConf {
		return pattern.MaxConf
	}
	if c < pattern.MinConf {
		return pattern.MinConf
	}
	return c
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringIntKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
