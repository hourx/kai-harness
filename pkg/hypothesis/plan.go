// Package hypothesis turns the ranked surface queue into an engagement plan:
// hypotheses grouped into passes an operator can actually run.
//
// The queue answers "what is most likely to pay"; the plan answers "in what
// order can I work today, and what do I need to have signed in". It is pure
// data — plan.json is meant to be read, and hand-edited if the operator
// disagrees with a heuristic.
package hypothesis

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/surface"
)

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Needs values: what has to exist before a step can be attempted.
const (
	NeedNone        = "none"
	NeedSession     = "session"
	NeedTwoSessions = "two-sessions"
)

// Step is one hypothesis with its preconditions and probe.
type Step struct {
	Rank   int    `json:"rank"`
	Wave   int    `json:"wave"`
	Needs  string `json:"needs"`
	Target string `json:"target"`
	Class  string `json:"class"`
	Score  int    `json:"score"`
	// Boost is the pattern delta's contribution to the ordering inside this
	// step's wave (see pkg/pattern). Recorded, not folded into Score, so the
	// plan can show why one class outranks another.
	Boost   int      `json:"pattern_boost,omitempty"`
	Probe   string   `json:"probe,omitempty"`
	Why     []string `json:"why,omitempty"`
	Cluster string   `json:"cluster,omitempty"`
	Pointer string   `json:"method_pointer"`
	Merged  []string `json:"merged_hypotheses,omitempty"`
}

// Wave groups steps that share a precondition.
type Wave struct {
	N       int      `json:"n"`
	Name    string   `json:"name"`
	Needs   string   `json:"needs"`
	Count   int      `json:"count"`
	Classes []string `json:"classes"`
}

// Plan is the ordered, precondition-grouped engagement plan.
type Plan struct {
	Program   string   `json:"program"`
	Generated string   `json:"generated"`
	Source    string   `json:"source"`
	Steps     []Step   `json:"steps"`
	Waves     []Wave   `json:"waves"`
	Notes     []string `json:"notes"`
}

// needsByClass maps a hypothesis class to the least it needs to be tested. It is
// a heuristic, deliberately explicit and editable: the operator knows the program
// better than a table does.
var needsByClass = map[string]string{
	"surface-review":       NeedNone,
	"supply-chain":         NeedNone,
	"smart-contract":       NeedNone,
	"graphql":              NeedNone,
	"api-surface":          NeedNone,
	"infra-or-other":       NeedNone,
	"auth-bypass/ATO":      NeedSession,
	"file-upload/SSRF":     NeedSession,
	"mobile-app":           NeedSession,
	"agentic-ai":           NeedSession,
	"access-control":       NeedSession,
	"privilege-escalation": NeedSession,
	"IDOR/BOLA":            NeedTwoSessions,
	"business-logic":       NeedTwoSessions,
}

var waveNames = map[string]string{
	NeedNone:        "no session needed",
	NeedSession:     "one authenticated session",
	NeedTwoSessions: "two identities",
}

// Options adjusts the ordering without changing what the plan contains. The zero
// value reproduces the plain ordering exactly.
type Options struct {
	// Boost is a small, per-class ranking signal — the pattern delta in practice.
	// It orders steps inside one wave; it never moves a step across waves, because
	// a missing session is a fact and a pattern is a hint.
	Boost func(class string) int
}

// Build groups and orders a ranked queue. One step per class: a queue can hold
// dozens of paths that all ask the same question, and the operator's protocol is
// one target per probe — the highest-scoring path becomes the step, the rest are
// recorded as merged so nothing is silently lost.
func Build(p surface.Plan) Plan {
	return BuildWith(p, Options{})
}

// BuildWith is Build with an ordering adjustment applied.
func BuildWith(p surface.Plan, o Options) Plan {
	out := Plan{Program: p.Program, Source: p.Generated, Generated: now()}

	byClass := map[string][]surface.Hypothesis{}
	for _, h := range p.Items {
		class := strings.TrimSpace(h.Class)
		if class == "" {
			class = "unclassified"
		}
		byClass[class] = append(byClass[class], h)
	}
	classes := make([]string, 0, len(byClass))
	for c := range byClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)

	for _, c := range classes {
		group := byClass[c]
		sort.SliceStable(group, func(i, j int) bool {
			if group[i].Score != group[j].Score {
				return group[i].Score > group[j].Score
			}
			return group[i].Target < group[j].Target
		})
		top := group[0]
		boost := 0
		if o.Boost != nil {
			boost = o.Boost(top.Class)
		}
		st := Step{
			Needs:   needs(top.Class),
			Target:  top.Target,
			Class:   c,
			Score:   top.Score,
			Boost:   boost,
			Probe:   top.Probe,
			Why:     top.Why,
			Cluster: top.Cluster,
			Pointer: "plan.md#" + slug(c),
		}
		for _, extra := range group[1:] {
			st.Merged = append(st.Merged, extra.Target)
		}
		out.Steps = append(out.Steps, st)
	}

	waveOf := map[string]int{NeedNone: 1, NeedSession: 2, NeedTwoSessions: 3}
	sort.SliceStable(out.Steps, func(i, j int) bool {
		a, b := out.Steps[i], out.Steps[j]
		if wa, wb := waveOf[a.Needs], waveOf[b.Needs]; wa != wb {
			return wa < wb
		}
		if ka, kb := a.Score+a.Boost, b.Score+b.Boost; ka != kb {
			return ka > kb
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		return a.Target < b.Target
	})
	for i := range out.Steps {
		out.Steps[i].Rank = i + 1
		out.Steps[i].Wave = waveOf[out.Steps[i].Needs]
	}
	out.Waves = waves(out.Steps)

	out.Notes = []string{
		"Preconditions are a heuristic table (needsByClass in pkg/hypothesis); edit plan.json if this program disagrees.",
		"One step per class: the queue is path-level, so several paths asking the same question collapse into the highest-scoring one.",
		"Ranking and scope are hints, not verdicts. Run the scope gate (`kai scope`) before every request.",
		"kai never sends a request while planning, and never submits a report.",
	}
	if o.Boost != nil {
		boosted := 0
		for _, s := range out.Steps {
			if s.Boost != 0 {
				boosted++
			}
		}
		out.Notes = append(out.Notes, fmt.Sprintf(
			"Ordering inside a wave includes the pattern delta: %d of %d step(s) carry a boost from what this archetype already produced here (kai patterns %s). Waves never move.",
			boosted, len(out.Steps), p.Program))
	}
	if len(p.Items) > len(out.Steps) {
		out.Notes = append(out.Notes, fmt.Sprintf("%d queue items collapsed into %d steps.", len(p.Items), len(out.Steps)))
	}
	return out
}

func needs(class string) string {
	if n, ok := needsByClass[class]; ok {
		return n
	}
	// Unknown class: assume it needs a session, and say so in the plan body.
	return NeedSession
}

func waves(steps []Step) []Wave {
	seen := map[int][]string{}
	for _, s := range steps {
		seen[s.Wave] = append(seen[s.Wave], s.Class)
	}
	nums := make([]int, 0, len(seen))
	for n := range seen {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	out := make([]Wave, 0, len(nums))
	for _, n := range nums {
		classes := seen[n]
		sort.Strings(classes)
		need := NeedNone
		switch n {
		case 2:
			need = NeedSession
		case 3:
			need = NeedTwoSessions
		}
		out = append(out, Wave{N: n, Name: waveNames[need], Needs: need, Count: len(classes), Classes: classes})
	}
	return out
}

// Write saves plan.json and plan.md into the program directory.
func Write(pDir string, p Plan) (string, string, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", "", err
	}
	jsonPath := filepath.Join(pDir, "plan.json")
	if err := os.WriteFile(jsonPath, append(b, '\n'), 0o600); err != nil {
		return "", "", err
	}
	mdPath := filepath.Join(pDir, "plan.md")
	if err := os.WriteFile(mdPath, []byte(p.Markdown()), 0o600); err != nil {
		return "", "", err
	}
	return jsonPath, mdPath, nil
}

// Markdown renders the plan for a human.
func (p Plan) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Test plan — %s\n\n", p.Program)
	fmt.Fprintf(&b, "Generated %s from the ranked queue (%s). %d steps in %d waves.\n\n",
		p.Generated, sourceNote(p.Source), len(p.Steps), len(p.Waves))

	for _, w := range p.Waves {
		fmt.Fprintf(&b, "## Wave %d — %s (%d step(s))\n\n", w.N, w.Name, w.Count)
		for _, s := range p.Steps {
			if s.Wave != w.N {
				continue
			}
			if s.Boost != 0 {
				fmt.Fprintf(&b, "### %d. %s — `%s` (score %d, pattern %+d)\n\n", s.Rank, s.Class, s.Target, s.Score, s.Boost)
			} else {
				fmt.Fprintf(&b, "### %d. %s — `%s` (score %d)\n\n", s.Rank, s.Class, s.Target, s.Score)
			}
			if s.Probe != "" {
				fmt.Fprintf(&b, "- probe: %s\n", s.Probe)
			}
			if s.Cluster != "" {
				fmt.Fprintf(&b, "- cluster: %s\n", s.Cluster)
			}
			if len(s.Why) > 0 {
				fmt.Fprintf(&b, "- why: %s\n", strings.Join(s.Why, "; "))
			}
			if len(s.Merged) > 0 {
				fmt.Fprintf(&b, "- same question on %d other path(s): %s\n", len(s.Merged), strings.Join(trim(s.Merged, 5), ", "))
			}
			b.WriteString("- record the result: `kai outcome " + p.Program + " --status <negation|informational|finding> --class \"" + s.Class + "\" \"" + s.Target + "\"`\n\n")
		}
	}

	b.WriteString("## Notes\n\n")
	for _, n := range p.Notes {
		b.WriteString("- " + n + "\n")
	}
	return b.String()
}

func sourceNote(ts string) string {
	if ts == "" {
		return "unknown build time"
	}
	return ts
}

func trim(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	out := append([]string{}, in[:n]...)
	return append(out, fmt.Sprintf("+%d more", len(in)-n))
}

func slug(s string) string {
	var b strings.Builder
	last := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			last = false
		default:
			if !last {
				b.WriteByte('-')
				last = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
