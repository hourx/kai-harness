package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/model"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/pattern"
	"github.com/hourx/kai-harness/pkg/scope"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// cmdPatterns prints the two layers a ranking is built from: what ships with the
// binary for this shape, and what this workspace has learned. It is a read: the
// only thing it can write is the delta file, and only when asked.
func cmdPatterns(args []string) int {
	pos, rest := split(args, map[string]bool{"dir": true, "archetype": true})
	fs := flag.NewFlagSet("patterns", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "print as JSON")
	write := fs.Bool("write", false, "write state/patterns-delta.json")
	dir := fs.String("dir", "", "directory of extra layer files (*.json) to merge on top")
	declared := fs.String("archetype", "", "key the patterns to this archetype instead of the recorded one")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai patterns <program> [--json] [--write] [--dir DIR] [--archetype NAME]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}

	arch, source := patternArchetype(p, *declared)
	// The same merge the shadow loop and the ranking use: the shipped layer, what
	// this workspace adopted, then any directory the operator named. A reference
	// view that showed an unadopted number would disagree with the plan it explains.
	lib, layers, problems, err := loadPatternLayers(p, *dir)
	if err != nil {
		return fail(err)
	}

	tbl, err := outcome.Load(p.Dir)
	if err != nil {
		return fail(err)
	}
	delta := pattern.BuildDelta(p.Name, arch, tbl.Records(), time.Now().UTC())

	if *write {
		path, err := pattern.Write(p.Dir, delta)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("wrote   %s\n", path)
	}

	queueClasses := queueClasses(p.Dir)
	gaps := lib.MissingClasses(arch, queueClasses)

	if *asJSON {
		b, err := json.MarshalIndent(map[string]any{
			"program":        p.Name,
			"archetype":      arch,
			"archetype_from": source,
			"library":        lib.For(arch),
			"delta":          delta,
			"queue_classes":  queueClasses,
			"unanswered":     gaps,
			"problems":       problems,
		}, "", "  ")
		if err != nil {
			return fail(err)
		}
		fmt.Println(string(b))
		return problemsExit(problems)
	}

	fmt.Print(patternReport(p.Name, arch, source, lib, delta, layers, queueClasses, gaps, problems))
	return problemsExit(problems)
}

// problemsExit keeps a broken layer visible: a file that half-loaded is a ranking
// built on half the knowledge, and that should not exit 0.
func problemsExit(problems []string) int {
	if len(problems) == 0 {
		return 0
	}
	return 1
}

// patternReport is the human view. It prints in the order the decisions are made:
// which shape, what applies to it, what this workspace already knows, what nothing
// answers yet.
func patternReport(program, arch, source string, lib pattern.Library, delta pattern.Delta, layers int, queueClasses, gaps, problems []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Patterns — %s\n\n", program)
	shown := arch
	if arch == pattern.Any {
		shown = "every shape"
	}
	fmt.Fprintf(&b, "Archetype  **%s** (%s)\n\n", shown, source)
	applicable := lib.For(arch)
	own, inherited, any := 0, 0, 0
	for _, pt := range applicable {
		switch {
		case pt.Key.Archetype == pattern.Any:
			any++
		case pt.Key.Archetype == pattern.CanonicalArchetype(arch):
			own++
		default:
			inherited++
		}
	}
	fmt.Fprintf(&b, "Library    %d pattern(s) total — %d for this shape, %d inherited, %d for every shape, %d layer file(s) merged\n\n",
		lib.Len(), own, inherited, any, layers)

	b.WriteString("## What applies to this shape\n\n")
	for _, f := range pattern.Families {
		var rows []pattern.Pattern
		for _, pt := range applicable {
			if pt.Key.Family == f {
				rows = append(rows, pt)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "### %s\n\n", f)
		for _, pt := range rows {
			scopeNote := pattern.Origin(pt, arch)
			if pt.Note != "" {
				// The number here is not what shipped: say so where the number is
				// printed, not only in the layer file nobody opens.
				scopeNote += " · adopted by the operator"
			}
			feeds := ""
			if pt.Class != "" {
				feeds = " · feeds `" + pattern.Label(pt.Class) + "`"
			}
			fmt.Fprintf(&b, "- **%s** (%.2f, %s%s) — %s\n  %s\n", pattern.Label(pt.Key.Name), pt.Confidence, scopeNote, feeds, pt.Title, pt.Why)
		}
		b.WriteString("\n")
	}

	b.WriteString(delta.Markdown())

	if len(queueClasses) > 0 {
		fmt.Fprintf(&b, "## Questions the queue asks — %d class(es)\n\n", len(queueClasses))
		for _, c := range queueClasses {
			mark := "no pattern"
			if from, ok := lib.Covered(arch, c); ok {
				mark = "covered (" + from + ")"
			}
			st, seen := delta.Stat(pattern.Key{Archetype: delta.Archetype, Family: pattern.FamilyClass, Name: c})
			here := ""
			if seen {
				here = fmt.Sprintf(" · fired %d, paid %d, negation %d", st.Fired, st.Paid, st.Negation)
			}
			fmt.Fprintf(&b, "- `%s` — %s%s\n", pattern.Label(c), mark, here)
		}
		b.WriteString("\n")
	}
	if len(gaps) > 0 {
		fmt.Fprintf(&b, "Unanswered: %d class(es) the queue asks about and the library has no opinion on. That is a gap in the layer, not a finding — write one as a layer file and merge it with --dir.\n\n", len(gaps))
	}

	b.WriteString("## Layers\n\n")
	b.WriteString("The shipped layer is generic by construction: nothing in it came from a live campaign. Extra layers are plain JSON, merged left to right on top of it, and a later file wins a shared key so a correction never becomes a duplicate.\n\n")
	if layers == 0 {
		b.WriteString("No --dir given. A layer file is either a bare array of patterns or `{\"patterns\": [...]}`, with each entry shaped like the ones above.\n\n")
	}
	if len(problems) > 0 {
		fmt.Fprintf(&b, "**%d problem(s) in the layers — nothing was silently dropped:**\n\n", len(problems))
		for _, pr := range problems {
			b.WriteString("- " + pr + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// cmdContribute builds the tier-2 aggregate and refuses to pretend it sent it.
// There is no transport in kai: the payload is printed, audited, and handed over.
func cmdContribute(args []string) int {
	pos, rest := split(args, map[string]bool{"out": true, "archetype": true})
	fs := flag.NewFlagSet("contribute", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "print only the payload")
	out := fs.String("out", "", "also write the payload to this file")
	declared := fs.String("archetype", "", "key the payload to this archetype instead of the recorded one")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai contribute <program> [--json] [--out file] [--archetype NAME]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}

	arch, source := patternArchetype(p, *declared)
	tbl, err := outcome.Load(p.Dir)
	if err != nil {
		return fail(err)
	}
	salt, err := pattern.Salt(p.Dir)
	if err != nil {
		return fail(err)
	}
	hosts, _ := scope.Load(filepath.Join(p.Dir, "scope.txt"))
	recs := tbl.Records()
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "kai: no outcomes recorded yet — there is nothing to contribute but the shape")
	}

	c := pattern.Payload(p.Name, arch, recs, hosts, salt, time.Now().UTC())
	if err := c.Audit(); err != nil {
		return fail(err)
	}
	// The scan is against this program's own names: a payload that mentions where
	// it came from is not anonymous, whatever the schema claims.
	needles := append([]string{p.Name, filepath.Base(p.Dir)}, hosts...)
	for _, r := range recs {
		needles = append(needles, r.Target)
	}
	if err := c.AuditForbidden(needles); err != nil {
		return fail(err)
	}
	b, err := c.JSON()
	if err != nil {
		return fail(err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, b, 0o600); err != nil {
			return fail(err)
		}
	}

	if *asJSON {
		fmt.Print(string(b))
		return 0
	}
	fmt.Printf("# Contribution payload — %s\n\n", p.Name)
	fmt.Printf("Archetype   %s (%s)\n", c.Archetype, source)
	fmt.Printf("Keys        %d class key(s)\n", len(c.Keys))
	fmt.Printf("Hosts       %d salted fingerprint(s)\n", len(c.HostFingerprints))
	fmt.Printf("Salt        state/%s (local; delete it and the fingerprints change)\n", pattern.SaltFile)
	if *out != "" {
		fmt.Printf("Wrote       %s\n", *out)
	}
	fmt.Printf("\nAudit       passed — %s\n\n", pattern.ContributeNotice)
	fmt.Println("```json")
	fmt.Print(string(b))
	fmt.Println("```")
	fmt.Println()
	fmt.Println("Nothing was sent: kai has no transport. Hand this payload over yourself, or paste it wherever it is wanted.")
	return 0
}

// patternArchetype resolves which shape the patterns are keyed to, and says where
// the answer came from. The recorded model wins, because it is the same verdict
// the queue on disk was built against.
func patternArchetype(p *workspace.Program, flagValue string) (arch, source string) {
	if v := strings.TrimSpace(flagValue); v != "" {
		return pattern.CanonicalArchetype(v), "from --archetype"
	}
	if v := recordedArchetype(p.Dir); v != "" {
		return v, "recorded in state/model.json"
	}
	if v := declaredArchetype(p, ""); v != "" {
		return pattern.CanonicalArchetype(v), "declared in the contract"
	}
	return pattern.Any, "no archetype recorded — run `kai model " + p.Name + " --write`"
}

// recordedArchetype reads the archetype the model was last written with.
func recordedArchetype(pDir string) string {
	b, err := os.ReadFile(model.Path(pDir))
	if err != nil {
		return ""
	}
	var m struct {
		Archetype string `json:"archetype"`
	}
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	return pattern.CanonicalArchetype(m.Archetype)
}

// queueClasses lists the classes the ranked queue on disk asks about. An absent
// queue is not an error: the report simply has nothing to compare against.
func queueClasses(pDir string) []string {
	b, err := os.ReadFile(filepath.Join(pDir, "next.json"))
	if err != nil {
		return nil
	}
	var plan struct {
		Items []struct {
			Class string `json:"class"`
		} `json:"items"`
	}
	if json.Unmarshal(b, &plan) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, it := range plan.Items {
		c := pattern.Canonical(it.Class)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
