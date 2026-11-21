package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/model"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/pattern"
	"github.com/hourx/kai-harness/pkg/shadow"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// cmdShadow runs the lesson loop: it reads outcomes, proposes, and applies only
// what the operator names explicitly. The default invocation is a read.
func cmdShadow(args []string) int {
	pos, rest := split(args, map[string]bool{"adopt": true, "revert": true, "dir": true, "archetype": true})
	fs := flag.NewFlagSet("shadow", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	write := fs.Bool("write", false, "write state/shadow.json")
	adopt := fs.String("adopt", "", "adopt one proposal by id")
	revert := fs.String("revert", "", "revert one proposal by id, or all")
	dir := fs.String("dir", "", "directory of extra layer files (*.json) merged on top")
	declared := fs.String("archetype", "", "key the report to this archetype instead of the recorded one")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai shadow <program> [--json] [--write] [--adopt ID] [--revert ID|all] [--dir D] [--archetype NAME]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	if *adopt != "" && *revert != "" {
		return fail(errors.New("adopt and revert are one action each — run them separately"))
	}
	if *revert != "" {
		return shadowRevert(p, *revert)
	}

	arch, source := patternArchetype(p, *declared)
	lib, layers, problems, err := loadPatternLayers(p, *dir)
	if err != nil {
		return fail(err)
	}

	obs, skipped := gatherObservations(p.Name)
	entities := entityStrength(p)
	rep := shadow.Evaluate(p.Name, arch, lib, obs, entities, time.Now().UTC())

	if *adopt != "" {
		return shadowAdopt(p, lib, rep, *adopt)
	}

	if *write {
		path, err := writeShadow(p, rep)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("wrote   %s\n", path)
	}
	if *asJSON {
		b, err := json.MarshalIndent(map[string]any{
			"report":         rep,
			"archetype_from": source,
			"layer_files":    layers,
			"skipped":        skipped,
			"layer_problems": problems,
			"adopted_here":   adoptedIDs(p),
		}, "", "  ")
		if err != nil {
			return fail(err)
		}
		fmt.Println(string(b))
		return problemsExit(problems)
	}
	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "note: %d workspace(s) could not be read: %s\n", len(skipped), strings.Join(skipped, ", "))
	}
	fmt.Print(rep.Markdown())
	for _, s := range problems {
		fmt.Fprintf(os.Stderr, "layer problem: %s\n", s)
	}
	return problemsExit(problems)
}

// loadPatternLayers merges the layers in the order their precedence demands: the
// shipped library, then what this workspace adopted, then any directory the
// operator named. An explicit --dir is the freshest intent, so it wins.
func loadPatternLayers(p *workspace.Program, dir string) (pattern.Library, int, []string, error) {
	lib := pattern.Public()
	layers := 0
	var problems []string

	if ad, ok, err := pattern.WorkspaceAdapter(p.Dir); err != nil {
		return pattern.Library{}, 0, nil, err
	} else if ok {
		// Merged, not shadowed: a corrected pattern has to replace the shipped one,
		// which is the whole reason the workspace layer exists.
		merged, probs, err := pattern.LoadAdapters(lib, ad)
		if err != nil {
			return pattern.Library{}, 0, nil, err
		}
		lib, problems = merged, append(problems, probs...)
		layers++
	}
	if dir != "" {
		adapters, err := pattern.LoadDir(dir)
		if err != nil {
			return pattern.Library{}, 0, nil, err
		}
		layers += len(adapters)
		merged, probs, err := pattern.LoadAdapters(lib, adapters...)
		if err != nil {
			return pattern.Library{}, 0, nil, err
		}
		lib, problems = merged, append(problems, probs...)
	}
	return lib, layers, problems, nil
}

// gatherObservations reads the outcome log of every workspace on this machine.
// A shape's class can only be re-graded from evidence across engagements, and the
// evidence lives in the workspaces, not in a service.
func gatherObservations(self string) ([]shadow.Observation, []string) {
	names, err := workspace.List()
	if err != nil {
		return nil, []string{"workspace list: " + err.Error()}
	}
	sort.Strings(names)
	var obs []shadow.Observation
	var skipped []string
	for _, name := range names {
		op, err := workspace.Open(name)
		if err != nil {
			skipped = append(skipped, name+" (open: "+err.Error()+")")
			continue
		}
		tbl, err := outcome.Load(op.Dir)
		if err != nil {
			skipped = append(skipped, name+" (outcomes: "+err.Error()+")")
			continue
		}
		if tbl.Len() == 0 {
			// A workspace with nothing recorded contributes nothing, and saying so
			// on every run would be noise: skip it silently.
			continue
		}
		arch, _ := patternArchetype(op, "")
		obs = append(obs, shadow.Observation{Program: op.Name, Archetype: arch, Records: tbl.Records()})
	}
	return obs, skipped
}

// entityStrength counts, per entity the model named, how many observed paths
// address it by name. A gap proposal needs the model; without one there is
// nothing to notice.
//
// The join is a path segment because that is how the model derived the entity in
// the first place, and this number is only ever used to decide whether an object
// is load-bearing enough to be worth a sentence in the library.
func entityStrength(p *workspace.Program) map[string]int {
	m, err := model.Load(p.Dir)
	if err != nil || m == nil {
		return nil
	}
	out := map[string]int{}
	for _, e := range m.Entities {
		if e.Name != "" {
			out[e.Name] = 0
		}
	}
	if len(out) == 0 {
		return nil
	}
	for _, a := range m.Actions {
		for seg := range pathSegments(a.Path) {
			if _, ok := out[seg]; ok {
				out[seg]++
			}
		}
	}
	return out
}

// pathSegments is the set of path segments that could name an object. Segments
// with no letter are keys or versions, not entities.
func pathSegments(p string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, seg := range strings.Split(strings.ToLower(p), "/") {
		if seg == "" || !strings.ContainsAny(seg, "abcdefghijklmnopqrstuvwxyz") {
			continue
		}
		out[seg] = struct{}{}
	}
	return out
}

func adoptedIDs(p *workspace.Program) []string {
	o, ok, err := pattern.LoadOverrides(p.Dir)
	if err != nil || !ok {
		return nil
	}
	ids := make([]string, 0, len(o.Adopted))
	for _, a := range o.Adopted {
		ids = append(ids, a.ID)
	}
	sort.Strings(ids)
	return ids
}

// shadowAdopt applies exactly one proposal. It re-derives the report rather than
// trusting a stored file, so an adoption always reflects the evidence as it is
// now — a lesson that no longer clears its gate cannot be adopted by accident.
func shadowAdopt(p *workspace.Program, lib pattern.Library, rep shadow.Report, id string) int {
	var found *shadow.Proposal
	for i := range rep.Proposals {
		if rep.Proposals[i].ID == id {
			found = &rep.Proposals[i]
			break
		}
	}
	if found == nil {
		return fail(fmt.Errorf("no proposal %q in this report — run `kai shadow %s` to list what cleared the gates", id, p.Name))
	}
	if !found.Adoptable {
		return fail(fmt.Errorf("%s is a gap proposal: it is closed by writing a pattern (kai patterns --dir), not by adopting it", id))
	}
	o, _, err := pattern.LoadOverrides(p.Dir)
	if err != nil {
		return fail(err)
	}
	base, ok := lib.Lookup(found.Key)
	if !ok {
		return fail(fmt.Errorf("%s is not in the library — nothing to adjust", found.Key))
	}
	next, err := pattern.Adopt(o, lib, found.Key, found.Kind,
		found.Evidence.Paid, found.Evidence.Fired, found.Evidence.Where, found.Reason, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	path, err := pattern.SaveOverrides(p.Dir, next)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("adopted  %s\n", id)
	fmt.Printf("pattern  %s: confidence %.2f → %.2f (source %s)\n", base.Key, base.Confidence, found.To, "operator/shadow")
	fmt.Printf("layer    %s\n", path)
	fmt.Printf("ranking  %+d point(s) for class %q — adopted lessons are a tie-breaker, not a rewrite\n",
		next.Nudge(base.Key.Name), base.Key.Name)
	fmt.Printf("revert   kai shadow %s --revert %s\n", p.Name, id)
	return 0
}

// shadowRevert removes one lesson or all of them. Rollback is a pointer change:
// the file shrinks, or it disappears.
func shadowRevert(p *workspace.Program, id string) int {
	o, ok, err := pattern.LoadOverrides(p.Dir)
	if err != nil {
		return fail(err)
	}
	if !ok {
		fmt.Printf("nothing to revert in %s — no adopted lessons\n", p.Name)
		return 0
	}
	if id != "all" && !o.ValidAdoptID(id) {
		return fail(fmt.Errorf("no adopted lesson %q here — run `kai shadow %s --json` to see what is adopted", id, p.Name))
	}
	keys := pattern.Reverted(o, id)
	next := pattern.Revert(o, id)
	path, err := pattern.SaveOverrides(p.Dir, next)
	if err != nil {
		return fail(err)
	}
	if id == "all" {
		fmt.Printf("reverted %d lesson(s): %s\n", len(keys), strings.Join(keys, ", "))
	} else {
		fmt.Printf("reverted %s: %s\n", id, strings.Join(keys, ", "))
	}
	if path == "" {
		fmt.Printf("layer    removed — the shipped library is in charge again\n")
	} else {
		fmt.Printf("layer    %s (%d lesson(s) left)\n", path, len(next.Adopted))
	}
	return 0
}

func writeShadow(p *workspace.Program, rep shadow.Report) (string, error) {
	path := p.StatePath("shadow.json")
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	return path, nil
}
