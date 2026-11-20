package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/archetype"
	"github.com/hourx/kai-harness/pkg/evidence"
	"github.com/hourx/kai-harness/pkg/model"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/program"
	"github.com/hourx/kai-harness/pkg/recon"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// cmdModel derives the program model from artifacts that are already on disk —
// recon, evidence, recorded outcomes, the contract — and prints it. Nothing is
// sent and nothing is decided: the model is the picture the queue is built on,
// written down so two runs can be compared.
func cmdModel(args []string) int {
	pos, rest := split(args, map[string]bool{"json": true, "write": true, "archetype": true, "top": true})
	fs := flag.NewFlagSet("model", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "print the whole model as JSON")
	write := fs.Bool("write", false, "write state/model.json and state/model.md")
	declared := fs.String("archetype", "", "declare the archetype instead of inferring it")
	top := fs.Int("top", 5, "how many exploration rows to show")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai model <program> [--json] [--write] [--archetype NAME] [--top N]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}

	store, err := recon.LoadStore(p.Dir, p.Name)
	if err != nil {
		return fail(err)
	}
	nonWeb, _ := intakeSurface(p)
	items, err := evidence.Load(p.Dir)
	if err != nil {
		return fail(err)
	}
	tbl, err := outcome.Load(p.Dir)
	if err != nil {
		return fail(err)
	}

	verdict := archetype.Classify(declaredArchetype(p, *declared), surfaceMap(p, store, nonWeb), nonWeb)
	m, err := model.Derive(model.Options{
		Program:         p,
		Store:           store,
		NonWeb:          nonWeb,
		Evidence:        items,
		Outcomes:        tbl,
		Records:         tbl.Records(),
		Archetype:       verdict.Name,
		ArchetypeSource: verdict.Source,
		Now:             time.Now().UTC(),
	})
	if err != nil {
		return fail(err)
	}

	// Persist first: --json and --write are independent requests, and a run that
	// asked for both must not silently do only one.
	if *write {
		if err := m.Save(p.Dir); err != nil {
			return fail(err)
		}
		if err := os.WriteFile(filepath.Join(p.Dir, "state", "model.md"), []byte(m.Markdown()), 0o600); err != nil {
			return fail(err)
		}
	}

	if *asJSON {
		b, err := m.JSON()
		if err != nil {
			return fail(err)
		}
		os.Stdout.Write(b)
		fmt.Println()
		return 0
	}

	fmt.Print(archetype.Markdown(verdict))
	fmt.Print("\n")
	fmt.Print(m.Markdown())

	if *write {
		fmt.Printf("wrote %s and state/model.md\n", model.Path(p.Dir))
	}

	// The model exists to steer the next action, so it closes with the rows that
	// say what has not been touched — not with the facts it just restated.
	rows := m.NeverTested()
	if len(rows) == 0 {
		fmt.Println("every in-scope asset has something recorded against it")
		return 0
	}
	limit := *top
	if limit <= 0 || limit > len(rows) {
		limit = len(rows)
	}
	fmt.Printf("## Never touched (%d)\n\n", len(rows))
	for _, r := range rows[:limit] {
		fmt.Printf("- %s\n", r)
	}
	if len(rows) > limit {
		fmt.Printf("- … and %d more: kai model %s --json\n", len(rows)-limit, p.Name)
	}
	return 0
}

// declaredArchetype prefers the operator's own word — the command line first,
// then the program contract — over anything inferred from traffic shape.
func declaredArchetype(p *workspace.Program, flagValue string) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	c, ok, err := program.LoadContract(p)
	if err != nil || !ok {
		return ""
	}
	return c.Archetype
}

// surfaceMap rebuilds the same endpoint map the queue is built from, so the
// archetype verdict and the model describe one surface, not two.
func surfaceMap(p *workspace.Program, store *recon.Store, nonWeb []surface.NonWebAsset) *surface.Map {
	eps := map[string][]string{}
	if store != nil {
		for path, rec := range store.Endpoints {
			if rec == nil {
				continue
			}
			eps[path] = append([]string(nil), rec.Params...)
		}
	}
	return surface.BuildWithNonWeb(p.Name, eps, nonWeb, time.Now().UTC())
}
