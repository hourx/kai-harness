package pattern

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hourx/kai-harness/pkg/archetype"
)

// Adapter supplies patterns from outside the binary: a file a team maintains, a
// service, a test double. kai never reaches for one on its own — an adapter runs
// only because the operator named it, and a failure to load is reported rather
// than swallowed.
type Adapter interface {
	// Name identifies the source in the report.
	Name() string
	// Patterns returns the layer. An error stops the merge: half a layer is
	// worse than none, because the missing half is invisible.
	Patterns() ([]Pattern, error)
}

// FileAdapter reads a JSON layer from disk. Both shapes are accepted: a bare
// array of patterns, or an object with a "patterns" field so a file can carry
// its own metadata later without breaking this reader.
type FileAdapter struct {
	Path string
}

// Name identifies the file in the report.
func (f FileAdapter) Name() string { return filepath.Base(f.Path) }

// Patterns reads and validates the file's layer.
func (f FileAdapter) Patterns() ([]Pattern, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	return parseLayer(f.Path, b)
}

// parseLayer accepts the bare-array and wrapped-object shapes.
func parseLayer(path string, b []byte) ([]Pattern, error) {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" {
		return nil, fmt.Errorf("%s: empty file", path)
	}
	if strings.HasPrefix(trimmed, "[") {
		var ps []Pattern
		if err := json.Unmarshal(b, &ps); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return ps, nil
	}
	var wrapped struct {
		Schema   string    `json:"schema"`
		Patterns []Pattern `json:"patterns"`
	}
	if err := json.Unmarshal(b, &wrapped); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if wrapped.Patterns == nil {
		return nil, fmt.Errorf("%s: no \"patterns\" array and not a bare array", path)
	}
	return wrapped.Patterns, nil
}

// LoadAdapters merges adapters left to right onto a base library. A later adapter
// wins a shared key, which is what makes an operator's file a correction of the
// public layer rather than a duplicate of it.
//
// Problems are returned, not printed: every pattern that failed validation is
// reported with its reason, so a layer that quietly sits at half strength cannot
// happen.
func LoadAdapters(base Library, adapters ...Adapter) (Library, []string, error) {
	lib := base
	var problems []string
	for _, a := range adapters {
		ps, err := a.Patterns()
		if err != nil {
			// A layer that does not parse is a problem, not a fatal error: the
			// operator sees the file, the reason, and everything else still loads.
			problems = append(problems, fmt.Sprintf("%s: %v", a.Name(), err))
			continue
		}
		good := make([]Pattern, 0, len(ps))
		for i, p := range ps {
			// A layer file is written by hand, so both spellings of a key are
			// accepted and folded here. A shape nothing recognises is still an
			// error: widening it to every shape would hide the typo.
			raw := p.Key
			if arch := strings.TrimSpace(raw.Archetype); arch != Any && !archetype.Known(arch) {
				problems = append(problems, fmt.Sprintf("%s: entry %d: unknown archetype %q (known: %s)",
					a.Name(), i+1, raw.Archetype, strings.Join(archetype.Names(), ", ")))
				continue
			}
			p.Key = NewKey(raw.Archetype, raw.Family, raw.Name)
			p.Class = Canonical(p.Class)
			if err := p.Validate(); err != nil {
				problems = append(problems, fmt.Sprintf("%s: entry %d: %v", a.Name(), i+1, err))
				continue
			}
			if p.Source == "" {
				p.Source = a.Name()
			}
			good = append(good, p)
		}
		merged, err := lib.With(good...)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", a.Name(), err))
			continue
		}
		lib = merged
	}
	sort.Strings(problems)
	return lib, problems, nil
}

// LoadDir returns one file adapter per *.json in dir, sorted by name so the merge
// order — and therefore which file wins a shared key — does not depend on the
// filesystem.
func LoadDir(dir string) ([]Adapter, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Adapter
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".json") {
			continue
		}
		out = append(out, FileAdapter{Path: filepath.Join(dir, e.Name())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}
