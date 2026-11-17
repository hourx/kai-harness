package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hourx/kai/internal/program"
	"github.com/hourx/kai/internal/workspace"
)

// cmdExport writes the agent-facing context set into a Kairos campaign folder.
// It is still a pure context export: no hunting, no validation, no submission,
// and no writes back into kai's own state directory.
func cmdExport(args []string) int {
	pos, rest := split(args, map[string]bool{"to": true})
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	to := fs.String("to", "", "destination directory (usually Bug Bounty/<program>/context)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 || *to == "" {
		return fail(errors.New("usage: kai export <program> --to <dir>"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(*to, 0o755); err != nil {
		return fail(err)
	}

	brief, err := program.CompactBrief(p.Dir)
	if err != nil {
		return fail(err)
	}
	gate, err := program.ValidationGate(p.Dir)
	if err != nil {
		return fail(err)
	}

	generated := map[string]string{
		"brief.md":           brief,
		"validation-gate.md": gate,
	}
	copied := []string{
		"next.json", "next.md", "boundaries.md", "diff.md",
		"map.json", "map.md", "program.md", "scope.txt", "out-of-scope.txt",
	}
	wrote := 0
	for name, text := range generated {
		dest := filepath.Join(*to, name)
		if err := os.WriteFile(dest, []byte(text), 0o600); err != nil {
			return fail(err)
		}
		fmt.Println("wrote", dest)
		wrote++
	}
	for _, name := range copied {
		src := filepath.Join(p.Dir, name)
		b, err := os.ReadFile(src)
		if err != nil || len(b) == 0 {
			continue
		}
		dest := filepath.Join(*to, name)
		if err := os.WriteFile(dest, b, 0o600); err != nil {
			return fail(err)
		}
		fmt.Println("wrote", dest)
		wrote++
	}
	if wrote == 0 {
		return fail(errors.New("nothing to export — run: kai intake " + p.Name + " && kai recon " + p.Name))
	}
	fmt.Printf("exported %d context file(s) to %s\n", wrote, *to)
	return 0
}
