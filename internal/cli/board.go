package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hourx/kai-harness/pkg/board"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// cmdBoard aggregates every program under KAI_HOME into one ranked "what to do
// today" view. It reads state only — no network, no LLM — so the same disk
// state always produces the same board.
func cmdBoard(args []string) int {
	pos, rest := split(args, map[string]bool{"out": true})
	fs := flag.NewFlagSet("board", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", "", "write the markdown board to this file")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	home := workspace.Home()
	rep, err := board.Snapshot(home)
	if err != nil {
		return fail(err)
	}
	if len(pos) > 0 {
		name := pos[0]
		if err := workspace.ValidateName(name); err != nil {
			return fail(err)
		}
		kept := rep.Programs[:0]
		for _, row := range rep.Programs {
			if row.Name == name {
				kept = append(kept, row)
			}
		}
		if len(kept) == 0 {
			return fail(fmt.Errorf("unknown program %q under %s", name, home))
		}
		rep.Programs = kept
		todo := rep.Todo[:0]
		for _, a := range rep.Todo {
			if a.Program == name {
				todo = append(todo, a)
			}
		}
		rep.Todo = todo
	}

	jsonPath := filepath.Join(home, "board.json")
	mdPath := filepath.Join(home, "board.md")
	if *out != "" {
		mdPath = *out
	}
	if b, err := json.MarshalIndent(rep, "", "  "); err != nil {
		return fail(err)
	} else if err := os.WriteFile(jsonPath, append(b, '\n'), 0o600); err != nil {
		return fail(err)
	}
	if err := os.WriteFile(mdPath, []byte(rep.Markdown()), 0o600); err != nil {
		return fail(err)
	}

	fmt.Print(rep.Markdown())
	fmt.Printf("\nwrote %s\nwrote %s\n", jsonPath, mdPath)
	return 0
}
