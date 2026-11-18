package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hourx/kai/internal/program"
	"github.com/hourx/kai/internal/workspace"
)

func safeSlug(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "/"))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if out == "" {
		out = "page"
	}
	return out
}

func pageMarkdown(p program.PageDoc) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", p.Title)
	fmt.Fprintf(&b, "Source: %s\n\n", p.URL)
	b.WriteString("## Scope (verbatim)\n\n")
	if p.Scope == "" {
		b.WriteString("- not stated on this page\n")
	} else {
		b.WriteString(p.Scope + "\n")
	}
	b.WriteString("\n## Out of scope (verbatim)\n\n")
	if p.OutOfScope == "" {
		b.WriteString("- not stated on this page\n")
	} else {
		b.WriteString(p.OutOfScope + "\n")
	}
	b.WriteString("\n## Full text\n\n")
	b.WriteString(p.Body)
	if !strings.HasSuffix(p.Body, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

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

	// A next.json written by an older kai has no tags/clusters. Regenerate it
	// so agents never fall back to dumping 150 raw hypotheses. This is still
	// deterministic context generation — no requests, no hunting.
	nb, nerr := os.ReadFile(filepath.Join(p.Dir, "next.json"))
	if nerr != nil || !bytes.Contains(nb, []byte(`"clusters"`)) {
		if _, e := buildSurface(p); e != nil {
			fmt.Fprintf(os.Stderr, "kai: next.json schema lama dan regenerate gagal (%v) — jalankan: kai recon %s\n", e, p.Name)
		} else {
			fmt.Println("regenerated next.json (tags + clusters)")
		}
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

	// Per-page scope and the AI-agent rulebook come from the last intake.
	var in program.Intake
	if raw, err := os.ReadFile(filepath.Join(p.Dir, "intake.json")); err == nil {
		_ = json.Unmarshal(raw, &in)
	}
	if len(in.Pages) > 0 {
		pagesDir := filepath.Join(*to, "pages")
		if err := os.MkdirAll(pagesDir, 0o755); err != nil {
			return fail(err)
		}
		used := map[string]bool{}
		for _, page := range in.Pages {
			base := safeSlug(page.URL)
			name := base
			for i := 2; used[name]; i++ {
				name = fmt.Sprintf("%s-%d", base, i)
			}
			used[name] = true
			dest := filepath.Join(pagesDir, name+".md")
			if err := os.WriteFile(dest, []byte(pageMarkdown(page)), 0o600); err != nil {
				return fail(err)
			}
			fmt.Println("wrote", dest)
			wrote++
			if strings.HasSuffix(strings.ToLower(strings.TrimSuffix(page.URL, "/")), "llms.txt") {
				dest := filepath.Join(*to, "llms.md")
				if err := os.WriteFile(dest, []byte(pageMarkdown(page)), 0o600); err != nil {
					return fail(err)
				}
				fmt.Println("wrote", dest)
				wrote++
			}
		}
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
