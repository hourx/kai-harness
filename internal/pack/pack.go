// Package pack builds the handoff ZIP that Kairos consumes.
//
// The archive layout mirrors workspace/<program>/ from
// Kairos/workspace/_template so the agent needs no translation layer.
package pack

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hourx/bountykit/internal/version"
	"github.com/hourx/bountykit/internal/workspace"
)

// Artifacts are the recon files bugbounty-pipeline already knows how to read.
var Artifacts = []string{
	"subs.txt",
	"live.txt",
	"urls.txt",
	"js.ts",
	"endpoints.txt",
	"nuclei.txt",
	"ranked.txt",
	"smuggling.txt",
}

// Result describes a built archive.
type Result struct {
	Path  string
	Bytes int64
	Files int
}

type manifestEntry struct {
	Path   string `json:"path"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type manifest struct {
	Program    string          `json:"program"`
	Generated  string          `json:"generated"`
	Tool       string          `json:"tool"`
	ScopeRules int             `json:"scope_rules"`
	Files      []manifestEntry `json:"files"`
}

// Options controls what goes into the archive.
type Options struct {
	OutDir string
	// IncludeRaw copies data/<program>/raw/ into the archive.
	IncludeRaw bool
	// IncludeSession copies the stored session (cookies, auth header) into the
	// archive. Off by default: the pack travels to another machine.
	IncludeSession bool
}

// Build writes <outDir>/<program>_<ts>.zip and returns its path.
func Build(p *workspace.Program, opts Options) (Result, error) {
	outDir := opts.OutDir
	if outDir == "" {
		outDir = "dist"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	zipPath := filepath.Join(outDir, fmt.Sprintf("%s_%s.zip", p.Name, now.Format("20060102T150405Z")))

	f, err := os.Create(zipPath)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	root := p.Name + "/"
	m := manifest{Program: p.Name, Generated: now.Format(time.RFC3339), Tool: "bountykit " + version.String()}

	add := func(name string, data []byte) error {
		h := sha256.Sum256(data)
		entry := manifestEntry{Path: name, Bytes: len(data), SHA256: hex.EncodeToString(h[:])}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: root + name, Method: zip.Deflate, Modified: now})
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		m.Files = append(m.Files, entry)
		return nil
	}

	addFile := func(name, src string) error {
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		return add(name, b)
	}

	for _, name := range []string{"program.md", "scope.txt", "out-of-scope.txt", "policy.md"} {
		if _, err := os.Stat(filepath.Join(p.Dir, name)); err != nil {
			continue
		}
		if err := addFile(name, filepath.Join(p.Dir, name)); err != nil {
			return Result{}, err
		}
	}

	// Recon artifacts, only when they exist.
	for _, name := range Artifacts {
		if b, ok := p.ReadState(name); ok && len(b) > 0 {
			if err := add(filepath.Join("recon", name), b); err != nil {
				return Result{}, err
			}
		}
	}

	// Diff is the anti-duplicate payload: what did not exist last run.
	if b, err := os.ReadFile(filepath.Join(p.Dir, "diff.md")); err == nil {
		if err := add("bountykit/diff.md", b); err != nil {
			return Result{}, err
		}
	}

	// The structured Phase 0 intake is machine-readable for the agent.
	if b, err := os.ReadFile(filepath.Join(p.Dir, "intake.json")); err == nil {
		if err := add("bountykit/intake.json", b); err != nil {
			return Result{}, err
		}
	}

	// The surface map and the ranked queue are the agent's entry point.
	for _, name := range []string{"map.md", "map.json", "next.md", "next.json"} {
		b, err := os.ReadFile(filepath.Join(p.Dir, name))
		if err != nil {
			continue
		}
		if err := add(filepath.Join("bountykit", name), b); err != nil {
			return Result{}, err
		}
	}

	// Session material only on explicit request.
	if opts.IncludeSession {
		b, err := os.ReadFile(filepath.Join(p.Dir, "session.json"))
		if err == nil {
			if err := add("bountykit/session.json", b); err != nil {
				return Result{}, err
			}
		}
	}

	if opts.IncludeRaw {
		rawDir := filepath.Join(p.Dir, "raw")
		if err := filepath.Walk(rawDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			rel, relErr := filepath.Rel(p.Dir, path)
			if relErr != nil {
				return relErr
			}
			return addFile(filepath.ToSlash(rel), path)
		}); err != nil && !os.IsNotExist(err) {
			return Result{}, err
		}
	}

	ledger := fmt.Sprintf(`# LEDGER — %s

| When (UTC) | Event |
| --- | --- |
| %s | pack built by bountykit %s |
`, p.Name, now.Format(time.RFC3339), version.String())
	if err := add("LEDGER.md", []byte(ledger)); err != nil {
		return Result{}, err
	}

	scopeRules, _ := countLines(filepath.Join(p.Dir, "scope.txt"))
	m.ScopeRules = scopeRules
	if err := add("BRIEF.md", []byte(brief(p, now, opts))); err != nil {
		return Result{}, err
	}

	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Result{}, err
	}
	if err := add("bountykit/MANIFEST.json", mb); err != nil {
		return Result{}, err
	}

	if err := zw.Close(); err != nil {
		return Result{}, err
	}
	if err := f.Close(); err != nil {
		return Result{}, err
	}
	info, err := os.Stat(zipPath)
	if err != nil {
		return Result{}, err
	}
	return Result{Path: zipPath, Bytes: info.Size(), Files: len(m.Files)}, nil
}

func countLines(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.SplitN(line, "#", 2)[0]
		if strings.TrimSpace(trimmed) != "" {
			n++
		}
	}
	return n, nil
}

// artifactNotes explains why an artifact can be empty, so the agent never
// reads an empty file as "nothing to see here, move on".
var artifactNotes = map[string]string{
	"subs.txt":      "no host passed the scope gate",
	"live.txt":      "no host responded over HTTP",
	"urls.txt":      "no URL was collected",
	"js.ts":         "no JavaScript bundle was found in this run",
	"endpoints.txt": "no path was extracted",
	"ranked.txt":    "no host to rank",
	"nuclei.txt":    "only produced when recon runs with --nuclei",
	"smuggling.txt": "not implemented yet (v0.3)",
}

// briefNext is the subset of next.json the brief needs.
type briefNext struct {
	Items []struct {
		Target string   `json:"target"`
		Class  string   `json:"class"`
		Score  int      `json:"score"`
		Why    []string `json:"why"`
		Probe  string   `json:"probe"`
	} `json:"items"`
}

func brief(p *workspace.Program, now time.Time, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — handoff brief\n\n", p.Name)
	fmt.Fprintf(&b, "| Field | Value |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| Generated | %s |\n", now.Format(time.RFC3339))
	fmt.Fprintf(&b, "| Tool | bountykit %s |\n", version.String())
	if p.Meta.Platform != "" {
		fmt.Fprintf(&b, "| Platform | %s |\n", p.Meta.Platform)
	}
	if p.Meta.ProgramURL != "" {
		fmt.Fprintf(&b, "| Program URL | %s |\n", p.Meta.ProgramURL)
	}
	fmt.Fprintf(&b, "| Scope verdict | %s |\n", p.Meta.ScopeVerdict)
	fmt.Fprintf(&b, "| Pack phase | 0–3 (scope, recon, mapping, queue) |\n")
	switch {
	case opts.IncludeSession:
		b.WriteString("| Session | **included** in `bountykit/session.json` — delete after use |\n\n")
	case sessionExists(p):
		b.WriteString("| Session | stored on the operator machine, not included |\n\n")
	default:
		b.WriteString("| Session | none — mapping is unauthenticated only |\n\n")
	}

	b.WriteString("## Phase 0 (program selection)\n\n")
	rawIntake, err := os.ReadFile(filepath.Join(p.Dir, "intake.json"))
	var pi struct {
		Name      string `json:"name"`
		URL       string `json:"url"`
		Scorecard struct {
			Verdict  string   `json:"verdict"`
			Total    int      `json:"total"`
			Money    int      `json:"money"`
			Crowding int      `json:"crowding"`
			Speed    int      `json:"speed"`
			Surface  int      `json:"surface"`
			Reasons  []string `json:"reasons"`
		} `json:"scorecard"`
	}
	if err == nil && json.Unmarshal(rawIntake, &pi) == nil && pi.Scorecard.Verdict != "" {
		sc := pi.Scorecard
		fmt.Fprintf(&b, "**%s — %s, %d/100.** money %d/25 · crowding %d/35 · speed %d/20 · surface %d/20\n\n",
			pi.Name, sc.Verdict, sc.Total, sc.Money, sc.Crowding, sc.Speed, sc.Surface)
		for i, r := range sc.Reasons {
			if i >= 4 {
				break
			}
			fmt.Fprintf(&b, "- %s\n", r)
		}
		b.WriteString("\nFull scorecard: `program.md`. Policy, out-of-scope classes and required headers: `policy.md`.\n\n")
	} else {
		b.WriteString("No Phase 0 intake for this program. Run `bountykit intake <hackerone-url>` ")
		b.WriteString("before choosing what to hunt — payout, crowding and published scope all matter.\n\n")
	}

	b.WriteString("## Scope (authoritative)\n\n")
	fmt.Fprintf(&b, "`scope.txt`:\n\n```\n%s\n```\n\n", strings.TrimSpace(readOr(p, "scope.txt")))
	fmt.Fprintf(&b, "`out-of-scope.txt`:\n\n```\n%s\n```\n\n", strings.TrimSpace(readOr(p, "out-of-scope.txt")))
	b.WriteString("> Out-of-scope always wins. Never touch a host before it passes ")
	b.WriteString("`kairos-scope " + p.Name + " <host>`.\n\n")

	b.WriteString("## What this pack contains\n\n| Artifact | Lines |\n| --- | --- |\n")
	missing := make([]string, 0, len(Artifacts))
	for _, name := range Artifacts {
		n := p.CountLines(name)
		if n == 0 {
			missing = append(missing, name)
		}
		fmt.Fprintf(&b, "| `recon/%s` | %d |\n", name, n)
	}
	b.WriteString("\n")

	if len(missing) > 0 {
		b.WriteString("## Empty artifacts\n\n")
		for _, name := range missing {
			note := artifactNotes[name]
			if note == "" {
				note = "nothing collected"
			}
			fmt.Fprintf(&b, "- `recon/%s` — %s\n", name, note)
		}
		b.WriteString("\nAn empty file means this run genuinely collected nothing there. ")
		b.WriteString("It is never a placeholder for work the tool will do later. ")
		b.WriteString("**Do not infer the attack surface from an empty file.**\n\n")
	}

	b.WriteString("## Start here (ranked)\n\n")
	raw, readErr := os.ReadFile(filepath.Join(p.Dir, "next.json"))
	var n briefNext
	queueBuilt := readErr == nil && json.Unmarshal(raw, &n) == nil
	switch {
	case queueBuilt && len(n.Items) > 0:
		{
			limit := len(n.Items)
			if limit > 12 {
				limit = 12
			}
			b.WriteString("| # | class | target | score |\n| --- | --- | --- | --- |\n")
			for i, it := range n.Items[:limit] {
				fmt.Fprintf(&b, "| %d | %s | `%s` | %d |\n", i+1, it.Class, it.Target, it.Score)
			}
			b.WriteString("\nFirst probe for the top item: ")
			b.WriteString(n.Items[0].Probe)
			b.WriteString("\n\nFull queue and reasons: `bountykit/next.md`. ")
			b.WriteString("The ranking is evidence-weighted, not a verdict — still verify each one.\n\n")
		}
	case queueBuilt:
		b.WriteString("The queue was built and came back empty: no endpoint here has an object ")
		b.WriteString("reference, an ID parameter or a risky module name. That is a finding about ")
		b.WriteString("the surface, not a broken run. `bountykit/next.md` explains it in place.\n\n")
	default:
		b.WriteString("No ranked queue yet. Run `bountykit map ")
		b.WriteString(p.Name)
		b.WriteString("` and `bountykit next ")
		b.WriteString(p.Name)
		b.WriteString("` before hunting, so effort follows evidence instead of guessing.\n\n")
	}

	b.WriteString("## Surface diff\n\n")
	if raw, err := os.ReadFile(filepath.Join(p.Dir, "diff.md")); err == nil {
		text := strings.TrimSpace(string(raw))
		// Drop the diff's own H1 so the brief keeps one title.
		if i := strings.Index(text, "\n"); i >= 0 {
			text = strings.TrimSpace(text[i:])
		}
		if len(text) > 6000 {
			text = text[:6000] + "\n\n… truncated, see `bountykit/diff.md`\n"
		}
		b.WriteString(text)
		b.WriteString("\n\n")
		b.WriteString("> Anything listed as new is surface no other hunter has scanned yet. ")
		b.WriteString("Start there, not at the top of `recon/live.txt`.\n\n")
	} else {
		fmt.Fprintf(&b, "No recon run yet for `%s`. Run `bountykit recon %s` before hunting ", p.Name, p.Name)
		b.WriteString("so the agent knows what is new rather than guessing.\n\n")
	}

	b.WriteString("## Layout mapping\n\n")
	fmt.Fprintf(&b, "The `bugbounty-pipeline` skill writes to `targets-%s/`.\n", p.Name)
	b.WriteString("This pack uses the `docs/BUG-BOUNTY.md` convention instead:\n\n")
	b.WriteString("| pipeline path | this pack |\n| --- | --- |\n")
	for _, name := range Artifacts {
		fmt.Fprintf(&b, "| `targets-%s/%s` | `recon/%s` |\n", p.Name, name, name)
	}
	b.WriteString("\n")
	return b.String()
}

func sessionExists(p *workspace.Program) bool {
	_, err := os.Stat(filepath.Join(p.Dir, "session.json"))
	return err == nil
}

func readOr(p *workspace.Program, name string) string {
	b, err := os.ReadFile(filepath.Join(p.Dir, name))
	if err != nil {
		return ""
	}
	return string(b)
}
