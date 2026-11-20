package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hourx/kai-harness/pkg/evidence"
	"github.com/hourx/kai-harness/pkg/report"
	"github.com/hourx/kai-harness/pkg/scope"
	"github.com/hourx/kai-harness/pkg/triage"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// cmdReportDraft renders a submission draft in a platform's field set from one
// piece of captured evidence. It writes a file and prints the path; it never
// submits anything, and it never asserts scope on its own — the gate decides.
func cmdReportDraft(args []string) int {
	pos, rest := split(args, map[string]bool{
		"platform": true, "out": true, "title": true, "severity": true,
		"scope-line": true, "extra": true, "finding": true,
	})
	fs := flag.NewFlagSet("report-draft", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	platform := fs.String("platform", "hackerone", "field set: "+strings.Join(report.Platforms, "|"))
	out := fs.String("out", "", "write the draft here instead of <program>/reports/")
	title := fs.String("title", "", "subject line (defaults to the target)")
	severity := fs.String("severity", "", "your severity or CVSS — kai does not guess it")
	scopeLine := fs.String("scope-line", "", "quote the policy line that puts this asset in scope")
	findingID := fs.String("finding", "", "findings/ledger.json id")
	var extras kvFlag
	fs.Var(&extras, "extra", "extra labelled line, e.g. 'payout=1000', repeatable")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) < 2 {
		return fail(errors.New("usage: kai report-draft <program> <evidence-id> [--platform " + strings.Join(report.Platforms, "|") + "] [--title T] [--finding F] [--out file]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	ev, ok, err := evidence.Find(p.Dir, pos[1])
	if err != nil {
		return fail(err)
	}
	if !ok {
		items, _ := evidence.Load(p.Dir)
		ids := make([]string, 0, len(items))
		for _, it := range items {
			ids = append(ids, it.ID+" ("+it.Kind+")")
		}
		if len(ids) == 0 {
			return fail(fmt.Errorf("no evidence captured yet — run: kai evidence %s add --kind response --host H --path P", p.Name))
		}
		return fail(fmt.Errorf("no evidence with id %q — available: %s", pos[1], strings.Join(ids, ", ")))
	}

	in := report.Input{
		Program:   p.Name,
		Platform:  *platform,
		Title:     *title,
		Severity:  *severity,
		Target:    orFallback(ev.Target, joinTarget(ev)),
		Class:     "",
		FindingID: *findingID,
		Note:      ev.Note,
		ScopeLine: *scopeLine,
		Evidence:  []evidence.Item{ev},
	}
	if ev.Finding != "" && in.FindingID == "" {
		in.FindingID = ev.Finding
	}
	if !report.Valid(in.Platform) {
		return fail(fmt.Errorf("unknown platform %q — one of: %s", in.Platform, strings.Join(report.Platforms, ", ")))
	}

	// Prefill from the findings ledger when this evidence is attached to one.
	if in.FindingID != "" {
		if led, err := triage.Load(p.Dir); err == nil && led != nil {
			for _, f := range led.Findings {
				if f.ID == in.FindingID {
					in.Class = f.Class
					if in.Title == "" {
						in.Title = f.Class + " on " + f.Target
					}
					if in.Target == "" {
						in.Target = f.Target
					}
					if in.Note == "" {
						in.Note = f.Note
					}
				}
			}
		}
	}
	if in.Class == "" {
		in.Class = "Others"
	}

	// Scope is decided by the gate, never by this command.
	if ev.Host != "" {
		if gate, err := scope.LoadGate(p.Dir); err == nil {
			if t, err := scope.Parse(ev.Host); err == nil {
				allowed, reason := gate.Check(t)
				if allowed {
					in.ScopeVerdict = "in"
					if in.ScopeLine == "" {
						in.ScopeLine = "gate: IN — " + reason
					}
				} else {
					in.ScopeVerdict = "out"
					in.ScopeLine = "gate: OUT — " + reason + " (do not submit)"
				}
			}
		}
	}
	for _, e := range extras {
		label, value := e, ""
		if i := strings.Index(e, "="); i >= 0 {
			label, value = e[:i], e[i+1:]
		}
		in.Extra = append(in.Extra, report.KV{Label: label, Value: value})
	}
	in.Extra = report.SortKV(in.Extra)

	text, err := report.Render(in)
	if err != nil {
		return fail(err)
	}

	dest := *out
	if dest == "" {
		dir := filepath.Join(p.Dir, "reports")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fail(err)
		}
		dest = filepath.Join(dir, "draft-"+ev.ID+"-"+in.Platform+".md")
	}
	if err := os.WriteFile(dest, []byte(text), 0o600); err != nil {
		return fail(err)
	}
	fmt.Printf("draft written: %s\n", dest)
	fmt.Printf("  platform: %s   evidence: %s   finding: %s\n", in.Platform, ev.ID, orFallback(in.FindingID, "—"))
	if in.ScopeVerdict == "out" {
		fmt.Println("  WARNING: the scope gate says OUT for this host — do not submit")
	}
	fmt.Printf("  blanks left for you: description, impact, steps, severity\n")
	return 0
}

func orFallback(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func joinTarget(it evidence.Item) string {
	parts := []string{}
	if it.Method != "" {
		parts = append(parts, it.Method)
	}
	if it.Host != "" {
		parts = append(parts, it.Host+it.Path)
	} else if it.Path != "" {
		parts = append(parts, it.Path)
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}
