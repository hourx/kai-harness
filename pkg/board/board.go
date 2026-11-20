// Package board answers one question across every program: what is worth doing
// today.
//
// It reads only what is already on disk under KAI_HOME (meta, scope, recon
// store, ranked queue, outcome log, findings ledger, evidence index). No
// network, no LLM: a board that changes on its own is a board nobody trusts.
package board

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/evidence"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/recon"
	"github.com/hourx/kai-harness/pkg/scope"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/triage"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// StaleAfter is the age at which a recon surface is called stale.
const StaleAfter = 14 * 24 * time.Hour

// Program is one row of the board.
type Program struct {
	Name       string         `json:"name"`
	Platform   string         `json:"platform,omitempty"`
	Verdict    string         `json:"scope_verdict,omitempty"`
	InScope    int            `json:"in_scope_rules"`
	OutOfScope int            `json:"out_of_scope_rules"`
	Hosts      int            `json:"hosts"`
	Endpoints  int            `json:"endpoints"`
	Queue      int            `json:"queue"`
	TopTarget  string         `json:"top_target,omitempty"`
	TopClass   string         `json:"top_class,omitempty"`
	TopScore   int            `json:"top_score,omitempty"`
	LastRecon  string         `json:"last_recon,omitempty"`
	ReconDays  float64        `json:"recon_age_days"`
	LastOut    string         `json:"last_outcome,omitempty"`
	LastOutAt  string         `json:"last_outcome_at,omitempty"`
	Findings   []FindingCount `json:"findings,omitempty"`
	Evidence   int            `json:"evidence"`
	Blockers   []string       `json:"blockers,omitempty"`
}

// FindingCount is one status bucket of the findings ledger, ordered by status.
type FindingCount struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

// Action is one line of the "do today" list.
type Action struct {
	Rank    int    `json:"rank"`
	Program string `json:"program"`
	Why     string `json:"why"`
	Command string `json:"command"`
	Score   int    `json:"score,omitempty"`
}

// Report is the whole board.
type Report struct {
	Generated string    `json:"generated"`
	Home      string    `json:"home"`
	Programs  []Program `json:"programs"`
	Todo      []Action  `json:"todo"`
	Notes     []string  `json:"notes"`
}

// Snapshot builds the board for every program under KAI_HOME.
func Snapshot(home string) (Report, error) {
	names, err := workspace.List()
	if err != nil {
		return Report{}, err
	}
	rep := Report{
		Generated: time.Now().UTC().Format(time.RFC3339),
		Home:      home,
		Notes: []string{
			"The board reads state only; it never sends a request.",
			"Recon older than " + days(StaleAfter) + " is marked stale — a stale surface is a stale hypothesis queue.",
		},
	}
	for _, name := range names {
		row, err := inspect(name)
		if err != nil {
			row = Program{Name: name, Blockers: []string{err.Error()}}
		}
		rep.Programs = append(rep.Programs, row)
	}
	sort.SliceStable(rep.Programs, func(i, j int) bool {
		if rep.Programs[i].TopScore != rep.Programs[j].TopScore {
			return rep.Programs[i].TopScore > rep.Programs[j].TopScore
		}
		return rep.Programs[i].Name < rep.Programs[j].Name
	})
	rep.Todo = todo(rep.Programs)
	return rep, nil
}

func inspect(name string) (Program, error) {
	p, err := workspace.Open(name)
	if err != nil {
		return Program{Name: name}, err
	}
	row := Program{
		Name:     name,
		Platform: p.Meta.Platform,
		Verdict:  p.Meta.ScopeVerdict,
	}
	// Scope size is counted in rules, not lines: comments and blanks are not
	// rules, and the gate is the thing that decides.
	if in, err := scope.Load(filepath.Join(p.Dir, "scope.txt")); err == nil {
		row.InScope = len(in)
	}
	if out, err := scope.Load(filepath.Join(p.Dir, "out-of-scope.txt")); err == nil {
		row.OutOfScope = len(out)
	}
	if v := strings.TrimSpace(p.Meta.ScopeVerdict); v == "" || v == "unknown" {
		row.Blockers = append(row.Blockers, "scope verdict unset — `kai init` never confirmed it")
	}
	if row.InScope == 0 {
		row.Blockers = append(row.Blockers, "no scope.txt — the gate cannot answer IN")
	}

	if store, err := recon.LoadStore(p.Dir, name); err == nil && store != nil {
		row.Hosts = len(store.Hosts)
		row.Endpoints = len(store.Endpoints)
	}
	if ts := artifactTime(p.Dir, "assets.json", "map.json"); !ts.IsZero() {
		row.LastRecon = ts.UTC().Format(time.RFC3339)
		row.ReconDays = round1(time.Since(ts).Hours() / 24)
	}

	if q, err := surface.LoadPlan(p.Dir); err == nil {
		row.Queue = len(q.Items)
		if len(q.Items) > 0 {
			top := q.Items[0]
			for _, h := range q.Items {
				if h.Score > top.Score {
					top = h
				}
			}
			row.TopTarget, row.TopClass, row.TopScore = top.Target, top.Class, top.Score
		}
	}

	if tbl, err := outcome.Load(p.Dir); err == nil && tbl.Len() > 0 {
		var last outcome.Record
		for _, r := range tbl.Records() {
			if r.TS >= last.TS {
				last = r
			}
		}
		row.LastOut, row.LastOutAt = last.Status, last.TS
	}

	if led, err := triage.Load(p.Dir); err == nil && led != nil {
		counts := led.Counts()
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			row.Findings = append(row.Findings, FindingCount{Status: k, Count: counts[k]})
		}
	}

	if items, err := evidence.Load(p.Dir); err == nil {
		row.Evidence = len(items)
	}

	if row.Queue == 0 && row.Hosts > 0 {
		row.Blockers = append(row.Blockers, "no queue — run `kai map` then `kai next`")
	}
	if row.Hosts == 0 {
		row.Blockers = append(row.Blockers, "no recon yet — run `kai recon`")
	}
	return row, nil
}

func todo(rows []Program) []Action {
	var out []Action
	add := func(why, cmd, program string, score int) {
		out = append(out, Action{Program: program, Why: why, Command: cmd, Score: score})
	}
	// 1. Findings that need an operator's hand — money already on the table.
	for _, r := range rows {
		for _, f := range r.Findings {
			switch f.Status {
			case "candidate":
				add(fmt.Sprintf("%d candidate finding(s) not submitted", f.Count), "kai track "+r.Name+" list", r.Name, 1000)
			case "needs-info":
				add(fmt.Sprintf("%d finding(s) waiting on program info", f.Count), "kai track "+r.Name+" list", r.Name, 950)
			case "triaged":
				add(fmt.Sprintf("%d triaged finding(s) — watch the payout", f.Count), "kai track "+r.Name+" status", r.Name, 900)
			case "retest":
				add(fmt.Sprintf("%d finding(s) due for retest", f.Count), "kai track "+r.Name+" retest", r.Name, 880)
			}
		}
	}
	// 2. Fresh queue with a top hypothesis — the actual hunting work.
	for _, r := range rows {
		if r.Queue == 0 {
			continue
		}
		if r.ReconDays > StaleAfter.Hours()/24 {
			add(fmt.Sprintf("queue is %s old (%d items) — refresh before trusting it", days(time.Duration(r.ReconDays*24)*time.Hour), r.Queue),
				"kai recon "+r.Name, r.Name, 200)
			continue
		}
		add(fmt.Sprintf("top hypothesis %s (%s, score %d)", r.TopClass, r.TopTarget, r.TopScore), "kai plan "+r.Name, r.Name, 500+r.TopScore)
	}
	// 3. Nothing to test yet.
	for _, r := range rows {
		if r.Queue == 0 && r.Hosts == 0 {
			add("no surface yet", "kai recon "+r.Name, r.Name, 100)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Program < out[j].Program
	})
	for i := range out {
		out[i].Rank = i + 1
		out[i].Score = 0
	}
	return out
}

func artifactTime(dir string, names ...string) time.Time {
	var newest time.Time
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		if fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest
}

func days(d time.Duration) string {
	if d < 48*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

// Markdown renders the board for a human.
func (r Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Board — %s\n\n", r.Generated)
	fmt.Fprintf(&b, "%d program(s) under %s.\n\n", len(r.Programs), r.Home)

	b.WriteString("## Programs\n\n")
	for _, p := range r.Programs {
		fmt.Fprintf(&b, "### %s\n\n", p.Name)
		if p.Platform != "" {
			fmt.Fprintf(&b, "- platform: %s (verdict: %s)\n", p.Platform, orDash(p.Verdict))
		}
		fmt.Fprintf(&b, "- scope: %d in / %d out\n", p.InScope, p.OutOfScope)
		fmt.Fprintf(&b, "- surface: %d host(s), %d endpoint(s), last recon %s\n", p.Hosts, p.Endpoints, orDash(p.LastRecon))
		if p.Queue > 0 {
			fmt.Fprintf(&b, "- queue: %d item(s), top %s — `%s` (score %d)\n", p.Queue, p.TopClass, p.TopTarget, p.TopScore)
		} else {
			b.WriteString("- queue: empty\n")
		}
		if p.LastOut != "" {
			fmt.Fprintf(&b, "- last outcome: %s at %s\n", p.LastOut, p.LastOutAt)
		}
		if len(p.Findings) > 0 {
			parts := make([]string, 0, len(p.Findings))
			for _, f := range p.Findings {
				parts = append(parts, fmt.Sprintf("%s %d", f.Status, f.Count))
			}
			fmt.Fprintf(&b, "- findings: %s\n", strings.Join(parts, ", "))
		}
		fmt.Fprintf(&b, "- evidence: %d item(s)\n", p.Evidence)
		for _, bl := range p.Blockers {
			fmt.Fprintf(&b, "- blocker: %s\n", bl)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Do today\n\n")
	if len(r.Todo) == 0 {
		b.WriteString("_nothing queued — the board has no data to rank_\n\n")
	}
	for _, a := range r.Todo {
		fmt.Fprintf(&b, "%d. **%s** — %s\n   - `%s`\n", a.Rank, a.Program, a.Why, a.Command)
	}

	b.WriteString("\n## Notes\n\n")
	for _, n := range r.Notes {
		b.WriteString("- " + n + "\n")
	}
	return b.String()
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
