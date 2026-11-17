// Package triage is a manual ledger for the post-submission lifecycle:
// submitted → needs-info → triaged → duplicate/informative/resolved → paid.
// It never talks to a platform; entries are operator-owned facts.
package triage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Finding struct {
	ID          string `json:"id"`
	SourceIndex int    `json:"source_index,omitempty"`
	Target      string `json:"target"`
	Class       string `json:"class,omitempty"`
	Probe       string `json:"probe,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Status      string `json:"status"`
	Note        string `json:"note,omitempty"`
	SubmittedAt string `json:"submitted_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
	RetestAt    string `json:"retest_at,omitempty"`
	Snapshot    string `json:"snapshot,omitempty"`
	Amount      int    `json:"amount,omitempty"`
}

type Ledger struct {
	Program  string    `json:"program"`
	Findings []Finding `json:"findings,omitempty"`
	Lessons  []string  `json:"lessons,omitempty"`
	Dupes    []string  `json:"dupes,omitempty"`
}

var validStatus = map[string]bool{
	"candidate": true, "submitted": true, "needs-info": true, "triaged": true,
	"duplicate": true, "informative": true, "resolved": true, "paid": true, "retest": true,
}

func Path(pDir string) string { return filepath.Join(pDir, "findings", "ledger.json") }

func Load(pDir string) (*Ledger, error) {
	b, err := os.ReadFile(Path(pDir))
	if err != nil {
		if os.IsNotExist(err) {
			return &Ledger{Program: filepath.Base(pDir)}, nil
		}
		return nil, err
	}
	var l Ledger
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	if l.Findings == nil {
		l.Findings = []Finding{}
	}
	return &l, nil
}

func (l *Ledger) Save(pDir string) error {
	l.Program = filepath.Base(pDir)
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(Path(pDir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(Path(pDir), b, 0o600); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(dir, "lessons.md"), []byte(l.LessonsMarkdown()), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "dupes.md"), []byte(l.DupesMarkdown()), 0o600)
	return nil
}

func (l *Ledger) Add(target, class, probe, platform string, index int) (Finding, error) {
	if strings.TrimSpace(target) == "" {
		return Finding{}, fmt.Errorf("empty target")
	}
	id := fmt.Sprintf("f-%03d", len(l.Findings)+1)
	f := Finding{
		ID: id, SourceIndex: index, Target: target, Class: class, Probe: probe,
		Platform: platform, Status: "submitted", SubmittedAt: now(), UpdatedAt: now(),
	}
	l.Findings = append(l.Findings, f)
	return f, nil
}

func (l *Ledger) find(id string) *Finding {
	for i := range l.Findings {
		if l.Findings[i].ID == id {
			return &l.Findings[i]
		}
	}
	return nil
}

func (l *Ledger) SetStatus(id, status, note string) error {
	if !validStatus[status] {
		return fmt.Errorf("unknown status %q", status)
	}
	f := l.find(id)
	if f == nil {
		return fmt.Errorf("no finding %s", id)
	}
	f.Status = status
	f.Note = note
	f.UpdatedAt = now()
	switch status {
	case "duplicate", "informative":
		entry := f.Target + " — " + note
		if strings.TrimSpace(note) == "" {
			entry = f.Target + " — no distinguishing impact recorded"
		}
		l.Dupes = append(l.Dupes, entry)
		l.Lessons = append(l.Lessons, fmt.Sprintf("don't repeat `%s` without a new angle: %s", f.Target, note))
	}
	return nil
}

func (l *Ledger) Payout(id string, amount int) error {
	f := l.find(id)
	if f == nil {
		return fmt.Errorf("no finding %s", id)
	}
	f.Status = "paid"
	f.Amount = amount
	f.UpdatedAt = now()
	return nil
}

func (l *Ledger) Retest(id, snapshot string) error {
	f := l.find(id)
	if f == nil {
		return fmt.Errorf("no finding %s", id)
	}
	f.Status = "retest"
	f.RetestAt = now()
	f.Snapshot = snapshot
	f.UpdatedAt = now()
	return nil
}

func (l Ledger) Counts() map[string]int {
	out := map[string]int{}
	for _, f := range l.Findings {
		out[f.Status]++
	}
	return out
}

func (l Ledger) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Triage ledger — %s\n\n", l.Program)
	if len(l.Findings) == 0 {
		b.WriteString("No submitted findings yet. Use `kai track <program> submit <n>` after packing a queue.\n\n")
		return b.String()
	}
	b.WriteString("| id | status | target | note |\n| --- | --- | --- | --- |\n")
	for _, f := range l.Findings {
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s |\n", f.ID, f.Status, f.Target, dash(f.Note))
	}
	b.WriteString("\n")
	if len(l.Dupes) > 0 {
		b.WriteString("## Known duplicates / informative\n\n")
		for _, d := range l.Dupes {
			fmt.Fprintf(&b, "- %s\n", d)
		}
		b.WriteString("\n")
	}
	if len(l.Lessons) > 0 {
		b.WriteString("## Lessons\n\n")
		for _, x := range l.Lessons {
			fmt.Fprintf(&b, "- %s\n", x)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (l Ledger) LessonsMarkdown() string {
	var b strings.Builder
	b.WriteString("# Lessons\n\n")
	if len(l.Lessons) == 0 {
		b.WriteString("Empty. Add a note when a triager rejects a finding.\n")
	}
	for _, x := range l.Lessons {
		fmt.Fprintf(&b, "- %s\n", x)
	}
	return b.String()
}

func (l Ledger) DupesMarkdown() string {
	var b strings.Builder
	b.WriteString("# Known duplicates\n\n")
	if len(l.Dupes) == 0 {
		b.WriteString("Empty.\n")
	}
	for _, d := range l.Dupes {
		fmt.Fprintf(&b, "- %s\n", d)
	}
	return b.String()
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// SortedStatuses is handy for briefs.
func SortedStatuses(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
