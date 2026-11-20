// Package outcome records what happened to a target after it was tested.
//
// It is the return path of kai's loop: `kai outcome` appends, `kai next` reads
// and re-ranks with it. Pure data — no network, no LLM, and no dependency on
// the wall clock beyond the timestamp written into each record.
package outcome

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Accepted statuses, in the order the CLI documents them.
const (
	StatusNegation      = "negation"      // tested, not a bug
	StatusInformational = "informational" // tested, no security impact
	StatusFinding       = "finding"       // proven bug, not yet submitted
	StatusReported      = "reported"      // submitted to the program
	StatusPaid          = "paid"          // rewarded
)

// Statuses is the closed set accepted by Valid.
var Statuses = []string{StatusNegation, StatusInformational, StatusFinding, StatusReported, StatusPaid}

// Valid reports whether status is one of the accepted values.
func Valid(status string) bool {
	for _, s := range Statuses {
		if s == status {
			return true
		}
	}
	return false
}

// Yields reports whether a status means the target was worth testing at all:
// a target that produced a finding stays interesting, a negative does not.
func Yields(status string) bool {
	switch status {
	case StatusFinding, StatusReported, StatusPaid:
		return true
	}
	return false
}

// Record is one line of outcomes.jsonl.
type Record struct {
	TS     string `json:"ts"`
	Target string `json:"target"`
	Status string `json:"status"`
	Class  string `json:"class,omitempty"`
	Note   string `json:"note,omitempty"`
}

// Time parses the record timestamp; the zero time means "unparseable".
func (r Record) Time() time.Time {
	t, err := time.Parse(time.RFC3339, r.TS)
	if err != nil {
		return time.Time{}
	}
	return t
}

// FreshnessTolerance covers records written with second precision (older logs,
// hand-written lines): a probe recorded in the same second as the recon run is
// fresh, not stale. Without it, second-truncation makes the probe look older
// than the surface it was run against.
const FreshnessTolerance = time.Second

// Fresh reports whether a record is newer than the last surface change. A zero
// timestamp counts as stale, so a corrupt log cannot hide work.
func Fresh(r Record, surfaceTS time.Time) bool {
	if r.Time().IsZero() {
		return false
	}
	return !r.Time().Add(FreshnessTolerance).Before(surfaceTS)
}

// Path is where a program's outcome log lives.
func Path(pDir string) string { return filepath.Join(pDir, "state", "outcomes.jsonl") }

// Append adds one record to the program's outcome log, creating state/ if
// needed. The file is 0600: notes describe bugs that are not public yet.
func Append(pDir string, r Record) error {
	if r.TS == "" {
		// Full precision: a second-truncated timestamp can land before the
		// recon run that produced the surface, which would read as stale.
		r.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := os.MkdirAll(filepath.Dir(Path(pDir)), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(Path(pDir), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

// Table holds the latest record per target, in first-seen order.
type Table struct {
	latest map[string]Record
	order  []string
	total  int
}

// NewTable builds a table from records already in chronological order.
func NewTable(records ...Record) *Table {
	t := &Table{latest: map[string]Record{}}
	for _, r := range records {
		t.Add(r)
	}
	return t
}

// Add records one outcome; a later record for the same target wins.
func (t *Table) Add(r Record) {
	key := Normalize(r.Target)
	if key == "" {
		return
	}
	r.Target = key
	if _, seen := t.latest[key]; !seen {
		t.order = append(t.order, key)
	}
	t.latest[key] = r
	t.total++
}

// Last returns the most recent record for a target.
func (t *Table) Last(target string) (Record, bool) {
	if t == nil {
		return Record{}, false
	}
	r, ok := t.latest[Normalize(target)]
	return r, ok
}

// Len is the number of distinct targets with history.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.latest)
}

// Records returns every latest record in first-seen order.
func (t *Table) Records() []Record {
	if t == nil {
		return nil
	}
	out := make([]Record, 0, len(t.order))
	for _, k := range t.order {
		out = append(out, t.latest[k])
	}
	return out
}

// Normalize makes target keys comparable between the plan and the log: extra
// whitespace collapses, and a leading HTTP method is upper-cased so "get /a"
// and "GET /a" are one target rather than two queue slots.
func Normalize(target string) string {
	fields := strings.Fields(target)
	if len(fields) > 0 && isMethod(strings.ToUpper(fields[0])) {
		fields[0] = strings.ToUpper(fields[0])
	}
	return strings.Join(fields, " ")
}

func isMethod(s string) bool {
	switch s {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// Load reads state/outcomes.jsonl. A missing file is an empty table, not an
// error: most programs have no history yet.
func Load(pDir string) (*Table, error) {
	f, err := os.Open(Path(pDir))
	if err != nil {
		if os.IsNotExist(err) {
			return NewTable(), nil
		}
		return nil, err
	}
	defer f.Close()
	t := NewTable()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("outcomes.jsonl: %w", err)
		}
		t.Add(r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return t, nil
}

// SurfaceTS is the recorded time of the last surface change: the newest
// modification time among the artifacts a recon run actually produces. Derived
// files (map.json, next.json) are rewritten by every `kai next`, so they are
// deliberately excluded — counting them would make every outcome look stale
// forever. The value comes from the filesystem because that is where the
// evidence lives; nothing here is inferred from the current clock.
func SurfaceTS(pDir string) time.Time {
	var newest time.Time
	for _, rel := range []string{
		"assets.json",
		filepath.Join("recon", "live.txt"),
		filepath.Join("recon", "subs.txt"),
	} {
		if st, err := os.Stat(filepath.Join(pDir, rel)); err == nil && st.ModTime().After(newest) {
			newest = st.ModTime()
		}
	}
	return newest.UTC()
}
