package recon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// HostRef is a compact host pointer used in diffs.
type HostRef struct {
	Host   string `json:"host"`
	Status int    `json:"status,omitempty"`
	Title  string `json:"title,omitempty"`
}

// JSChange records a bundle whose content hash moved.
type JSChange struct {
	URL string `json:"url"`
	Old string `json:"old,omitempty"`
	New string `json:"new"`
}

// Diff is the delta between two snapshots. Everything in NewHosts,
// NewEndpoints, ChangedJS and NewParams is surface that did not exist in the
// previous run — the highest-value input for a hunting session.
type Diff struct {
	From         string     `json:"from"`
	To           string     `json:"to"`
	Baseline     bool       `json:"baseline"`
	NewHosts     []HostRef  `json:"new_hosts,omitempty"`
	GoneHosts    []string   `json:"gone_hosts,omitempty"`
	NewEndpoints []string   `json:"new_endpoints,omitempty"`
	ChangedJS    []JSChange `json:"changed_js,omitempty"`
	NewParams    []string   `json:"new_params,omitempty"`
}

func snapshotsDir(dir string) string { return filepath.Join(dir, "snapshots") }

// Snapshot copies the current store into snapshots/<ts>/assets.json.
func Snapshot(dir string, s *Store, ts string) error {
	dest := filepath.Join(snapshotsDir(dir), ts)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dest, "assets.json"), b, 0o600)
}

// SnapshotNames lists snapshots oldest first.
func SnapshotNames(dir string) []string {
	entries, err := os.ReadDir(snapshotsDir(dir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func loadSnapshot(dir, ts string) (*Store, error) {
	b, err := os.ReadFile(filepath.Join(snapshotsDir(dir), ts, "assets.json"))
	if err != nil {
		return nil, err
	}
	s := NewStore("")
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	return s, nil
}

// ComputeDiff compares two stores.
func ComputeDiff(prev, cur *Store, prevTS, curTS string) Diff {
	d := Diff{From: prevTS, To: curTS}
	if prev == nil {
		d.Baseline = true
		return d
	}
	for host, h := range cur.Hosts {
		if _, ok := prev.Hosts[host]; !ok {
			d.NewHosts = append(d.NewHosts, HostRef{Host: host, Status: h.Status, Title: h.Title})
		}
	}
	for host := range prev.Hosts {
		if _, ok := cur.Hosts[host]; !ok {
			d.GoneHosts = append(d.GoneHosts, host)
		}
	}
	for path := range cur.Endpoints {
		if _, ok := prev.Endpoints[path]; !ok {
			d.NewEndpoints = append(d.NewEndpoints, path)
		}
	}
	prevParams := map[string]struct{}{}
	for _, e := range prev.Endpoints {
		for _, p := range e.Params {
			prevParams[p] = struct{}{}
		}
	}
	curParams := map[string]struct{}{}
	for _, e := range cur.Endpoints {
		for _, p := range e.Params {
			curParams[p] = struct{}{}
			if _, ok := prevParams[p]; !ok {
				if p != "*" {
					d.NewParams = append(d.NewParams, p)
				}
			}
		}
	}
	for u, j := range cur.JS {
		old, ok := prev.JS[u]
		switch {
		case !ok:
			d.ChangedJS = append(d.ChangedJS, JSChange{URL: u, New: j.SHA256})
		case old.SHA256 != j.SHA256:
			d.ChangedJS = append(d.ChangedJS, JSChange{URL: u, Old: old.SHA256, New: j.SHA256})
		}
	}

	sort.Slice(d.NewHosts, func(i, j int) bool { return d.NewHosts[i].Host < d.NewHosts[j].Host })
	sort.Strings(d.GoneHosts)
	sort.Strings(d.NewEndpoints)
	sort.Strings(d.NewParams)
	sort.Slice(d.ChangedJS, func(i, j int) bool { return d.ChangedJS[i].URL < d.ChangedJS[j].URL })
	return d
}

// WriteDiff stores diff.json and diff.md at the program root.
func WriteDiff(dir string, d Diff) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "diff.json"), b, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "diff.md"), []byte(d.Markdown()), 0o600)
}

// LoadDiff reads diff.json.
func LoadDiff(dir string) (*Diff, error) {
	b, err := os.ReadFile(filepath.Join(dir, "diff.json"))
	if err != nil {
		return nil, err
	}
	var d Diff
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Markdown renders the diff for humans and for the agent brief.
func (d Diff) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Surface diff\n\n")
	fmt.Fprintf(&b, "`%s` → `%s`\n\n", d.From, d.To)
	if d.Baseline {
		b.WriteString("**Baseline snapshot.** No previous run to compare against — every host below is new by definition.\n")
		return b.String()
	}

	section := func(title string, n int) {
		fmt.Fprintf(&b, "## %s (%d)\n\n", title, n)
	}
	if len(d.NewHosts) > 0 {
		section("New hosts", len(d.NewHosts))
		for _, h := range d.NewHosts {
			fmt.Fprintf(&b, "- `%s`", h.Host)
			if h.Status > 0 {
				fmt.Fprintf(&b, " [%d]", h.Status)
			}
			if h.Title != "" {
				fmt.Fprintf(&b, " — %s", h.Title)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if len(d.ChangedJS) > 0 {
		section("Changed JavaScript bundles", len(d.ChangedJS))
		for _, j := range d.ChangedJS {
			if j.Old == "" {
				fmt.Fprintf(&b, "- `%s` (new)\n", j.URL)
				continue
			}
			fmt.Fprintf(&b, "- `%s` `%s` → `%s`\n", j.URL, short(j.Old), short(j.New))
		}
		b.WriteString("\n")
	}
	if len(d.NewEndpoints) > 0 {
		section("New endpoints", len(d.NewEndpoints))
		limit := len(d.NewEndpoints)
		if limit > 200 {
			limit = 200
		}
		for _, e := range d.NewEndpoints[:limit] {
			fmt.Fprintf(&b, "- `%s`\n", e)
		}
		if len(d.NewEndpoints) > limit {
			fmt.Fprintf(&b, "- … %d more\n", len(d.NewEndpoints)-limit)
		}
		b.WriteString("\n")
	}
	if len(d.NewParams) > 0 {
		section("New parameters", len(d.NewParams))
		fmt.Fprintf(&b, "`%s`\n\n", strings.Join(d.NewParams, "`, `"))
	}
	if len(d.GoneHosts) > 0 {
		section("Hosts no longer resolving", len(d.GoneHosts))
		for _, h := range d.GoneHosts {
			fmt.Fprintf(&b, "- `%s`\n", h)
		}
		b.WriteString("\n")
	}
	if len(d.NewHosts)+len(d.NewEndpoints)+len(d.ChangedJS)+len(d.NewParams) == 0 {
		b.WriteString("**No new surface since the previous run.** Re-testing the same paths will most likely produce duplicates; wait for the target to ship, or change the hypothesis.\n")
	}
	return b.String()
}

func short(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

// NowStamp returns the snapshot stamp format used everywhere.
func NowStamp(t time.Time) string { return t.UTC().Format("20060102T150405Z") }
