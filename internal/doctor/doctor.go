// Package doctor performs a read-only environment check for kai.
package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai/internal/netx"
	"github.com/hourx/kai/internal/recon"
	"github.com/hourx/kai/internal/session"
	"github.com/hourx/kai/internal/workspace"
)

// Item is one environment check.
type Item struct {
	Name   string
	Status string // OK, WARN, FAIL
	Detail string
}

// Report is the full environment check.
type Report struct {
	Items []Item
}

// Run performs all checks. It makes one short public HTTP request unless
// opts.Net is false.
func Run(ctx context.Context, opts Options) Report {
	var r Report
	add := func(name, status, detail string) {
		r.Items = append(r.Items, Item{Name: name, Status: status, Detail: detail})
	}

	if _, err := exec.LookPath("git"); err != nil {
		add("git", "WARN", "not found — analyze --clone and git pull will fail")
	} else {
		out, err := exec.Command("git", "--version").Output()
		if err != nil {
			add("git", "WARN", err.Error())
		} else {
			add("git", "OK", strings.TrimSpace(string(out)))
		}
	}

	if _, err := exec.LookPath("go"); err != nil {
		add("go", "WARN", "not found — use a prebuilt binary or go install elsewhere")
	} else {
		out, err := exec.Command("go", "version").Output()
		if err != nil {
			add("go", "WARN", err.Error())
		} else {
			add("go", "OK", strings.TrimSpace(string(out)))
		}
	}

	adapters := recon.Adapters()
	if len(adapters) == 0 {
		add("recon adapters", "WARN", "none found — crt.sh + direct HTTP still work")
	} else {
		names := make([]string, 0, len(adapters))
		for n := range adapters {
			names = append(names, n)
		}
		sort.Strings(names)
		add("recon adapters", "OK", strings.Join(names, ", "))
	}

	proxy := os.Getenv("HTTPS_PROXY")
	if proxy == "" {
		proxy = os.Getenv("https_proxy")
	}
	if proxy == "" {
		add("proxy", "OK", "not configured (direct egress)")
	} else {
		add("proxy", "OK", "HTTPS_PROXY set (credentials hidden)")
	}

	home := workspace.Home()
	if err := os.MkdirAll(home, 0o755); err != nil {
		add("state root", "FAIL", err.Error())
	} else {
		add("state root", "OK", home)
	}

	names, err := workspace.List()
	if err != nil {
		add("programs", "FAIL", err.Error())
	} else if len(names) == 0 {
		add("programs", "WARN", "none yet — kai intake <url> makes one")
	} else {
		for _, name := range names {
			p, err := workspace.Open(name)
			if err != nil {
				add("program "+name, "FAIL", err.Error())
				continue
			}
			var notes []string
			if _, err := os.Stat(filepath.Join(p.Dir, "intake.json")); err == nil {
				notes = append(notes, "intake")
			}
			if _, err := os.Stat(filepath.Join(p.Dir, "boundaries.md")); err == nil {
				notes = append(notes, "boundaries")
			}
			if _, err := os.Stat(filepath.Join(p.Dir, "assets.json")); err == nil {
				notes = append(notes, "assets")
			}
			if s, err := session.Load(p.Dir); err == nil {
				notes = append(notes, fmt.Sprintf("session(%d cookies,%d headers)", len(s.Cookies), len(s.Headers)))
			}
			if len(notes) == 0 {
				notes = append(notes, "empty workspace")
			}
			add("program "+name, "OK", strings.Join(notes, ", "))
		}
	}

	if opts.Net {
		c := netx.New("kai-doctor/0.9", 5, nil)
		defer c.Close()
		ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		resp, err := c.Get(ctx2, "https://hackerone.com/graphql", 256)
		switch {
		case err != nil:
			add("network", "WARN", err.Error())
		case resp.StatusCode >= 500:
			add("network", "WARN", fmt.Sprintf("HTTP %d from HackerOne", resp.StatusCode))
		default:
			add("network", "OK", fmt.Sprintf("HTTP %d from HackerOne", resp.StatusCode))
		}
	}

	return r
}

// Options controls the checks.
type Options struct {
	Net bool
}

// Text renders the report.
func (r Report) Text() string {
	var b strings.Builder
	b.WriteString("# kai doctor\n\n")
	for _, it := range r.Items {
		fmt.Fprintf(&b, "%-4s %-24s %s\n", it.Status, it.Name, it.Detail)
	}
	fails := 0
	for _, it := range r.Items {
		if it.Status == "FAIL" {
			fails++
		}
	}
	fmt.Fprintf(&b, "\n%d check(s), %d failure(s)\n", len(r.Items), fails)
	return b.String()
}

// Failures returns the number of hard failures.
func (r Report) Failures() int {
	n := 0
	for _, it := range r.Items {
		if it.Status == "FAIL" {
			n++
		}
	}
	return n
}
