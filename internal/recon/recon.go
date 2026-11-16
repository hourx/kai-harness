// Package recon discovers and fingerprints a program's attack surface.
//
// The output is deliberately small and deterministic: a handful of text files
// the agent already knows how to read, plus a diff against the previous run.
package recon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hourx/bountykit/internal/netx"
	"github.com/hourx/bountykit/internal/scope"
	"github.com/hourx/bountykit/internal/version"
	"github.com/hourx/bountykit/internal/workspace"
)

// Options controls a recon run.
type Options struct {
	Domains []string
	// SeedHosts are exact hosts from scope.txt, probed directly without any
	// subdomain enumeration. Programs scoped to a handful of hosts need this.
	SeedHosts  []string
	RPS        int
	MaxHosts   int
	MaxBundles int
	Nuclei     bool
	UserAgent  string
	Adapters   map[string]string
	Log        io.Writer
	// Session, when set, is attached to every in-scope request.
	Session        string
	SessionHeaders map[string]string
	// Confirm is called before each phase. Returning false aborts the run.
	Confirm func(step, detail string) bool
}

// Summary reports what a run produced.
type Summary struct {
	Domains      []string
	Discovered   int
	Gated        int
	Resolved     int
	Live         int
	URLs         int
	Bundles      int
	Endpoints    int
	NewHosts     int
	NewEndpoints int
	ChangedJS    int
	Baseline     bool
	Elapsed      time.Duration
}

// Adapters reports which optional external tools are on PATH.
func Adapters() map[string]string {
	out := map[string]string{}
	for _, name := range []string{"subfinder", "assetfinder", "gau", "waybackurls", "nuclei"} {
		if p, err := exec.LookPath(name); err == nil {
			out[name] = p
		}
	}
	return out
}

// Run executes the recon pipeline for one program.
func Run(ctx context.Context, p *workspace.Program, opts Options) (Summary, error) {
	start := time.Now()
	var sum Summary
	sum.Domains = opts.Domains
	if len(opts.Domains) == 0 && len(opts.SeedHosts) == 0 {
		return sum, errors.New("no domains or seed hosts: pass --domain or import scope with: bountykit intake <url>")
	}
	if opts.RPS <= 0 {
		opts.RPS = 10
	}
	if opts.MaxHosts <= 0 {
		opts.MaxHosts = 500
	}
	if opts.MaxBundles <= 0 {
		opts.MaxBundles = 100
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "bountykit/" + strings.SplitN(version.Version, "-", 2)[0] + " (+https://github.com/hourx/bountykit)"
	}
	logf := func(format string, args ...any) {
		if opts.Log != nil {
			fmt.Fprintf(opts.Log, format+"\n", args...)
		}
	}
	step := func(name, detail string) bool {
		if opts.Confirm == nil {
			return true
		}
		return opts.Confirm(name, detail)
	}

	gate, err := scope.LoadGate(p.Dir)
	if err != nil {
		return sum, err
	}
	allow := func(u *url.URL) bool {
		t, err := scope.Parse(u.Host)
		if err != nil {
			return false
		}
		ok, _ := gate.Check(t)
		return ok
	}
	client := netx.New(opts.UserAgent, opts.RPS, allow)
	defer client.Close()
	if opts.Session != "" || len(opts.SessionHeaders) > 0 {
		allowed := append([]string{}, opts.SeedHosts...)
		allowed = append(allowed, opts.Domains...)
		client.SetSession(netx.Session{Cookies: opts.Session, Headers: opts.SessionHeaders, Hosts: allowed})
	}

	discoverDetail := fmt.Sprintf("subdomain enumeration for %s", strings.Join(opts.Domains, ", "))
	if len(opts.Domains) == 0 {
		discoverDetail = fmt.Sprintf("probe %d in-scope seed host(s) directly — no wildcard to enumerate", len(opts.SeedHosts))
	}
	if !step("discover", discoverDetail) {
		return sum, fmt.Errorf("aborted")
	}

	// 1. Discover.
	hostSet := map[string]struct{}{}
	for _, domain := range opts.Domains {
		hosts, sources := Discover(ctx, client, domain, opts.Adapters)
		logf("  %-24s %4d hosts  (%s)", domain, len(hosts), strings.Join(sources, ", "))
		for _, h := range hosts {
			hostSet[h] = struct{}{}
		}
	}
	discovered := make([]string, 0, len(hostSet))
	for h := range hostSet {
		discovered = append(discovered, h)
	}
	for _, h := range opts.SeedHosts {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if h != "" {
			hostSet[h] = struct{}{}
			discovered = append(discovered, h)
		}
	}
	discovered = Uniq(discovered)
	sort.Strings(discovered)
	sum.Discovered = len(discovered)

	// 2. Gate before any request leaves the machine.
	gated := make([]string, 0, len(discovered))
	for _, h := range discovered {
		t, err := scope.Parse(h)
		if err != nil {
			continue
		}
		if ok, _ := gate.Check(t); ok {
			gated = append(gated, h)
		}
	}
	sum.Gated = len(gated)
	if len(gated) > opts.MaxHosts {
		gated = gated[:opts.MaxHosts]
	}
	logf("gated   %d in scope, probing %d", sum.Gated, len(gated))

	if !step("probe", fmt.Sprintf("resolve and HTTP-probe %d in-scope hosts", len(gated))) {
		return sum, fmt.Errorf("aborted")
	}

	// 3. Resolve.
	type resolved struct {
		host  string
		ips   []string
		cname string
	}
	var (
		mu  sync.Mutex
		res []resolved
		wg  sync.WaitGroup
		sem = make(chan struct{}, 20)
	)
	for _, h := range gated {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ips, cname := Resolve(ctx, h)
			if len(ips) == 0 {
				return
			}
			mu.Lock()
			res = append(res, resolved{host: h, ips: ips, cname: cname})
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	sort.Slice(res, func(i, j int) bool { return res[i].host < res[j].host })
	sum.Resolved = len(res)
	logf("resolved %d/%d", sum.Resolved, len(gated))

	// 4. Probe.
	probes := make([]ProbeResult, len(res))
	var pw sync.WaitGroup
	psem := make(chan struct{}, 8)
	for i, r := range res {
		pw.Add(1)
		go func(i int, r resolved) {
			defer pw.Done()
			psem <- struct{}{}
			defer func() { <-psem }()
			probes[i] = Probe(ctx, client, r.host, r.ips, r.cname)
		}(i, r)
	}
	pw.Wait()

	live := 0
	for _, pr := range probes {
		if pr.URL != "" {
			live++
		}
	}
	sum.Live = live
	logf("live    %d hosts responded", live)

	if !step("harvest", "collect historical URLs, JavaScript bundles and endpoints") {
		return sum, fmt.Errorf("aborted")
	}

	// 5. URLs.
	urlSet := map[string]struct{}{}
	addURL := func(raw string) {
		if raw == "" {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		t, err := scope.Parse(u.Host)
		if err != nil {
			return
		}
		if ok, _ := gate.Check(t); !ok {
			return
		}
		urlSet[raw] = struct{}{}
	}
	for _, pr := range probes {
		addURL(pr.URL)
		for _, l := range pr.Links {
			addURL(l)
		}
		for _, j := range pr.JS {
			addURL(j)
		}
	}
	if len(opts.Adapters) > 0 {
		for _, domain := range opts.Domains {
			for _, u := range HistoricalURLs(ctx, domain, opts.Adapters) {
				addURL(u)
			}
		}
	}
	urls := make([]string, 0, len(urlSet))
	for u := range urlSet {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	sum.URLs = len(urls)

	// 6. Bundles. Only URLs that already passed the scope gate (step 5)
	// are fetched. Sending session cookies to a CDN found in a <script>
	// tag would be a credential leak; the gate is the floor for every fetch.
	jsSet := map[string]struct{}{}
	for _, u := range urls {
		if isJSURL(u) {
			jsSet[u] = struct{}{}
		}
	}
	jsList := make([]string, 0, len(jsSet))
	for u := range jsSet {
		jsList = append(jsList, u)
	}
	sort.Strings(jsList)
	bundles := FetchBundles(ctx, client, jsList, opts.MaxBundles)
	sum.Bundles = len(bundles)
	logf("urls    %d, bundles %d", sum.URLs, sum.Bundles)

	// 7. Endpoints.
	paths := ExtractPaths(urls, bundles)
	sum.Endpoints = len(paths)

	// 8. Persist.
	now := time.Now().UTC()
	store, err := LoadStore(p.Dir, p.Name)
	if err != nil {
		return sum, err
	}
	for _, pr := range probes {
		if len(pr.IPs) == 0 {
			continue
		}
		h := store.Host(pr.Host, now)
		h.IPs = Uniq(h.IPs, pr.IPs)
		h.CNAME = pr.CNAME
		h.URL = pr.URL
		if pr.Status != 0 {
			h.Status = pr.Status
		}
		h.Title = pr.Title
		h.Tech = Uniq(h.Tech, pr.Tech)
		if pr.TLS != nil {
			h.TLS = pr.TLS
		}
		h.Sources = Uniq(h.Sources, []string{"recon"})
	}
	for path, params := range paths {
		if !looksLikeEndpoint(path) {
			continue
		}
		e := store.Endpoint(path, now)
		e.Params = Uniq(e.Params, params)
		e.Sources = Uniq(e.Sources, []string{"url"})
	}
	// Drop artifacts left by older runs (numeric-only paths, template junk)
	// so a tool fix actually cleans the state instead of accumulating noise.
	for path := range store.Endpoints {
		if !looksLikeEndpoint(path) {
			delete(store.Endpoints, path)
		}
	}
	for _, b := range bundles {
		store.Bundle(b.URL, b.SHA, b.Bytes, now)
	}
	if err := store.Save(p.Dir); err != nil {
		return sum, err
	}
	if err := writeStateFiles(p, store, urls); err != nil {
		return sum, err
	}

	// 9. Nuclei, optional.
	if opts.Nuclei {
		if path, ok := opts.Adapters["nuclei"]; ok {
			logf("nuclei  running (this can take a while)")
			cmd := exec.CommandContext(ctx, path,
				"-l", p.StatePath("live_urls.txt"),
				"-severity", "low,medium,high,critical",
				"-rate-limit", "5", "-silent",
				"-o", p.StatePath("nuclei.txt"))
			cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
			_ = cmd.Run()
		} else {
			logf("nuclei  skipped (not installed)")
		}
	}

	// 10. Snapshot + diff.
	ts := NowStamp(now)
	if err := Snapshot(p.Dir, store, ts); err != nil {
		return sum, err
	}
	names := SnapshotNames(p.Dir)
	var prev *Store
	prevTS := ""
	if len(names) >= 2 {
		prevTS = names[len(names)-2]
		prev, _ = loadSnapshot(p.Dir, prevTS)
	}
	d := ComputeDiff(prev, store, prevTS, ts)
	if err := WriteDiff(p.Dir, d); err != nil {
		return sum, err
	}
	sum.NewHosts = len(d.NewHosts)
	sum.NewEndpoints = len(d.NewEndpoints)
	sum.ChangedJS = len(d.ChangedJS)
	sum.Baseline = d.Baseline
	sum.Elapsed = time.Since(start)
	return sum, nil
}

func writeStateFiles(p *workspace.Program, s *Store, urls []string) error {
	dir := filepath.Join(p.Dir, "state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	hosts := s.SortedHosts()
	if err := writeLines(p.StatePath("subs.txt"), hosts); err != nil {
		return err
	}

	var live, liveURLs []string
	for _, h := range hosts {
		r := s.Hosts[h]
		if r.Status == 0 && r.URL == "" {
			continue
		}
		line := r.Host
		if r.Status > 0 {
			line = fmt.Sprintf("%-45s [%d] %s", r.Host, r.Status, r.Title)
		}
		if len(r.Tech) > 0 {
			line += " [" + strings.Join(r.Tech, ",") + "]"
		}
		live = append(live, strings.TrimRight(line, " "))
		if r.URL != "" {
			liveURLs = append(liveURLs, r.URL)
		}
	}
	if err := writeLines(p.StatePath("live.txt"), live); err != nil {
		return err
	}
	if err := writeLines(p.StatePath("live_urls.txt"), liveURLs); err != nil {
		return err
	}
	if err := writeLines(p.StatePath("urls.txt"), urls); err != nil {
		return err
	}

	var bundles []string
	for _, u := range s.SortedJS() {
		j := s.JS[u]
		bundles = append(bundles, fmt.Sprintf("%s\t%s\t%d", j.URL, j.SHA256, j.Bytes))
	}
	if err := writeLines(p.StatePath("js.ts"), bundles); err != nil {
		return err
	}

	var endpoints []string
	for _, path := range s.SortedEndpoints() {
		if path == "*" {
			continue
		}
		e := s.Endpoints[path]
		line := path
		if len(e.Params) > 0 {
			line += " ?" + strings.Join(e.Params, ",")
		}
		endpoints = append(endpoints, line)
	}
	if err := writeLines(p.StatePath("endpoints.txt"), endpoints); err != nil {
		return err
	}
	return writeLines(p.StatePath("ranked.txt"), rankHosts(s))
}

func writeLines(path string, lines []string) error {
	if len(lines) == 0 {
		return os.WriteFile(path, nil, 0o600)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// rankHosts orders assets by how likely they are to hide an interesting bug.
func rankHosts(s *Store) []string {
	hostWords := []string{"admin", "api", "dev", "staging", "stage", "test", "internal", "beta", "old", "backup", "jenkins", "gitlab", "grafana", "kibana", "sso", "auth", "portal", "dashboard", "upload", "files", "debug"}
	titleWords := []string{"admin", "login", "dashboard", "internal", "swagger", "api", "graphql"}
	type scored struct {
		score int
		line  string
	}
	var out []scored
	for host, h := range s.Hosts {
		score := 0
		low := strings.ToLower(host)
		for _, w := range hostWords {
			if strings.Contains(low, w) {
				score += 10
			}
		}
		switch {
		case h.Status == 401 || h.Status == 403:
			score += 8
		case h.Status >= 200 && h.Status < 300:
			score += 4
		}
		tl := strings.ToLower(h.Title)
		for _, w := range titleWords {
			if strings.Contains(tl, w) {
				score += 6
			}
		}
		if h.TLS != nil && h.TLS.Expired {
			score += 3
		}
		if len(h.Tech) > 0 {
			score++
		}
		out = append(out, scored{score: score, line: fmt.Sprintf("%4d  %-45s [%d] %s", score, host, h.Status, h.Title)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].line < out[j].line
	})
	lines := make([]string, 0, len(out))
	for _, o := range out {
		lines = append(lines, o.line)
	}
	return lines
}
