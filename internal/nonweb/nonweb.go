// Package nonweb performs a deterministic, opt-in analysis of in-scope source
// repositories and contract addresses collected during Phase 0.
//
// It never submits anything and never contacts a target application. Network
// use is limited to cloning a repository when the operator passes --clone.
package nonweb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai/internal/netx"
	"github.com/hourx/kai/internal/program"
	"github.com/hourx/kai/internal/workspace"
)

// Workflow is one CI workflow file and the risky patterns found in it.
type Workflow struct {
	File     string   `json:"file"`
	Triggers []string `json:"triggers,omitempty"`
	Risks    []string `json:"risks,omitempty"`
}

// Repo is one source-code target.
type Repo struct {
	URL         string     `json:"url"`
	Slug        string     `json:"slug"`
	Status      string     `json:"status"`
	Path        string     `json:"path,omitempty"`
	Workflows   []Workflow `json:"workflows,omitempty"`
	Manifests   []string   `json:"manifests,omitempty"`
	Scripts     []string   `json:"scripts,omitempty"`
	EntryPoints []string   `json:"entry_points,omitempty"`
	Risks       []string   `json:"risks,omitempty"`
	Description string     `json:"description,omitempty"`
	Origin      string     `json:"origin,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// Contract is one in-scope on-chain address.
type Contract struct {
	Address  string `json:"address"`
	Explorer string `json:"explorer,omitempty"`
	Chain    string `json:"chain,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Report is the analysis artifact for one program.
type Report struct {
	Program   string     `json:"program"`
	Generated time.Time  `json:"generated"`
	Source    string     `json:"source"`
	Repos     []Repo     `json:"repos,omitempty"`
	Contracts []Contract `json:"contracts,omitempty"`
	Notes     []string   `json:"notes,omitempty"`
}

// Options controls the analysis pass.
type Options struct {
	Clone   bool
	Refresh bool
	Log     func(format string, args ...any)
}

var (
	slugRE     = regexp.MustCompile(`github\.com[:/]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?].*)?$`)
	orgRE      = regexp.MustCompile(`(?i)^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/?$`)
	addressRE  = regexp.MustCompile(`0x[0-9a-fA-F]{40}`)
	explorerRE = regexp.MustCompile(`https://([a-z0-9.-]*scan[a-z0-9.-]*)/address/`)
)

// githubAPI is a var so tests can point it at a local server.
var githubAPI = "https://api.github.com"

type ghRepo struct {
	FullName    string `json:"full_name"`
	HTMLURL     string `json:"html_url"`
	Archived    bool   `json:"archived"`
	Fork        bool   `json:"fork"`
	Description string `json:"description"`
	UpdatedAt   string `json:"updated_at"`
}

// listOrgRepos reads public repositories for a GitHub user or organisation.
// It deliberately uses a client without any session: the GitHub API never
// receives target cookies.
func listOrgRepos(ctx context.Context, org string) ([]ghRepo, string) {
	c := netx.New("kai-nonweb/0.9", 5, nil)
	defer c.Close()

	var out []ghRepo
	for page := 1; page <= 2; page++ {
		u := fmt.Sprintf("%s/users/%s/repos?per_page=100&page=%d&type=public&sort=updated",
			githubAPI, url.PathEscape(org), page)
		resp, err := c.Get(ctx, u, 4<<20)
		if err != nil {
			return out, "GitHub API error: " + err.Error()
		}
		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			return out, "GitHub API rate-limited — set GITHUB_TOKEN or try again later"
		}
		if resp.StatusCode != 200 {
			return out, fmt.Sprintf("GitHub API HTTP %d", resp.StatusCode)
		}
		var batch []ghRepo
		if err := json.Unmarshal(resp.Body, &batch); err != nil {
			return out, "GitHub API returned invalid JSON"
		}
		out = append(out, batch...)
		if len(batch) < 100 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt > out[j].UpdatedAt })
	return out, ""
}

// usableRepos drops archived and forked repos: most bounty policies exclude
// them unless a direct impact on the company's own assets is demonstrated.
func usableRepos(repos []ghRepo, max int) ([]ghRepo, int) {
	var out []ghRepo
	skipped := 0
	for _, r := range repos {
		if r.Archived || r.Fork {
			skipped++
			continue
		}
		out = append(out, r)
		if len(out) >= max {
			break
		}
	}
	return out, skipped
}

// Analyze reads Phase 0 intake and enriches non-web assets.
func Analyze(ctx context.Context, p *workspace.Program, opts Options) (Report, error) {
	rep := Report{Program: p.Name, Generated: time.Now().UTC(), Source: filepath.Join(p.Dir, "intake.json")}
	raw, err := os.ReadFile(rep.Source)
	if err != nil {
		return rep, fmt.Errorf("no intake for %s — run: kai intake <url> --name %s", p.Name, p.Name)
	}
	var in program.Intake
	if err := json.Unmarshal(raw, &in); err != nil {
		return rep, err
	}
	logf := func(format string, args ...any) {
		if opts.Log != nil {
			opts.Log(format, args...)
		}
	}

	// Source repositories: structured assets first, then prose candidates.
	var repoURLs []string
	seen := map[string]bool{}
	addRepo := func(url string) {
		if url == "" || seen[url] {
			return
		}
		seen[url] = true
		repoURLs = append(repoURLs, url)
	}
	for _, a := range in.Assets {
		if strings.Contains(strings.ToUpper(a.Type), "SOURCE") && a.Eligible {
			addRepo(a.Identifier)
		}
	}
	for _, c := range in.Candidates {
		if c.Type == "SOURCE_CODE" {
			addRepo(c.Identifier)
		}
	}
	if len(repoURLs) > 12 {
		repoURLs = repoURLs[:12]
	}
	for _, u := range repoURLs {
		if m := orgRE.FindStringSubmatch(strings.TrimSuffix(u, "/")); m != nil {
			org := m[1]
			found, note := listOrgRepos(ctx, org)
			if note != "" {
				rep.Notes = append(rep.Notes, note)
			}
			repos, skipped := usableRepos(found, 30)
			rep.Notes = append(rep.Notes, fmt.Sprintf("GitHub %s: %d public repos listed, %d eligible (archived/forks excluded)", org, len(found), len(repos)))
			if skipped > 0 {
				rep.Notes = append(rep.Notes, fmt.Sprintf("%d repo(s) skipped as archived or fork — check the policy before claiming impact", skipped))
			}
			if len(found) > 30 {
				rep.Notes = append(rep.Notes, "only the 30 most recently updated repos are tracked")
			}
			for _, r := range repos {
				url := r.HTMLURL
				if url == "" && r.FullName != "" {
					url = "https://github.com/" + r.FullName
				}
				rr := analyzeRepo(ctx, p, url, opts, logf)
				rr.Origin = "GitHub API: " + org
				rr.Description = r.Description
				rep.Repos = append(rep.Repos, rr)
			}
			continue
		}
		rep.Repos = append(rep.Repos, analyzeRepo(ctx, p, u, opts, logf))
	}

	// Contract addresses from structured scope and from prose.
	var addrs []string
	seenAddr := map[string]bool{}
	addAddr := func(a string) {
		if a == "" || seenAddr[a] {
			return
		}
		seenAddr[a] = true
		addrs = append(addrs, a)
	}
	for _, a := range in.Assets {
		if strings.Contains(strings.ToUpper(a.Type), "CONTRACT") && a.Eligible {
			addAddr(a.Identifier)
		}
	}
	for _, c := range in.Candidates {
		if c.Type == "CONTRACT" {
			addAddr(c.Identifier)
		}
	}
	for _, a := range addrs {
		explorer := ""
		if i := strings.Index(string(raw), a); i >= 0 {
			if m := explorerRE.FindStringSubmatch(string(raw)[max(0, i-120):i]); m != nil {
				explorer = m[1]
			}
		}
		chain := "unknown"
		if strings.Contains(explorer, "arbiscan") {
			chain = "arbitrum"
		} else if strings.Contains(explorer, "etherscan") {
			chain = "ethereum"
		}
		rep.Contracts = append(rep.Contracts, Contract{
			Address:  a,
			Explorer: explorer,
			Chain:    chain,
			Note:     "read verified source and past audits; use a local fork, never mainnet testing if the policy forbids it",
		})
	}
	if len(rep.Repos) == 0 && len(rep.Contracts) == 0 {
		rep.Notes = append(rep.Notes, "Phase 0 published no source repository or contract address — nothing to analyse here")
	}
	if !opts.Clone {
		rep.Notes = append(rep.Notes, "repositories were not cloned; run 'kai analyze <program> --clone' for workflow and manifest data")
	}
	return rep, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func analyzeRepo(ctx context.Context, p *workspace.Program, u string, opts Options, logf func(format string, args ...any)) Repo {
	r := Repo{URL: u, Status: "not-cloned"}
	m := slugRE.FindStringSubmatch(u)
	if m == nil {
		parts := strings.Split(strings.Trim(strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://"), "/"), "/")
		if len(parts) == 2 && parts[0] == "github.com" {
			r.Status = "org-url"
			r.Slug = parts[1]
			r.Error = "organisation URL — list its repositories before cloning"
			return r
		}
		r.Status = "unparsed"
		r.Error = "cannot extract owner/repo from URL"
		return r
	}
	r.Slug = m[1] + "-" + m[2]
	r.Path = filepath.Join(p.Dir, "repos", r.Slug)

	if opts.Clone {
		if _, err := os.Stat(filepath.Join(r.Path, ".git")); err == nil {
			if opts.Refresh {
				logf("  refresh %s", r.Slug)
				cmd := exec.CommandContext(ctx, "git", "-C", r.Path, "pull", "--ff-only", "--quiet")
				cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
				if err := cmd.Run(); err != nil {
					r.Error = "git pull: " + err.Error()
				}
			}
		} else {
			logf("  clone   %s", r.Slug)
			if err := os.MkdirAll(filepath.Dir(r.Path), 0o755); err != nil {
				r.Error = err.Error()
			} else {
				repoURL := "https://" + strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
				ctx2, cancel := context.WithTimeout(ctx, 180*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx2, "git", "clone", "--depth", "1", "--quiet", repoURL, r.Path)
				cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
				if err := cmd.Run(); err != nil {
					r.Error = "git clone: " + err.Error()
				}
			}
		}
	}

	if _, err := os.Stat(r.Path); err != nil {
		if r.Error == "" {
			r.Error = "not present locally"
		}
		return r
	}
	r.Status = "local"
	scanRepo(&r, logf)
	return r
}

var (
	prTargetRE   = regexp.MustCompile(`\bpull_request_target\b`)
	onRE         = regexp.MustCompile(`(?m)^\s*on:\s*(?:\[)?\s*([a-z_]+)`)
	eventRE      = regexp.MustCompile(`\$\{\{\s*github\.event\.`)
	secretsRE    = regexp.MustCompile(`\$\{\{\s*secrets\.`)
	selfHostedRE = regexp.MustCompile(`runs-on:\s*self-hosted`)
	writeAllRE   = regexp.MustCompile(`permissions:\s*write-all`)
	curlBashRE   = regexp.MustCompile(`(curl|wget)[^\n|]*\|\s*(ba)?sh`)
)

func scanRepo(r *Repo, logf func(format string, args ...any)) {
	workflowDir := filepath.Join(r.Path, ".github", "workflows")
	if entries, err := os.ReadDir(workflowDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := strings.ToLower(e.Name())
			if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(workflowDir, e.Name()))
			if err != nil {
				continue
			}
			w := Workflow{File: filepath.Join(".github/workflows", e.Name())}
			text := string(b)
			if len(text) > 200_000 {
				text = text[:200_000]
			}
			for _, m := range onRE.FindAllStringSubmatch(text, -1) {
				if m[1] != "" {
					w.Triggers = append(w.Triggers, m[1])
				}
			}
			if prTargetRE.MatchString(text) {
				w.Triggers = append(w.Triggers, "pull_request_target")
				w.Risks = append(w.Risks, "PR-triggered workflow runs with the base repository token")
			}
			if eventRE.MatchString(text) {
				w.Risks = append(w.Risks, "untrusted github.event data interpolated into the workflow")
			}
			if secretsRE.MatchString(text) && prTargetRE.MatchString(text) {
				w.Risks = append(w.Risks, "secrets referenced from a PR-triggered workflow")
			}
			if selfHostedRE.MatchString(text) {
				w.Risks = append(w.Risks, "self-hosted runner")
			}
			if writeAllRE.MatchString(text) {
				w.Risks = append(w.Risks, "write-all permissions")
			}
			if curlBashRE.MatchString(text) {
				w.Risks = append(w.Risks, "remote script piped into a shell")
			}
			w.Triggers = uniqueStrings(w.Triggers)
			w.Risks = uniqueStrings(w.Risks)
			r.Workflows = append(r.Workflows, w)
			r.Risks = append(r.Risks, w.Risks...)
		}
	}

	for _, name := range []string{
		"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
		"go.mod", "Cargo.toml", "pyproject.toml", "requirements.txt",
		"foundry.toml", "hardhat.config.js", "hardhat.config.ts",
		"Dockerfile", "Makefile", "SECURITY.md", ".github/CODEOWNERS",
	} {
		if _, err := os.Stat(filepath.Join(r.Path, name)); err == nil {
			r.Manifests = append(r.Manifests, name)
		}
	}
	for _, dir := range []string{"contracts", "src", "packages", "apps"} {
		if st, err := os.Stat(filepath.Join(r.Path, dir)); err == nil && st.IsDir() {
			r.EntryPoints = append(r.EntryPoints, dir+"/")
		}
	}
	if b, err := os.ReadFile(filepath.Join(r.Path, "package.json")); err == nil {
		var pj struct {
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal(b, &pj) == nil {
			for _, k := range []string{"preinstall", "install", "postinstall", "prepare"} {
				if v := pj.Scripts[k]; v != "" {
					r.Scripts = append(r.Scripts, k+": "+v)
				}
			}
			if len(r.Scripts) > 0 {
				r.Risks = append(r.Risks, "install-time scripts can execute during dependency installation")
			}
		}
	}
	sort.Strings(r.Manifests)
	sort.Strings(r.EntryPoints)
	r.Risks = uniqueStrings(r.Risks)
	logf("  scanned %s: %d workflow(s), %d manifest(s)", r.Slug, len(r.Workflows), len(r.Manifests))
}

// RiskScore converts CI findings into a bounded ranking boost (0–45).
// Routine "untrusted event" matches are common; PR-token and secret exposure
// are much stronger signals and should surface above generic IDOR candidates.
func RiskScore(risks []string) int {
	score := 0
	for _, r := range risks {
		low := strings.ToLower(r)
		switch {
		case strings.Contains(low, "base repository token"):
			score += 30
		case strings.Contains(low, "secrets referenced"):
			score += 25
		case strings.Contains(low, "remote script"):
			score += 15
		case strings.Contains(low, "install-time"):
			score += 10
		case strings.Contains(low, "untrusted"):
			score += 5
		}
	}
	if score > 45 {
		return 45
	}
	return score
}

// TopRisk returns the most severe finding for the probe hint.
func TopRisk(risks []string) string {
	order := []string{"base repository token", "secrets referenced", "remote script", "install-time", "untrusted"}
	for _, want := range order {
		for _, r := range risks {
			if strings.Contains(strings.ToLower(r), want) {
				return r
			}
		}
	}
	if len(risks) > 0 {
		return risks[0]
	}
	return ""
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// Save writes nonweb.json and nonweb.md into the program directory.
func Save(p *workspace.Program, rep Report) error {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(p.Dir, "nonweb.json"), b, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(p.Dir, "nonweb.md"), []byte(rep.Markdown()), 0o600)
}

// Load reads a previous analysis, if any.
func Load(p *workspace.Program) (*Report, error) {
	b, err := os.ReadFile(filepath.Join(p.Dir, "nonweb.json"))
	if err != nil {
		return nil, err
	}
	var rep Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

// Markdown renders the analysis.
func (rep Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Non-web surface — %s\n\n", rep.Program)
	fmt.Fprintf(&b, "Generated %s · source `%s`\n\n", rep.Generated.Format(time.RFC3339), rep.Source)

	if len(rep.Repos) == 0 && len(rep.Contracts) == 0 {
		b.WriteString("No source repository or contract address was published in Phase 0.\n\n")
	}
	for _, r := range rep.Repos {
		fmt.Fprintf(&b, "## Repo `%s` — %s\n\n", r.Slug, r.Status)
		fmt.Fprintf(&b, "URL: %s\n", r.URL)
		if r.Origin != "" {
			fmt.Fprintf(&b, "Origin: %s\n", r.Origin)
		}
		if r.Description != "" {
			fmt.Fprintf(&b, "About: %s\n", r.Description)
		}
		if r.Error != "" {
			fmt.Fprintf(&b, "Note: %s\n\n", r.Error)
		}
		if len(r.Risks) > 0 {
			b.WriteString("Risks found:\n\n")
			for _, x := range r.Risks {
				fmt.Fprintf(&b, "- %s\n", x)
			}
			b.WriteString("\n")
		}
		for _, w := range r.Workflows {
			fmt.Fprintf(&b, "- workflow `%s`: triggers `%s`; risks: %s\n", w.File,
				strings.Join(orDash(w.Triggers), ", "), strings.Join(orDash(w.Risks), "; "))
		}
		if len(r.Workflows) > 0 {
			b.WriteString("\n")
		}
		if len(r.Manifests) > 0 {
			fmt.Fprintf(&b, "Manifests: `%s`\n\n", strings.Join(r.Manifests, "`, `"))
		}
		if len(r.Scripts) > 0 {
			fmt.Fprintf(&b, "Install-time scripts: `%s`\n\n", strings.Join(r.Scripts, "`, `"))
		}
		if len(r.EntryPoints) > 0 {
			fmt.Fprintf(&b, "Entry points: `%s`\n\n", strings.Join(r.EntryPoints, "`, `"))
		}
	}
	if len(rep.Contracts) > 0 {
		b.WriteString("## Contracts\n\n| address | chain | explorer |\n| --- | --- | --- |\n")
		for _, c := range rep.Contracts {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", c.Address, c.Chain, orDash([]string{c.Explorer})[0])
		}
		b.WriteString("\nRead verified source and past audits before forming a hypothesis.\n\n")
	}
	if len(rep.Notes) > 0 {
		b.WriteString("## Notes\n\n")
		for _, n := range rep.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func orDash(v []string) []string {
	if len(v) == 0 {
		return []string{"—"}
	}
	return v
}
