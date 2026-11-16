// Package audit verifies that a handoff ZIP is internally consistent before
// it is given to the agent. It performs no network access and changes nothing.
package audit

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Check is one assertion about the pack.
type Check struct {
	Name   string
	OK     bool
	Detail string
}

// Result is the full set of assertions.
type Result struct {
	Name   string
	Source string
	Checks []Check
}

// Failed returns the number of failed checks.
func (r Result) Failed() int {
	n := 0
	for _, c := range r.Checks {
		if !c.OK {
			n++
		}
	}
	return n
}

// Text renders a compact report.
func (r Result) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Audit — %s\n\nSource: %s\n\n", r.Name, r.Source)
	for _, c := range r.Checks {
		status := "PASS"
		if !c.OK {
			status = "FAIL"
		}
		fmt.Fprintf(&b, "%-4s %s", status, c.Name)
		if !c.OK && c.Detail != "" {
			fmt.Fprintf(&b, "  -> %s", c.Detail)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "\nTOTAL: %d/%d passed\n", len(r.Checks)-r.Failed(), len(r.Checks))
	return b.String()
}

// RunZip audits a handoff archive.
func RunZip(path string) (Result, error) {
	tmp, err := os.MkdirTemp("", "kai-audit-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(tmp)
	if err := extractZip(path, tmp); err != nil {
		return Result{}, err
	}
	root, err := findRoot(tmp)
	if err != nil {
		return Result{}, err
	}
	res := runDir(root, filepath.Base(root), path)
	return res, nil
}

func extractZip(path, dest string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		name := filepath.Clean(f.Name)
		if name == "." || strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return fmt.Errorf("unsafe path in archive: %s", f.Name)
		}
		target := filepath.Join(dest, name)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

func findRoot(dir string) (string, error) {
	var found []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && info.Name() == "BRIEF.md" {
			found = append(found, filepath.Dir(path))
		}
		return nil
	})
	if len(found) == 0 {
		return "", fmt.Errorf("no BRIEF.md found in archive — not a kai handoff ZIP")
	}
	sort.Strings(found)
	return found[0], nil
}

func runDir(root, name, source string) Result {
	r := Result{Name: name, Source: source}
	rd := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			return ""
		}
		return string(b)
	}
	lines := func(p string) []string {
		var out []string
		for _, l := range strings.Split(rd(p), "\n") {
			if s := strings.TrimSpace(l); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	add := func(n string, ok bool, detail string) {
		r.Checks = append(r.Checks, Check{Name: n, OK: ok, Detail: detail})
	}

	// Manifest integrity.
	var manifest struct {
		Program string `json:"program"`
		Tool    string `json:"tool"`
		Files   []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	mb := rd("bountykit/MANIFEST.json")
	if mb == "" || json.Unmarshal([]byte(mb), &manifest) != nil {
		add("MANIFEST present and parseable", false, "")
	} else {
		bad := []string{}
		for _, f := range manifest.Files {
			b, err := os.ReadFile(filepath.Join(root, f.Path))
			if err != nil {
				bad = append(bad, "missing:"+f.Path)
				continue
			}
			sum := sha256.Sum256(b)
			if hex.EncodeToString(sum[:]) != f.SHA256 {
				bad = append(bad, "hash:"+f.Path)
			}
		}
		add(fmt.Sprintf("MANIFEST hashes (%d files)", len(manifest.Files)), len(bad) == 0, strings.Join(bad, ", "))
	}

	brief := rd("BRIEF.md")
	programDoc := rd("program.md")
	ledger := rd("LEDGER.md")
	boundsDoc := rd("boundaries.md")
	nextMD := rd("bountykit/next.md")
	diffMD := rd("bountykit/diff.md")
	intakeJSON := rd("bountykit/intake.json")
	nextJSON := rd("bountykit/next.json")
	mapJSON := rd("bountykit/map.json")

	add("version consistent in BRIEF/LEDGER/MANIFEST",
		manifest.Tool != "" && strings.Contains(brief, manifest.Tool) && strings.Contains(ledger, manifest.Tool),
		manifest.Tool)

	var in struct {
		Name      string `json:"name"`
		Scorecard struct {
			Verdict  string `json:"verdict"`
			Total    int    `json:"total"`
			Money    int    `json:"money"`
			Crowding int    `json:"crowding"`
			Speed    int    `json:"speed"`
			Surface  int    `json:"surface"`
		} `json:"scorecard"`
		Boundaries struct {
			MainnetTesting    string   `json:"mainnet_testing"`
			SubmissionChannel string   `json:"submission_channel"`
			SubmissionContact []string `json:"submission_contact"`
			RequiredHeaders   []string `json:"required_headers"`
		} `json:"boundaries"`
	}
	if intakeJSON == "" || json.Unmarshal([]byte(intakeJSON), &in) != nil {
		add("intake.json parseable", false, "")
	} else {
		add("intake.json parseable", true, "")
		headline := fmt.Sprintf("**%s — %s, %d/100.**", in.Name, in.Scorecard.Verdict, in.Scorecard.Total)
		add("score headline in BRIEF", strings.Contains(brief, headline), headline)
		add("score verdict in program.md",
			strings.Contains(programDoc, fmt.Sprintf("**Verdict: %s — %d/100**", in.Scorecard.Verdict, in.Scorecard.Total)), "")
		allComponents := true
		for _, v := range []int{in.Scorecard.Money, in.Scorecard.Crowding, in.Scorecard.Speed, in.Scorecard.Surface} {
			if !strings.Contains(brief, fmt.Sprintf("%d/", v)) {
				allComponents = false
			}
		}
		add("component scores in BRIEF", allComponents, "")
	}

	b := in.Boundaries
	if b.MainnetTesting != "" {
		add("mainnet boundary in BRIEF/boundaries", strings.Contains(brief, b.MainnetTesting) && strings.Contains(boundsDoc, b.MainnetTesting), b.MainnetTesting)
	} else {
		add("mainnet boundary present", false, "missing from intake.json")
	}
	if b.SubmissionChannel != "" {
		add("submission channel in BRIEF/boundaries",
			strings.Contains(strings.ToLower(brief), "submit via: **"+b.SubmissionChannel+"**") && strings.Contains(boundsDoc, b.SubmissionChannel),
			b.SubmissionChannel)
	}
	if len(b.SubmissionContact) > 0 {
		okBrief := strings.Contains(strings.ToLower(brief), "published contacts")
		okBounds := strings.Contains(boundsDoc, "Published contacts")
		add("contacts labelled as contacts, not report channel", okBrief && okBounds, "")
	}
	headersOK := len(b.RequiredHeaders) > 0
	for _, h := range b.RequiredHeaders {
		if !strings.Contains(brief, h) || !strings.Contains(boundsDoc, h) {
			headersOK = false
		}
	}
	if len(b.RequiredHeaders) > 0 {
		add("required headers mirrored", headersOK, strings.Join(b.RequiredHeaders, ", "))
	}

	scope := []string{}
	for _, l := range lines("scope.txt") {
		if !strings.HasPrefix(l, "#") {
			scope = append(scope, l)
		}
	}
	scopeOK := len(scope) > 0
	for _, s := range scope {
		if !strings.Contains(brief, s) || !strings.Contains(boundsDoc, "IN `"+s+"`") {
			scopeOK = false
		}
	}
	add(fmt.Sprintf("scope rules mirrored (%d)", len(scope)), scopeOK, strings.Join(scope, ","))

	add("session usage stated honestly",
		strings.Contains(brief, "authenticated context") || strings.Contains(brief, "Session | none") || strings.Contains(brief, "Session | stored"),
		"")
	add("no session.json in archive", func() bool {
		_, err := os.Stat(filepath.Join(root, "bountykit/session.json"))
		return os.IsNotExist(err)
	}(), "")

	var plan struct {
		Items []struct {
			Target string `json:"target"`
		} `json:"items"`
	}
	if nextJSON == "" || json.Unmarshal([]byte(nextJSON), &plan) != nil {
		add("next.json parseable", false, "")
	} else {
		add("next.json parseable", true, "")
		limit := 12
		if len(plan.Items) < limit {
			limit = len(plan.Items)
		}
		missing := []string{}
		for _, it := range plan.Items[:limit] {
			if !strings.Contains(brief, it.Target) {
				missing = append(missing, it.Target)
			}
		}
		add("BRIEF ranked table == next.json top 12", len(missing) == 0, strings.Join(missing, ", "))
		if limit > 10 {
			limit = 10
		}
		for _, it := range plan.Items[:limit] {
			if !strings.Contains(nextMD, it.Target) {
				missing = append(missing, it.Target)
			}
		}
		add("next.md top 10 == next.json", len(missing) == 0, strings.Join(missing, ", "))
	}

	var mp struct {
		Stats struct {
			Endpoints int `json:"endpoints"`
		} `json:"stats"`
		Modules map[string][]string `json:"modules"`
		NonWeb  []struct {
			Identifier string `json:"identifier"`
		} `json:"non_web"`
	}
	if mapJSON == "" || json.Unmarshal([]byte(mapJSON), &mp) != nil {
		add("map.json parseable", false, "")
	} else {
		paths := map[string]bool{}
		for _, list := range mp.Modules {
			for _, p := range list {
				paths[p] = true
			}
		}
		add("map stats == module paths", mp.Stats.Endpoints == len(paths), fmt.Sprintf("%d vs %d", mp.Stats.Endpoints, len(paths)))
		eps := map[string]bool{}
		for _, l := range lines("recon/endpoints.txt") {
			eps[strings.SplitN(l, " ?", 2)[0]] = true
		}
		same := len(eps) == len(paths)
		for p := range paths {
			if !eps[p] {
				same = false
			}
		}
		add("endpoints.txt == map.json", same, fmt.Sprintf("txt=%d map=%d", len(eps), len(paths)))
		valid := map[string]bool{}
		for p := range paths {
			valid[p] = true
		}
		for _, a := range mp.NonWeb {
			valid[a.Identifier] = true
		}
		orphan := []string{}
		for _, it := range plan.Items {
			t := strings.TrimPrefix(it.Target, "GET ")
			if !valid[t] {
				orphan = append(orphan, t)
			}
		}
		add("every next target is backed by map/endpoints", len(orphan) == 0, strings.Join(orphan[:min(3, len(orphan))], ", "))
	}

	for _, name := range []string{"subs.txt", "live.txt", "urls.txt", "js.ts", "endpoints.txt", "nuclei.txt", "ranked.txt", "smuggling.txt"} {
		b, err := os.ReadFile(filepath.Join(root, "recon", name))
		n := 0
		if err == nil && len(b) > 0 {
			n = len(strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"))
		}
		add(fmt.Sprintf("BRIEF count recon/%s", name), strings.Contains(brief, fmt.Sprintf("`recon/%s` | %d |", name, n)), fmt.Sprint(n))
	}

	if diffMD != "" {
		i := strings.Index(brief, "## Surface diff")
		j := strings.Index(brief, "## Layout mapping")
		section := ""
		if i >= 0 && j > i {
			section = brief[i:j]
		}
		key := "No new surface since the previous run"
		if !strings.Contains(diffMD, key) {
			lines := strings.Split(diffMD, "\n")
			for _, l := range lines {
				if strings.HasPrefix(l, "## ") && strings.Contains(l, "(") {
					key = strings.TrimPrefix(l, "## ")
					break
				}
			}
		}
		add("diff section matches diff.md", strings.Contains(section, key), key)
	}
	_, statErr := os.Stat(filepath.Join(root, "bountykit/rules-diff.md"))
	add("rules-diff.md present", statErr == nil, "")
	add("no false mainnet claim", !strings.Contains(strings.ToLower(brief), "mainnet testing is forbidden") || strings.Contains(strings.ToLower(brief), "forbidden"), "")
	return r
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
