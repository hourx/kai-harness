// Package driver describes a bug-bounty platform as data.
//
// A driver is a manifest plus, when a platform needs something other than an
// HTML page read, one small Go parser named by the manifest. Adding a platform
// means adding a manifest directory; the core does not learn the platform's
// name anywhere else. The manifests are embedded, so a `go install`ed binary
// carries them and nothing is fetched at runtime.
//
// This is a registry seam, not a plugin loader: no dynamic loading, no external
// dependency, no manifest that can execute anything.
package driver

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
)

//go:embed drivers/*/manifest.json
var manifests embed.FS

// ManifestVersion is the schema version of the manifest format itself. A
// manifest with a version this build does not know is refused, not guessed at.
const ManifestVersion = 1

// Manifest is one platform, declared as data.
type Manifest struct {
	Version     int    `json:"version"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Homepage    string `json:"homepage,omitempty"`
	Description string `json:"description,omitempty"`

	// Parser names the intake reader for this platform. "generic" reads an
	// HTML policy page; another id means the core ships a small Go file for it.
	Parser string `json:"parser"`

	// IntakeURLs are glob patterns matched against the URL the operator passes
	// to `kai intake`. More specific patterns win over the fallback.
	IntakeURLs []string `json:"intake_urls"`

	// PolicyFetch describes where the policy comes from, for provenance.
	PolicyFetch PolicyFetch `json:"policy_fetch"`

	// ScopeExtraction describes how scope is read out of that policy.
	ScopeExtraction ScopeExtraction `json:"scope_extraction"`

	// MandatoryConditions are non-negotiable program requirements that announce
	// themselves outside the field set (a reporting identity, a required
	// header). They are recorded in the contract; kai does not enforce them.
	MandatoryConditions []Condition `json:"mandatory_conditions,omitempty"`

	// ReportFieldSet is the platform's own submission vocabulary, in order.
	ReportFieldSet []string `json:"report_field_set"`

	// RewardFields are the fields the platform publishes money in.
	RewardFields []string `json:"reward_fields,omitempty"`

	// RequiresAuth is true when the policy is only visible after login. The
	// generic reader records the wall instead of pretending it read the policy.
	RequiresAuth bool `json:"requires_auth"`

	// SubmitChannel and SubmitURL describe where a report goes. kai drafts, it
	// never submits.
	SubmitChannel string `json:"submit_channel,omitempty"`
	SubmitURL     string `json:"submit_url,omitempty"`
}

// PolicyFetch says where a platform's policy text comes from.
type PolicyFetch struct {
	// Kind is one of: graphql, html, securitytxt.
	Kind     string `json:"kind"`
	Endpoint string `json:"endpoint,omitempty"`
	Path     string `json:"path,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// ScopeExtraction says how scope is read out of the policy.
type ScopeExtraction struct {
	// Kind is one of: structured (machine-readable assets) or html (headings).
	Kind string `json:"kind"`
	// InHeadings / OutHeadings are the section titles an HTML page uses. A
	// heading match is a candidate, never a verdict — policy text still wins.
	InHeadings  []string `json:"in_headings,omitempty"`
	OutHeadings []string `json:"out_headings,omitempty"`
	// Notes is provenance: which field or section the structured reader uses.
	Notes string `json:"notes,omitempty"`
}

// Condition is a program requirement that is not a scope rule.
type Condition struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// registry is the loaded set of manifests, keyed by id.
var registry = map[string]Manifest{}

func init() {
	entries, err := manifests.ReadDir("drivers")
	if err != nil {
		panic("driver: embedded manifests missing: " + err.Error())
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := manifests.ReadFile("drivers/" + e.Name() + "/manifest.json")
		if err != nil {
			panic("driver: " + e.Name() + ": " + err.Error())
		}
		var m Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			panic("driver: " + e.Name() + ": invalid manifest: " + err.Error())
		}
		if err := m.Validate(); err != nil {
			panic("driver: " + e.Name() + ": " + err.Error())
		}
		if _, dup := registry[m.ID]; dup {
			panic("driver: duplicate manifest id " + m.ID)
		}
		registry[m.ID] = m
	}
}

// All returns every manifest, ordered by id. The order is stable so listings
// and tests do not depend on map iteration.
func All() []Manifest {
	out := make([]Manifest, 0, len(registry))
	for _, m := range registry {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns one manifest by id.
func Get(id string) (Manifest, bool) {
	m, ok := registry[id]
	return m, ok
}

// Match returns the manifest that claims this URL, and the pattern that claimed
// it. The most specific pattern wins; a pattern host match beats a wildcard
// host, and a longer host beats a shorter one, so `app.example.com` cannot be
// swallowed by a `com`-shaped rule.
func Match(raw string) (Manifest, string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return Manifest{}, "", false
	}
	host := strings.ToLower(u.Hostname())
	reqPath := u.EscapedPath()
	if reqPath == "" {
		reqPath = "/"
	}

	type hit struct {
		m     Manifest
		pat   string
		score int
	}
	var best hit
	best.score = -1 // a wildcard pattern scores 0, so "no hit yet" must be lower
	for _, m := range All() {
		for _, pat := range m.IntakeURLs {
			hostPat, pathPat, ok := splitPattern(pat)
			if !ok || !hostMatches(hostPat, host) {
				continue
			}
			if !pathMatches(pathPat, reqPath) {
				continue
			}
			score := hostScore(hostPat)
			if score > best.score {
				best = hit{m: m, pat: pat, score: score}
			}
		}
	}
	if best.m.ID == "" {
		return Manifest{}, "", false
	}
	return best.m, best.pat, true
}

// splitPattern splits "host/path" into its two halves. A bare host gets "/*".
func splitPattern(pat string) (host, pathPat string, ok bool) {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return "", "", false
	}
	if i := strings.Index(pat, "/"); i >= 0 {
		host, pathPat = pat[:i], pat[i:]
	} else {
		host, pathPat = pat, "/*"
	}
	if host == "" {
		return "", "", false
	}
	if pathPat == "" || pathPat == "/" {
		pathPat = "/*"
	}
	return strings.ToLower(host), pathPat, true
}

// hostMatches understands an exact host and the "*.suffix" form. A wildcard
// covers subdomains only; the apex is a separate rule, as in scope files.
func hostMatches(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
	}
	return pattern == host
}

// hostScore ranks pattern specificity: a literal host beats a wildcard, and a
// longer literal beats a shorter one.
func hostScore(pattern string) int {
	if pattern == "*" {
		return 0
	}
	if strings.HasPrefix(pattern, "*.") {
		return 100 + len(pattern)
	}
	return 1000 + len(pattern)
}

func pathMatches(pattern, reqPath string) bool {
	if pattern == "" || pattern == "*" || pattern == "/*" {
		return true
	}
	if ok, err := path.Match(pattern, reqPath); err == nil && ok {
		return true
	}
	// A trailing /* also claims the bare directory: /bugs/* matches /bugs.
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if prefix == "" {
			return true
		}
		return reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/")
	}
	return false
}

// Validate reports a manifest that would misbehave at runtime.
func (m Manifest) Validate() error {
	switch {
	case m.ID == "":
		return fmt.Errorf("manifest has no id")
	case m.Name == "":
		return fmt.Errorf("manifest %s has no name", m.ID)
	case m.Version == 0:
		return fmt.Errorf("manifest %s has no version", m.ID)
	case m.Version > ManifestVersion:
		return fmt.Errorf("manifest %s is version %d, this build understands %d", m.ID, m.Version, ManifestVersion)
	case m.Parser == "":
		return fmt.Errorf("manifest %s names no parser", m.ID)
	case len(m.IntakeURLs) == 0:
		return fmt.Errorf("manifest %s matches no intake URL", m.ID)
	case len(m.ReportFieldSet) == 0:
		return fmt.Errorf("manifest %s has no report field set", m.ID)
	}
	switch m.PolicyFetch.Kind {
	case "graphql", "html", "securitytxt":
	default:
		return fmt.Errorf("manifest %s: unknown policy_fetch kind %q", m.ID, m.PolicyFetch.Kind)
	}
	switch m.ScopeExtraction.Kind {
	case "structured", "html":
	default:
		return fmt.Errorf("manifest %s: unknown scope_extraction kind %q", m.ID, m.ScopeExtraction.Kind)
	}
	for _, pat := range m.IntakeURLs {
		if _, _, ok := splitPattern(pat); !ok {
			return fmt.Errorf("manifest %s: unusable intake pattern %q", m.ID, pat)
		}
	}
	return nil
}
