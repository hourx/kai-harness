// Package surface turns raw endpoints into a structured map and a ranked test
// queue. It does not send a single request: it only reasons about what recon
// already collected.
package surface

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/strutil"
)

// NonWebAsset is an in-scope target that has no host-level scope rule: a repo,
// contract, app ID, API path or an AI/model surface.
type NonWebAsset struct {
	Identifier string `json:"identifier"`
	Type       string `json:"type"`
	Detail     string `json:"detail,omitempty"`
	Unverified bool   `json:"unverified,omitempty"`
	Boost      int    `json:"boost,omitempty"`
	Hint       string `json:"hint,omitempty"`
}

// Ref is a path segment that looks like an object reference.
type Ref struct {
	Endpoint string `json:"endpoint"`
	Segment  string `json:"segment"`
	Kind     string `json:"kind"`
}

// Stats summarizes the surface.
type Stats struct {
	Endpoints int `json:"endpoints"`
	Modules   int `json:"modules"`
	Refs      int `json:"refs"`
	IDParams  int `json:"id_params"`
	Loose     int `json:"loose_params"`
}

// Map is the structured view of a program's endpoints.
type Map struct {
	Program     string              `json:"program"`
	Generated   string              `json:"generated"`
	Modules     map[string][]string `json:"modules"`
	APIVersions []string            `json:"api_versions,omitempty"`
	GraphQL     []string            `json:"graphql,omitempty"`
	IDParams    map[string][]string `json:"id_params,omitempty"`
	Refs        []Ref               `json:"refs,omitempty"`
	// Loose are parameter names found in JavaScript with no path of their own.
	Loose  []string      `json:"loose_params,omitempty"`
	NonWeb []NonWebAsset `json:"non_web,omitempty"`
	Stats  Stats         `json:"stats"`
}

var (
	uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRE  = regexp.MustCompile(`^[0-9a-fA-F]{16,64}$`)
	numRE  = regexp.MustCompile(`^[0-9]+$`)
	verRE  = regexp.MustCompile(`^v[0-9]+$`)
)

var classRules = []struct {
	name  string
	words []string
}{
	{"auth", []string{"login", "logout", "signin", "signout", "oauth", "token", "sso", "session", "register", "signup", "password", "reset", "verify", "mfa", "otp", "2fa", "magic"}},
	{"admin", []string{"admin", "internal", "manage", "console", "staff", "superuser", "root"}},
	{"billing", []string{"billing", "payment", "invoice", "order", "checkout", "subscription", "plan", "wallet", "transfer", "payout", "refund", "coupon", "credit", "balance", "price"}},
	{"upload", []string{"upload", "attachment", "file", "import", "export", "media", "avatar", "document"}},
	{"graphql", []string{"graphql", "gql"}},
	{"account", []string{"user", "account", "profile", "member", "team", "tenant", "org", "invite", "role", "permission"}},
}

var idNames = map[string]bool{
	"id": true, "uid": true, "uuid": true, "guid": true, "ref": true,
	"tenant": true, "org": true, "team": true, "account": true, "user": true,
	"order": true, "invoice": true, "file": true, "project": true,
	"workspace": true, "customer": true, "member": true, "object": true,
}

// Build assembles the map from path -> params.
func Build(program string, endpoints map[string][]string, now time.Time) *Map {
	return BuildWithNonWeb(program, endpoints, nil, now)
}

// BuildWithNonWeb also records non-host targets from Phase 0 intake.
func BuildWithNonWeb(program string, endpoints map[string][]string, nonWeb []NonWebAsset, now time.Time) *Map {
	m := &Map{
		Program:   program,
		Generated: now.UTC().Format(time.RFC3339),
		Modules:   map[string][]string{},
		IDParams:  map[string][]string{},
	}
	versions := map[string]struct{}{}
	graphql := map[string]struct{}{}

	paths := make([]string, 0, len(endpoints))
	for p := range endpoints {
		if p != "*" {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)

	for _, path := range paths {
		params := endpoints[path]
		m.Modules[Module(path)] = append(m.Modules[Module(path)], path)
		for _, v := range apiVersions(path) {
			versions[v] = struct{}{}
		}
		if isGraphQL(path) {
			graphql[path] = struct{}{}
		}
		for _, p := range params {
			if IsIDParam(p) {
				m.IDParams[p] = append(m.IDParams[p], path)
			}
		}
		if ref, ok := ObjectRef(path); ok {
			m.Refs = append(m.Refs, ref)
		}
	}

	for k := range m.Modules {
		sort.Strings(m.Modules[k])
	}
	for k := range m.IDParams {
		sort.Strings(m.IDParams[k])
	}
	m.APIVersions = keys(versions)
	m.GraphQL = keys(graphql)
	m.Loose = UniqLoose(endpoints["*"])
	m.NonWeb = nonWeb
	sort.Slice(m.NonWeb, func(i, j int) bool {
		if m.NonWeb[i].Type != m.NonWeb[j].Type {
			return m.NonWeb[i].Type < m.NonWeb[j].Type
		}
		return m.NonWeb[i].Identifier < m.NonWeb[j].Identifier
	})
	sort.Slice(m.Refs, func(i, j int) bool {
		if m.Refs[i].Endpoint != m.Refs[j].Endpoint {
			return m.Refs[i].Endpoint < m.Refs[j].Endpoint
		}
		return m.Refs[i].Segment < m.Refs[j].Segment
	})
	m.Stats = Stats{
		Endpoints: len(paths),
		Modules:   len(m.Modules),
		Refs:      len(m.Refs),
		IDParams:  len(m.IDParams),
		Loose:     len(m.Loose),
	}
	return m
}

// UniqLoose returns the loose parameters without duplicates, sorted.
// UniqLoose merges the slices, drops blanks and duplicates, and sorts the
// result. The package-facing name is kept; the implementation lives in strutil
// so there is exactly one dedupe semantics in the tree.
func UniqLoose(in []string) []string { return strutil.UniqueSorted(in) }
func keys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func segments(path string) []string {
	raw := strings.Split(strings.Trim(path, "/"), "/")
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Module is the first meaningful path segment (skipping api, rest and vN).
//
// Segments that cannot be a path name are skipped rather than returned: a URL
// lifted out of a JavaScript bundle often contains the string concatenation that
// built it (`/" + "`), and a module called `" + "` would name an entity no
// operator can test.
func Module(path string) string {
	segs := segments(path)
	for _, s := range segs {
		low := strings.ToLower(s)
		if low == "api" || low == "rest" || verRE.MatchString(low) {
			continue
		}
		if !pathSegment(low) {
			continue
		}
		return low
	}
	// Nothing usable: reporting the root is honest, resurrecting "api" or "v1"
	// as a module would name an entity that does not exist.
	return "/"
}

// pathSegment reports whether a segment is a plausible path name: letters,
// digits and the punctuation a URL carries. Everything else is source code.
func pathSegment(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == '~' || r == '%' || r == '@' || r == '+':
		default:
			return false
		}
	}
	return true
}

// Class names the business area a path belongs to.
//
// Matching is per path segment and per hyphen/underscore token, not by
// substring: "profile" must not match the upload rule because it contains
// "file", and "user-guide" is documentation, not an account endpoint.
func Class(path string) string {
	tokens := pathTokens(path)
	for _, rule := range classRules {
		for _, w := range rule.words {
			if tokenMatch(tokens, w) {
				return rule.name
			}
		}
	}
	return "generic"
}

func pathTokens(path string) []string {
	var out []string
	for _, seg := range segments(path) {
		out = append(out, splitWord(seg)...)
	}
	return out
}

func splitWord(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
}

// tokenMatch accepts the exact word and its regular plural.
func tokenMatch(tokens []string, word string) bool {
	for _, t := range tokens {
		if t == word || t == word+"s" || t == word+"es" {
			return true
		}
	}
	return false
}

func isGraphQL(path string) bool {
	low := strings.ToLower(path)
	return strings.Contains(low, "graphql") || strings.Contains(low, "gql")
}

func apiVersions(path string) []string {
	var out []string
	segs := segments(path)
	for i, s := range segs {
		low := strings.ToLower(s)
		if !verRE.MatchString(low) {
			continue
		}
		if i > 0 && (strings.ToLower(segs[i-1]) == "api" || strings.ToLower(segs[i-1]) == "rest") {
			out = append(out, "/"+strings.ToLower(segs[i-1])+"/"+low)
			continue
		}
		out = append(out, "/"+low)
	}
	return out
}

// IsIDParam reports whether a query parameter names an object reference.
func IsIDParam(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if idNames[n] {
		return true
	}
	return strings.HasSuffix(n, "_id") || strings.HasSuffix(n, "-id")
}

// ObjectRef finds a path segment that is a numeric id, a UUID or a long hex id.
func ObjectRef(path string) (Ref, bool) {
	segs := segments(path)
	// "/412" alone is a number, not an object reference: there is no
	// resource to swap IDs on. Require a named segment as context.
	if len(segs) == 1 {
		return Ref{}, false
	}
	for _, s := range segs {
		low := strings.ToLower(s)
		switch {
		case numRE.MatchString(low) && len(low) >= 1:
			return Ref{Endpoint: path, Segment: s, Kind: "numeric"}, true
		case uuidRE.MatchString(low):
			return Ref{Endpoint: path, Segment: s, Kind: "uuid"}, true
		case hexRE.MatchString(low):
			return Ref{Endpoint: path, Segment: s, Kind: "hex"}, true
		case len(low) > 1 && low[0] == ':' && (low[1] >= 'a' && low[1] <= 'z' || low[1] == '{'):
			return Ref{Endpoint: path, Segment: s, Kind: "param"}, true
		case low == "{id}" || strings.HasPrefix(low, "${") && strings.HasSuffix(low, "}"):
			return Ref{Endpoint: path, Segment: s, Kind: "template"}, true
		}
	}
	return Ref{}, false
}

// Markdown renders the map for the agent.
func (m *Map) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Surface map — %s\n\n", m.Program)
	fmt.Fprintf(&b, "Generated %s · %d endpoints · %d modules · %d object refs · %d id params\n\n",
		m.Generated, m.Stats.Endpoints, m.Stats.Modules, m.Stats.Refs, m.Stats.IDParams)

	if len(m.APIVersions) > 0 {
		fmt.Fprintf(&b, "**API versions:** `%s`\n\n", strings.Join(m.APIVersions, "`, `"))
	}
	if len(m.GraphQL) > 0 {
		fmt.Fprintf(&b, "**GraphQL:** `%s`\n\n", strings.Join(m.GraphQL, "`, `"))
	}

	b.WriteString("## Modules\n\n")
	mods := make([]string, 0, len(m.Modules))
	for k := range m.Modules {
		mods = append(mods, k)
	}
	sort.Strings(mods)
	for _, mod := range mods {
		paths := m.Modules[mod]
		fmt.Fprintf(&b, "### %s (%d)\n\n", mod, len(paths))
		for _, p := range paths {
			fmt.Fprintf(&b, "- `%s`\n", p)
		}
		b.WriteString("\n")
	}

	if len(m.Refs) > 0 {
		b.WriteString("## Object references\n\n| endpoint | segment | kind |\n| --- | --- | --- |\n")
		for _, r := range m.Refs {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", r.Endpoint, r.Segment, r.Kind)
		}
		b.WriteString("\n")
	}
	if len(m.IDParams) > 0 {
		b.WriteString("## ID parameters\n\n| parameter | seen on |\n| --- | --- |\n")
		params := make([]string, 0, len(m.IDParams))
		for p := range m.IDParams {
			params = append(params, p)
		}
		sort.Strings(params)
		for _, p := range params {
			fmt.Fprintf(&b, "| `%s` | %s |\n", p, "`"+strings.Join(m.IDParams[p], "`, `")+"`")
		}
		b.WriteString("\n")
	}
	if len(m.NonWeb) > 0 {
		b.WriteString("## Non-web assets\n\n")
		for _, a := range m.NonWeb {
			mark := ""
			if a.Unverified {
				mark = " (candidate from prose — verify)"
			}
			fmt.Fprintf(&b, "- `%s` — %s%s\n", a.Identifier, a.Type, mark)
		}
		b.WriteString("\n")
	}
	if len(m.Loose) > 0 {
		b.WriteString("## Parameters seen only in JavaScript\n\n")
		b.WriteString("These names appear in a bundle but no collected URL uses them yet. ")
		b.WriteString("They are hints for reading the JavaScript that sends them.\n\n")
		fmt.Fprintf(&b, "`%s`\n\n", strings.Join(m.Loose, "`, `"))
	}
	return b.String()
}
