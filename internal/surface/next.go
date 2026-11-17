package surface

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai/internal/recon"
)

// Hypothesis is one ranked thing to test, with the evidence that put it there.
// Tags let a subagent retrieve by concern instead of loading all 150 items.
// Cluster groups endpoints with the same object root so the same surface is
// not tested twice under different variable names.
type Hypothesis struct {
	Target   string   `json:"target"`
	Class    string   `json:"class"`
	Score    int      `json:"score"`
	Why      []string `json:"why"`
	Probe    string   `json:"probe"`
	Tags     []string `json:"tags,omitempty"`
	Cluster  string   `json:"cluster,omitempty"`
	Variants []string `json:"variants,omitempty"`
}

// Cluster is one object root shared by several hypotheses.
type Cluster struct {
	Key     string   `json:"key"`
	Targets []string `json:"targets"`
	Count   int      `json:"count"`
}

// Plan is the ordered test queue for a program.
type Plan struct {
	Program   string       `json:"program"`
	Generated string       `json:"generated"`
	Items     []Hypothesis `json:"items"`
	Clusters  []Cluster    `json:"clusters,omitempty"`
}

var probes = map[string]string{
	"IDOR/BOLA":            "Create two accounts. Fetch the object as A, then as B with the same id. A 200 containing B's data is the bug.",
	"auth-bypass/ATO":      "Walk login → MFA → reset. Skip each step by requesting the next URL directly with the session you already have.",
	"privilege-escalation": "Use the lowest-privilege token against this route before trying an admin token.",
	"business-logic":       "Submit twice concurrently; try negative, zero and decimal quantities; stack two coupons.",
	"file-upload/SSRF":     "Upload an SVG containing a script; try a double extension and a mismatched Content-Type.",
	"graphql":              "Send introspection, then batch the same query with two different identities.",
	"access-control":       "Send it with no cookie, then with a low-privilege cookie. Try `/`, `//`, `/./`, `%2e` and `x..;/` path variants.",
	"surface-review":       "Fingerprint the host, pick one flow, then read the JavaScript that drives it.",
	"supply-chain":         "Read the CI workflows and publish tokens. Look for pull_request_target, dependency confusion, unsigned artifacts and leaked package credentials.",
	"smart-contract":       "Read verified source and past audits; build a Foundry fork PoC. Never test against live mainnet if the policy forbids it.",
	"api-surface":          "Map each endpoint's auth and object references; compare responses with and without a session, then across two identities.",
	"agentic-ai":           "Trace the trust boundary: tool output → model → action. Prove an injected instruction reaches a real side effect on another user or the control plane.",
	"mobile-app":           "Inspect the app's API calls and local storage; check whether client-side controls are re-enforced on the server.",
	"infra-or-other":       "Read the policy's impact examples for this asset class, then pick the one with the most concrete payout path.",
}

var classLabel = map[string]string{
	"auth":    "auth-bypass/ATO",
	"admin":   "privilege-escalation",
	"billing": "business-logic",
	"upload":  "file-upload/SSRF",
	"graphql": "graphql",
	"account": "access-control",
	"generic": "surface-review",
}

// BuildPlan ranks endpoints and hosts into an ordered queue.
func BuildPlan(program string, m *Map, endpoints map[string][]string, d *recon.Diff, hosts map[string]*recon.HostRecord, now time.Time) *Plan {
	p := &Plan{Program: program, Generated: now.UTC().Format(time.RFC3339)}

	newEndpoint := map[string]bool{}
	newHost := map[string]bool{}
	if d != nil {
		for _, e := range d.NewEndpoints {
			newEndpoint[e] = true
		}
		for _, h := range d.NewHosts {
			newHost[h.Host] = true
		}
	}

	seen := map[string]bool{}
	add := func(h Hypothesis) {
		if h.Target == "" || seen[h.Target+"|"+h.Class] {
			return
		}
		seen[h.Target+"|"+h.Class] = true
		if len(h.Tags) == 0 {
			h.Tags = tagsFor(h.Class, h.Target)
		}
		if h.Cluster == "" {
			h.Cluster = clusterKey(h.Target)
		}
		p.Items = append(p.Items, h)
	}

	paths := make([]string, 0, len(endpoints))
	for path := range endpoints {
		if path != "*" {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)

	for _, path := range paths {
		params := endpoints[path]
		score := 0
		var why []string

		hasRef := false
		if _, ok := ObjectRef(path); ok {
			hasRef = true
			why = append(why, "path holds an object reference")
		}
		var idParam string
		for _, name := range params {
			if IsIDParam(name) {
				idParam = name
				break
			}
		}
		if idParam != "" {
			hasRef = true
			why = append(why, "parameter `"+idParam+"` is an object reference")
		}

		baseClass := Class(path)
		class := classLabel[baseClass]
		if hasRef {
			class = "IDOR/BOLA"
		}
		score += classScore(class)
		if hasRef {
			// The reference itself is the strongest single signal: it is the
			// object another account might be able to fetch.
			score += 50
		}
		bonus, sensitive := sensitivity(path)
		score += bonus
		why = append(why, sensitive...)
		if newEndpoint[path] {
			score += 100
			why = append(why, "endpoint is new since the last run")
		}
		if len(params) > 0 {
			score += 15
			why = append(why, fmt.Sprintf("%d parameter(s)", len(params)))
		}
		if class == "surface-review" && score < 30 {
			continue
		}
		add(Hypothesis{
			Target: "GET " + path,
			Class:  class,
			Score:  score,
			Why:    why,
			Probe:  probes[class],
		})
	}

	// Parameters seen only in JavaScript. Weak on their own, but they tell the
	// agent which request to look for in the bundle.
	for _, name := range m.Loose {
		class := "surface-review"
		score := 30
		if looseRisky(name) {
			class = "business-logic"
			score = 55
		}
		add(Hypothesis{
			Target: "parameter " + name,
			Class:  class,
			Score:  score,
			Why:    []string{"appears in a JavaScript bundle but no collected URL uses it"},
			Probe:  probes[class],
		})
	}

	for host, h := range hosts {
		switch {
		case h.Status == 401 || h.Status == 403:
			why := []string{fmt.Sprintf("responds %d without a session", h.Status)}
			score := 45
			for _, w := range hostWordMatches(host) {
				score += 10
				why = append(why, "host name contains `"+w+"`")
			}
			add(Hypothesis{Target: host, Class: "access-control", Score: score, Why: why, Probe: probes["access-control"]})
		case newHost[host]:
			add(Hypothesis{
				Target: host,
				Class:  "surface-review",
				Score:  80,
				Why:    []string{"host is new since the last run", fmt.Sprintf("status %d", h.Status)},
				Probe:  probes["surface-review"],
			})
		}
	}

	sort.Slice(p.Items, func(i, j int) bool {
		if p.Items[i].Score != p.Items[j].Score {
			return p.Items[i].Score > p.Items[j].Score
		}
		return p.Items[i].Target < p.Items[j].Target
	})
	if len(p.Items) > 150 {
		p.Items = p.Items[:150]
	}

	// Cluster endpoints that share an object root. This is a derived view:
	// `items` keeps its old shape and order, so existing consumers do not
	// change; agents may read clusters first and avoid re-testing variants.
	groups := map[string][]string{}
	for _, it := range p.Items {
		if it.Cluster != "" {
			groups[it.Cluster] = append(groups[it.Cluster], it.Target)
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		if len(groups[k]) > 1 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		p.Clusters = append(p.Clusters, Cluster{Key: k, Targets: groups[k], Count: len(groups[k])})
		for i := range p.Items {
			if p.Items[i].Cluster != k {
				continue
			}
			for _, other := range groups[k] {
				if other != p.Items[i].Target {
					p.Items[i].Variants = append(p.Items[i].Variants, other)
				}
			}
		}
	}
	return p
}

// tagsFor is a small retrieval index: api/auth-required/idor/priority-high.
// It is computed from fields kai already knows — no guess about impact.
func tagsFor(class, target string) []string {
	low := strings.ToLower(target)
	out := []string{}
	if strings.Contains(low, "/api/") || strings.Contains(low, "api.") {
		out = append(out, "api")
	}
	switch class {
	case "IDOR/BOLA", "access-control":
		out = append(out, "idor")
	case "auth-bypass/ATO", "privilege-escalation":
		out = append(out, "auth", "auth-required")
	case "business-logic":
		out = append(out, "logic")
	case "file-upload/SSRF", "supply-chain", "smart-contract":
		out = append(out, "infra")
	}
	if strings.Contains(low, "token") || strings.Contains(low, "oauth") ||
		strings.Contains(low, "session") || strings.Contains(low, "login") {
		out = append(out, "auth-required")
	}
	return uniqTags(out)
}

func uniqTags(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// clusterKey normalises an endpoint into its object root so ten endpoints
// under /api/organizations/{id}/... become one cluster, not ten hypotheses.
func clusterKey(target string) string {
	path := strings.TrimSpace(target)
	if i := strings.IndexAny(path, " \t"); i > 0 {
		path = strings.TrimSpace(path[i:])
	}
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 4 {
		parts = parts[:4]
	}
	for i, p := range parts {
		if p == "" {
			continue
		}
		if numRE.MatchString(p) || uuidRE.MatchString(p) || hexRE.MatchString(p) || idNames[strings.ToLower(p)] {
			parts[i] = "{id}"
		}
	}
	return "/" + strings.Join(parts, "/")
}

// hostWordMatches returns the risky words present in the subdomain part of a
// host. It deliberately ignores the last two labels so that a domain like
// acme.test does not match "test" on every single host.
func hostWordMatches(host string) []string {
	labels := strings.Split(strings.ToLower(host), ".")
	if len(labels) > 2 {
		labels = labels[:len(labels)-2]
	} else if len(labels) > 0 {
		labels = labels[:1]
	}
	var tokens []string
	for _, l := range labels {
		tokens = append(tokens, splitWord(l)...)
	}
	var out []string
	for _, w := range []string{"admin", "internal", "manage", "dev", "staging", "stage", "test", "beta", "old", "api", "console", "portal", "dashboard", "debug"} {
		if tokenMatch(tokens, w) {
			out = append(out, w)
		}
	}
	return out
}

// sensitivity rewards paths where an IDOR would actually pay: key material,
// recovery, exports, balances and transfers outrank a generic app lookup.
// Without this, every "{id}" route ties at the same score and the queue stops
// being a priority list.
func sensitivity(path string) (int, []string) {
	low := strings.ToLower(path)
	rules := []struct {
		word  string
		bonus int
	}{
		{"key_material", 30}, {"recovery", 25}, {"secret", 25}, {"credential", 25},
		{"export", 20}, {"admin", 20}, {"withdraw", 20},
		{"token", 15}, {"transfer", 15}, {"balance", 15}, {"payment", 15}, {"rpc", 15},
		{"invoice", 10}, {"session", 10}, {"auth", 10}, {"mfa", 10},
	}
	total := 0
	var why []string
	for _, r := range rules {
		if strings.Contains(low, r.word) {
			total += r.bonus
			why = append(why, "sensitive path includes `"+r.word+"`")
		}
	}
	return total, why
}

// classScore ranks the business area a hypothesis belongs to.
func classScore(class string) int {
	switch class {
	case "IDOR/BOLA":
		return 50
	case "business-logic":
		return 60
	case "auth-bypass/ATO":
		return 60
	case "privilege-escalation":
		return 55
	case "file-upload/SSRF":
		return 45
	case "graphql":
		return 40
	case "access-control":
		return 35
	default:
		return 10
	}
}

// looseRisky reports whether an orphan parameter name tends to move money,
// ownership or privilege when the server trusts it.
func looseRisky(name string) bool {
	risky := []string{"amount", "price", "total", "quantity", "qty", "coupon", "discount", "credit", "balance", "role", "plan", "admin", "owner", "tenant", "is_admin", "verified"}
	n := strings.ToLower(strings.TrimSpace(name))
	for _, w := range risky {
		if n == w || strings.HasPrefix(n, w+"_") || strings.HasSuffix(n, "_"+w) {
			return true
		}
	}
	return false
}

// AddNonWeb appends Phase 0 non-host targets to the ranked queue. It never
// touches a target: it only turns published scope into a test hypothesis.
func AddNonWeb(p *Plan, assets []NonWebAsset, constraints []string) {
	for _, a := range assets {
		class, score := nonWebClass(a)
		score += a.Boost
		why := []string{"in-scope " + strings.ToLower(a.Type) + " asset from Phase 0 intake"}
		if a.Detail != "" {
			why = append(why, a.Detail)
		}
		if a.Unverified && a.Type != "SYSTEM" {
			score -= 30
			why = append(why, "candidate from page text — verify against the policy first")
		}
		if a.Type == "SYSTEM" {
			why = append(why, "named system from impact-based scope — not a host rule")
		}
		probe := probes[class]
		if a.Hint != "" {
			probe = a.Hint + " " + probe
		}
		for _, c := range constraints {
			low := strings.ToLower(c)
			if strings.Contains(low, "mainnet") && strings.Contains(low, "do not") {
				probe = "Use testnet or a local fork only — mainnet testing is forbidden. " + probe
				break
			}
		}
		p.Items = append(p.Items, Hypothesis{
			Target: a.Identifier,
			Class:  class,
			Score:  score,
			Why:    why,
			Probe:  probe,
		})
	}
	sort.Slice(p.Items, func(i, j int) bool {
		if p.Items[i].Score != p.Items[j].Score {
			return p.Items[i].Score > p.Items[j].Score
		}
		return p.Items[i].Target < p.Items[j].Target
	})
	if len(p.Items) > 150 {
		p.Items = p.Items[:150]
	}
}

func nonWebClass(a NonWebAsset) (string, int) {
	t := strings.ToUpper(a.Type)
	id := strings.ToLower(a.Identifier)
	switch {
	case strings.Contains(t, "CONTRACT") || strings.HasPrefix(id, "0x"):
		return "smart-contract", 75
	case strings.Contains(t, "SOURCE") || strings.Contains(id, "github.com"):
		return "supply-chain", 70
	case strings.Contains(t, "API") || strings.Contains(a.Detail, "path-restricted"):
		return "api-surface", 65
	case strings.Contains(t, "AI") || strings.Contains(id, "model") || strings.Contains(id, "agent"):
		return "agentic-ai", 70
	case strings.Contains(t, "PLAY") || strings.Contains(t, "STORE") || strings.Contains(t, "TESTFLIGHT"):
		return "mobile-app", 60
	default:
		return "infra-or-other", 40
	}
}

// ApplyConstraints attaches the program's hard boundary to every probe.
// BRIEF.md already leads with it; this makes the reminder survive even when
// the agent opens next.md directly.
func ApplyConstraints(p *Plan, constraints []string) {
	for i := range p.Items {
		probe := strings.ToLower(p.Items[i].Probe)
		if strings.Contains(probe, "mainnet") {
			continue
		}
		for _, c := range constraints {
			low := strings.ToLower(c)
			if strings.Contains(low, "mainnet") && (strings.Contains(low, "do not") || strings.Contains(low, "forbidden")) {
				p.Items[i].Probe = "Boundary: no mainnet/live testing — use testnet or a local fork. " + p.Items[i].Probe
				break
			}
		}
	}
}

// Markdown renders the queue.
func (p *Plan) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Next — ranked test queue — %s\n\n", p.Program)
	fmt.Fprintf(&b, "Generated %s · %d hypotheses\n\n", p.Generated, len(p.Items))
	if len(p.Items) == 0 {
		b.WriteString("No hypothesis cleared the evidence bar. That is a real result, not a missing run: ")
		b.WriteString("nothing in this surface has an object reference, an ID parameter, a risky module name, ")
		b.WriteString("or a host that behaves like it wants a login.\n\n")
		b.WriteString("Widen the surface instead of guessing: run `kai recon` again after the target ships, ")
		b.WriteString("or import a session with `kai session` so the authenticated area is mapped too.\n")
		return b.String()
	}

	b.WriteString("| # | score | class | target |\n| --- | --- | --- | --- |\n")
	limit := len(p.Items)
	if limit > 25 {
		limit = 25
	}
	for i, h := range p.Items[:limit] {
		fmt.Fprintf(&b, "| %d | %d | %s | `%s` |\n", i+1, h.Score, h.Class, h.Target)
	}
	b.WriteString("\n## Detail (top 10)\n\n")
	detail := limit
	if detail > 10 {
		detail = 10
	}
	for i, h := range p.Items[:detail] {
		fmt.Fprintf(&b, "### %d. `%s` — %s (score %d)\n\n", i+1, h.Target, h.Class, h.Score)
		if len(h.Why) > 0 {
			fmt.Fprintf(&b, "- why: %s\n", strings.Join(h.Why, "; "))
		}
		fmt.Fprintf(&b, "- first probe: %s\n\n", h.Probe)
	}
	b.WriteString("> Ranking is a hint, not a verdict. The top item is where the evidence is strongest, ")
	b.WriteString("not where the bug definitely is. Still run the scope gate before every request.\n")
	return b.String()
}
