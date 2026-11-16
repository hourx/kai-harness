package surface

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hourx/bountykit/internal/recon"
)

// Hypothesis is one ranked thing to test, with the evidence that put it there.
type Hypothesis struct {
	Target string   `json:"target"`
	Class  string   `json:"class"`
	Score  int      `json:"score"`
	Why    []string `json:"why"`
	Probe  string   `json:"probe"`
}

// Plan is the ordered test queue for a program.
type Plan struct {
	Program   string       `json:"program"`
	Generated string       `json:"generated"`
	Items     []Hypothesis `json:"items"`
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
	return p
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

// Markdown renders the queue.
func (p *Plan) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Next — ranked test queue — %s\n\n", p.Program)
	fmt.Fprintf(&b, "Generated %s · %d hypotheses\n\n", p.Generated, len(p.Items))
	if len(p.Items) == 0 {
		b.WriteString("No hypothesis cleared the evidence bar. That is a real result, not a missing run: ")
		b.WriteString("nothing in this surface has an object reference, an ID parameter, a risky module name, ")
		b.WriteString("or a host that behaves like it wants a login.\n\n")
		b.WriteString("Widen the surface instead of guessing: run `bountykit recon` again after the target ships, ")
		b.WriteString("or import a session with `bountykit session` so the authenticated area is mapped too.\n")
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
