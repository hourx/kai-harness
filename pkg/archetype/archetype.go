// Package archetype names the shape of a program: what kind of thing the attack
// surface is, so every later sweep can use the right questions.
//
// An archetype is not a label for its own sake. A wallet API, a GraphQL gateway
// and a web app fail in different ways; naming the shape decides which probe
// shapes are worth writing before a single request is sent.
package archetype

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hourx/kai-harness/pkg/surface"
)

// Known archetypes. The list is closed on purpose: an unknown name is a data
// problem, not a new category to be invented at runtime.
const (
	Chain      = "chain"
	GraphQLAPI = "graphql-api"
	API        = "api"
	MobileAPI  = "mobile-api"
	WebApp     = "web-app"
	Mixed      = "mixed"
	Unknown    = "unknown"
)

// Names returns the closed set, sorted, for help text and validation.
func Names() []string {
	return []string{API, Chain, GraphQLAPI, MobileAPI, Mixed, Unknown, WebApp}
}

// Verdict is the classification plus the evidence that produced it.
type Verdict struct {
	Name       string   `json:"archetype"`
	Confidence string   `json:"confidence"` // high | medium | low
	Source     string   `json:"source"`     // declared | inferred
	Why        []string `json:"why"`
	Signals    []string `json:"signals,omitempty"`
}

// Parent returns the shape whose knowledge also applies to name, or "" when the
// shape stands alone.
//
// A GraphQL gateway and a mobile backend are both API servers: everything known
// about an API surface still holds for them, and their own knowledge is a delta on
// top of it rather than a replacement. Without this the report calls a class
// covered by a pattern that plainly applies a gap, and an operator who sees false
// gaps stops believing the true ones.
func Parent(name string) string {
	switch Normalize(name) {
	case GraphQLAPI, MobileAPI:
		return API
	}
	return ""
}

// Known reports whether name is one of the archetypes this package understands.
func Known(name string) bool {
	n := Normalize(name)
	for _, k := range Names() {
		if n == k {
			return true
		}
	}
	return false
}

// Normalize lowercases and collapses the spellings people actually type, so a
// declared value from a contract and an inferred value from traffic meet in the
// same closed set instead of producing two names for one thing.
func Normalize(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "_", "-")
	n = strings.ReplaceAll(n, " ", "-")
	if v, ok := aliases[n]; ok {
		return v
	}
	// Camel-case spellings (GraphQLAPI, WebApp) lose their word boundaries when
	// lowercased, so they are matched on the bare form as well.
	bare := bareForm.Replace(n)
	if v, ok := aliases[bare]; ok {
		return v
	}
	return n
}

// aliases maps every accepted spelling to the canonical name, including the
// canonical names themselves so a lookup never misses.
var aliases = map[string]string{
	API:        API,
	"rest":     API,
	"rest-api": API,
	"json-api": API,
	"http-api": API,
	// The concatenated forms are the bare keys, not hyphenated ones: this table
	// is consulted with both the hyphenated and the boundary-free spelling.
	"restapi":         API,
	"graphqlapi":      GraphQLAPI,
	"graphql":         GraphQLAPI,
	"gql":             GraphQLAPI,
	GraphQLAPI:        GraphQLAPI,
	"graphql-gateway": GraphQLAPI,
	MobileAPI:         MobileAPI,
	"mobile":          MobileAPI,
	"mobileapi":       MobileAPI,
	"app-api":         MobileAPI,
	"android":         MobileAPI,
	"ios":             MobileAPI,
	WebApp:            WebApp,
	"web":             WebApp,
	"webapp":          WebApp,
	"frontend":        WebApp,
	"web-application": WebApp,
	Chain:             Chain,
	"smart-contract":  Chain,
	"contracts":       Chain,
	"web3":            Chain,
	"blockchain":      Chain,
	Mixed:             Mixed,
	Unknown:           Unknown,
}

var bareForm = strings.NewReplacer("-", "", "_", "", " ", "", ".", "")

// Classify prefers a declaration in the program contract and only infers when
// the contract stays silent. Inference never overrides a human decision.
func Classify(declared string, m *surface.Map, nonWeb []surface.NonWebAsset) Verdict {
	if d := Normalize(declared); d != "" {
		v := Verdict{Name: d, Confidence: "high", Source: "declared",
			Why: []string{fmt.Sprintf("the program contract declares %q", d)}}
		if !Known(d) {
			v.Confidence = "low"
			v.Why = append(v.Why, fmt.Sprintf("%q is not one of the known archetypes (%s) — sweeps will use generic questions",
				d, strings.Join(Names(), ", ")))
		}
		return v
	}
	if m == nil {
		return Verdict{Name: Unknown, Confidence: "low", Source: "inferred",
			Why: []string{"there is no surface map yet — run recon first"}}
	}
	return infer(m, nonWeb)
}

type candidate struct {
	name    string
	score   int
	reasons []string
	signals []string
}

func infer(m *surface.Map, nonWeb []surface.NonWebAsset) Verdict {
	if len(nonWeb) == 0 {
		nonWeb = m.NonWeb
	}
	var cands []candidate

	paths := allPaths(m)
	total := len(paths)

	// Chain: contracts and programs are the surface, and web paths are a side dish.
	var chainCount int
	for _, a := range nonWeb {
		switch strings.ToLower(a.Type) {
		case "contract", "program", "contract-set", "chain":
			chainCount++
		}
	}
	if chainCount > 0 {
		c := candidate{name: Chain, signals: []string{fmt.Sprintf("chain_assets=%d", chainCount)}}
		c.reasons = append(c.reasons, fmt.Sprintf("%d on-chain assets were registered in scope", chainCount))
		c.score = 40 + 10*min(chainCount, 3)
		if total == 0 {
			c.score += 40
			c.reasons = append(c.reasons, "no web paths at all — the surface is entirely on-chain")
		} else if total < 10 {
			c.score += 15
			c.reasons = append(c.reasons, "only a handful of web paths support the chain surface")
		}
		cands = append(cands, c)
	}

	// GraphQL: a single endpoint that carries everything.
	if n := len(m.GraphQL); n > 0 {
		c := candidate{name: GraphQLAPI, score: 45 + 10*min(n, 3),
			signals: []string{fmt.Sprintf("graphql_endpoints=%d", n)},
			reasons: []string{fmt.Sprintf("%d GraphQL endpoint(s): %s", n, strings.Join(firstN(m.GraphQL, 3), ", "))}}
		if total > 0 && ratio(n, total+len(m.GraphQL)) >= 0.35 {
			c.score += 15
			c.reasons = append(c.reasons, "GraphQL is a large share of the surface, not a debug route")
		}
		cands = append(cands, c)
	}

	// API vs web app: transport prefixes and UI-shaped modules.
	apiPaths, uiModules := 0, 0
	authPaths := 0
	for _, p := range paths {
		if hasAPIPrefix(p) {
			apiPaths++
		}
	}
	for mod, eps := range m.Modules {
		if isUIModule(mod) {
			uiModules += len(eps)
		}
		for _, p := range eps {
			if isAuthPath(p) {
				authPaths++
			}
		}
	}
	if total > 0 {
		r := ratio(apiPaths, total)
		c := candidate{name: API, score: 10 + int(r*50),
			signals: []string{fmt.Sprintf("api_prefixed=%.0f%%", r*100)},
			reasons: []string{fmt.Sprintf("%.0f%% of %d paths sit under an API prefix", r*100, total)}}
		for _, vv := range m.APIVersions {
			c.signals = append(c.signals, "api_version="+vv)
		}
		cands = append(cands, c)

		webWeight := 15.0
		if total >= 3 {
			webWeight = 40
		}
		w := candidate{name: WebApp, score: 10 + int((1-r)*webWeight),
			reasons: []string{fmt.Sprintf("%.0f%% of paths carry no API prefix", (1-r)*100)}}
		if uiModules > 0 {
			w.score += 15
			w.signals = append(w.signals, fmt.Sprintf("ui_module_endpoints=%d", uiModules))
			w.reasons = append(w.reasons, "UI-shaped modules are present (account, admin, settings, checkout…)")
		}
		if authPaths > 0 {
			w.score += 10
			w.signals = append(w.signals, fmt.Sprintf("auth_endpoints=%d", authPaths))
			w.reasons = append(w.reasons, fmt.Sprintf("%d authentication endpoints suggest a session-driven app", authPaths))
		}
		cands = append(cands, w)

		// Mobile: the paths the app bundle uses, not the browser.
		mob := 0
		for _, p := range paths {
			if isMobilePath(p) {
				mob++
			}
		}
		if mob > 0 {
			c := candidate{name: MobileAPI, score: 20 + 10*min(mob, 3),
				signals: []string{fmt.Sprintf("mobile_paths=%d", mob)},
				reasons: []string{fmt.Sprintf("%d paths look app-specific (/app, /mobile, device, push)", mob)}}
			if uiModules == 0 && authPaths == 0 {
				c.score += 20
				c.reasons = append(c.reasons, "no UI or session endpoints — traffic comes from a client, not a browser")
			}
			cands = append(cands, c)
		}
	}

	if len(cands) == 0 {
		return Verdict{Name: Unknown, Confidence: "low", Source: "inferred",
			Why: []string{"the surface map has no paths and no on-chain assets"}}
	}

	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].name < cands[j].name
	})
	best := cands[0]
	if best.score < 30 {
		return Verdict{Name: Unknown, Confidence: "low", Source: "inferred",
			Why:     append([]string{fmt.Sprintf("the strongest candidate (%s, score %d) rests on too little evidence to name the shape", best.name, best.score)}, best.reasons...),
			Signals: best.signals}
	}
	second := 0
	if len(cands) > 1 {
		second = cands[1].score
	}
	conf := "low"
	margin := best.score - second
	switch {
	case margin >= 20:
		conf = "high"
	case margin >= 8:
		conf = "medium"
	}

	v := Verdict{Name: best.name, Confidence: conf, Source: "inferred", Why: best.reasons, Signals: best.signals}
	if margin < 8 && len(cands) > 1 {
		v.Why = append(v.Why, fmt.Sprintf("close call against %s (%d vs %d) — declare the archetype in program.yaml to settle it",
			cands[1].name, best.score, cands[1].score))
	}
	return v
}

// Markdown renders the verdict for humans, one fact per line.
func Markdown(v Verdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Archetype: %s\n\n", v.Name)
	fmt.Fprintf(&b, "- confidence: %s\n- source: %s\n", v.Confidence, v.Source)
	if len(v.Signals) > 0 {
		fmt.Fprintf(&b, "- signals: %s\n", strings.Join(v.Signals, ", "))
	}
	b.WriteString("\n## Why\n\n")
	for _, w := range v.Why {
		fmt.Fprintf(&b, "- %s\n", w)
	}
	return b.String()
}

func allPaths(m *surface.Map) []string {
	seen := map[string]bool{}
	var out []string
	for _, eps := range m.Modules {
		for _, p := range eps {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

func hasAPIPrefix(p string) bool {
	for _, s := range strings.Split(strings.Trim(strings.ToLower(p), "/"), "/") {
		switch s {
		case "api", "apis", "rest", "internal", "public", "external":
			return true
		}
		if len(s) == 2 && s[0] == 'v' && s[1] >= '0' && s[1] <= '9' {
			return true
		}
	}
	return false
}

var uiWords = []string{"dashboard", "settings", "profile", "account", "checkout", "cart", "admin", "console", "inbox", "feed", "home", "page", "portal", "ui"}

func isUIModule(mod string) bool {
	low := strings.ToLower(mod)
	for _, w := range uiWords {
		if low == w || strings.Contains(low, w) {
			return true
		}
	}
	return false
}

func isAuthPath(p string) bool {
	low := strings.ToLower(p)
	for _, w := range []string{"login", "signin", "logout", "signout", "session", "oauth", "sso", "password", "register", "signup", "mfa", "otp"} {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

func isMobilePath(p string) bool {
	low := strings.ToLower(p)
	for _, w := range []string{"/app/", "/mobile", "device", "/push", "/apns", "/fcm", "/sync"} {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func firstN(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
