// Package program turns a public program page into Phase 0 intake data: what
// it pays, how crowded it is, and which scope rules are safe to automate.
//
// It is deliberately read-only. Nothing here submits a report or touches a
// target asset; the only requests go to the platform's public directory API.
package program

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/internal/strutil"
)

// Asset is one entry from a platform's structured scope.
type Asset struct {
	Identifier  string `json:"identifier"`
	Type        string `json:"type"`
	HumanType   string `json:"human_type,omitempty"`
	Eligible    bool   `json:"eligible_for_submission"`
	Bounty      bool   `json:"eligible_for_bounty"`
	MaxSeverity string `json:"max_severity,omitempty"`
	Instruction string `json:"instruction,omitempty"`
}

// BountyRow is one severity-based reward band.
type BountyRow struct {
	Name     string `json:"name"`
	Low      int    `json:"low"`
	Medium   int    `json:"medium"`
	High     int    `json:"high"`
	Critical int    `json:"critical"`
	Minimums [4]int `json:"minimums"`
}

// SeverityStat is the platform's own paid-report statistics.
type SeverityStat struct {
	Average float64 `json:"average"`
	Count   int     `json:"count"`
}

// Candidate is a host or asset mentioned in prose. It is NOT promoted into
// scope.txt automatically: unlike a structured platform field, a regex match
// cannot tell an in-scope asset from an example or an out-of-scope mention.
type Candidate struct {
	Identifier string `json:"identifier"`
	Host       string `json:"host,omitempty"`
	Path       string `json:"path,omitempty"`
	Type       string `json:"type"`
	Section    string `json:"section,omitempty"`
}

// Reference is another page followed from the main program page.
type Reference struct {
	URL    string `json:"url"`
	Title  string `json:"title,omitempty"`
	Why    string `json:"why,omitempty"`
	Status string `json:"status,omitempty"`
}

// PageDoc is one fetched reference page kept as per-page context. The agent
// needs scope and out-of-scope verbatim per category, not one merged policy
// where those sections lose their owner.
type PageDoc struct {
	URL        string `json:"url"`
	Title      string `json:"title,omitempty"`
	Scope      string `json:"scope,omitempty"`
	OutOfScope string `json:"out_of_scope,omitempty"`
	Body       string `json:"body,omitempty"`
}

// Intake is everything Phase 0 can learn without logging in.
type Intake struct {
	Platform      string                  `json:"platform"`
	Confidence    string                  `json:"confidence"`
	Handle        string                  `json:"handle"`
	Name          string                  `json:"name"`
	URL           string                  `json:"url"`
	Website       string                  `json:"website,omitempty"`
	State         string                  `json:"state,omitempty"`
	Submission    string                  `json:"submission_state,omitempty"`
	OffersBounty  bool                    `json:"offers_bounties"`
	Currency      string                  `json:"currency,omitempty"`
	Base          int                     `json:"base_bounty,omitempty"`
	Minimum       int                     `json:"minimum_bounty,omitempty"`
	TopLower      int                     `json:"top_bounty_lower,omitempty"`
	TopUpper      int                     `json:"top_bounty_upper,omitempty"`
	AverageLower  int                     `json:"average_bounty_lower,omitempty"`
	AverageUpper  int                     `json:"average_bounty_upper,omitempty"`
	Resolved      int                     `json:"resolved_reports"`
	Reports90d    int                     `json:"reports_received_90d"`
	ReportsKnown  bool                    `json:"reports_known"`
	ResponseEff   float64                 `json:"response_efficiency_pct"`
	BountyRows    []BountyRow             `json:"bounty_rows,omitempty"`
	SeverityStats map[string]SeverityStat `json:"severity_stats,omitempty"`
	Assets        []Asset                 `json:"assets,omitempty"`
	Candidates    []Candidate             `json:"candidate_assets,omitempty"`
	References    []Reference             `json:"references,omitempty"`
	Discovered    []Reference             `json:"discovered,omitempty"`
	Pages         []PageDoc               `json:"pages,omitempty"`
	LLMs          []Reference             `json:"llms,omitempty"`
	Constraints   []string                `json:"constraints,omitempty"`
	Boundaries    Boundaries              `json:"boundaries,omitempty"`
	TrustScope    bool                    `json:"trust_scope,omitempty"`
	Scorecard     Score                   `json:"scorecard,omitempty"`
	Policy        string                  `json:"-"`
	PolicyHash    string                  `json:"policy_hash,omitempty"`
	FetchedAt     time.Time               `json:"fetched_at"`
}

// Score is the Phase 0 recommendation. Each component is independent so the
// operator can disagree with the weighting without losing the raw numbers.
type Score struct {
	Total    int      `json:"total"`
	Verdict  string   `json:"verdict"`
	Money    int      `json:"money"`
	Crowding int      `json:"crowding"`
	Speed    int      `json:"speed"`
	Surface  int      `json:"surface"`
	Reasons  []string `json:"reasons"`
}

// Scope holds the rules derived from structured scope, plus what could not be
// represented in a host-only gate.
type Scope struct {
	In        []string `json:"in"`
	Out       []string `json:"out"`
	PathOnly  []Asset  `json:"path_scoped"`
	NonWeb    []Asset  `json:"non_web"`
	OutNonWeb []Asset  `json:"out_non_web"`
}

// Scope converts structured assets into rules the gate can enforce.
//
// An asset with a URL path is deliberately NOT emitted: scope.txt only
// understands hosts, and silently widening "example.com/api/*" to the whole
// host would let recon touch paths the program never authorised.
func (in *Intake) Scope() Scope {
	var s Scope
	for _, a := range in.Assets {
		rule, kind := normalizeRule(a)
		if kind == "path" || kind == "non-web" || kind == "unparsed" || rule == "" {
			// Cannot be expressed as a host rule. Keep it visible, but never
			// present an out-of-scope asset as something to test.
			if a.Eligible {
				if kind == "path" {
					s.PathOnly = append(s.PathOnly, a)
				} else {
					s.NonWeb = append(s.NonWeb, a)
				}
			} else {
				s.OutNonWeb = append(s.OutNonWeb, a)
			}
			continue
		}
		if a.Eligible {
			s.In = append(s.In, rule)
		} else {
			s.Out = append(s.Out, rule)
		}
	}
	s.In = strutil.Unique(s.In)
	s.Out = strutil.Unique(s.Out)
	sort.Strings(s.In)
	sort.Strings(s.Out)
	if in.TrustScope {
		for _, c := range in.Candidates {
			if c.Host == "" || (c.Path != "" && c.Path != "/") || strings.Contains(strings.ToLower(c.Section), "out of scope") {
				continue
			}
			rule := c.Host
			if strings.HasPrefix(c.Identifier, "*.") && !strings.HasPrefix(rule, "*.") {
				rule = "*." + rule
			}
			s.In = append(s.In, rule)
		}
		s.In = strutil.Unique(s.In)
		sort.Strings(s.In)
	}
	return s
}

// normalizeRule returns a scope rule and its kind: host, wildcard, cidr,
// path (host plus an unrepresentable path), non-web, or unparsed.
func normalizeRule(a Asset) (rule, kind string) {
	id := strings.TrimSpace(a.Identifier)
	if id == "" {
		return "", "unparsed"
	}
	switch strings.ToUpper(a.Type) {
	case "CIDR", "IP_ADDRESS", "IP", "IPV4", "IPV6":
		return strings.TrimSuffix(id, "."), "cidr"
	case "WILDCARD":
		id = strings.TrimPrefix(id, "*.")
		host, path := splitHost(id)
		if host == "" {
			return "", "unparsed"
		}
		if path != "" {
			return "", "path"
		}
		return "*." + host, "wildcard"
	case "URL", "URL_PATH", "API", "HOST", "DOMAIN", "HOSTNAME":
		host, path := splitHost(id)
		if host == "" {
			return "", "unparsed"
		}
		if path != "" {
			return "", "path"
		}
		if strings.HasPrefix(host, "*.") {
			return host, "wildcard"
		}
		return host, "host"
	default:
		return "", "non-web"
	}
}

func splitHost(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	path := ""
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", ""
		}
		raw = u.Host
		path = u.Path
	} else if i := strings.IndexAny(raw, "/?:"); i >= 0 {
		// ":" is handled below for ports; only treat it as a separator when
		// the remainder is not a port number.
		if raw[i] != ':' {
			path, raw = raw[i:], raw[:i]
		}
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	raw = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if raw == "" || strings.ContainsAny(raw, " \t") {
		return "", ""
	}
	if path == "/" {
		path = ""
	}
	return raw, path
}

// Score produces the Phase 0 recommendation.
func (in *Intake) Score() Score {
	s := Score{}
	reasons := []string{}

	// Money: 0-25. The ceiling matters more than the floor for a first bug.
	switch {
	case in.TopUpper >= 50000:
		s.Money = 25
	case in.TopUpper >= 20000:
		s.Money = 21
	case in.TopUpper >= 10000:
		s.Money = 17
	case in.TopUpper >= 5000:
		s.Money = 12
	case in.TopUpper > 0:
		s.Money = 7
	}
	if !in.OffersBounty {
		s.Money = 0
		reasons = append(reasons, "no monetary rewards — VDP only; do not rank it like a bounty program")
	} else if in.TopUpper > 0 {
		msg := "reward ceiling " + money(in.TopUpper)
		if in.AverageUpper > 0 {
			msg += ", typical band " + money(in.AverageLower) + "–" + money(in.AverageUpper)
		}
		reasons = append(reasons, msg)
	}

	// Crowding: 0-35. Reports per 90 days is the closest public proxy for
	// how many hunters are already walking the same paths. Missing data is
	// scored as unknown, never as "zero competition".
	if !in.ReportsKnown {
		s.Crowding = 17
		reasons = append(reasons, "no public report count — crowding unknown, not zero")
	} else {
		switch {
		case in.Reports90d <= 50:
			s.Crowding = 35
		case in.Reports90d <= 150:
			s.Crowding = 29
		case in.Reports90d <= 400:
			s.Crowding = 21
		case in.Reports90d <= 1000:
			s.Crowding = 12
		case in.Reports90d <= 2500:
			s.Crowding = 6
		default:
			s.Crowding = 0
		}
		if in.Reports90d > 0 {
			reason := fmt.Sprintf("%d reports in 90 days — crowded", in.Reports90d)
			if strings.EqualFold(in.Confidence, "heuristic") {
				reason = fmt.Sprintf("%d reports submitted (period not stated) — crowded", in.Reports90d)
			}
			if in.Reports90d > 400 {
				reason += "; duplicates are likely unless you find new surface"
			}
			reasons = append(reasons, reason)
		}
	}

	// Speed: 0-20.
	s.Speed = int(float64(in.ResponseEff) / 100 * 20)
	if in.ResponseEff > 0 {
		reasons = append(reasons, fmt.Sprintf("response efficiency %.0f%%", in.ResponseEff))
	}

	// Surface: 0-20. Wildcards and mobile widen the hunt; a huge flat scope
	// is not automatically better because nobody can cover it in depth.
	sc := in.Scope()
	web := len(sc.In)
	var hasWildcard, hasMobile bool
	for _, a := range in.Assets {
		if !a.Eligible {
			continue
		}
		if strings.EqualFold(a.Type, "WILDCARD") || strings.HasPrefix(a.Identifier, "*.") {
			hasWildcard = true
		}
		if strings.Contains(strings.ToUpper(a.Type), "APP") || strings.Contains(strings.ToUpper(a.Type), "STORE") {
			hasMobile = true
		}
	}
	switch {
	case web == 0:
		s.Surface = 0
	case web <= 4:
		s.Surface = 8
	case web <= 20:
		s.Surface = 14
	case web <= 100:
		s.Surface = 18
	default:
		s.Surface = 16
	}
	if hasWildcard {
		s.Surface += 2
	}
	if hasMobile {
		s.Surface += 1
	}
	if s.Surface > 20 {
		s.Surface = 20
	}
	if web > 0 {
		reasons = append(reasons, fmt.Sprintf("%d enforceable in-scope rules", web))
	} else {
		reasons = append(reasons, "no host-level scope rules — read policy.md before touching anything")
	}
	if hasWildcard {
		reasons = append(reasons, "wildcard scope: subdomain discovery is worth running")
	} else if web > 0 {
		reasons = append(reasons, "exact hosts only: subdomain enumeration will add nothing in scope")
	}
	if len(sc.PathOnly) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d path-scoped asset(s) excluded from scope.txt — host gate would be too broad", len(sc.PathOnly)))
	}
	if len(in.Assets) == 0 {
		reasons = append(reasons, "no structured scope published; the full scope is in the policy text")
	}
	if len(in.Candidates) > 0 {
		hosts, systems := 0, 0
		for _, c := range in.Candidates {
			if c.Type == "SYSTEM" {
				systems++
			} else {
				hosts++
			}
		}
		reasons = append(reasons, fmt.Sprintf("%d surface candidate(s) from prose (%d host, %d system) — unverified", len(in.Candidates), hosts, systems))
		if s.Surface < 20 {
			s.Surface += 4
			if s.Surface > 20 {
				s.Surface = 20
			}
		}
	}
	if strings.EqualFold(in.Confidence, "heuristic") {
		reasons = append(reasons, "extracted from page text by heuristics — the score is a triage hint, not a guarantee")
	}

	s.Total = s.Money + s.Crowding + s.Speed + s.Surface
	switch {
	case strings.EqualFold(in.Confidence, "heuristic"):
		s.Verdict = "review"
	case !in.OffersBounty:
		s.Verdict = "vdp-only"
	case s.Total >= 70:
		s.Verdict = "go"
	case s.Total >= 50:
		s.Verdict = "careful"
	default:
		s.Verdict = "skip"
	}
	s.Reasons = reasons
	return s
}

func money(n int) string {
	if n >= 1_000_000 {
		v := float64(n) / 1e6
		if v == float64(int(v)) {
			return fmt.Sprintf("$%dM", int(v))
		}
		return fmt.Sprintf("$%.1fM", v)
	}
	if n >= 1000 {
		v := float64(n) / 1e3
		if v == float64(int(v)) {
			return fmt.Sprintf("$%dk", int(v))
		}
		return fmt.Sprintf("$%.1fk", v)
	}
	return fmt.Sprintf("$%d", n)
}

// Markdown is the Phase 0 scorecard the operator reads.
func (in *Intake) Markdown() string {
	var b strings.Builder
	sc := in.Scope()
	s := in.Score()
	fmt.Fprintf(&b, "# Phase 0 — %s (%s)\n\n", in.Name, in.Platform)
	fmt.Fprintf(&b, "**Verdict: %s — %d/100**\n\n", s.Verdict, s.Total)
	fmt.Fprintf(&b, "| money | crowding | speed | surface |\n| ---: | ---: | ---: | ---: |\n| %d/25 | %d/35 | %d/20 | %d/20 |\n\n",
		s.Money, s.Crowding, s.Speed, s.Surface)
	fmt.Fprintf(&b, "%s\n\n", in.URL)
	fmt.Fprintf(&b, "Fetched %s · confidence `%s` · state `%s` · submission `%s` · website %s\n\n",
		in.FetchedAt.Format(time.RFC3339), in.confidenceLabel(), in.State, in.Submission, strutil.Dash(in.Website))

	b.WriteString("## Why this score\n\n")
	for _, r := range s.Reasons {
		fmt.Fprintf(&b, "- %s\n", r)
	}
	b.WriteString("\n")

	b.WriteString("## Key boundaries\n\n")
	if bd := in.Boundaries; bd.MainnetTesting != "" {
		fmt.Fprintf(&b, "| Rule | Value |\n| --- | --- |\n")
		fmt.Fprintf(&b, "| Mainnet / live testing | **%s** |\n", bd.MainnetTesting)
		fmt.Fprintf(&b, "| Expected environment | %s |\n", strutil.Dash(bd.TestingEnvironment))
		fmt.Fprintf(&b, "| PoC | %s |\n", yesNotStated(bd.PoCRequired))
		fmt.Fprintf(&b, "| KYC | %s |\n", yesNotStated(bd.KYCRequired))
		if bd.SubmissionChannel != "" {
			fmt.Fprintf(&b, "| Submit via | %s |\n", bd.SubmissionChannel)
		}
		if len(bd.SubmissionContact) > 0 {
			label := "Published contacts"
			if bd.SubmissionChannel == "email-or-contact" {
				label = "Email / contacts (check policy)"
			}
			fmt.Fprintf(&b, "| %s | `%s` |\n", label, strings.Join(bd.SubmissionContact, "`, `"))
		}
		if len(bd.RequiredHeaders) > 0 {
			fmt.Fprintf(&b, "| Headers | `%s` |\n", strings.Join(bd.RequiredHeaders, "`, `"))
		}
		b.WriteString("\nFull rules and verbatim text: `boundaries.md`.\n\n")
	} else {
		b.WriteString("No structured boundaries extracted — treat as unknown, read `policy.md`.\n\n")
	}

	b.WriteString("## Rewards\n\n")
	if !in.OffersBounty {
		b.WriteString("No bounty table — this program awards recognition, not money.\n\n")
	} else if len(in.BountyRows) == 0 && in.TopUpper == 0 {
		b.WriteString("No reward figures could be extracted from the page text. Read `policy.md`.\n\n")
	} else {
		simple := len(in.BountyRows) > 0
		for _, row := range in.BountyRows {
			if row.Medium != 0 || row.High != 0 || row.Critical != 0 {
				simple = false
			}
		}
		if simple {
			b.WriteString("| severity | max |\n| --- | ---: |\n")
			for _, row := range in.BountyRows {
				fmt.Fprintf(&b, "| %s | %s |\n", strutil.Dash(row.Name), money(row.Low))
			}
		} else {
			fmt.Fprintf(&b, "| | low | medium | high | critical |\n| --- | ---: | ---: | ---: | ---: |\n")
			if len(in.BountyRows) == 0 {
				fmt.Fprintf(&b, "| reward | %s | %s | %s | %s |\n", money(in.AverageLower), money(in.AverageLower), money(in.AverageUpper), money(in.TopUpper))
			} else {
				for _, row := range in.BountyRows {
					fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", strutil.Dash(row.Name),
						money(row.Low), money(row.Medium), money(row.High), money(row.Critical))
					if row.Minimums != [4]int{} {
						fmt.Fprintf(&b, "| %s min | %s | %s | %s | %s |\n", strutil.Dash(row.Name),
							money(row.Minimums[0]), money(row.Minimums[1]), money(row.Minimums[2]), money(row.Minimums[3]))
					}
				}
			}
		}
		var facts []string
		if in.Base > 0 {
			facts = append(facts, "base "+money(in.Base))
		}
		if in.TopUpper > 0 {
			if in.TopLower > 0 {
				facts = append(facts, "top "+money(in.TopLower)+"–"+money(in.TopUpper))
			} else {
				facts = append(facts, "top up to "+money(in.TopUpper))
			}
		}
		if in.AverageUpper > 0 {
			facts = append(facts, "average "+money(in.AverageLower)+"–"+money(in.AverageUpper))
		}
		facts = append(facts, in.Currency)
		b.WriteString("\n" + strings.Join(facts, " · ") + "\n\n")
	}

	if len(in.SeverityStats) > 0 {
		b.WriteString("## Where reports land\n\n| severity | paid reports | average |\n| --- | ---: | ---: |\n")
		for _, k := range []string{"critical", "high", "medium", "low"} {
			if st, ok := in.SeverityStats[k]; ok {
				fmt.Fprintf(&b, "| %s | %d | %s |\n", k, st.Count, money(int(st.Average)))
			}
		}
		if in.ReportsKnown {
			fmt.Fprintf(&b, "\n%d reports resolved in total, %d received in the last 90 days.\n\n", in.Resolved, in.Reports90d)
		} else if in.Resolved > 0 {
			fmt.Fprintf(&b, "\n%d paid reports reported by the platform.\n\n", in.Resolved)
		} else {
			b.WriteString("\n")
		}
	}

	b.WriteString("## Scope derived from the platform\n\n")
	fmt.Fprintf(&b, "- %d in-scope host rules\n- %d out-of-scope host rules\n- %d path-scoped assets excluded (host gate would be too broad)\n- %d non-web assets (apps, source, hardware)\n\n",
		len(sc.In), len(sc.Out), len(sc.PathOnly), len(sc.NonWeb))
	if len(sc.In) > 0 {
		b.WriteString("In scope:\n\n")
		for _, r := range sc.In {
			fmt.Fprintf(&b, "- `%s`\n", r)
		}
		b.WriteString("\n")
	}
	if len(sc.Out) > 0 {
		b.WriteString("Out of scope:\n\n")
		for _, r := range sc.Out {
			fmt.Fprintf(&b, "- `%s`\n", r)
		}
		b.WriteString("\n")
	}
	if len(sc.NonWeb) > 0 {
		b.WriteString("In scope but not host-based — track these separately:\n\n")
		for _, a := range sc.NonWeb {
			fmt.Fprintf(&b, "- `%s` (%s)%s\n", a.Identifier, a.Type, bountyMark(a))
		}
		b.WriteString("\n")
	}
	if len(sc.PathOnly) > 0 {
		b.WriteString("Path-restricted — read the policy before testing:\n\n")
		for _, a := range sc.PathOnly {
			fmt.Fprintf(&b, "- `%s`\n", a.Identifier)
		}
		b.WriteString("\n")
	}

	if len(in.Candidates) > 0 {
		b.WriteString("## Candidates from prose (unverified)\n\n")
		b.WriteString("SYSTEM entries are named systems from an impact-based scope, **not hostnames**. ")
		b.WriteString("Only real hosts are promoted by `--trust-scope`; system names become hints in `next`.\n\n")
		for _, c := range in.Candidates {
			fmt.Fprintf(&b, "- `%s` (%s, section: %s)\n", c.Identifier, c.Type, strutil.Dash(c.Section))
		}
		b.WriteString("\n")
	}
	if len(in.Constraints) > 0 {
		b.WriteString("## Testing constraints found in the policy\n\n")
		for _, c := range in.Constraints {
			fmt.Fprintf(&b, "- %s\n", c)
		}
		b.WriteString("\n")
	}

	if len(in.Discovered) > 0 {
		b.WriteString("## Documentation discovered (linked from the main page)\n\n")
		for _, r := range in.Discovered {
			fmt.Fprintf(&b, "- `%s` — %s (%s)\n", r.URL, strutil.Dash(r.Title), r.Status)
		}
		b.WriteString("\nThese links were found in the page HTML, including JavaScript-rendered ")
		b.WriteString("landing pages. Only those listed under 'Documentation read' were fetched.\n\n")
	}

	if len(in.LLMs) > 0 {
		b.WriteString("## AI-agent rules (llms.txt)\n\n")
		for _, r := range in.LLMs {
			fmt.Fprintf(&b, "- `%s` — %s (%s)\n", r.URL, strutil.Dash(r.Title), r.Status)
		}
		b.WriteString("\nThese rules are mandatory for automated research and are exported as context/llms.md.\n\n")
	}
	if len(in.Pages) > 0 {
		fmt.Fprintf(&b, "## Per-page context\n\n%d reference page(s) kept with verbatim scope sections — exported as context/pages/.\n\n", len(in.Pages))
	}

	if len(in.References) > 0 {
		b.WriteString("## Documentation read (linked from the main page)\n\n")
		for _, r := range in.References {
			fmt.Fprintf(&b, "- `%s` — %s (%s)\n", r.URL, strutil.Dash(r.Title), r.Status)
		}
		b.WriteString("\nThese pages are folded into the policy text and the rules above.\n\n")
	}

	b.WriteString("## Read before testing\n\n")
	b.WriteString("`policy.md` holds the full program policy: out-of-scope vulnerability classes, ")
	b.WriteString("required research headers, account rules and disclosure terms. ")
	b.WriteString("The host gate cannot enforce any of those.\n")
	return b.String()
}

func (in *Intake) confidenceLabel() string {
	if in.Confidence == "" {
		return "structured"
	}
	return in.Confidence
}

func bountyMark(a Asset) string {
	if a.Bounty {
		return " — bounty eligible"
	}
	return ""
}
