package program

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/netx"
	"github.com/hourx/kai-harness/pkg/strutil"
)

// DetectPlatform maps a URL to a reader. HackerOne is handled separately by
// its structured GraphQL API; everything else goes through the page reader.
func DetectPlatform(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	// A bare handle ("temu") is HackerOne shorthand. A dotted string is a
	// hostname and goes through the normal URL path below.
	if raw != "" && !strings.ContainsAny(raw, "/:. ") {
		if h1HandleRE.MatchString(raw) {
			return "h1", nil
		}
		return "", fmt.Errorf("invalid program handle %q", raw)
	}
	u, err := parseURL(raw)
	if err != nil {
		return "", err
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	switch {
	case strings.HasSuffix(host, "hackerone.com"):
		return "h1", nil
	case strings.HasSuffix(host, "gitbook.io"):
		return "gitbook", nil
	case strings.HasSuffix(host, "cantina.xyz"):
		return "cantina", nil
	case strings.HasSuffix(host, "immunefi.com"):
		return "immunefi", nil
	case strings.HasSuffix(host, "bugbounty.meta.com"):
		return "meta", nil
	case strings.HasSuffix(host, "ethereum.org"):
		return "ethereum", nil
	default:
		return "web", nil
	}
}

func parseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty program URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid program URL %q", raw)
	}
	return u, nil
}

var (
	blockTags = []*regexp.Regexp{
		regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`),
		regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`),
		regexp.MustCompile(`(?is)<noscript[^>]*>.*?</noscript>`),
		regexp.MustCompile(`(?is)<svg[^>]*>.*?</svg>`),
		regexp.MustCompile(`(?is)<iframe[^>]*>.*?</iframe>`),
	}
	headingRE   = regexp.MustCompile(`(?is)<h[1-6][^>]*>(.*?)</h[1-6]>`)
	tagRE       = regexp.MustCompile(`(?s)<[^>]+>`)
	blankRE     = regexp.MustCompile(`\n{3,}`)
	mdHeadingRE = regexp.MustCompile(`(?m)^#{1,6}[ \t]+`)
	ogTitleRE   = regexp.MustCompile(`(?is)<meta[^>]+(?:property|name)=["']og:title["'][^>]+content=["']([^"']+)["']`)
	titleRE     = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

// htmlToText keeps headings as markdown-ish "## " lines so the in-scope
// section can be isolated. It is intentionally simple: a policy is prose,
// not markup we need to render.
func htmlToText(b []byte) string {
	s := string(b)
	for _, re := range blockTags {
		s = re.ReplaceAllString(s, " ")
	}
	s = headingRE.ReplaceAllString(s, "\n\n## $1\n\n")
	s = tagRE.ReplaceAllString(s, "\n")
	s = html.UnescapeString(s)
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return blankRE.ReplaceAllString(strings.Join(out, "\n"), "\n\n")
}

// FetchWeb reads a program page that has no structured public API.
//
// It never guesses scope into scope.txt: candidates extracted from prose are
// returned separately and only promoted when the operator passes --trust-scope.
func FetchWeb(ctx context.Context, c *netx.Client, raw string, options ...FetchOptions) (*Intake, error) {
	fopt := FetchOptions{}
	if len(options) > 0 {
		fopt = options[0]
	}
	fopt = fopt.defaults()
	u, err := parseURL(raw)
	if err != nil {
		return nil, err
	}
	platform, _ := DetectPlatform(u.String())
	pageURL := u.String()
	fetchURL := pageURL
	var policy string

	resp, err := c.Get(ctx, fetchURL, 2<<20)
	if err != nil {
		return nil, err
	}
	status, body := resp.StatusCode, resp.Body
	// GitBook is often served from a custom domain (docs.ticko.xyz), so the
	// hostname alone is not enough. Its HTML is a shell; the real policy is
	// published as Markdown beside the page.
	if platform != "gitbook" && strings.Contains(strings.ToLower(string(body)), "gitbook") &&
		!strings.HasSuffix(strings.ToLower(fetchURL), ".md") {
		mdURL := strings.TrimSuffix(fetchURL, "/") + ".md"
		if mdResp, mdErr := c.Get(ctx, mdURL, 2<<20); mdErr == nil && mdResp.StatusCode == 200 && len(mdResp.Body) > 300 {
			platform = "gitbook"
			fetchURL = mdURL
			status, body = mdResp.StatusCode, mdResp.Body
		}
	}
	if platform == "meta" && status == 400 && len(body) > 1000 {
		// accepted with a caveat recorded below
	} else if status != 200 {
		return nil, fmt.Errorf("%s returned HTTP %d", fetchURL, status)
	}
	pureMD := strings.HasSuffix(fetchURL, ".md")
	if pureMD {
		policy = html.UnescapeString(string(body))
		policy = mdHeadingRE.ReplaceAllString(policy, "## ")
	} else {
		policy = htmlToText(body)
	}
	if len(policy) < 300 {
		return nil, fmt.Errorf("%s produced too little readable text (%d bytes)", fetchURL, len(policy))
	}

	var refs, discovered, llmsRefs []Reference
	var refCandidates []Candidate
	var pageDocs []PageDoc
	if fopt.Follow {
		var linked []string
		refs, discovered, linked, refCandidates, pageDocs, llmsRefs = followReferences(ctx, c, u, policy, string(body), fopt, platform == "gitbook")
		for _, t := range linked {
			policy += "\n\n" + t
		}
		if len(policy) > 320_000 {
			policy = policy[:320_000] + "\n\n[… linked documentation truncated; see the source pages]"
		}
	}

	name := pageTitle(body, policy)
	if name == "" || strings.EqualFold(name, "program") || strings.EqualFold(name, "bug bounty program") {
		// A generic page title ("Bug bounty program") is less useful than
		// the project name in the hostname. Keep real titles as they are.
		host := strings.ToLower(u.Hostname())
		parts := strings.Split(host, ".")
		if strings.HasSuffix(host, ".gitbook.io") && len(parts) > 2 {
			name = parts[0] // hyperliquid.gitbook.io → hyperliquid
		} else if len(parts) > 1 {
			name = parts[len(parts)-2]
		}
	}
	in := &Intake{
		Platform:     platform,
		Confidence:   "heuristic",
		Handle:       slugFromURL(u.Hostname() + u.Path),
		Name:         name,
		URL:          pageURL,
		Website:      websiteFromURL(u),
		State:        "unknown",
		Submission:   "unknown",
		OffersBounty: true,
		Currency:     "USD",
		Policy:       policy,
		References:   refs,
		Discovered:   discovered,
		Pages:        pageDocs,
		LLMs:         llmsRefs,
		FetchedAt:    time.Now().UTC(),
	}
	if platform == "immunefi" && strings.Contains(policy, "Paused") {
		in.State = "paused"
	}
	in.TopUpper, in.BountyRows = extractRewards(policy)
	in.Resolved, in.Reports90d, in.ReportsKnown = extractCounters(policy)
	in.Assets = extractContractAssets(policy)
	in.Candidates = append(extractCandidates(policy), extractSystems(policy)...)
	in.Candidates = append(in.Candidates, refCandidates...)
	in.Candidates = uniqueCandidates(in.Candidates)
	in.Constraints = extractConstraints(policy)
	in.Boundaries = ExtractBoundaries(policy, in.Confidence)
	in.PolicyHash = hashPolicy(policy)
	in.Scorecard = in.Score()
	return in, nil
}

var noiseHosts = map[string]bool{
	"immunefi.com": true, "cantina.xyz": true, "hackerone.com": true,
	"gitbook.io": true, "meta.com": true, "ethereum.org": true,
	"twitter.com": true, "x.com": true, "discord.gg": true, "discord.com": true,
	"t.me": true, "telegram.me": true, "telegram.org": true,
	"etherscan.io": true, "arbiscan.io": true, "example.com": true,
	"docs.github.com": true,
}

var fileExt = map[string]bool{
	"sol": true, "js": true, "ts": true, "md": true, "go": true, "py": true,
	"json": true, "pdf": true, "png": true, "jpg": true, "html": true,
	"css": true, "tsx": true, "rs": true, "yml": true, "yaml": true,
}

var systemRE = regexp.MustCompile(`(?i)\b(core|nodes?|APIs?|VM|order book|session keys?|signatures?|contracts?|settlement|liquidation|margin|oracle|testnet|mainnet|wallet|engine|chain|ledger|servers?)\b`)

// extractSystems finds named systems in an impact-based scope section. Such
// programs have no host list, but they still define a testable surface: the
// VM, node APIs, session keys, settlement logic and so on.
func extractSystems(policy string) []Candidate {
	text := strings.Join(strings.Fields(plain(sections(policy, "in scope", "assets in scope", "scope"))), " ")
	var out []Candidate
	seen := map[string]bool{}
	for _, m := range systemRE.FindAllString(text, -1) {
		name := strings.TrimSpace(m)
		if name == "" || len(name) > 60 {
			continue
		}
		low := strings.ToLower(name)
		if low == "a node" || low == "the api" || strings.HasPrefix(low, "an ") {
			continue
		}
		key := low
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Candidate{Identifier: name, Type: "SYSTEM", Section: "in-scope section"})
		if len(out) >= 15 {
			break
		}
	}
	return out
}

func uniqueCandidates(in []Candidate) []Candidate {
	seen := map[string]bool{}
	out := make([]Candidate, 0, len(in))
	for _, c := range in {
		key := c.Type + ":" + strings.ToLower(c.Identifier)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

// looksLikeFileHost rejects "Reactor.sol" and similar source-file names that
// the bare-domain regex cannot distinguish from a hostname.
func isNoiseHost(host string) bool {
	if noiseHosts[host] {
		return true
	}
	for _, suffix := range []string{".gitbook.io", ".discord.com", ".googleusercontent.com"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func looksLikeFileHost(host string) bool {
	i := strings.LastIndex(host, ".")
	return i > 0 && fileExt[strings.ToLower(host[i+1:])]
}

var (
	urlRE      = regexp.MustCompile(`https?://[^\s<>\)\]\}]+`)
	domainRE   = regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b`)
	contractRE = regexp.MustCompile(`0x[0-9a-fA-F]{40}`)
)

// sections returns prose under an in-scope heading, including subheadings.
// Page converters flatten heading levels, so a scope section can be followed
// by many "## " subheadings; only an unrelated major heading ends it.
func sections(policy string, words ...string) string {
	var out []string
	active := false
	badHeadings := []string{
		"out of scope", "not in scope", "exclusion", "not eligible", "not looking for",
		"prohibited", "ineligibility", "program rules", "disclosure", "submission",
		"payout", "leaderboard", "resources", "terms", "rules of engagement",
		"eligibility", "how to", "reporting", "contact", "default",
	}
	for _, line := range strings.Split(policy, "\n") {
		if strings.HasPrefix(line, "## ") {
			low := strings.ToLower(strings.TrimPrefix(line, "## "))
			stop := false
			for _, bad := range badHeadings {
				if strings.Contains(low, bad) {
					stop = true
					break
				}
			}
			keep := active
			if !stop {
				for _, w := range words {
					if strings.Contains(low, strings.ToLower(w)) {
						keep = true
						break
					}
				}
			}
			active = keep && !stop
			// A heading can name the asset itself, e.g.
			// "Web Applications (app.uniswap.org and ...)".
			if active {
				out = append(out, strings.TrimPrefix(line, "## "))
			}
			continue
		}
		if active && strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func extractCandidates(policy string) []Candidate {
	text := sections(policy, "in scope", "assets in scope", "scope", "target")
	emailDomains := map[string]bool{}
	for _, e := range emailRE.FindAllString(policy, -1) {
		if i := strings.LastIndex(e, "@"); i >= 0 {
			emailDomains[strings.ToLower(e[i+1:])] = true
		}
	}
	var out []Candidate
	seen := map[string]bool{}
	add := func(c Candidate) {
		if c.Identifier == "" || seen[c.Identifier] {
			return
		}
		seen[c.Identifier] = true
		out = append(out, c)
	}

	for _, raw := range urlRE.FindAllString(text, -1) {
		raw = strings.TrimRight(raw, ".,;:")
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if isNoiseHost(host) || strings.HasSuffix(host, ".etherscan.io") {
			continue
		}
		typ := "URL"
		if strings.Contains(host, "github.com") {
			typ = "SOURCE_CODE"
		} else if strings.Contains(strings.ToLower(u.Path), "api") {
			typ = "API"
		}
		add(Candidate{Identifier: raw, Host: host, Path: u.Path, Type: typ, Section: "in-scope section"})
	}

	for _, raw := range contractRE.FindAllString(text, -1) {
		add(Candidate{Identifier: raw, Type: "CONTRACT", Section: "in-scope section"})
	}

	for _, raw := range domainRE.FindAllString(text, -1) {
		host := strings.ToLower(strings.TrimSuffix(raw, "."))
		if isNoiseHost(host) || host == "github.com" || looksLikeFileHost(host) || len(host) < 5 ||
			strings.HasPrefix(host, "docs.") || emailDomains[host] {
			continue
		}
		add(Candidate{Identifier: host, Host: host, Type: "HOST", Section: "in-scope section"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identifier < out[j].Identifier })
	return out
}

func extractContractAssets(policy string) []Asset {
	var out []Asset
	seen := map[string]bool{}
	text := sections(policy, "assets in scope", "in scope", "scope")
	for _, m := range contractRE.FindAllString(text, -1) {
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, Asset{Identifier: m, Type: "CONTRACT", Eligible: true, Bounty: true})
	}
	return out
}

var (
	maxRewardRE = regexp.MustCompile(`(?i)(?:maximum bounty|max(?:imum)? payout|maximum reward|up to)\s*[:\-]?\s*\$?\s*([\d,.]+)\s*([kKmM]?)`)
	sevRewardRE = regexp.MustCompile(`(?im)(critical|high|medium|low|others|informational)[^$]{0,80}?\$\s*([\d,.]+)\s*([kKmM]?)`)
	// "Critical (<1M USDC)", "up to $300k", "200,000 USDT" style pages.
	sevCapRE = regexp.MustCompile(`(?im)(critical|high|medium|low|others|informational)\s*(?:[^$\n]{0,30}?)?[<(]?\s*(?:up to\s*)?\$?\s*([\d,.]+)\s*([kKmM]?)\s*(?:USDC|USDT|USD|\$)`)
)

func extractRewards(policy string) (int, []BountyRow) {
	max := 0
	if m := maxRewardRE.FindStringSubmatch(policy); m != nil {
		max = amount(m[1], m[2])
	}
	rows := []BountyRow{}
	seen := map[string]bool{}
	for _, m := range sevRewardRE.FindAllStringSubmatch(policy, -1) {
		name := strings.ToLower(m[1])
		n := amount(m[2], m[3])
		if n <= 0 || seen[name] {
			continue
		}
		seen[name] = true
		rows = append(rows, BountyRow{Name: name, Low: n})
		if len(rows) >= 8 {
			break
		}
	}
	for _, m := range sevCapRE.FindAllStringSubmatch(policy, -1) {
		name := strings.ToLower(m[1])
		if seen[name] {
			continue
		}
		if n := amount(m[2], m[3]); n > 0 {
			seen[name] = true
			rows = append(rows, BountyRow{Name: name, Low: n})
			if max < n {
				max = n
			}
		}
	}
	return max, rows
}

func amount(num, suffix string) int {
	n, err := strconv.ParseFloat(strings.ReplaceAll(num, ",", ""), 64)
	if err != nil {
		return 0
	}
	switch strings.ToLower(suffix) {
	case "k":
		n *= 1000
	case "m":
		n *= 1_000_000
	}
	if n > 100_000_000 {
		return 0
	}
	return int(n)
}

var (
	findingsRE = regexp.MustCompile(`(?is)(?:findings submitted|bug reports|submissions received)\s*[:\-]?\s*([\d,]+)`)
	paidRE     = regexp.MustCompile(`(?i)([\d,.]+[kKmM]?)\s+from\s+([\d,]+)\s+paid reports`)
)

func extractCounters(policy string) (resolved, reports int, known bool) {
	if m := paidRE.FindStringSubmatch(policy); m != nil {
		resolved = parseCount(m[2])
		known = true
	}
	if m := findingsRE.FindStringSubmatch(policy); m != nil {
		reports = parseCount(m[1])
		known = true
	}
	return resolved, reports, known
}

func parseCount(s string) int {
	s = strings.ReplaceAll(s, ",", "")
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

var constraintRules = []struct {
	pattern string
	label   string
}{
	{`(?i)(do not test|not test|no testing|testing (on|against)|must not test)[^\n]{0,100}(mainnet|production|live system)`, "Do NOT test on mainnet/production — use testnet or local forks"},
	{`(?i)proof of concept.{0,30}required|poc required|poc is always required`, "PoC required for every report"},
	{`(?i)\bkyc\b`, "KYC / identity verification required"},
	{`(?i)public disclosure`, "No public disclosure before the issue is fixed and paid"},
	{`(?i)phishing|social engineering`, "No phishing or social engineering"},
	{`(?i)third-party`, "Third-party systems and applications are out of scope"},
	{`(?i)denial.of.service|\bDoS\b`, "DoS testing is restricted — read the exact wording"},
	{`(?i)local.?fork|foundry`, "Local forks / Foundry are the expected test environment"},
	{`(?i)deposit required`, "A deposit is required to submit"},
}

func extractConstraints(policy string) []string {
	text := plain(policy)
	var out []string
	for _, r := range constraintRules {
		if regexp.MustCompile(r.pattern).MatchString(text) {
			out = append(out, r.label)
		}
	}
	return strutil.Unique(out)
}

func pageTitle(htmlBody []byte, text string) string {
	if m := ogTitleRE.FindSubmatch(htmlBody); m != nil {
		return cleanTitle(string(m[1]))
	}
	if m := titleRE.FindSubmatch(htmlBody); m != nil {
		return cleanTitle(string(m[1]))
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "## ") {
			return cleanTitle(strings.TrimPrefix(line, "## "))
		}
	}
	return "program"
}

func cleanTitle(s string) string {
	s = html.UnescapeString(strings.TrimSpace(s))
	if i := strings.IndexAny(s, "|—–"); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func slugFromURL(raw string) string {
	parts := strings.Split(strings.Trim(raw, "/"), "/")
	s := parts[len(parts)-1]
	s = strings.ToLower(regexp.MustCompile(`[^a-z0-9._-]+`).ReplaceAllString(s, "-"))
	return strings.Trim(s, "-")
}

func websiteFromURL(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}
