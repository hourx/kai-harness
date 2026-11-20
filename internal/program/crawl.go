package program

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/hourx/kai-harness/internal/netx"
)

// FetchOptions controls how much of a program's documentation is read.
type FetchOptions struct {
	Follow   bool
	MaxLinks int
}

func (o FetchOptions) defaults() FetchOptions {
	if o.MaxLinks == 0 {
		o.MaxLinks = 8
	}
	if o.MaxLinks < 0 {
		o.MaxLinks = 0
	}
	return o
}

var (
	mdLinkRE  = regexp.MustCompile(`\]\((https?://[^)\s]+)\)`)
	bareURLRE = regexp.MustCompile(`https?://[^\s<>"')\]}]+`)
	// JS-heavy pages hide their documentation links in href attributes; the
	// readable text often contains only the anchor label. Read both.
	hrefRE     = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
	relevantRE = regexp.MustCompile(`(?i)(testnet|mainnet|bug.?bounty|security|report|submit|reward|scope|policy|faucet|guide|api|developer|docs|whitepaper|terms)`)
	// llms.txt is not an asset to skip: it is the machine-readable rulebook for
	// AI agents. It is fetched first-class and does not consume the doc cap.
	llmsRE    = regexp.MustCompile(`(?i)^.*/llms\.txt$|^llms\.txt$`)
	skipAsset = regexp.MustCompile(`(?i)\.(png|jpe?g|gif|svg|ico|woff2?|ttf|pdf|zip|json|js|css)(\?|$)|/files/|/assets/|_next/`)
)

// linkScore ranks doc links before the fetch cap is applied. A cap that fills
// up with "Hall of fame" and payment settings is worse than no cap: the pages
// that define scope are never read and the agent is handed a partial policy.
func linkScore(u *url.URL) int {
	p := strings.ToLower(u.Path)
	score := 0
	for _, kw := range []struct {
		word string
		pts  int
	}{
		{"main-scope", 100}, {"rules", 90}, {"scope", 80}, {"report", 70},
		{"security", 60}, {"testnet", 60}, {"ai-security", 55}, {"policy", 50},
		{"terms", 40}, {"faq", 40}, {"guide", 30}, {"docs", 20}, {"api", 20},
	} {
		if strings.Contains(p, kw.word) {
			score += kw.pts
		}
	}
	for _, low := range []string{"payment", "hall-of-fame", "anniversary", "blog", "index"} {
		if strings.Contains(p, low) {
			score -= 60
		}
	}
	return score
}

// pageDoc keeps a fetched page's own scope sections verbatim. A merged policy
// loses which rule came from which category page; export needs that mapping.
func pageDoc(title, url, text string) PageDoc {
	if len(text) > 40_000 {
		text = text[:40_000] + "\n[… truncated; see the source page]"
	}
	return PageDoc{
		URL:        url,
		Title:      title,
		Scope:      trimExcerpt(sectionByTitle(text, "in scope", "scope", "assets in scope")),
		OutOfScope: trimExcerpt(sectionByTitle(text, "out of scope", "not in scope", "exclusions")),
		Body:       text,
	}
}

// followReferences reads other pages linked from the main policy. Public bug
// bounty docs routinely split scope, testnet access and submission rules over
// several pages; reading only the first one gives a dangerously partial view.
//
// Only pages on the same registrable domain are followed, with a hard cap, so
// this never turns into an unbounded crawl of the whole internet.
func followReferences(ctx context.Context, c *netx.Client, primary *url.URL, policy, rawHTML string, opts FetchOptions, gitbook bool) ([]Reference, []Reference, []string, []Candidate, []PageDoc, []Reference) {
	opts = opts.defaults()
	if opts.MaxLinks == 0 {
		return nil, nil, nil, nil, nil, nil
	}
	base := baseDomain(primary.Hostname())
	selfPath := strings.TrimSuffix(strings.ToLower(primary.Path), "/")
	seen := map[string]bool{strings.TrimSuffix(primary.String(), "/"): true}
	scores := map[string]int{}
	var targets, discovered, llmsTargets []string

	consider := func(raw string) {
		raw = strings.TrimRight(raw, ".,;:)>")
		raw = strings.ReplaceAll(raw, "&amp;", "&")
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		// Most landing pages use relative hrefs. Without this, every doc
		// link on a JS-rendered policy page is dropped before it is seen.
		if u.Hostname() == "" {
			u = primary.ResolveReference(u)
		}
		if u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		q := u.Query()
		if q.Has("ask") || q.Has("goal") {
			return
		}
		// "#lc-icon__burger" is a UI anchor, not a documentation page.
		if u.Fragment != "" && strings.TrimSuffix(strings.ToLower(u.Path), "/") == selfPath {
			return
		}
		if llmsRE.MatchString(strings.ToLower(u.Path)) {
			key := strings.TrimSuffix(u.String(), "/")
			if !seen[key] {
				seen[key] = true
				llmsTargets = append(llmsTargets, u.String())
			}
			return // fetched first-class, outside the documentation cap
		}
		if skipAsset.MatchString(u.String()) {
			return
		}
		host := strings.ToLower(u.Hostname())
		trimmedPath := strings.TrimSuffix(strings.ToLower(u.Path), ".md")
		if trimmedPath == selfPath && strings.HasSuffix(u.Path, ".md") {
			return // the same page in markdown form, not a new reference
		}
		if host != primary.Hostname() && !strings.HasSuffix(host, "."+base) {
			return
		}
		if !relevantRE.MatchString(u.Path + " " + u.String()) {
			return
		}
		key := strings.TrimSuffix(u.String(), "/")
		if seen[key] {
			return
		}
		seen[key] = true
		scores[u.String()] = linkScore(u)
		if len(discovered) < 50 {
			discovered = append(discovered, u.String())
		}
		targets = append(targets, u.String())
	}

	for _, m := range mdLinkRE.FindAllStringSubmatch(policy, -1) {
		consider(m[1])
	}
	for _, raw := range bareURLRE.FindAllString(policy, -1) {
		consider(raw)
	}
	for _, m := range hrefRE.FindAllStringSubmatch(rawHTML, -1) {
		consider(m[1])
	}

	// Fetch the useful pages first. A DOM-order cap fills up with payment
	// settings and the hall of fame while scope rules stay unread.
	sort.SliceStable(targets, func(i, j int) bool {
		return scores[targets[i]] > scores[targets[j]]
	})
	if len(targets) > opts.MaxLinks {
		targets = targets[:opts.MaxLinks]
	}

	var refs []Reference
	var texts []string
	var found []Candidate
	var docs []PageDoc
	discoveredRefs := make([]Reference, 0, len(discovered))
	for _, u := range discovered {
		discoveredRefs = append(discoveredRefs, Reference{URL: u, Status: "seen"})
	}
	for _, target := range targets {
		title, text, _, err := fetchPage(ctx, c, target, gitbook)
		ref := Reference{URL: target, Title: title, Status: "read"}
		if err != nil {
			ref.Status = "error: " + err.Error()
		} else if len(text) < 100 {
			ref.Status = "empty"
		} else {
			texts = append(texts, fmt.Sprintf("## Referenced page: %s\nSource: %s\n\n%s", title, target, text))
			found = append(found, hostsFromText(text, title)...)
			docs = append(docs, pageDoc(title, target, text))
		}
		refs = append(refs, ref)
	}

	// llms.txt is the machine-readable rulebook for AI agents. Fetch it even
	// when MaxLinks is exhausted; it is mandatory context and never a finding.
	var llmsRefs []Reference
	for _, target := range llmsTargets {
		title, text, _, err := fetchPage(ctx, c, target, gitbook)
		ref := Reference{URL: target, Title: title, Status: "read"}
		if err != nil {
			ref.Status = "error: " + err.Error()
		} else if len(text) < 100 {
			ref.Status = "empty"
		} else {
			llmTitle := title
			if llmTitle == "" {
				llmTitle = "llms.txt"
			}
			texts = append(texts, fmt.Sprintf("## AI-agent rules: %s\nSource: %s\n\n%s", llmTitle, target, text))
			docs = append(docs, pageDoc(llmTitle, target, text))
		}
		llmsRefs = append(llmsRefs, ref)
	}
	return refs, discoveredRefs, texts, found, docs, llmsRefs
}

// hostsFromText picks up concrete hosts mentioned in a linked page, such as
// "Go to testnet.ticko.xyz". They stay unverified candidates — a docs link is
// not automatically an in-scope test target.
func hostsFromText(text, section string) []Candidate {
	emails := map[string]bool{}
	for _, e := range emailRE.FindAllString(text, -1) {
		if i := strings.LastIndex(e, "@"); i >= 0 {
			emails[strings.ToLower(e[i+1:])] = true
		}
	}
	seen := map[string]bool{}
	var out []Candidate
	add := func(raw string) {
		raw = strings.TrimRight(raw, ".,;:)>")
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return
		}
		host := strings.ToLower(u.Hostname())
		if isNoiseHost(host) || emails[host] || looksLikeFileHost(host) || strings.HasPrefix(host, "docs.") || len(host) < 5 {
			return
		}
		if seen[host] {
			return
		}
		path := u.Path
		if path == "/" {
			path = ""
		}
		seen[host] = true
		out = append(out, Candidate{Identifier: host, Host: host, Path: path, Type: "HOST", Section: section})
	}
	for _, raw := range urlRE.FindAllString(text, -1) {
		add(raw)
	}
	for _, raw := range domainRE.FindAllString(text, -1) {
		add(raw)
	}
	return out
}

// fetchPage reads one linked page, preferring GitBook's markdown variant.
func fetchPage(ctx context.Context, c *netx.Client, raw string, gitbook bool) (title, text string, status int, err error) {
	resp, err := c.Get(ctx, raw, 2<<20)
	if err != nil {
		return "", "", 0, err
	}
	status, body := resp.StatusCode, resp.Body
	pureMD := strings.HasSuffix(strings.ToLower(raw), ".md")
	if gitbook && !pureMD {
		md := strings.TrimSuffix(raw, "/") + ".md"
		if r, e := c.Get(ctx, md, 2<<20); e == nil && r.StatusCode == 200 && len(r.Body) > 100 {
			status, body, pureMD = r.StatusCode, r.Body, true
		}
	}
	if status != 200 && !(status == 400 && len(body) > 1000) {
		return "", "", status, fmt.Errorf("HTTP %d", status)
	}
	if pureMD {
		text = mdHeadingRE.ReplaceAllString(html.UnescapeString(string(body)), "## ")
	} else {
		text = htmlToText(body)
	}
	return pageTitle(body, text), text, status, nil
}

func baseDomain(host string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(host, ".")), ".")
	if len(parts) <= 2 {
		return strings.Join(parts, ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
