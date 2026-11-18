package program

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/hourx/kai/internal/netx"
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
	skipAsset  = regexp.MustCompile(`(?i)\.(png|jpe?g|gif|svg|ico|woff2?|ttf|pdf|zip|json|js|css)(\?|$)|/files/|llms\.txt|/assets/|_next/`)
)

// followReferences reads other pages linked from the main policy. Public bug
// bounty docs routinely split scope, testnet access and submission rules over
// several pages; reading only the first one gives a dangerously partial view.
//
// Only pages on the same registrable domain are followed, with a hard cap, so
// this never turns into an unbounded crawl of the whole internet.
func followReferences(ctx context.Context, c *netx.Client, primary *url.URL, policy, rawHTML string, opts FetchOptions, gitbook bool) ([]Reference, []Reference, []string, []Candidate) {
	opts = opts.defaults()
	if opts.MaxLinks == 0 {
		return nil, nil, nil, nil
	}
	base := baseDomain(primary.Hostname())
	selfPath := strings.TrimSuffix(strings.ToLower(primary.Path), "/")
	seen := map[string]bool{strings.TrimSuffix(primary.String(), "/"): true}
	var targets, discovered []string

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
		if len(discovered) < 50 {
			discovered = append(discovered, u.String())
		}
		if len(targets) < opts.MaxLinks {
			targets = append(targets, u.String())
		}
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

	var refs []Reference
	var texts []string
	var found []Candidate
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
		}
		refs = append(refs, ref)
	}
	return refs, discoveredRefs, texts, found
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
