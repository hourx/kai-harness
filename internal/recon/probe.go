package recon

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/internal/netx"
)

var (
	titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	tagRE   = regexp.MustCompile(`(?s)<[^>]+>`)
	linkRE  = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)["']`)
	spaceRE = regexp.MustCompile(`\s+`)
)

// ProbeResult is everything learned about one host in a single pass.
type ProbeResult struct {
	Host   string
	IPs    []string
	CNAME  string
	URL    string
	Status int
	Title  string
	Tech   []string
	TLS    *TLSInfo
	Links  []string
	JS     []string
}

// Resolve returns the A/AAAA records and canonical name for host.
func Resolve(ctx context.Context, host string) ([]string, string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var ips []string
	if addrs, err := net.DefaultResolver.LookupHost(ctx, host); err == nil {
		ips = append(ips, addrs...)
		sort.Strings(ips)
	}
	cname := ""
	if c, err := net.DefaultResolver.LookupCNAME(ctx, host); err == nil {
		c = strings.TrimSuffix(c, ".")
		if !strings.EqualFold(c, host) {
			cname = c
		}
	}
	return ips, cname
}

// Probe requests https then http for host and records what came back.
func Probe(ctx context.Context, c *netx.Client, host string, ips []string, cname string) ProbeResult {
	res := ProbeResult{Host: host, IPs: ips, CNAME: cname}

	for _, scheme := range []string{"https", "http"} {
		target := scheme + "://" + host + "/"
		resp, err := c.Get(ctx, target, 2<<20)
		if err != nil {
			continue
		}
		res.URL = resp.FinalURL
		res.Status = resp.StatusCode
		res.Tech = detectTech(resp.Header, resp.Body)
		if resp.TLS != nil {
			res.TLS = tlsInfo(resp.TLS)
		}
		ctype := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.Contains(ctype, "html") || ctype == "" {
			res.Title = extractTitle(resp.Body)
			res.Links, res.JS = extractLinks(resp.FinalURL, resp.Body)
		}
		return res
	}
	return res
}

func extractTitle(body []byte) string {
	m := titleRE.FindSubmatch(body)
	if m == nil {
		return ""
	}
	title := spaceRE.ReplaceAllString(string(tagRE.ReplaceAll(m[1], []byte(" "))), " ")
	title = strings.TrimSpace(title)
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}

// extractLinks returns absolute URLs found in the document, split into
// page links and script bundles.
func extractLinks(base string, body []byte) (links, js []string) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, nil
	}
	seen := map[string]struct{}{}
	for _, m := range linkRE.FindAllSubmatch(body, -1) {
		raw := strings.TrimSpace(string(m[1]))
		if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "mailto:") {
			continue
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := baseURL.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			continue
		}
		key := abs.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if strings.HasSuffix(strings.ToLower(abs.Path), ".js") {
			js = append(js, key)
			continue
		}
		links = append(links, key)
	}
	sort.Strings(links)
	sort.Strings(js)
	return links, js
}

// tlsInfo records the leaf certificate so an expired or mismatched cert shows
// up in the pack instead of being hidden by the client.
func tlsInfo(st *tls.ConnectionState) *TLSInfo {
	if st == nil || len(st.PeerCertificates) == 0 {
		return nil
	}
	leaf := st.PeerCertificates[0]
	return &TLSInfo{
		Subject:  leaf.Subject.CommonName,
		Issuer:   leaf.Issuer.CommonName,
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
		Expired:  time.Now().After(leaf.NotAfter),
		SANs:     Uniq(leaf.DNSNames),
	}
}

// detectTech infers the stack from headers, cookies and body markers.
func detectTech(h map[string][]string, body []byte) []string {
	seen := map[string]struct{}{}
	add := func(t string) { seen[t] = struct{}{} }

	header := func(name string) string {
		for k, v := range h {
			if strings.EqualFold(k, name) && len(v) > 0 {
				return v[0]
			}
		}
		return ""
	}

	if s := header("Server"); s != "" {
		add("server:" + firstWord(s))
	}
	if s := header("X-Powered-By"); s != "" {
		add("powered-by:" + firstWord(s))
	}
	if header("CF-Ray") != "" {
		add("cloudflare")
	}
	if header("X-Vercel-Id") != "" || header("X-Vercel-Cache") != "" {
		add("vercel")
	}
	if header("X-Amz-Cf-Id") != "" {
		add("cloudfront")
	}
	if header("X-Generator") != "" {
		add("generator:" + firstWord(header("X-Generator")))
	}
	for _, c := range h["Set-Cookie"] {
		low := strings.ToLower(c)
		switch {
		case strings.Contains(low, "phpsessid"):
			add("php")
		case strings.Contains(low, "jsessionid"):
			add("java")
		case strings.Contains(low, "laravel_session"):
			add("laravel")
		case strings.Contains(low, "wordpress"):
			add("wordpress")
		case strings.Contains(low, "awsalb"):
			add("aws-alb")
		}
	}

	hay := strings.ToLower(string(body))
	markers := map[string]string{
		"/_next/":        "nextjs",
		"wp-content":     "wordpress",
		"__nuxt__":       "nuxt",
		"ng-version":     "angular",
		"data-reactroot": "react",
		"__vue__":        "vue",
		"jquery":         "jquery",
		"drupal":         "drupal",
		"shopify":        "shopify",
	}
	for marker, tech := range markers {
		if strings.Contains(hay, marker) {
			add(tech)
		}
	}

	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func firstWord(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return s
	}
	return fields[0]
}
