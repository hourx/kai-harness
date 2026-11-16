package recon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/hourx/kai/internal/netx"
)

var (
	// Quoted absolute paths inside JS bundles.
	jsPathRE      = regexp.MustCompile("[\"'`](/[A-Za-z0-9_\\-./{}:$]{2,120})[\"'`]")
	paramRE       = regexp.MustCompile(`[?&]([A-Za-z_][A-Za-z0-9_-]{0,40})=`)
	colonParamRE  = regexp.MustCompile(`:[A-Za-z_][A-Za-z0-9_]*`)
	dollarParamRE = regexp.MustCompile(`\$\{[^}]{1,40}\}`)
	staticExt     = map[string]bool{
		".js": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
		".ico": true, ".css": true, ".woff": true, ".woff2": true, ".ttf": true,
		".eot": true, ".map": true, ".mp4": true, ".webp": true, ".avif": true,
	}
)

// PathOf returns the normalized path of rawurl and its query parameter names.
func PathOf(rawurl string) (string, []string) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", nil
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	if path == "" {
		path = "/"
	}
	if isStatic(path) {
		return "", nil
	}
	var params []string
	for _, m := range paramRE.FindAllStringSubmatch(u.RawQuery, -1) {
		params = append(params, m[1])
	}
	for k := range u.Query() {
		params = append(params, k)
	}
	return path, Uniq(params)
}

// isJSURL accepts versioned bundles whose query string follows ".js".
func isJSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Path != "" && strings.HasSuffix(strings.ToLower(u.Path), ".js")
}

// normalizePath collapses the many placeholder styles found in JS bundles
// (":id", "${id}", "${this.appId}") into one "{id}" form so the same endpoint
// does not produce several duplicate hypotheses.
func normalizePath(path string) string {
	p := dollarParamRE.ReplaceAllString(path, "{id}")
	p = colonParamRE.ReplaceAllString(p, "{id}")
	return p
}

// looksLikeEndpoint rejects strings that JS regexes commonly mistake for
// API paths: "/412", "/12345", "/ab", template junk and double slashes.
func looksLikeEndpoint(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") || strings.Contains(path, "//") {
		return false
	}
	if strings.HasPrefix(strings.ToLower(path), "/cdn-cgi/") {
		return false // Cloudflare challenge artifacts, not app endpoints
	}
	letters := 0
	for _, r := range path {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			letters++
		}
	}
	if letters < 3 {
		return false
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for _, s := range segs {
		if s == "" || strings.Trim(s, "{}:$") == "" {
			return false
		}
	}
	return true
}

func isStatic(path string) bool {
	low := strings.ToLower(path)
	for ext := range staticExt {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

// Bundle is a fetched JavaScript file.
type Bundle struct {
	URL   string
	SHA   string
	Bytes int
	Body  []byte
}

// FetchBundles downloads up to limit bundles concurrently.
func FetchBundles(ctx context.Context, c *netx.Client, urls []string, limit int) []Bundle {
	if len(urls) > limit {
		urls = urls[:limit]
	}
	var (
		mu  sync.Mutex
		out []Bundle
		wg  sync.WaitGroup
		sem = make(chan struct{}, 8)
	)
	for _, u := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resp, err := c.Get(ctx, u, 4<<20)
			if err != nil || resp.StatusCode >= 400 {
				return
			}
			sum := sha256.Sum256(resp.Body)
			b := Bundle{URL: u, SHA: hex.EncodeToString(sum[:]), Bytes: len(resp.Body), Body: resp.Body}
			mu.Lock()
			out = append(out, b)
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// HistoricalURLs asks gau and waybackurls for archived URLs under domain.
func HistoricalURLs(ctx context.Context, domain string, adapters map[string]string) []string {
	var (
		mu  sync.Mutex
		out []string
		wg  sync.WaitGroup
	)
	collect := func(list []string) {
		mu.Lock()
		out = append(out, list...)
		mu.Unlock()
	}
	if path, ok := adapters["gau"]; ok {
		wg.Add(1)
		go func() { defer wg.Done(); collect(runTool(ctx, path, "--subs", domain)) }()
	}
	if path, ok := adapters["waybackurls"]; ok {
		wg.Add(1)
		go func() { defer wg.Done(); collect(runTool(ctx, path, domain)) }()
	}
	wg.Wait()

	clean := make([]string, 0, len(out))
	for _, raw := range out {
		raw = strings.TrimSpace(raw)
		if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
			continue
		}
		clean = append(clean, raw)
		if len(clean) >= 20000 {
			break
		}
	}
	return Uniq(clean)
}

// ExtractPaths turns URLs and JS bodies into a path -> params map.
func ExtractPaths(urls []string, bundles []Bundle) map[string][]string {
	found := map[string][]string{}
	absorb := func(raw string) {
		path, params := PathOf(raw)
		if path == "" {
			return
		}
		path = normalizePath(path)
		if !looksLikeEndpoint(path) {
			return
		}
		found[path] = Uniq(found[path], params)
	}
	for _, u := range urls {
		absorb(u)
	}
	for _, b := range bundles {
		for _, m := range jsPathRE.FindAllSubmatch(b.Body, -1) {
			absorb("https://placeholder" + string(m[1]))
		}
		for _, m := range paramRE.FindAllSubmatch(b.Body, -1) {
			// Parameters mentioned in JS are attached to no path of their own;
			// keep them under a synthetic key so they are not lost.
			found["*"] = Uniq(found["*"], []string{string(m[1])})
		}
	}
	return found
}
