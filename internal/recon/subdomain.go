package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hourx/kai-harness/internal/netx"
)

// Discover collects candidate hosts for a base domain from every available
// source: subfinder, assetfinder, crt.sh and Cert Spotter. The apex is always
// seeded.
//
// Adapters are used when present because they are faster; the public CT APIs
// are the fallback that always exists, and they are queried independently so
// one provider being down does not empty the result.
func Discover(ctx context.Context, c *netx.Client, domain string, adapters map[string]string) ([]string, []string) {
	type result struct {
		name  string
		hosts []string
		note  string
	}
	var (
		mu      sync.Mutex
		hosts   []string
		sources []string
	)
	add := func(r result) {
		clean := normalizeHosts(domain, r.hosts)
		mu.Lock()
		defer mu.Unlock()
		if len(clean) == 0 {
			note := r.note
			if note == "" {
				note = "empty"
			}
			sources = append(sources, fmt.Sprintf("%s(%s)", r.name, note))
			return
		}
		hosts = append(hosts, clean...)
		sources = append(sources, r.name)
	}

	var wg sync.WaitGroup
	run := func(fn func() result) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			add(fn())
		}()
	}
	if path, ok := adapters["subfinder"]; ok {
		run(func() result {
			return result{name: "subfinder", hosts: runTool(ctx, path, "-d", domain, "-silent")}
		})
	}
	if path, ok := adapters["assetfinder"]; ok {
		run(func() result {
			return result{name: "assetfinder", hosts: runTool(ctx, path, "--subs-only", domain)}
		})
	}
	run(func() result {
		list, note := crtSh(ctx, c, domain)
		return result{name: "crt.sh", hosts: list, note: note}
	})
	run(func() result {
		list, note := certSpotter(ctx, c, domain)
		return result{name: "certspotter", hosts: list, note: note}
	})
	wg.Wait()

	hosts = append(hosts, domain)
	if len(sources) == 0 {
		sources = append(sources, "seed")
	}
	return Uniq(hosts), Uniq(sources)
}

// normalizeHosts lowercases, strips wildcard prefixes and keeps only hosts
// that belong to domain.
func normalizeHosts(domain string, raw []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, h := range raw {
		h = strings.ToLower(strings.TrimSpace(h))
		h = strings.TrimPrefix(h, "*.")
		h = strings.TrimSuffix(h, ".")
		if h == "" || strings.ContainsAny(h, " \t/?#@") {
			continue
		}
		if h != domain && !strings.HasSuffix(h, "."+domain) {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

func runTool(ctx context.Context, path string, args ...string) []string {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

// getJSON performs a GET with retries. Public CT endpoints return 502 and
// malformed bodies often enough that a single attempt is not trustworthy.
func getJSON(ctx context.Context, c *netx.Client, endpoint string, max int64, out any) (string, error) {
	var last string
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := c.Get(ctx, endpoint, max)
		switch {
		case err != nil:
			last = "error"
		case resp.StatusCode != 200:
			last = fmt.Sprintf("status %d", resp.StatusCode)
		default:
			if err := json.Unmarshal(resp.Body, out); err == nil {
				return "ok", nil
			}
			last = "invalid json"
		}
		if ctx.Err() != nil {
			return last, ctx.Err()
		}
		backoff := time.Duration(attempt+1) * 2 * time.Second
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return last, ctx.Err()
		}
	}
	return last, fmt.Errorf("all attempts failed: %s", last)
}

type crtEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

// crtSh queries certificate transparency for every known name under domain.
func crtSh(ctx context.Context, c *netx.Client, domain string) ([]string, string) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	endpoint := "https://crt.sh/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	var entries []crtEntry
	status, err := getJSON(ctx, c, endpoint, 32<<20, &entries)
	if err != nil {
		return nil, status
	}
	var out []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			if name = strings.TrimSpace(name); name != "" {
				out = append(out, name)
			}
		}
		if e.CommonName != "" {
			out = append(out, e.CommonName)
		}
		if len(out) >= 5000 {
			break
		}
	}
	return out, "ok"
}

type csEntry struct {
	DNSNames []string `json:"dns_names"`
}

// certSpotter is a second CT source; it tends to answer when crt.sh is down.
func certSpotter(ctx context.Context, c *netx.Client, domain string) ([]string, string) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	endpoint := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(domain) +
		"&include_subdomains=true&expand=dns_names"
	var entries []csEntry
	status, err := getJSON(ctx, c, endpoint, 32<<20, &entries)
	if err != nil {
		return nil, status
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.DNSNames...)
		if len(out) >= 5000 {
			break
		}
	}
	return out, "ok"
}
