package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/internal/netx"
)

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"/api/v1/apps/${this.appId}/smart_wallets": "/api/v1/apps/{id}/smart_wallets",
		"/api/v1/apps/:app_id/smart_wallets":       "/api/v1/apps/{id}/smart_wallets",
		"/explorer/tx/${e.txHash}":                 "/explorer/tx/{id}",
		"/charting_library/v${bu}":                 "/charting_library/v{id}",
		"/api/v1/users/42":                         "/api/v1/users/42",
	}
	for raw, want := range cases {
		if got := normalizePath(raw); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestIsJSURL(t *testing.T) {
	cases := map[string]bool{
		"https://testnet.ticko.xyz/assets/app.js":     true,
		"https://testnet.ticko.xyz/assets/app.js?v=7": true,
		"https://testnet.ticko.xyz/assets/app.JS#x":   true,
		"https://testnet.ticko.xyz/dashboard":         false,
		"https://testnet.ticko.xyz/app.jsx":           false,
	}
	for raw, want := range cases {
		if got := isJSURL(raw); got != want {
			t.Errorf("isJSURL(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestLooksLikeEndpoint(t *testing.T) {
	cases := map[string]bool{
		"/api/v1/users": true,
		"/api/users/42": true,
		"/412":          false,
		"/12345":        false,
		"/ab":           false,
		"//api":         false,
		"/app.js":       true, // PathOf filters static extensions later
	}
	for path, want := range cases {
		if got := looksLikeEndpoint(path); got != want {
			t.Errorf("looksLikeEndpoint(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestPathOf(t *testing.T) {
	cases := []struct {
		raw        string
		wantPath   string
		wantParams []string
	}{
		{"https://api.example.com/v1/users/42?id=7&sort=asc", "/v1/users/42", []string{"id", "sort"}},
		{"https://api.example.com/v1/users/", "/v1/users", nil},
		{"https://api.example.com/", "/", nil},
		{"https://api.example.com/static/app.js", "", nil},
		{"https://api.example.com/logo.PNG", "", nil},
	}
	for _, tc := range cases {
		path, params := PathOf(tc.raw)
		if path != tc.wantPath {
			t.Errorf("PathOf(%q) path = %q, want %q", tc.raw, path, tc.wantPath)
		}
		if len(params) != len(tc.wantParams) {
			t.Errorf("PathOf(%q) params = %v, want %v", tc.raw, params, tc.wantParams)
			continue
		}
		for i := range tc.wantParams {
			if params[i] != tc.wantParams[i] {
				t.Errorf("PathOf(%q) params = %v, want %v", tc.raw, params, tc.wantParams)
			}
		}
	}
}

func TestNormalizeHosts(t *testing.T) {
	got := normalizeHosts("example.com", []string{
		"*.example.com", "API.Example.com.", "example.com",
		"example.com.evil.test", "other.test", "a.b.example.com",
	})
	want := map[string]bool{"example.com": true, "api.example.com": true, "a.b.example.com": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %d entries", got, len(want))
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("unexpected host %q", h)
		}
	}
}

func TestExtractLinks(t *testing.T) {
	body := []byte(`
		<html><head>
		<script src="/static/app.js"></script>
		<script src="https://cdn.example.com/lib.js"></script>
		</head><body>
		<a href="/dashboard">d</a>
		<a href="mailto:x@example.com">m</a>
		<a href="#top">t</a>
		</body></html>`)
	links, js := extractLinks("https://app.example.com/login", body)

	if len(js) != 2 {
		t.Fatalf("js = %v, want 2 entries", js)
	}
	for _, want := range []string{"https://app.example.com/static/app.js", "https://cdn.example.com/lib.js"} {
		found := false
		for _, j := range js {
			if j == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing js %q in %v", want, js)
		}
	}
	if len(links) != 1 || links[0] != "https://app.example.com/dashboard" {
		t.Errorf("links = %v", links)
	}
}

func TestComputeDiff(t *testing.T) {
	now := time.Now().UTC()
	prev := NewStore("p")
	prev.Host("old.example.com", now)
	prev.Endpoint("/v1/users", now).Params = []string{"id"}
	prev.Bundle("https://a/app.js", "aaaa", 10, now)

	cur := NewStore("p")
	cur.Host("old.example.com", now)
	cur.Host("new.example.com", now)
	cur.Endpoint("/v1/users", now).Params = []string{"id", "role"}
	cur.Endpoint("/v2/admin", now)
	cur.Bundle("https://a/app.js", "bbbb", 10, now)

	d := ComputeDiff(prev, cur, "t1", "t2")
	if len(d.NewHosts) != 1 || d.NewHosts[0].Host != "new.example.com" {
		t.Errorf("NewHosts = %+v", d.NewHosts)
	}
	if len(d.NewEndpoints) != 1 || d.NewEndpoints[0] != "/v2/admin" {
		t.Errorf("NewEndpoints = %v", d.NewEndpoints)
	}
	if len(d.NewParams) != 1 || d.NewParams[0] != "role" {
		t.Errorf("NewParams = %v", d.NewParams)
	}
	if len(d.ChangedJS) != 1 || d.ChangedJS[0].Old != "aaaa" || d.ChangedJS[0].New != "bbbb" {
		t.Errorf("ChangedJS = %+v", d.ChangedJS)
	}
}

func TestComputeDiffBaseline(t *testing.T) {
	cur := NewStore("p")
	cur.Host("a.example.com", time.Now().UTC())
	d := ComputeDiff(nil, cur, "", "t1")
	if !d.Baseline {
		t.Fatal("nil previous store must produce a baseline diff")
	}
	if !strings.Contains(d.Markdown(), "Baseline") {
		t.Errorf("markdown should mention baseline:\n%s", d.Markdown())
	}
}

func TestProbeAgainstLocalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>  Admin  Panel </title></head>
			<body><script src="/app.js"></script><a href="/login">l</a></body></html>`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	c := netx.New("kai-test", 20, nil)
	defer c.Close()

	res := Probe(context.Background(), c, host, []string{"127.0.0.1"}, "")
	if res.Status != 200 {
		t.Fatalf("status = %d", res.Status)
	}
	if res.Title != "Admin Panel" {
		t.Errorf("title = %q", res.Title)
	}
	if len(res.JS) != 1 || !strings.HasSuffix(res.JS[0], "/app.js") {
		t.Errorf("js = %v", res.JS)
	}
	foundServer := false
	for _, tech := range res.Tech {
		if tech == "server:nginx/1.25" {
			foundServer = true
		}
	}
	if !foundServer {
		t.Errorf("tech = %v, want server:nginx/1.25", res.Tech)
	}
}
