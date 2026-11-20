package program

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hourx/kai-harness/pkg/netx"
)

func TestHeaderFalsePositiveFromGitBookImage(t *testing.T) {
	policy := "See ![img](https://1035376029-files.gitbook.io/~/files/v0/gitbook-x-prod.appspot.com/image.png)\n" +
		"Research header: X-HackerOne-Research: username\n"
	b := ExtractBoundaries(policy, "heuristic")
	if len(b.RequiredHeaders) != 1 || b.RequiredHeaders[0] != "X-HACKERONE-RESEARCH" {
		t.Errorf("RequiredHeaders = %v, want only the real research header", b.RequiredHeaders)
	}
}

func TestHrefDiscoveryFromJSLanding(t *testing.T) {
	shellHTML := `<html><body><div id="root">Bug bounty</div>` +
		`<a href="/bugbounty/i/cloud">Cloud</a>` +
		`<a href="/bugbounty/i/report">Report</a>` +
		`<a href="/bugbounty/i/llms.txt">llms</a>` +
		`<a href="/bugbounty/#lc-icon__burger">menu</a>` +
		`</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/bugbounty/i/") {
			w.Write([]byte("Documentation page with enough readable text to be fetched. " +
				"Scope rules live on api.example.com. Report to security@example.com."))
			return
		}
		// A JS shell: readable text is short, but every doc link is in an href.
		w.Write([]byte(shellHTML))
	}))
	defer srv.Close()

	c := netx.New("test", 50, nil)
	defer c.Close()
	u, _ := url.Parse(srv.URL + "/bugbounty")
	refs, discovered, texts, _, docs, llmsRefs := followReferences(context.Background(), c, u,
		"Bug bounty program", shellHTML,
		FetchOptions{MaxLinks: 1}, false)

	if len(discovered) < 2 {
		t.Fatalf("discovered = %+v, want relative hrefs from the HTML shell", discovered)
	}
	seen := map[string]bool{}
	for _, d := range discovered {
		seen[d.URL] = true
	}
	if !seen[srv.URL+"/bugbounty/i/cloud"] || !seen[srv.URL+"/bugbounty/i/report"] {
		t.Errorf("discovered missing relative links: %+v", discovered)
	}
	if seen[srv.URL+"/bugbounty/i/llms.txt"] {
		t.Errorf("llms.txt must be filtered as an asset: %+v", discovered)
	}
	for _, d := range discovered {
		if strings.Contains(d.URL, "#lc-icon__burger") {
			t.Errorf("UI anchor must not be a reference: %+v", discovered)
		}
	}
	if len(refs) != 1 {
		t.Fatalf("refs=%+v, want one capped doc page", refs)
	}
	if len(llmsRefs) != 1 || !strings.Contains(llmsRefs[0].URL, "llms.txt") {
		t.Errorf("llmsRefs=%+v, want llms.txt fetched first-class", llmsRefs)
	}
	if len(docs) != 2 || len(texts) != 2 {
		t.Fatalf("docs=%d texts=%d, want one normal page plus llms.txt", len(docs), len(texts))
	}
	if !strings.Contains(refs[0].URL, "/i/report") {
		t.Errorf("cap picked %s, want the higher-scoring report page", refs[0].URL)
	}
}

func TestHostsFromReferencedPage(t *testing.T) {
	text := "## Navigate to the testnet\nGo to [testnet.ticko.xyz](https://testnet.ticko.xyz/).\n" +
		"Join Discord https://discord.com/invite/ticko and see https://1035376029-files.gitbook.io/x.png\n" +
		"Report to security@ticko.market\n"
	got := hostsFromText(text, "Testnet Guide")
	if len(got) != 1 || got[0].Identifier != "testnet.ticko.xyz" {
		t.Errorf("hosts = %+v, want only testnet.ticko.xyz", got)
	}
	if got[0].Path != "" {
		t.Errorf("root URL must not be treated as path-restricted: %+v", got[0])
	}
	if got[0].Type != "HOST" || got[0].Section != "Testnet Guide" {
		t.Errorf("candidate metadata = %+v", got[0])
	}

	// Regression: --trust-scope must promote this root host into scope.txt.
	in := &Intake{TrustScope: true, Candidates: got}
	sc := in.Scope()
	if len(sc.In) != 1 || sc.In[0] != "testnet.ticko.xyz" {
		t.Errorf("trusted scope = %v, want [testnet.ticko.xyz]", sc.In)
	}
}

func TestFollowReferencesSameDomainOnly(t *testing.T) {
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`GitBook main. [Testnet Guide](/testnet-guide) and [External](https://evil.test/steal).`))
		case "/testnet-guide.md":
			_, _ = w.Write([]byte("# Testnet Guide\n\nGo to [testnet.ticko.xyz](https://testnet.ticko.xyz/) and claim testnet USDT from the faucet before placing an order.\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := netx.New("test", 50, nil)
	defer c.Close()
	u, _ := url.Parse(srv.URL)
	policy := "GitBook main. [Testnet Guide](http://" + u.Host + "/testnet-guide) and [External](https://evil.test/steal)."
	refs, discovered, texts, cands, _, _ := followReferences(context.Background(), c, u, policy, "", FetchOptions{MaxLinks: 5}, true)

	if len(refs) != 1 || !strings.Contains(refs[0].URL, "testnet-guide") {
		t.Errorf("refs = %+v", refs)
	}
	if len(discovered) != 1 || !strings.Contains(discovered[0].URL, "testnet-guide") {
		t.Errorf("discovered = %+v", discovered)
	}
	if len(texts) != 1 || !strings.Contains(texts[0], "testnet.ticko.xyz") {
		t.Errorf("linked text = %v", texts)
	}
	if len(cands) != 1 || cands[0].Identifier != "testnet.ticko.xyz" {
		t.Errorf("candidates = %+v", cands)
	}
	for _, h := range hits {
		if strings.Contains(h, "steal") {
			t.Error("followed an external link")
		}
	}
}

func TestBaseDomain(t *testing.T) {
	cases := map[string]string{
		"docs.ticko.xyz":         "ticko.xyz",
		"ticko.xyz":              "ticko.xyz",
		"hyperliquid.gitbook.io": "gitbook.io",
	}
	for in, want := range cases {
		if got := baseDomain(in); got != want {
			t.Errorf("baseDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
