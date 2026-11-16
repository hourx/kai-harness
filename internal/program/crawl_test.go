package program

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hourx/bountykit/internal/netx"
)

func TestHeaderFalsePositiveFromGitBookImage(t *testing.T) {
	policy := "See ![img](https://1035376029-files.gitbook.io/~/files/v0/gitbook-x-prod.appspot.com/image.png)\n" +
		"Research header: X-HackerOne-Research: username\n"
	b := ExtractBoundaries(policy, "heuristic")
	if len(b.RequiredHeaders) != 1 || b.RequiredHeaders[0] != "X-HACKERONE-RESEARCH" {
		t.Errorf("RequiredHeaders = %v, want only the real research header", b.RequiredHeaders)
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
	refs, texts, cands := followReferences(context.Background(), c, u, policy, FetchOptions{MaxLinks: 5}, true)

	if len(refs) != 1 || !strings.Contains(refs[0].URL, "testnet-guide") {
		t.Errorf("refs = %+v", refs)
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
