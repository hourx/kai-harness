package program

import (
	"strings"
	"testing"
)

func TestNormalizeRule(t *testing.T) {
	cases := []struct {
		a    Asset
		rule string
		kind string
	}{
		{Asset{Identifier: "www.temu.com", Type: "URL"}, "www.temu.com", "host"},
		{Asset{Identifier: "https://seller.temu.com/", Type: "URL"}, "seller.temu.com", "host"},
		{Asset{Identifier: "https://example.com/api/*", Type: "URL"}, "", "path"},
		{Asset{Identifier: "*.shopify.com", Type: "WILDCARD"}, "*.shopify.com", "wildcard"},
		{Asset{Identifier: "shopify.com", Type: "WILDCARD"}, "*.shopify.com", "wildcard"},
		{Asset{Identifier: "203.0.113.0/24", Type: "CIDR"}, "203.0.113.0/24", "cidr"},
		{Asset{Identifier: "com.einnovation.temu", Type: "GOOGLE_PLAY_APP_ID"}, "", "non-web"},
		{Asset{Identifier: "1641486558", Type: "APPLE_STORE_APP_ID"}, "", "non-web"},
		{Asset{Identifier: "org/repo", Type: "SOURCE_CODE"}, "", "non-web"},
	}
	for _, tc := range cases {
		rule, kind := normalizeRule(tc.a)
		if rule != tc.rule || kind != tc.kind {
			t.Errorf("normalizeRule(%q, %q) = (%q, %q), want (%q, %q)",
				tc.a.Identifier, tc.a.Type, rule, kind, tc.rule, tc.kind)
		}
	}
}

func TestScopeRoutesEligibility(t *testing.T) {
	in := &Intake{Assets: []Asset{
		{Identifier: "app.example.com", Type: "URL", Eligible: true},
		{Identifier: "old.example.com", Type: "URL", Eligible: false},
		{Identifier: "*.example.com", Type: "WILDCARD", Eligible: true},
		{Identifier: "https://example.com/api/*", Type: "URL", Eligible: true},
		{Identifier: "com.example.app", Type: "GOOGLE_PLAY_APP_ID", Eligible: true},
	}}
	sc := in.Scope()
	if len(sc.In) != 2 {
		t.Errorf("In = %v, want 2 rules", sc.In)
	}
	if len(sc.Out) != 1 || sc.Out[0] != "old.example.com" {
		t.Errorf("Out = %v", sc.Out)
	}
	if len(sc.PathOnly) != 1 {
		t.Errorf("PathOnly = %v, want the path-restricted URL excluded from the gate", sc.PathOnly)
	}
	if len(sc.NonWeb) != 1 {
		t.Errorf("NonWeb = %v", sc.NonWeb)
	}
}

func TestScoreVerdicts(t *testing.T) {
	cases := []struct {
		name string
		in   Intake
		want string
	}{
		{
			name: "vdp cannot be a bounty recommendation",
			in:   Intake{OffersBounty: false, ResponseEff: 100, Resolved: 30000, Reports90d: 10},
			want: "vdp-only",
		},
		{
			name: "rich uncrowded program",
			in: Intake{
				OffersBounty: true, TopUpper: 50000, Reports90d: 20, ResponseEff: 100,
				Assets: []Asset{{Identifier: "*.new.example", Type: "WILDCARD", Eligible: true}},
			},
			want: "go",
		},
		{
			name: "crowded big program",
			in: Intake{
				OffersBounty: true, TopUpper: 200000, Reports90d: 5000, ResponseEff: 20,
				Assets: []Asset{{Identifier: "a.shop.example", Type: "URL", Eligible: true}},
			},
			want: "skip",
		},
	}
	for _, tc := range cases {
		got := tc.in.Score()
		if got.Verdict != tc.want {
			t.Errorf("%s: verdict = %s (%d/100), want %s", tc.name, got.Verdict, got.Total, tc.want)
		}
	}
}

func TestMarkdownCarriesCaveats(t *testing.T) {
	in := &Intake{
		Name: "Demo", Handle: "demo", URL: "https://hackerone.com/demo", Platform: "h1",
		OffersBounty: true, TopUpper: 10000, Reports90d: 100, ResponseEff: 80,
		Assets: []Asset{
			{Identifier: "app.example.com", Type: "URL", Eligible: true},
			{Identifier: "https://example.com/admin/*", Type: "URL", Eligible: true},
			{Identifier: "com.example.app", Type: "GOOGLE_PLAY_APP_ID", Eligible: true},
		},
	}
	md := in.Markdown()
	for _, needle := range []string{"Verdict:", "Rewards", "path-scoped", "non-web", "policy.md"} {
		if !strings.Contains(md, needle) {
			t.Errorf("markdown missing %q", needle)
		}
	}
	if strings.Contains(md, "https://example.com/admin/*\n- `app.example.com`") {
		t.Error("path-restricted asset leaked into the enforceable rule list")
	}
}
