package program

import (
	"strings"
	"testing"
)

func TestExtractRewardsStyles(t *testing.T) {
	cases := []struct {
		text string
		want int
	}{
		{"Maximum Bounty\n$1,100,000", 1100000},
		{"Max payout: $300k", 300000},
		{"Critical (<1M USDC): Significant loss of user funds.", 1000000},
		{"High (<50k USDC): Network downtime", 50000},
	}
	for _, tc := range cases {
		got, _ := extractRewards(tc.text)
		if got != tc.want {
			t.Errorf("extractRewards(%q) = %d, want %d", tc.text, got, tc.want)
		}
	}
}

func TestExtractCounters(t *testing.T) {
	resolved, reports, known := extractCounters("Findings submitted 1,148\n")
	if !known || reports != 1148 {
		t.Errorf("cantina counters = (%d, %d, %v)", resolved, reports, known)
	}
	resolved, _, known = extractCounters("Total paid: 1.4M from 27 paid reports")
	if !known || resolved != 27 {
		t.Errorf("immunefi counters = (%d, _, %v)", resolved, known)
	}
	if _, _, known := extractCounters("no numbers here"); known {
		t.Error("missing data must not be reported as known")
	}
}

func TestExtractCandidatesOnlyFromScopeSection(t *testing.T) {
	policy := `## Program Rules
The docs are at https://docs.example.com and https://out-of-scope.example.com.
Do not test https://not-in-scope.example.com.

## In Scope
Web applications: app.uniswap.org and https://app.example.org/login.
Smart contract: 0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5
Source: https://github.com/example/repo

## Out of Scope
https://out-of-scope.example.com is explicitly excluded.
`
	got := extractCandidates(policy)
	var ids []string
	for _, c := range got {
		ids = append(ids, c.Identifier)
	}
	joined := strings.Join(ids, " ")
	if !strings.Contains(joined, "app.uniswap.org") || !strings.Contains(joined, "github.com/example/repo") {
		t.Errorf("in-scope candidates missing: %v", ids)
	}
	if strings.Contains(joined, "not-in-scope") || strings.Contains(joined, "out-of-scope.example.com") {
		t.Errorf("out-of-scope hosts leaked into candidates: %v", ids)
	}
	if !strings.Contains(joined, "0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5") {
		t.Errorf("contract address missing: %v", ids)
	}
}

func TestHtmlToTextKeepsHeadings(t *testing.T) {
	raw := []byte(`<html><head><script>alert(1)</script><title>Demo</title></head>
<body><h1>Bug bounty</h1><h2>In Scope</h2><p>app.example.org</p><style>x{}</style></body></html>`)
	text := htmlToText(raw)
	if !strings.Contains(text, "## In Scope") {
		t.Errorf("headings were not preserved:\n%s", text)
	}
	if strings.Contains(text, "alert(1)") || strings.Contains(text, "x{}") {
		t.Errorf("script/style leaked into text:\n%s", text)
	}
}

func TestHeuristicIntakeIsReviewNotGo(t *testing.T) {
	in := &Intake{
		Name: "Demo", Platform: "cantina", Confidence: "heuristic", OffersBounty: true,
		TopUpper: 15500000, Reports90d: 1148, ReportsKnown: true, ResponseEff: 90,
		Assets: []Asset{{Identifier: "app.example.org", Type: "URL", Eligible: true}},
	}
	s := in.Score()
	if s.Verdict != "review" {
		t.Errorf("heuristic verdict = %s, want review", s.Verdict)
	}
	if len(in.Score().Reasons) == 0 || !strings.Contains(strings.Join(s.Reasons, " "), "heuristics") {
		t.Error("heuristic caveat missing from reasons")
	}
	if !strings.Contains(in.Markdown(), "confidence `heuristic`") {
		t.Error("scorecard must state its confidence")
	}
}
