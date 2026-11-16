package program

import (
	"strings"
	"testing"
)

const tickoFixture = `{% hint style="danger" %}
Do **not** test on Ticko Mainnet or any production system. Use Ticko Testnet.
{% endhint %}

## In Scope
**Ticko Mainnet (Beta)**: vulnerabilities causing loss of funds, incorrect
order matching, margin, liquidation, funding rate, oracle manipulation,
misuse of trading session keys or signatures, Node or API outages, logic
errors in Ticko Core (the Ticko VM and the onchain order book).

Report to security@ticko.market. Keep the report confidential until authorized.

| **Critical** | **200,000 USDT** |
| **High** | **25,000 USDT** |
| **Medium** | **3,000 USDT** |
| **Others** | **50 USDT** |
`

func TestTickoStyleMarkupIsUnderstood(t *testing.T) {
	b := ExtractBoundaries(tickoFixture, "heuristic")
	if b.MainnetTesting != "forbidden" {
		t.Errorf("MainnetTesting = %q, want forbidden (markdown bold/hint must not hide it)", b.MainnetTesting)
	}
	if b.TestingEnvironment != "testnet-or-local-fork" {
		t.Errorf("TestingEnvironment = %q", b.TestingEnvironment)
	}
	if len(b.SubmissionContact) != 1 || b.SubmissionContact[0] != "security@ticko.market" {
		t.Errorf("SubmissionContact = %v", b.SubmissionContact)
	}
	if !strings.Contains(b.DisclosureText, "confidential") {
		t.Errorf("disclosure fallback missed: %q", b.DisclosureText)
	}
	if !strings.Contains(b.InScopeText, "order matching") {
		t.Error("in-scope section was not captured")
	}
}

func TestOthersTierAndUSDTRewards(t *testing.T) {
	max, rows := extractRewards(tickoFixture)
	if max != 200000 {
		t.Errorf("max = %d, want 200000", max)
	}
	var others int
	for _, r := range rows {
		if r.Name == "others" {
			others = r.Low
		}
	}
	if others != 50 {
		t.Errorf("Others tier = %d, want 50 — the low-value tier matters for this operator", others)
	}
}

func TestSystemsFromImpactScope(t *testing.T) {
	got := extractSystems(tickoFixture)
	joined := []string{}
	for _, c := range got {
		joined = append(joined, strings.ToLower(c.Identifier))
	}
	want := []string{"core", "vm", "order book", "session keys", "signatures", "api"}
	for _, w := range want {
		found := false
		for _, g := range joined {
			if strings.Contains(g, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("system %q missing from %v", w, joined)
		}
	}
	for _, c := range got {
		if c.Type != "SYSTEM" || strings.Contains(c.Identifier, "\n") {
			t.Errorf("dirty system candidate: %+v", c)
		}
	}
}
