package program

import (
	"strings"
	"testing"
	"time"
)

const policyFixture = `We welcome reports.

## In scope
api.example.com and *.example.com are in scope.
Research header: X-HackerOne-Research: username

## Out of scope
- CSRF on unauthenticated forms
- Social engineering of employees
- cdn.example.com

## Prohibited Actions
No unauthorized testing on mainnet or production. Use local forks.
Do not access other users' data.

## Submission process
Send a detailed report with a working proof of concept. KYC is required for payout.

## Disclosure Policy
No public disclosure before the issue is fixed.
`

func TestExtractBoundariesEmailChannel(t *testing.T) {
	policy := `## Submission
Send your report to security@example.com. Please keep it confidential.
For press enquiries contact press@example.com.
`
	b := ExtractBoundaries(policy, "heuristic")
	if b.SubmissionChannel != "email:security@example.com" {
		t.Errorf("SubmissionChannel = %q, want email:security@example.com", b.SubmissionChannel)
	}
	if !strings.Contains(strings.Join(b.SubmissionContact, ","), "press@example.com") {
		t.Errorf("contacts lost the non-submission address: %v", b.SubmissionContact)
	}
}

func TestExtractBoundariesFull(t *testing.T) {
	b := ExtractBoundaries(policyFixture, "structured")
	if b.MainnetTesting != "forbidden" {
		t.Errorf("MainnetTesting = %q, want forbidden", b.MainnetTesting)
	}
	if b.TestingEnvironment != "testnet-or-local-fork" {
		t.Errorf("TestingEnvironment = %q", b.TestingEnvironment)
	}
	if !b.PoCRequired || !b.KYCRequired {
		t.Errorf("PoC/KYC flags = %t/%t, want true/true", b.PoCRequired, b.KYCRequired)
	}
	if len(b.RequiredHeaders) != 1 || b.RequiredHeaders[0] != "X-HACKERONE-RESEARCH" {
		t.Errorf("RequiredHeaders = %v", b.RequiredHeaders)
	}
	if !strings.Contains(b.OutOfScopeText, "Social engineering") {
		t.Errorf("out-of-scope text not captured: %q", b.OutOfScopeText)
	}
	if strings.Contains(b.InScopeText, "cdn.example.com") {
		t.Error("out-of-scope host leaked into in-scope text")
	}
	if !strings.Contains(b.SubmissionText, "proof of concept") {
		t.Errorf("submission text missing: %q", b.SubmissionText)
	}
	if !strings.Contains(b.DisclosureText, "No public disclosure") {
		t.Errorf("disclosure text missing: %q", b.DisclosureText)
	}
}

func TestMissingRulesAreUnknownNotAllowed(t *testing.T) {
	b := ExtractBoundaries("Only a short page with no rules.", "heuristic")
	if b.MainnetTesting != "unknown" {
		t.Errorf("MainnetTesting = %q, want unknown", b.MainnetTesting)
	}
	if b.OutOfScopeText != "" {
		t.Errorf("expected no out-of-scope text, got %q", b.OutOfScopeText)
	}
	joined := strings.Join(b.Notes, " ")
	if !strings.Contains(joined, "absence is not permission") {
		t.Errorf("missing caveat in notes: %v", b.Notes)
	}
	if !strings.Contains(joined, "page text") {
		t.Errorf("missing heuristic caveat in notes: %v", b.Notes)
	}
}

func TestBoundariesMarkdownIncludesEverything(t *testing.T) {
	in := &Intake{
		Name: "Demo", URL: "https://example.com/program", Platform: "h1",
		Confidence: "structured", FetchedAt: time.Date(2026, 11, 17, 1, 2, 0, 0, time.UTC),
		Boundaries: ExtractBoundaries(policyFixture, "structured"),
		Assets: []Asset{
			{Identifier: "api.example.com", Type: "URL", Eligible: true},
			{Identifier: "cdn.example.com", Type: "URL", Eligible: false},
		},
	}
	md := in.BoundariesMarkdown()
	for _, needle := range []string{
		"# Boundaries — Demo", "https://example.com/program", "confidence: `structured`",
		"IN `api.example.com`", "OUT `cdn.example.com`", "Out of scope (verbatim)",
		"no public disclosure", "mainnet", "X-HACKERONE-RESEARCH",
	} {
		if !strings.Contains(strings.ToLower(md), strings.ToLower(needle)) {
			t.Errorf("boundaries.md missing %q", needle)
		}
	}
}

func TestBoundariesMarkdownHonestEmptyScope(t *testing.T) {
	in := &Intake{Name: "Empty", URL: "https://example.org", Platform: "web", Confidence: "heuristic"}
	md := in.BoundariesMarkdown()
	if !strings.Contains(md, "recon will refuse to run") {
		t.Errorf("empty scope must be stated plainly:\n%s", md)
	}
	if !strings.Contains(md, "Not published in the page text") {
		t.Error("missing sections must not look like permission")
	}
}
