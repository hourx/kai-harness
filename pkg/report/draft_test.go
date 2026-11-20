package report

import (
	"strings"
	"testing"

	"github.com/hourx/kai-harness/pkg/evidence"
)

func sample(platform string) Input {
	return Input{
		Program:  "acme",
		Platform: platform,
		Title:    "IDOR on GET /v1/orders",
		Severity: "7.5 high",
		Target:   "api.example.com/v1/orders",
		Class:    "IDOR/BOLA",
		Evidence: []evidence.Item{{
			ID: "abc123", TS: "2026-01-01T00:00:00Z", Kind: "response",
			Host: "api.example.com", Method: "GET", Path: "/v1/orders", Status: 200,
			BlobSHA256: "deadbeefdeadbeefdeadbeef",
		}},
	}
}

func TestRenderPerPlatformCarriesItsOwnFields(t *testing.T) {
	fields := map[string][]string{
		"hackerone": {"## Title", "## Severity", "## Weakness (CWE)", "## Asset", "### Steps To Reproduce", "### Impact"},
		"bugcrowd":  {"## Summary", "## Target", "## Steps to Reproduce", "## Impact"},
		"yandex":    {"## Subject", "## Step-by-step instructions to reproduce", "## Result", "## Expected result and recommendations", "## Category", "## Vulnerability type"},
	}
	for platform, wants := range fields {
		out, err := Render(sample(platform))
		if err != nil {
			t.Fatalf("%s: %v", platform, err)
		}
		for _, w := range wants {
			if !strings.Contains(out, w) {
				t.Errorf("%s: missing field %q", platform, w)
			}
		}
		if !strings.Contains(out, "abc123") {
			t.Errorf("%s: evidence id missing from the draft", platform)
		}
		if !strings.Contains(out, "does not submit") {
			t.Errorf("%s: draft should state that kai does not submit", platform)
		}
	}
}

func TestRenderRejectsUnknownPlatform(t *testing.T) {
	if _, err := Render(sample("inteq")); err == nil {
		t.Fatal("an unknown platform must be an error, not a guess")
	}
}

func TestRenderNeedsASubject(t *testing.T) {
	in := Input{Program: "acme", Platform: "hackerone"}
	if _, err := Render(in); err == nil {
		t.Fatal("a draft with no title and no target cannot be triaged")
	}
}

func TestRenderWarnsOnThinEvidenceAndOutOfScope(t *testing.T) {
	thin := Input{Program: "acme", Platform: "bugcrowd", Target: "api.example.com/x"}
	out, err := Render(thin)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "No evidence attached") {
		t.Fatal("a draft with no evidence should say so loudly")
	}

	scoped := sample("hackerone")
	scoped.ScopeVerdict = "out"
	out, err = Render(scoped)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "returned OUT") {
		t.Fatal("an out-of-scope target should carry a warning")
	}
}

func TestPlatformsAreStable(t *testing.T) {
	if len(Platforms) == 0 {
		t.Fatal("no platforms registered")
	}
	for _, p := range Platforms {
		if !Valid(p) {
			t.Errorf("%s listed but not valid", p)
		}
	}
	if Valid("nope") {
		t.Fatal("Valid accepted an unregistered platform")
	}
}
