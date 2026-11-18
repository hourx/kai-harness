package program

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCompactFixture builds a minimal intake.json (and optionally a
// scope.txt) in a fresh directory and returns its path.
func writeCompactFixture(t *testing.T, assets []Asset, scopeText string) string {
	t.Helper()
	dir := t.TempDir()
	in := Intake{
		Name:      "fixture",
		URL:       "https://example.com/program",
		Platform:  "yandex",
		FetchedAt: time.Now().UTC(),
		Scorecard: Score{Total: 42, Verdict: "review"},
		Assets:    assets,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "intake.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if scopeText != "" {
		if err := os.WriteFile(filepath.Join(dir, "scope.txt"), []byte(scopeText), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestCompactBriefPrefersOperatorScope verifies the context card counts rules
// from the operator-approved scope.txt (source of truth for the gate), not
// from intake.json assets. Regression: prose-only programs showed scope(0).
func TestCompactBriefPrefersOperatorScope(t *testing.T) {
	assets := []Asset{{Identifier: "from-intake.example.com", Type: "DOMAIN", Eligible: true}}
	dir := writeCompactFixture(t, assets, "operator.example.com\n*.wild.example.com\n")
	card, err := CompactBrief(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(card, "scope(2):") {
		t.Errorf("expected scope(2) from operator scope.txt, got:\n%s", card)
	}
	if !strings.Contains(card, "operator.example.com") {
		t.Errorf("operator rule missing from card:\n%s", card)
	}
	if strings.Contains(card, "from-intake.example.com") {
		t.Errorf("intake asset must not leak into card when scope.txt is present:\n%s", card)
	}
}

// TestCompactBriefFallsBackToIntakeAssets verifies the intake-derived scope
// line is still used when no operator scope.txt exists yet.
func TestCompactBriefFallsBackToIntakeAssets(t *testing.T) {
	assets := []Asset{{Identifier: "from-intake.example.com", Type: "DOMAIN", Eligible: true}}
	dir := writeCompactFixture(t, assets, "")
	card, err := CompactBrief(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(card, "scope(1):") {
		t.Errorf("expected scope(1) fallback from intake assets, got:\n%s", card)
	}
}
