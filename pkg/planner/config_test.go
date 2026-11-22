package planner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// clearPlannerEnv makes the process environment irrelevant to these tests.
func clearPlannerEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"KAI_PLANNER", "KAI_PLANNER_ENDPOINT", "KAI_PLANNER_KEY",
		"KAI_PLANNER_MODEL", "KAI_PLANNER_MAX_TOKENS", "KAI_PLANNER_MAX_STEPS",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadConfigIsOffWithoutAnEndpoint(t *testing.T) {
	clearPlannerEnv(t)
	c := LoadConfig(t.TempDir())
	if c.Enabled {
		t.Fatal("planner must be off with no endpoint")
	}
	if c.Proposer() != nil {
		t.Error("a disabled config must not yield a proposer")
	}
	if c.Reason == "" {
		t.Error("a disabled planner must say why")
	}
	if c.MaxSteps != defaultMaxSteps {
		t.Errorf("default steps = %d", c.MaxSteps)
	}
}

func TestLoadConfigReadsTheWorkspaceFile(t *testing.T) {
	clearPlannerEnv(t)
	dir := t.TempDir()
	writeFile(t, ConfigPath(dir), `{"endpoint":"http://127.0.0.1:20128/v1","model":"m","max_steps":3,"max_tokens_per_day":5000}`)
	c := LoadConfig(dir)
	if !c.Enabled || c.Endpoint == "" || c.Model != "m" {
		t.Fatalf("config not loaded: %+v", c)
	}
	if c.MaxSteps != 3 || c.MaxTokens != 5000 {
		t.Errorf("budgets not loaded: %+v", c)
	}
	if p := c.Proposer(); p == nil || p.Name() != "llm" {
		t.Errorf("proposer = %v", p)
	}
}

func TestEnvironmentBeatsTheFile(t *testing.T) {
	clearPlannerEnv(t)
	dir := t.TempDir()
	writeFile(t, ConfigPath(dir), `{"endpoint":"http://file/v1","model":"file-model"}`)
	t.Setenv("KAI_PLANNER_ENDPOINT", "http://env/v1")
	c := LoadConfig(dir)
	if c.Endpoint != "http://env/v1" || c.Source != "environment" {
		t.Errorf("env did not win: endpoint=%q source=%q", c.Endpoint, c.Source)
	}
	if c.Model != "file-model" {
		t.Errorf("model should still come from the file: %q", c.Model)
	}
}

func TestKillSwitchBeatsEverything(t *testing.T) {
	clearPlannerEnv(t)
	dir := t.TempDir()
	writeFile(t, ConfigPath(dir), `{"endpoint":"http://x/v1","model":"m"}`)
	t.Setenv("KAI_PLANNER_ENDPOINT", "http://env/v1")
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(OffPath(dir), []byte("off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := LoadConfig(dir)
	if c.Enabled {
		t.Fatal("the kill switch must disable the planner")
	}
	if c.Proposer() != nil {
		t.Error("a killed planner must not yield a proposer")
	}
}

func TestEnvCanDisableThePlanner(t *testing.T) {
	clearPlannerEnv(t)
	dir := t.TempDir()
	writeFile(t, ConfigPath(dir), `{"endpoint":"http://x/v1","model":"m"}`)
	t.Setenv("KAI_PLANNER", "off")
	if LoadConfig(dir).Enabled {
		t.Fatal("KAI_PLANNER=off must disable the planner")
	}
}

func TestUsageLedgerCountsAndResets(t *testing.T) {
	dir := t.TempDir()
	day1 := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)

	if tok, calls := UsageToday(dir, day1); tok != 0 || calls != 0 {
		t.Errorf("fresh ledger = %d/%d", tok, calls)
	}
	if err := RecordUsage(dir, day1, 100); err != nil {
		t.Fatal(err)
	}
	if err := RecordUsage(dir, day1, 50); err != nil {
		t.Fatal(err)
	}
	if tok, calls := UsageToday(dir, day1); tok != 150 || calls != 2 {
		t.Errorf("day1 ledger = %d tokens / %d calls", tok, calls)
	}
	// A new day reads as zero without anyone deleting the file.
	if tok, calls := UsageToday(dir, day2); tok != 0 || calls != 0 {
		t.Errorf("day2 should start fresh: %d/%d", tok, calls)
	}
	if err := RecordUsage(dir, day2, 7); err != nil {
		t.Fatal(err)
	}
	if tok, _ := UsageToday(dir, day2); tok != 7 {
		t.Errorf("day2 ledger = %d", tok)
	}
}
