package program

import (
	"strings"
	"testing"
	"time"
)

func intakeAt(t time.Time, host string, reward int) *Intake {
	return &Intake{
		Platform: "h1", Confidence: "structured", Name: "Demo", Handle: "demo",
		FetchedAt: t, TopUpper: reward, PolicyHash: "abc",
		OffersBounty: true, ReportsKnown: true, Reports90d: 10,
		Assets:      []Asset{{Identifier: host, Type: "URL", Eligible: true, Bounty: true}},
		Constraints: []string{"poc required"},
	}
}

func TestSnapshotAndDiffDetectsRuleChanges(t *testing.T) {
	dir := t.TempDir()
	t1 := time.Date(2026, 11, 17, 1, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)

	first := intakeAt(t1, "old.example.com", 5000)
	d1, err := SnapshotAndDiff(dir, first)
	if err != nil {
		t.Fatal(err)
	}
	if !d1.Baseline {
		t.Errorf("first diff should be a baseline: %+v", d1)
	}

	cur := intakeAt(t2, "new.example.com", 10000)
	d2, err := SnapshotAndDiff(dir, cur)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Baseline {
		t.Fatal("second diff must compare against the baseline")
	}
	if !d2.Changed() {
		t.Error("scope and reward changed but diff says unchanged")
	}
	if len(d2.RemovedScopeRules) != 1 || d2.RemovedScopeRules[0] != "old.example.com" {
		t.Errorf("RemovedScopeRules = %v", d2.RemovedScopeRules)
	}
	if len(d2.NewScopeRules) != 1 || d2.NewScopeRules[0] != "new.example.com" {
		t.Errorf("NewScopeRules = %v", d2.NewScopeRules)
	}
	if !d2.RewardChanged || d2.OldRewardTop != 5000 || d2.NewRewardTop != 10000 {
		t.Errorf("reward change = %+v", d2)
	}
	if !strings.Contains(d2.Markdown(), "Reward changed") {
		t.Error("markdown missing reward section")
	}
}

func TestSnapshotAndDiffNoChange(t *testing.T) {
	dir := t.TempDir()
	t1 := time.Date(2026, 11, 17, 1, 0, 0, 0, time.UTC)
	if _, err := SnapshotAndDiff(dir, intakeAt(t1, "a.example.com", 5000)); err != nil {
		t.Fatal(err)
	}
	d, err := SnapshotAndDiff(dir, intakeAt(t1.Add(2*time.Hour), "a.example.com", 5000))
	if err != nil {
		t.Fatal(err)
	}
	if d.Changed() {
		t.Errorf("identical intake should be unchanged: %+v", d)
	}
	if !strings.Contains(d.Markdown(), "No rule changes") {
		t.Errorf("expected an honest no-change message:\n%s", d.Markdown())
	}
}

func TestPolicyHashSurvivesSnapshot(t *testing.T) {
	dir := t.TempDir()
	in := intakeAt(time.Now().UTC(), "a.example.com", 1000)
	in.Policy = "# policy text"
	in.PolicyHash = hashPolicy(in.Policy)
	if _, err := SnapshotAndDiff(dir, in); err != nil {
		t.Fatal(err)
	}
	next := intakeAt(time.Now().UTC().Add(time.Hour), "a.example.com", 1000)
	next.Policy = "# edited policy text"
	next.PolicyHash = hashPolicy(next.Policy)
	d, err := SnapshotAndDiff(dir, next)
	if err != nil {
		t.Fatal(err)
	}
	if !d.PolicyChanged {
		t.Error("policy edit must be detected even though Policy is not serialised")
	}
}
