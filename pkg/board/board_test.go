package board

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/pkg/evidence"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/triage"
	"github.com/hourx/kai-harness/pkg/workspace"
)

func TestSnapshotRanksFindingsFirst(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)

	p, err := workspace.Create("acme", workspace.Meta{Platform: "hackerone", ScopeVerdict: "confirmed"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.Dir, "scope.txt"), []byte("api.example.com\n*.example.org\n"), 0o600); err != nil {
		t.Fatalf("scope: %v", err)
	}
	queue := `{"program":"acme","generated":"2026-01-01T00:00:00Z","items":[
	  {"target":"GET /a","class":"surface-review","score":30},
	  {"target":"GET /b","class":"IDOR/BOLA","score":120}]}`
	if err := os.WriteFile(filepath.Join(p.Dir, "next.json"), []byte(queue), 0o600); err != nil {
		t.Fatalf("queue: %v", err)
	}
	if err := outcome.Append(p.Dir, outcome.Record{TS: "2026-01-02T00:00:00Z", Target: "GET /b", Status: "informational"}); err != nil {
		t.Fatalf("outcome: %v", err)
	}
	led, err := triage.Load(p.Dir)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	f, err := led.Add("GET /b", "IDOR/BOLA", "two accounts", "hackerone", 0)
	if err != nil {
		t.Fatalf("ledger add: %v", err)
	}
	if err := led.SetStatus(f.ID, "candidate", "ready to submit"); err != nil {
		t.Fatalf("ledger status: %v", err)
	}
	if err := led.Save(p.Dir); err != nil {
		t.Fatalf("ledger save: %v", err)
	}
	if _, _, err := evidence.Capture(p.Dir, evidence.Item{Kind: "response", Host: "api.example.com", Path: "/b", Status: 200}, []byte("{}"), "b.json"); err != nil {
		t.Fatalf("evidence: %v", err)
	}

	rep, err := Snapshot(home)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(rep.Programs) != 1 {
		t.Fatalf("want 1 program, got %d", len(rep.Programs))
	}
	row := rep.Programs[0]
	if row.Name != "acme" || row.Platform != "hackerone" {
		t.Fatalf("identity: %+v", row)
	}
	if row.InScope != 2 || row.Queue != 2 || row.TopScore != 120 || row.TopClass != "IDOR/BOLA" {
		t.Fatalf("counts: %+v", row)
	}
	if row.LastOut != "informational" || row.Evidence != 1 {
		t.Fatalf("history: %+v", row)
	}
	if len(row.Findings) != 1 || row.Findings[0].Status != "candidate" {
		t.Fatalf("findings: %+v", row.Findings)
	}
	if len(rep.Todo) == 0 {
		t.Fatal("a candidate finding should produce a todo")
	}
	if !strings.Contains(rep.Todo[0].Why, "candidate") {
		t.Fatalf("findings outrank hunting work: %+v", rep.Todo[0])
	}
	if !strings.Contains(rep.Markdown(), "Do today") {
		t.Fatal("markdown should carry the todo section")
	}
}

func TestSnapshotFlagsBlockers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	if _, err := workspace.Create("empty", workspace.Meta{Platform: "bugcrowd"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	rep, err := Snapshot(home)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	row := rep.Programs[0]
	joined := strings.Join(row.Blockers, "; ")
	if !strings.Contains(joined, "no recon yet") {
		t.Fatalf("a program with no surface should say so: %v", row.Blockers)
	}
	if len(rep.Todo) == 0 || !strings.Contains(rep.Todo[0].Command, "kai recon empty") {
		t.Fatalf("todo should point at the first missing step: %+v", rep.Todo)
	}
	// Scope verdict "unknown" is set by Create and must be surfaced as a blocker.
	if !strings.Contains(joined, "scope verdict") {
		t.Fatalf("unset verdict should block: %v", row.Blockers)
	}
}

func TestSnapshotEmptyHomeIsNotAnError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	rep, err := Snapshot(home)
	if err != nil {
		t.Fatalf("empty home should not error: %v", err)
	}
	if len(rep.Programs) != 0 || len(rep.Todo) != 0 {
		t.Fatalf("empty home produced rows: %+v", rep)
	}
	if !strings.Contains(rep.Markdown(), "nothing queued") {
		t.Fatal("empty board should say it has no data")
	}
}

func TestStaleReconYieldsRefreshAction(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	p, err := workspace.Create("old", workspace.Meta{Platform: "hackerone", ScopeVerdict: "confirmed"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.Dir, "next.json"), []byte(`{"program":"old","items":[{"target":"GET /x","class":"api-surface","score":10}]}`), 0o600); err != nil {
		t.Fatalf("queue: %v", err)
	}
	stale := time.Now().Add(-30 * 24 * time.Hour)
	if err := os.Chtimes(filepath.Join(p.Dir, "next.json"), stale, stale); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.Dir, "map.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("map: %v", err)
	}
	if err := os.Chtimes(filepath.Join(p.Dir, "map.json"), stale, stale); err != nil {
		t.Fatalf("chtimes map: %v", err)
	}
	rep, err := Snapshot(home)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	row := rep.Programs[0]
	if row.ReconDays < 29 {
		t.Fatalf("want a stale age, got %.1f", row.ReconDays)
	}
	found := false
	for _, a := range rep.Todo {
		if strings.Contains(a.Why, "old") {
			found = true
		}
	}
	if !found {
		t.Fatalf("stale queue should ask for a refresh: %+v", rep.Todo)
	}
}
