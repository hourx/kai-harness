package triage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLedgerLifecycle(t *testing.T) {
	dir := t.TempDir()
	l, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := l.Add("/api/orders/{id}", "IDOR/BOLA", "fetch as A then B", "h1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != "f-001" || f.Status != "submitted" {
		t.Fatalf("finding = %+v", f)
	}
	if err := l.SetStatus(f.ID, "needs-info", "need second account screenshot"); err != nil {
		t.Fatal(err)
	}
	if err := l.SetStatus(f.ID, "duplicate", "same root cause as f-001 earlier report"); err != nil {
		t.Fatal(err)
	}
	if len(l.Dupes) != 1 || len(l.Lessons) != 1 {
		t.Fatalf("dupes=%v lessons=%v", l.Dupes, l.Lessons)
	}
	if err := l.Payout(f.ID, 250, false); err == nil {
		t.Error("payout of a duplicate should be refused without --force")
	}
	if err := l.Payout(f.ID, 250, true); err != nil {
		t.Fatalf("forced payout failed: %v", err)
	}
	if err := l.Save(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "findings", "ledger.json")); err != nil {
		t.Error("ledger not written")
	}
	if _, err := os.Stat(filepath.Join(dir, "findings", "lessons.md")); err != nil {
		t.Error("lessons not written")
	}
	again, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.Findings[0].Amount != 250 || again.Findings[0].Status != "paid" {
		t.Errorf("persisted finding = %+v", again.Findings[0])
	}
	if !strings.Contains(again.Markdown(), "f-001") {
		t.Error("markdown missing finding")
	}
}

func TestSetStatusRejectsUnknown(t *testing.T) {
	l := &Ledger{}
	if _, err := l.Add("/x", "", "", "", 0); err != nil {
		t.Fatal(err)
	}
	if err := l.SetStatus("f-001", "magic", ""); err == nil {
		t.Error("unknown status accepted")
	}
	if err := l.SetStatus("nope", "paid", ""); err == nil {
		t.Error("unknown finding accepted")
	}
}
