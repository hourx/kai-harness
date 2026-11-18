package audit

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractZipRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("../escape.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("nope"))
	_ = zw.Close()
	_ = f.Close()

	dest := filepath.Join(dir, "out")
	if err := extractZip(path, dest); err == nil {
		t.Fatal("zip slip path was not rejected")
	}
	if _, err := os.Stat(filepath.Join(dir, "escape.txt")); err == nil {
		t.Error("a file escaped the extraction directory")
	}
}

func TestResultText(t *testing.T) {
	r := Result{Name: "demo", Source: "demo.zip", Checks: []Check{
		{Name: "check one", OK: true},
		{Name: "check two", OK: false, Detail: "missing file"},
	}}
	if r.Failed() != 1 {
		t.Errorf("Failed() = %d", r.Failed())
	}
	text := r.Text()
	for _, want := range []string{"# Audit — demo", "PASS check one", "FAIL check two", "-> missing file", "1/2 passed"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q:\n%s", want, text)
		}
	}
}

func TestScopeRulesStripsInlineComments(t *testing.T) {
	got := scopeRules([]string{
		"# full-line comment stays out",
		"yandex.com   # apex of *.yandex.com (MS)",
		"*.yandex.ru # MS infra",
		"",
		"ya.ru",
	})
	want := []string{"yandex.com", "*.yandex.ru", "ya.ru"}
	if len(got) != len(want) {
		t.Fatalf("scopeRules = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("scopeRules[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
