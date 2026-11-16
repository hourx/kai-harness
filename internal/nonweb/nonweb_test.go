package nonweb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hourx/kai/internal/workspace"
)

func TestScanRepoFindsWorkflowRisks(t *testing.T) {
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	yml := `name: ci
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
      - run: curl https://example.com/install.sh | bash
      - uses: actions/checkout@v4
`
	if err := os.WriteFile(filepath.Join(wf, "ci.yml"), []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"scripts":{"postinstall":"node setup.js","test":"go test ./..."}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"foundry.toml", "SECURITY.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "contracts"), 0o755); err != nil {
		t.Fatal(err)
	}

	r := &Repo{Slug: "org-repo", Path: dir}
	scanRepo(r, func(string, ...any) {})
	joined := strings.Join(r.Risks, " | ")
	for _, want := range []string{"base repository token", "untrusted github.event", "write-all", "remote script"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing risk %q in %q", want, joined)
		}
	}
	if len(r.Scripts) != 1 || !strings.Contains(r.Scripts[0], "postinstall") {
		t.Errorf("scripts = %v", r.Scripts)
	}
	if !contains(r.Manifests, "package.json") || !contains(r.Manifests, "foundry.toml") {
		t.Errorf("manifests = %v", r.Manifests)
	}
	if !contains(r.EntryPoints, "contracts/") {
		t.Errorf("entry points = %v", r.EntryPoints)
	}
}

func TestAnalyzeWithoutCloneDoesNotNetwork(t *testing.T) {
	t.Setenv("KAI_HOME", t.TempDir())
	p, err := workspace.Create("demo", workspace.Meta{})
	if err != nil {
		t.Fatal(err)
	}
	intake := `{"platform":"h1","confidence":"structured","name":"Demo","url":"https://hackerone.com/demo",
	"fetched_at":"2026-11-17T00:00:00Z","assets":[
	  {"identifier":"https://github.com/org/repo","type":"SOURCE_CODE","eligible_for_submission":true},
	  {"identifier":"0x1111111111111111111111111111111111111111","type":"CONTRACT","eligible_for_submission":true}
	]}`
	if err := os.WriteFile(filepath.Join(p.Dir, "intake.json"), []byte(intake), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Analyze(context.Background(), p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Repos) != 1 || rep.Repos[0].Status != "not-cloned" {
		t.Errorf("repos = %+v", rep.Repos)
	}
	if rep.Repos[0].Slug != "org-repo" {
		t.Errorf("slug = %q", rep.Repos[0].Slug)
	}
	if len(rep.Contracts) != 1 || rep.Contracts[0].Address != "0x1111111111111111111111111111111111111111" {
		t.Errorf("contracts = %+v", rep.Contracts)
	}
	if err := Save(p, rep); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p.Dir, "nonweb.md")); err != nil {
		t.Error("nonweb.md was not written")
	}
	if !strings.Contains(rep.Markdown(), "--clone") {
		t.Error("report should tell the operator how to enable deep analysis")
	}
}
func contains(v []string, want string) bool {
	for _, x := range v {
		if x == want {
			return true
		}
	}
	return false
}
