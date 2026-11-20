package pack

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hourx/kai-harness/internal/workspace"
)

func TestBuildKeepsBountykitContractDir(t *testing.T) {
	dir := t.TempDir()
	p := &workspace.Program{Name: "demo", Dir: dir, Meta: workspace.Meta{Name: "demo", ScopeVerdict: "bounty"}}
	for name, body := range map[string]string{
		"program.md":       "# demo\n",
		"scope.txt":        "app.example.com\n",
		"out-of-scope.txt": "# none\n",
		"intake.json":      `{"name":"demo","scorecard":{"verdict":"review","total":1}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Build(p, Options{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r, err := zip.OpenReader(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	found := false
	for _, f := range r.File {
		if strings.Contains(f.Name, "/bountykit/") {
			found = true
		}
		if strings.Contains(f.Name, "/kai/") {
			t.Errorf("archive uses product name as internal dir: %s", f.Name)
		}
	}
	if !found {
		t.Error("archive has no bountykit/ entries — Kairos contract broken")
	}
}
