package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hourx/kai-harness/pkg/evidence"
)

// End-to-end through the command entry points: the operators' two new verbs are
// only useful if `kai evidence import` really indexes a capture and `kai model`
// really prints the archetype and the gaps.
func setupDemoProgram(t *testing.T, name string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	dir := filepath.Join(home, name)
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	meta := `{"name":"` + name + `","platform":"hackerone"}`
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// runCapture runs a command with stdout and stderr pointed at one pipe.
func runCapture(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = w, w
	rc := fn()
	w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	b, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(b), rc
}

const demoHAR = `{"log":{"version":"1.2","creator":{"name":"kai-test"},
 "entries":[
  {"startedDateTime":"2026-11-20T09:00:00Z","request":{"method":"GET","url":"https://api.demo.example/v1/me","headers":[{"name":"Cookie","value":"sid=demo-session-value"}]},"response":{"status":200,"headers":[{"name":"Content-Type","value":"application/json"}],"content":{"size":12,"text":"{\"id\":7}"}}},
  {"startedDateTime":"2026-11-20T09:00:01Z","request":{"method":"GET","url":"data:text/plain,x","headers":[]},"response":{"status":0,"headers":[],"content":{}}},
  {"startedDateTime":"2026-11-20T09:00:02Z","request":{"method":"POST","url":"https://api.demo.example/v1/orders","headers":[],"postData":{"mimeType":"application/json","text":"{\"n\":1}"}},"response":{"status":403,"headers":[],"content":{}}}
]}}`

func TestEvidenceImportIndexesACapture(t *testing.T) {
	dir := setupDemoProgram(t, "demo")
	har := filepath.Join(t.TempDir(), "session.har")
	if err := os.WriteFile(har, []byte(demoHAR), 0o600); err != nil {
		t.Fatal(err)
	}

	out, rc := runCapture(t, func() int {
		return cmdEvidence([]string{"demo", "import", "--har", har})
	})
	if rc != 0 {
		t.Fatalf("rc = %d: %s", rc, out)
	}
	for _, want := range []string{"entries: 3", "kept: 2", "added: 2", "non-http scheme: 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	items, err := evidence.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("index holds %d items, want 2", len(items))
	}
	if items[0].Finding != "" {
		t.Errorf("imported evidence must not claim a finding: %+v", items[0])
	}

	// Re-running the same capture must not duplicate the index.
	again, rc := runCapture(t, func() int {
		return cmdEvidence([]string{"demo", "import", "--har", har})
	})
	if rc != 0 {
		t.Fatalf("rc = %d: %s", rc, again)
	}
	if !strings.Contains(again, "already known: 2") {
		t.Errorf("re-import did not report the existing entries:\n%s", again)
	}
	if items2, _ := evidence.Load(dir); len(items2) != 2 {
		t.Errorf("index grew on re-import: %d items", len(items2))
	}
}

func TestEvidenceImportFailsLoudlyOnAnEmptyCapture(t *testing.T) {
	dir := setupDemoProgram(t, "demo")
	har := filepath.Join(t.TempDir(), "junk.har")
	if err := os.WriteFile(har, []byte(`{"log":{"version":"1.2","entries":[{"request":{"url":"chrome-extension://a/b"}}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, rc := runCapture(t, func() int {
		return cmdEvidence([]string{"demo", "import", "--har", har})
	})
	if rc != 1 {
		t.Fatalf("rc = %d, want 1 — an index of nothing must not exit 0:\n%s", rc, out)
	}
	if !strings.Contains(out, "nothing indexed") {
		t.Errorf("no explanation printed:\n%s", out)
	}
	if items, _ := evidence.Load(dir); len(items) != 0 {
		t.Errorf("junk capture wrote %d items", len(items))
	}
}

func TestEvidenceImportNeedsACapture(t *testing.T) {
	setupDemoProgram(t, "demo")
	out, rc := runCapture(t, func() int {
		return cmdEvidence([]string{"demo", "import"})
	})
	if rc != 2 || !strings.Contains(out, "--har") {
		t.Errorf("rc = %d out = %q, want a usage error mentioning --har", rc, out)
	}
}

func TestModelCommandHonoursTheDeclaredArchetype(t *testing.T) {
	dir := setupDemoProgram(t, "demo")
	contract := `{"contract_version":1,"platform":"hackerone","name":"demo","archetype":"GraphQLAPI",
	 "scope":[{"rule":"api.demo.example"}]}`
	if err := os.WriteFile(filepath.Join(dir, "state", "program.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	// scope.txt is the in-scope surface the model measures coverage against.
	if err := os.WriteFile(filepath.Join(dir, "scope.txt"), []byte("api.demo.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	har := filepath.Join(t.TempDir(), "session.har")
	if err := os.WriteFile(har, []byte(demoHAR), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, rc := runCapture(t, func() int {
		return cmdEvidence([]string{"demo", "import", "--har", har})
	}); rc != 0 {
		t.Fatal("import failed")
	}

	out, rc := runCapture(t, func() int { return cmdModel([]string{"demo"}) })
	if rc != 0 {
		t.Fatalf("rc = %d: %s", rc, out)
	}
	// The canonical name is the hyphenated one; the declared camel-case spelling
	// must land on it rather than becoming a third name.
	if !strings.Contains(out, "# Archetype: graphql-api") {
		t.Errorf("declared archetype not honoured:\n%s", out)
	}
	if !strings.Contains(out, "source: declared") {
		t.Errorf("verdict does not say it came from a declaration:\n%s", out)
	}
	if !strings.Contains(out, "api.demo.example") {
		t.Errorf("model never mentions the asset that was imported:\n%s", out)
	}
}

func TestModelCommandWritesAndPrintsJSON(t *testing.T) {
	dir := setupDemoProgram(t, "demo")
	out, rc := runCapture(t, func() int { return cmdModel([]string{"demo"}) })
	if rc != 0 {
		t.Fatalf("rc = %d: %s", rc, out)
	}
	if !strings.Contains(out, "# Archetype:") {
		t.Errorf("no archetype verdict printed:\n%s", out)
	}

	js, rc := runCapture(t, func() int { return cmdModel([]string{"demo", "--json", "--write"}) })
	if rc != 0 {
		t.Fatalf("rc = %d: %s", rc, js)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(js), &got); err != nil {
		t.Fatalf("--json is not JSON: %v\n%s", err, js)
	}
	if got["program"] != "demo" {
		t.Errorf("json program = %v", got["program"])
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "model.json")); err != nil {
		t.Errorf("--write did not persist the model: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "state", "model.md")); err != nil || len(b) == 0 {
		t.Errorf("--write did not persist the markdown: %v", err)
	}
}

func TestModelCommandRejectsAnUnknownProgram(t *testing.T) {
	setupDemoProgram(t, "demo")
	out, rc := runCapture(t, func() int { return cmdModel([]string{"nope"}) })
	if rc != 2 || !strings.Contains(out, "unknown program") {
		t.Errorf("rc = %d out = %q", rc, out)
	}
}
