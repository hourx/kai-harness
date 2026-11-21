package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hourx/kai-harness/pkg/model"
	"github.com/hourx/kai-harness/pkg/outcome"
)

// preparePatternsProgram gives the command something to read: a recorded
// archetype, a queue with classes in it, two scope hosts and two outcomes — one
// that paid and one that was closed as not-a-bug.
func preparePatternsProgram(t *testing.T, name string) string {
	t.Helper()
	dir := setupDemoProgram(t, name)
	if err := os.WriteFile(model.Path(dir), []byte(`{"archetype":"graphql-api","generated":"2026-11-21T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	next := `{"program":"` + name + `","items":[` +
		`{"target":"GET /graphql","class":"graphql","score":40},` +
		`{"target":"GET /api/me","class":"api-surface","score":30},` +
		`{"target":"POST /api/orders","class":"business-logic","score":20},` +
		`{"target":"GET /api/files/1","class":"file-upload/SSRF","score":10}]}`
	if err := os.WriteFile(filepath.Join(dir, "next.json"), []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scope.txt"), []byte("shop.example.com\napi.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, r := range []outcome.Record{
		{Target: "GET /graphql", Status: outcome.StatusPaid, Class: "graphql"},
		{Target: "POST /api/orders", Status: outcome.StatusNegation, Class: "business-logic"},
	} {
		if err := outcome.Append(dir, r); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPatternsCommandPrintsBothLayers(t *testing.T) {
	preparePatternsProgram(t, "demo")
	out, rc := runCapture(t, func() int { return cmdPatterns([]string{"demo"}) })
	if rc != 0 {
		t.Fatalf("exit %d:\n%s", rc, out)
	}
	for _, want := range []string{
		"# Patterns — demo",
		"**graphql-api** (recorded in state/model.json)",
		"## What applies to this shape",
		"## This workspace's layer",
		"## Questions the queue asks — 4 class(es)",
		"`GraphQL` — covered (this shape) · fired 1, paid 1, negation 0",
		"`business-logic` — covered (inherited from `api`) · fired 1, paid 0, negation 1",
		"`API-surface` — covered (inherited from `api`)",
		"`file-upload/SSRF` — no pattern",
		"Unanswered: 1 class(es)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q\n%s", want, out)
		}
	}
}

func TestPatternsCommandWritesTheDeltaOnlyWhenAsked(t *testing.T) {
	dir := preparePatternsProgram(t, "demo")
	if _, rc := runCapture(t, func() int { return cmdPatterns([]string{"demo"}) }); rc != 0 {
		t.Fatalf("exit %d", rc)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "patterns-delta.json")); !os.IsNotExist(err) {
		t.Fatalf("a read must not write: stat err = %v", err)
	}
	out, rc := runCapture(t, func() int { return cmdPatterns([]string{"demo", "--write"}) })
	if rc != 0 || !strings.Contains(out, "patterns-delta.json") {
		t.Fatalf("--write: exit %d\n%s", rc, out)
	}
	body, err := os.ReadFile(filepath.Join(dir, "state", "patterns-delta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Program   string `json:"program"`
		Archetype string `json:"archetype"`
		Keys      []struct {
			Key struct {
				Name string `json:"name"`
			} `json:"key"`
			Fired int `json:"fired"`
			Paid  int `json:"paid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("delta is not readable JSON: %v\n%s", err, body)
	}
	if d.Program != "demo" || d.Archetype != "graphql-api" || len(d.Keys) != 2 {
		t.Fatalf("a delta key comes from an outcome, so two outcomes make two keys: %+v", d)
	}
	got := map[string][2]int{}
	for _, k := range d.Keys {
		got[k.Key.Name] = [2]int{k.Fired, k.Paid}
	}
	if got["graphql"] != [2]int{1, 1} || got["business-logic"] != [2]int{1, 0} {
		t.Fatalf("delta counts wrong: %v", got)
	}
}

func TestPatternsCommandReadsALayerDirectoryAndComplainsAboutBadEntries(t *testing.T) {
	preparePatternsProgram(t, "demo")
	layers := t.TempDir()
	good := `[{"key":{"archetype":"graphql-api","family":"class","name":"file-upload/ssrf"},"class":"file-upload/SSRF","title":"the queue does ask this","why":"seen on this shape","confidence":0.7}]`
	bad := `[{"key":{"archetype":"graphql-api","family":"class","name":"x"},"title":"","confidence":0.5}]`
	for name, body := range map[string]string{"a.json": good, "b.json": bad} {
		if err := os.WriteFile(filepath.Join(layers, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, rc := runCapture(t, func() int { return cmdPatterns([]string{"demo", "--dir", layers}) })
	if rc != 1 {
		t.Fatalf("a broken layer must not exit 0, got %d\n%s", rc, out)
	}
	for _, want := range []string{"2 layer file(s) merged", "problem(s) in the layers", "b.json", "entry 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q\n%s", want, out)
		}
	}
	// The good layer filled the gap, so the gap list shrinks but stays honest.
	if !strings.Contains(out, "`file-upload/SSRF` — covered (this shape)") {
		t.Errorf("the merged layer should cover the class the queue asks about\n%s", out)
	}
	if !strings.Contains(out, "the queue does ask this") {
		t.Errorf("a local pattern must reach the report\n%s", out)
	}
}

func TestPatternsCommandJSONAndArchetypeOverride(t *testing.T) {
	preparePatternsProgram(t, "demo")
	out, rc := runCapture(t, func() int { return cmdPatterns([]string{"demo", "--json", "--archetype", "chain"}) })
	if rc != 0 {
		t.Fatalf("exit %d:\n%s", rc, out)
	}
	var payload struct {
		Archetype     string `json:"archetype"`
		ArchetypeFrom string `json:"archetype_from"`
		Delta         struct {
			Archetype string `json:"archetype"`
			Keys      []any  `json:"keys"`
		} `json:"delta"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if payload.Archetype != "chain" || payload.ArchetypeFrom != "from --archetype" {
		t.Fatalf("the flag should win and say so: %+v", payload)
	}
	// The delta is keyed the same way, or a boost would ask about a different shape.
	if payload.Delta.Archetype != "chain" {
		t.Fatalf("delta archetype %q does not match the report", payload.Delta.Archetype)
	}
}

func TestContributeCommandHandsOverAPayloadAndSendsNothing(t *testing.T) {
	preparePatternsProgram(t, "demo")
	out, rc := runCapture(t, func() int { return cmdContribute([]string{"demo"}) })
	if rc != 0 {
		t.Fatalf("exit %d:\n%s", rc, out)
	}
	if !strings.Contains(out, "Nothing was sent") {
		t.Errorf("the command has no transport and must say so\n%s", out)
	}
	for _, leak := range []string{"shop.example.com", "api.example.com", "/graphql", "/api/orders"} {
		if strings.Contains(out, leak) {
			t.Errorf("the payload leaked %q\n%s", leak, out)
		}
	}

	// --out writes the same bytes, and only those bytes.
	dest := filepath.Join(t.TempDir(), "payload.json")
	if _, rc := runCapture(t, func() int { return cmdContribute([]string{"demo", "--json", "--out", dest}) }); rc != 0 {
		t.Fatalf("exit %d", rc)
	}
	body, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Schema           string   `json:"schema"`
		Archetype        string   `json:"archetype"`
		HostFingerprints []string `json:"host_fingerprints"`
		WhatThisIs       string   `json:"what_this_is"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if c.Schema != "kai-contribute/1" || c.Archetype != "graphql-api" {
		t.Fatalf("payload header wrong: %+v", c)
	}
	// Two scope hosts, fingerprinted, and no host text anywhere in the file.
	if len(c.HostFingerprints) != 2 {
		t.Fatalf("want 2 fingerprints, got %v", c.HostFingerprints)
	}
	if !strings.Contains(c.WhatThisIs, "No URLs") {
		t.Fatalf("the payload should carry its own notice: %q", c.WhatThisIs)
	}
	if strings.Contains(string(body), "example.com") {
		t.Fatalf("payload leaked a host:\n%s", body)
	}
	if info, err := os.Stat(dest); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("payload mode should be 0600, got %v (%v)", info.Mode().Perm(), err)
	}
}

func TestContributeCommandMakesItsOwnSaltOnce(t *testing.T) {
	dir := preparePatternsProgram(t, "demo")
	dest := filepath.Join(t.TempDir(), "one.json")
	if _, rc := runCapture(t, func() int { return cmdContribute([]string{"demo", "--json", "--out", dest}) }); rc != 0 {
		t.Fatal("first run failed")
	}
	first, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	dest2 := filepath.Join(t.TempDir(), "two.json")
	if _, rc := runCapture(t, func() int { return cmdContribute([]string{"demo", "--json", "--out", dest2}) }); rc != 0 {
		t.Fatal("second run failed")
	}
	second, err := os.ReadFile(dest2)
	if err != nil {
		t.Fatal(err)
	}
	// Same workspace, same salt: the fingerprints must be comparable run to run.
	if string(first) != string(second) {
		t.Fatalf("two runs produced different payloads:\n%s\n%s", first, second)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "patterns-salt")); err != nil {
		t.Fatalf("salt was not persisted: %v", err)
	}
}

func TestPatternsAndContributeNeedAProgram(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	for _, args := range [][]string{{"missing"}, {"missing", "--json"}} {
		out, rc := runCapture(t, func() int { return cmdPatterns(args) })
		if rc == 0 || !strings.Contains(out, "unknown program") {
			t.Errorf("kai patterns %v: exit %d, out %q", args, rc, out)
		}
		out, rc = runCapture(t, func() int { return cmdContribute(args) })
		if rc == 0 {
			t.Errorf("kai contribute %v should fail without a workspace, got exit %d: %s", args, rc, out)
		}
	}
	out, rc := runCapture(t, func() int { return cmdPatterns(nil) })
	if rc != 2 || !strings.Contains(out, "usage: kai patterns") {
		t.Errorf("no argument should print usage and exit 2, got exit %d: %s", rc, out)
	}
}
