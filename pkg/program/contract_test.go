package program

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/pkg/driver"
	"github.com/hourx/kai-harness/pkg/workspace"
)

func testIntake() *Intake {
	return &Intake{
		Platform:     "hackerone",
		Confidence:   "high",
		Handle:       "demo",
		Name:         "Demo Program",
		URL:          "https://hackerone.com/demo",
		OffersBounty: true,
		PolicyHash:   "deadbeef",
		FetchedAt:    time.Now().UTC().Truncate(time.Second),
		Scorecard:    Score{Total: 72, Verdict: "bounty"},
		Assets: []Asset{
			{Identifier: "example.com", Type: "url", Eligible: true, Bounty: true},
			{Identifier: "*.example.com", Type: "wildcard", Eligible: true, Bounty: true},
			{Identifier: "https://example.com/api/v1/*", Type: "url", Eligible: true},
			{Identifier: "legacy.example.net", Type: "url", Eligible: false},
		},
	}
}

func TestBuildContractCarriesTheDriversVocabulary(t *testing.T) {
	m, ok := driver.Get("hackerone")
	if !ok {
		t.Fatal("hackerone manifest missing")
	}
	in := testIntake()
	c := BuildContract(in, m)

	if c.ContractVersion != ContractVersion {
		t.Errorf("contract_version = %d, want %d", c.ContractVersion, ContractVersion)
	}
	if c.Driver != "hackerone" || c.DriverVersion != m.Version {
		t.Errorf("driver stamped as %s v%d", c.Driver, c.DriverVersion)
	}
	if len(c.Scope) == 0 {
		t.Fatal("no in-scope rules derived from eligible assets")
	}
	for _, r := range c.Scope {
		if r.Rule == "" {
			t.Error("a scope rule with no value cannot be defended")
		}
		if r.Source == "" {
			t.Errorf("rule %s has no source", r.Rule)
		}
	}
	// The out-of-scope asset must land in the out table, and the path-restricted
	// asset must not become a host rule.
	if !c.OutOfScopeSet()["legacy.example.net"] {
		t.Errorf("legacy.example.net missing from out_of_scope: %v", c.Out)
	}
	if c.InScopeSet()["legacy.example.net"] {
		t.Error("an asset that is not eligible for submission was authorised")
	}
	if len(c.PathOnly) != 1 {
		t.Errorf("path-restricted assets = %d, want 1", len(c.PathOnly))
	}
	if c.Intake.Hash == "" {
		t.Error("the contract must record the intake snapshot it rests on")
	}
	// The field set and mandatory conditions are the driver's, verbatim.
	if strings.Join(c.ReportFields, ",") != strings.Join(m.ReportFieldSet, ",") {
		t.Errorf("report field set = %v, want the driver's %v", c.ReportFields, m.ReportFieldSet)
	}
	if len(c.Mandatory) != len(m.MandatoryConditions) {
		t.Errorf("mandatory conditions = %d, want %d", len(c.Mandatory), len(m.MandatoryConditions))
	}
	if len(c.RewardFields) != len(m.RewardFields) {
		t.Errorf("reward fields = %d, want %d", len(c.RewardFields), len(m.RewardFields))
	}
	// The action table must never be empty in any of its three classes: an
	// unstated boundary is one the operator has to invent.
	if len(c.Actions.ReadOnly) == 0 || len(c.Actions.NeedsApproval) == 0 || len(c.Actions.Forbidden) == 0 {
		t.Errorf("action table incomplete: %+v", c.Actions)
	}
	if !contains(c.Actions.Forbidden, "denial of service, load or stress testing of any kind") {
		t.Error("DoS must be forbidden in every contract")
	}
}

func TestContractRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	p, err := workspace.Create("demo", workspace.Meta{ProgramURL: "https://hackerone.com/demo"})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := driver.Get("hackerone")
	c := BuildContract(testIntake(), m)
	if err := SaveContract(p, c); err != nil {
		t.Fatal(err)
	}
	// The file must be valid JSON (and therefore valid YAML 1.2).
	b, err := os.ReadFile(p.StatePath("program.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatalf("state/program.yaml is not valid JSON: %v", err)
	}
	got, ok, err := LoadContract(p)
	if err != nil || !ok {
		t.Fatalf("LoadContract: ok=%v err=%v", ok, err)
	}
	if got.Driver != c.Driver || len(got.Scope) != len(c.Scope) || len(got.Out) != len(c.Out) {
		t.Errorf("round trip changed the contract: %+v vs %+v", got, c)
	}
	if !got.WrittenAt.Equal(c.WrittenAt) {
		t.Errorf("written_at changed: %s vs %s", got.WrittenAt, c.WrittenAt)
	}
	perm := os.FileMode(0)
	if fi, err := os.Stat(p.StatePath("program.yaml")); err == nil {
		perm = fi.Mode().Perm()
	}
	if perm != 0o600 {
		t.Errorf("contract file mode = %o, want 600", perm)
	}
}

func TestLoadContractMissingAndFutureVersion(t *testing.T) {
	p := &workspace.Program{Name: "demo", Dir: t.TempDir()}
	if _, ok, err := LoadContract(p); ok || err != nil {
		t.Errorf("a workspace without a contract must load as absent, got ok=%v err=%v", ok, err)
	}
	if err := os.MkdirAll(p.StatePath(""), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.StatePath("program.yaml"), []byte(`{"contract_version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadContract(p); err == nil {
		t.Error("a contract from a newer version must be refused, not half-read")
	}
}

func TestContractAuditFindsTheDangerousDirection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	p, err := workspace.Create("demo", workspace.Meta{Platform: "hackerone"})
	if err != nil {
		t.Fatal(err)
	}
	c := Contract{
		ContractVersion: ContractVersion,
		Driver:          "hackerone",
		Platform:        "hackerone",
		Name:            "demo",
		Scope:           []Rule{{Rule: "example.com", Source: "structured scope (eligible)"}},
		Out:             []Rule{{Rule: "admin.example.com", Source: "structured scope (not eligible)"}},
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(p.Dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// scope.txt names a host the contract does not authorise, and one the
	// contract explicitly excludes. Both are the gate being broader than the
	// program allows.
	write("scope.txt", "example.com\nextra.example.org\nadmin.example.com\n")
	write("out-of-scope.txt", "example.com\n")

	problems := ContractAudit(p, c)
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, "scope.txt is broader than the contract: extra.example.org") {
		t.Errorf("a gate broader than the contract must be reported:\n%s", joined)
	}
	if !strings.Contains(joined, "contradiction: admin.example.com") {
		t.Errorf("a host in both scope.txt and the out table must be reported:\n%s", joined)
	}
	if !strings.Contains(joined, "contradiction: example.com is out of scope and authorised by the contract") {
		t.Errorf("a host in both the gate's out file and the contract's in table must be reported:\n%s", joined)
	}
	for _, s := range problems {
		if strings.HasPrefix(s, "note:") {
			t.Errorf("this case should produce contradictions, not notes: %s", s)
		}
	}
}

func TestContractAuditAgreesOnAConsistentWorkspace(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	p, err := workspace.Create("demo", workspace.Meta{Platform: "hackerone"})
	if err != nil {
		t.Fatal(err)
	}
	c := Contract{
		ContractVersion: ContractVersion,
		Driver:          "hackerone",
		Platform:        "hackerone",
		Name:            "demo",
		Scope:           []Rule{{Rule: "example.com", Source: "structured scope (eligible)"}},
		Out:             []Rule{{Rule: "admin.example.com", Source: "structured scope (not eligible)"}},
	}
	if err := os.WriteFile(filepath.Join(p.Dir, "scope.txt"), []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Dir, "out-of-scope.txt"), []byte("admin.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, s := range ContractAudit(p, c) {
		if !strings.HasPrefix(s, "note:") {
			t.Errorf("unexpected finding on a consistent workspace: %s", s)
		}
	}
}

// A workspace may label the platform with a short name ("h1" for the driver
// "hackerone"). Different strings, same platform: not a disagreement.
func TestAuditAcceptsAShortPlatformName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	p, err := workspace.Create("demo", workspace.Meta{Platform: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	c := Contract{
		ContractVersion: ContractVersion,
		Driver:          "hackerone",
		Platform:        "h1",
		Name:            "demo",
		Scope:           []Rule{{Rule: "example.com", Source: "structured scope (eligible)"}},
		Out:             []Rule{},
	}
	if err := os.WriteFile(filepath.Join(p.Dir, "scope.txt"), []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Dir, "out-of-scope.txt"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, s := range ContractAudit(p, c) {
		if strings.Contains(s, "meta.json says platform") {
			t.Errorf("a known short platform name must not read as a mismatch: %s", s)
		}
	}
}

// The header line must not print an empty field: "" would show up as a dangling
// comma, which reads like a value somebody forgot to fill in.
func TestMarkdownOmitsEmptyFacts(t *testing.T) {
	small := &Intake{
		Platform:  "h1",
		Name:      "Small",
		URL:       "https://hackerone.com/small",
		FetchedAt: time.Now().UTC(),
		Scorecard: Score{Total: 0},
		Assets:    []Asset{{Identifier: "example.com", Type: "url", Eligible: true}},
	}
	m, _ := driver.Get("hackerone")
	md := BuildContract(small, m).Markdown()
	if strings.Contains(md, "confidence ,") || strings.Contains(md, "(, ") || strings.Contains(md, "  ") {
		t.Errorf("empty facts leaked into the header:\n%s", md)
	}
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "- intake fetched:") {
			if !strings.HasSuffix(line, "(score 0)") {
				t.Errorf("header = %q, want it to end with the score only", line)
			}
		}
	}
}

func TestMarkdownNamesTheProvenance(t *testing.T) {
	m, _ := driver.Get("hackerone")
	md := BuildContract(testIntake(), m).Markdown()
	for _, want := range []string{"## Scope", "## Out of scope", "## Actions", "## Report field set", "Mandatory conditions", "driver: hackerone"} {
		if !strings.Contains(md, want) {
			t.Errorf("contract view is missing %q", want)
		}
	}
}

// An empty table must serialize as an empty list. A null would make a reader
// guess whether the program published no rules or the file lost them.
func TestEmptyTablesAreListsNotNull(t *testing.T) {
	small := &Intake{
		Platform:  "selfhosted",
		Name:      "Small",
		URL:       "https://example.org/security",
		FetchedAt: time.Now().UTC(),
		Assets:    []Asset{{Identifier: "example.org", Type: "url", Eligible: true}},
	}
	m, _ := driver.Get("selfhosted")
	b, err := BuildContract(small, m).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"out_of_scope": []`, `"path_scoped": []`, `"non_web": []`, `"mandatory_conditions": []`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("empty table serialized as null or missing: want %s\n%s", field, b)
		}
	}
}
