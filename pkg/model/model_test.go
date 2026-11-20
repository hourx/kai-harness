package model

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/pkg/evidence"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/recon"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/workspace"
)

var fixedNow = time.Date(2026, 11, 21, 3, 0, 0, 0, time.UTC)

func fixtureProgram(t *testing.T) *workspace.Program {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scope.txt"), []byte(
		"# scope\napp.example.test\n*.example.test\napi.example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "out-of-scope.txt"), []byte(
		"status.example.test\n# internal only\nblog.example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &workspace.Program{Name: "example", Dir: dir}
}

func fixtureStore() *recon.Store {
	eps := map[string][]string{
		"/api/v1/orders":                        {"user_id", "page"},
		"/api/v1/orders/{order_id}":             {"order_id"},
		"/api/v2/orders/{uuid}":                 {"uuid"},
		"/api/v1/orders/create":                 {"amount"},
		"/api/v1/orders/{order_id}/update":      {"amount"},
		"/api/v1/orders/{order_id}/delete":      {},
		"/api/v1/billing/invoices":              {"account_id"},
		"/api/v1/billing/invoices/{invoice_id}": {"invoice_id"},
		"/api/v1/session/login":                 {"email", "password"},
		"/api/v1/misc/ping":                     {},
		"/api/v1/misc/health":                   {},
		"/api/v1/misc/version":                  {},
		"/api/v1/misc/metrics":                  {},
		"/api/v1/misc/whoami":                   {},
	}
	store := recon.NewStore("example")
	for path, params := range eps {
		store.Endpoints[path] = &recon.EndpointRecord{Path: path, Params: params}
	}
	return store
}

func fixtureOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		Program:         fixtureProgram(t),
		Store:           fixtureStore(),
		Archetype:       "api",
		ArchetypeSource: ProvSpec,
		Now:             fixedNow,
		Records: []outcome.Record{
			{TS: "2026-11-20T10:00:00Z", Target: "https://app.example.test/api/v1/orders", Status: outcome.StatusNegation, Class: "IDOR/BOLA", Note: "ownership check held for foreign order id"},
			{TS: "2026-11-20T12:00:00Z", Target: "billing.example.test/invoices", Status: outcome.StatusInformational, Class: "business-logic", Note: "403 on cross-account invoice fetch"},
		},
		Evidence: []evidence.Item{
			{ID: "ev-0001", TS: "2026-11-20T10:00:00Z", Kind: "response", Host: "app.example.test", Path: "/api/v1/orders", Status: 403},
		},
	}
}

func TestDeriveFactsAndGaps(t *testing.T) {
	m, err := Derive(fixtureOptions(t))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if m.Program != "example" || m.Archetype != "api" || m.Generated != fixedNow.Format(time.RFC3339) {
		t.Fatalf("header wrong: %+v", m)
	}
	if len(m.Entities) == 0 || len(m.Actions) != 14 {
		t.Fatalf("entities=%d actions=%d, want >0 entities and 14 actions", len(m.Entities), len(m.Actions))
	}

	// The orders module is addressed by a numeric id and a uuid: that is the
	// anomaly the model must notice without being told.
	var dualKey bool
	for _, a := range m.Anomalies {
		if a.Kind == "dual-key-types" && a.Target == "module:orders" {
			dualKey = true
		}
	}
	if !dualKey {
		t.Fatalf("expected a dual-key-types anomaly on orders, got %+v", m.Anomalies)
	}

	// Coverage must name the assets nobody touched, not only the ones with rows.
	cov := map[string]string{}
	for _, c := range m.Coverage {
		cov[c.Asset] = c.Tested
	}
	if cov["app.example.test"] != TestedYes {
		t.Fatalf("app.example.test should be tested=yes, got %q (rows %+v)", cov["app.example.test"], m.Coverage)
	}
	if cov["api.example.test"] != TestedNo {
		t.Fatalf("api.example.test should be tested=no, got %q", cov["api.example.test"])
	}

	// Actions carry the side effect the sweep reasons about.
	for _, a := range m.Actions {
		if a.Path == "/api/v1/session/login" {
			if a.SideEffect != "auth" || a.AuthRequired != "no" {
				t.Fatalf("login action mis-derived: %+v", a)
			}
		}
		if a.Path == "/api/v1/billing/invoices" && a.SideEffect != "value" {
			t.Fatalf("billing action side effect = %q, want value", a.SideEffect)
		}
	}

	// Exploration maps statuses onto exits and keeps the note as the reason.
	if len(m.Exploration) != 2 {
		t.Fatalf("exploration rows = %d, want 2", len(m.Exploration))
	}
	for _, e := range m.Exploration {
		// A negation where the control held is "blocked" (the sweep was stopped by
		// a real check), anything else with no yield is "tried".
		want := OutcomeTried
		if strings.Contains(e.Why, "403") {
			want = OutcomeBlocked
		}
		if e.Outcome != want {
			t.Fatalf("exploration %s outcome = %q, want %q", e.Target, e.Outcome, want)
		}
		if e.Why == "" || e.EvidenceRef == "" && e.Target != "billing.example.test/invoices" {
			t.Fatalf("exploration row lost its reason or evidence: %+v", e)
		}
	}

	// Declaring no invariants is not a pass: the model has to say so out loud.
	var sawInvariantGap, sawCapabilityGap bool
	for _, g := range m.Gaps {
		if len(g) > 15 && g[:13] == "invariants[st" {
			sawInvariantGap = true
		}
		if len(g) > 12 && g[:12] == "capabilities" {
			sawCapabilityGap = true
		}
	}
	if !sawInvariantGap || !sawCapabilityGap {
		t.Fatalf("gaps must state the missing invariants and capabilities, got %+v", m.Gaps)
	}

	// Boundaries come from the scope files, not from guesswork.
	if len(m.Boundaries) != 1 || m.Boundaries[0].Outside == "" {
		t.Fatalf("scope boundary missing out-of-scope rules: %+v", m.Boundaries)
	}
}

func TestDeriveIsDeterministic(t *testing.T) {
	a, err := Derive(fixtureOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Derive(fixtureOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Save(t.TempDir()); err != nil {
		t.Fatalf("save: %v", err)
	}
	if a.Markdown() != b.Markdown() {
		t.Fatal("two derivations of the same artifacts rendered differently")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m, err := Derive(fixtureOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}
	back, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if back.Program != m.Program || len(back.Actions) != len(m.Actions) || len(back.Anomalies) != len(m.Anomalies) {
		t.Fatalf("round trip changed the model: %d/%d actions, %d/%d anomalies",
			len(back.Actions), len(m.Actions), len(back.Anomalies), len(m.Anomalies))
	}
	if _, err := Load(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("loading a program with no model should fail with instructions")
	}
}

func TestSweepEmitsProbesOnlyWhenModelKnowsEnough(t *testing.T) {
	m, err := Derive(fixtureOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	// With no capabilities and no invariants, the sweeps that need them stay
	// silent — a hypothesis invented from nothing is noise.
	hs := Sweep(m)
	var sawCapability, sawInvariant bool
	for _, h := range hs {
		for _, tag := range h.Tags {
			if tag == TagCapability {
				sawCapability = true
			}
			if tag == TagInvariant {
				sawInvariant = true
			}
		}
	}
	if sawCapability || sawInvariant {
		t.Fatal("capability/invariant sweeps must not fire on an empty matrix")
	}
	if len(hs) == 0 {
		t.Fatal("parity/transition/anomaly sweeps should have produced something on this surface")
	}
	// Every probe must be executable: a target and a probe sentence.
	for _, h := range hs {
		if h.Target == "" || h.Probe == "" || len(h.Why) == 0 || h.Score <= 0 {
			t.Fatalf("incomplete hypothesis: %+v", h)
		}
	}

	// Now teach the model one capability and one checked invariant: both sweeps
	// must turn into probes, and the parity sweep must keep its evidence.
	m.Capabilities = []Capability{{
		Role: "user", Action: "GET", Object: "/api/v1/orders/{order_id}",
		Allowed: "yes", Enforcement: "client", Source: ProvSpec,
	}}
	m.Invariants = []Invariant{{
		ID: "inv:refund", Statement: "a refund cannot exceed the captured amount",
		Check: "create an order, refund 1 more unit than captured, compare balance", Domain: "value", Source: ProvSpec,
	}}
	hs = Sweep(m)
	var cap, inv int
	for _, h := range hs {
		for _, tag := range h.Tags {
			switch tag {
			case TagCapability:
				cap++
				if h.Score < 70 {
					t.Fatalf("client-side enforcement should score high, got %d", h.Score)
				}
			case TagInvariant:
				inv++
				if h.Probe != m.Invariants[0].Check {
					t.Fatalf("invariant probe must be the declared check, got %q", h.Probe)
				}
			}
		}
	}
	if cap != 1 || inv != 1 {
		t.Fatalf("capability probes=%d invariant probes=%d, want 1 and 1", cap, inv)
	}
	if hs[0].Score < hs[len(hs)-1].Score {
		t.Fatal("hypotheses must be sorted by score, highest first")
	}
}

func TestParityKeyAndPrefix(t *testing.T) {
	cases := []struct{ path, key, prefix string }{
		{"/api/v1/orders/{order_id}", "orders", "api"},
		{"/api/v2/orders/1234abcd", "orders", "api"},
		{"/rest/orders/550e8400-e29b-41d4-a716-446655440000", "orders", "rest"},
		{"/v1/orders", "orders", "v1"},
		{"/", "", "web"},
	}
	for _, c := range cases {
		if got := parityKey(c.path); got != c.key {
			t.Errorf("parityKey(%q) = %q, want %q", c.path, got, c.key)
		}
		if got := apiPrefix(c.path); got != c.prefix {
			t.Errorf("apiPrefix(%q) = %q, want %q", c.path, got, c.prefix)
		}
	}
	// Two generations of one action must land in the same parity group.
	if parityKey("/api/v1/orders/{order_id}") != parityKey("/rest/orders/{id}") {
		t.Fatal("the same action on two transports must share a parity key")
	}
}

func TestNonWebAssetEntersCoverage(t *testing.T) {
	o := fixtureOptions(t)
	o.NonWeb = []surface.NonWebAsset{{Identifier: "0xabc0000000000000000000000000000000000001", Type: "contract"}}
	m, err := Derive(o)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range m.Coverage {
		if c.Asset == "contract:0xabc0000000000000000000000000000000000001" {
			found = true
			if c.Tested != TestedNo {
				t.Fatalf("an untouched contract must read tested=no, got %q", c.Tested)
			}
		}
	}
	if !found {
		t.Fatalf("non-web asset missing from coverage: %+v", m.Coverage)
	}
	for _, g := range m.NeverTested() {
		if g == "contract:0xabc0000000000000000000000000000000000001" {
			return
		}
	}
	t.Fatal("NeverTested must include the untouched contract")
}

// The closing list in `kai model` is a to-do list: anything with work recorded
// against it must not appear there, or the operator re-tests what is already done.
func TestNeverTestedCountsPartialAsTouched(t *testing.T) {
	m := &Model{Coverage: []Coverage{
		{Asset: "done.example", Tested: TestedYes},
		{Asset: "started.example", Tested: TestedPartial},
		{Asset: "idle.example", Tested: TestedNo},
		{Asset: "blank.example"},
	}}
	got := m.NeverTested()
	if len(got) != 2 || got[0] != "idle.example" || got[1] != "blank.example" {
		t.Errorf("NeverTested() = %v, want [idle.example blank.example]", got)
	}
}
