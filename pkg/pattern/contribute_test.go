package pattern

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/pkg/outcome"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHostFingerprintIsStableInsideAWorkspaceAndUselessOutside(t *testing.T) {
	a := HostFingerprint("salt-a", "shop.example.com")
	b := HostFingerprint("salt-a", "SHOP.example.com") // same host, other spelling
	c := HostFingerprint("salt-b", "shop.example.com") // other salt
	if a != b {
		t.Fatalf("case must not change the fingerprint: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("two salts produced the same fingerprint %q", a)
	}
	if len(a) != 16 {
		t.Fatalf("fingerprint %q is not 16 hex chars", a)
	}
	if strings.Contains(a, "shop") || strings.Contains(a, "example") {
		t.Fatalf("fingerprint %q leaks the host", a)
	}
	if HostFingerprint("", "shop.example.com") != "" || HostFingerprint("salt-a", "") != "" {
		t.Fatal("an empty salt or host must yield nothing, never a weak hash")
	}
}

func TestPayloadCarriesKeysAndFingerprintsAndNothingElse(t *testing.T) {
	now := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	records := []outcome.Record{
		rec("https://shop.example.com/api/orders/1234?user=42", "IDOR/BOLA", outcome.StatusPaid, "2026-11-20T01:00:00Z"),
		rec("https://shop.example.com/graphql", "graphql", outcome.StatusNegation, "2026-11-20T02:00:00Z"),
	}
	hosts := []string{"shop.example.com", "api.example.com", "shop.example.com"}

	c := Payload("yandex", "graphql-api", records, hosts, "salt-a", now)
	raw := mustJSON(t, c)
	if strings.Contains(string(raw), "null") {
		t.Fatalf("a payload with no keys must carry an empty list, not null:\n%s", raw)
	}
	if empty := mustJSON(t, Payload("yandex", "graphql-api", nil, nil, "salt-a", now)); strings.Contains(string(empty), "null") {
		t.Fatalf("an empty payload must still be well shaped:\n%s", empty)
	}
	if err := c.Audit(); err != nil {
		t.Fatalf("Audit refused a clean payload: %v", err)
	}
	if len(c.HostFingerprints) != 2 {
		t.Fatalf("want 2 unique fingerprints, got %v", c.HostFingerprints)
	}
	for i := 1; i < len(c.HostFingerprints); i++ {
		if c.HostFingerprints[i-1] > c.HostFingerprints[i] {
			t.Fatalf("fingerprints are not sorted: %v", c.HostFingerprints)
		}
	}

	raw = mustJSON(t, c)
	// The whole point: the payload must not mention where it came from.
	for _, needle := range []string{"shop.example.com", "api.example.com", "example.com", "/api/orders", "1234", "user=42", "yandex", "https://"} {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("payload contains %q:\n%s", needle, raw)
		}
	}
	if err := c.AuditForbidden([]string{"shop.example.com", "/api/orders/1234", "yandex"}); err != nil {
		t.Fatalf("AuditForbidden flagged a clean payload: %v", err)
	}
}

func TestAuditRefusesAnythingShapedLikeATarget(t *testing.T) {
	base := Contribution{Schema: ContributeSchema, Archetype: "api"}
	for name, key := range map[string]Key{
		"hostname":  NewKey("api", FamilyClass, "api.example.com"),
		"url":       NewKey("api", FamilyClass, "https-api-example-com"),
		"address":   NewKey("api", FamilyClass, "10.0.0.1"),
		"long id":   NewKey("api", FamilyClass, "tenant-1234567"),
		"uppercase": {Archetype: "api", Family: FamilyClass, Name: "GraphQL"},
	} {
		c := base
		c.Keys = []KeyStat{{Key: key, Fired: 1}}
		if err := c.Audit(); err == nil {
			t.Errorf("%s: Audit accepted %s", name, key)
		}
	}
	// An entity key is not publishable: only class keys are.
	c := base
	c.Keys = []KeyStat{{Key: NewKey("api", FamilyEntity, "account"), Fired: 1}}
	if err := c.Audit(); err == nil {
		t.Error("Audit accepted an entity key")
	}
	// A fingerprint that is not a fingerprint.
	c = base
	c.HostFingerprints = []string{"shop.example.com"}
	if err := c.Audit(); err == nil {
		t.Error("Audit accepted a raw host in the fingerprints")
	}
	// A foreign schema.
	if err := (Contribution{Schema: "kai-contribute/99", Archetype: "api"}).Audit(); err == nil {
		t.Error("Audit accepted an unknown schema")
	}
}

func TestAuditForbiddenCatchesWhatTheStructureCannot(t *testing.T) {
	c := Contribution{Schema: ContributeSchema, Archetype: "api", WhatThisIs: "leaked from shop.example.com"}
	if err := c.AuditForbidden([]string{"shop.example.com"}); err == nil {
		t.Fatal("AuditForbidden missed a host in the free text")
	}
	if err := c.AuditForbidden([]string{"xy"}); err != nil {
		t.Fatalf("short needles match by accident and must be skipped: %v", err)
	}
}

func TestSaltIsCreatedOnceAndStaysLocal(t *testing.T) {
	dir := t.TempDir()
	first, err := Salt(dir)
	if err != nil {
		t.Fatalf("Salt: %v", err)
	}
	if len(first) != 32 {
		t.Fatalf("salt %q is not 32 hex chars", first)
	}
	second, err := Salt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("the salt must be stable across calls, or fingerprints stop matching")
	}
	info, err := os.Stat(filepath.Join(dir, "state", SaltFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("salt mode %v, want 0600", info.Mode().Perm())
	}
	other, err := Salt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("two workspaces shared a salt, so their fingerprints are linkable")
	}
}
