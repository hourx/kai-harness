package driver

import "testing"

func TestManifestsLoadAndValidate(t *testing.T) {
	all := All()
	if len(all) < 3 {
		t.Fatalf("expected at least 3 embedded manifests, got %d", len(all))
	}
	seen := map[string]bool{}
	for _, m := range all {
		if err := m.Validate(); err != nil {
			t.Errorf("%s: %v", m.ID, err)
		}
		if seen[m.ID] {
			t.Errorf("duplicate manifest id %s", m.ID)
		}
		seen[m.ID] = true
	}
	for _, want := range []string{"hackerone", "bugcrowd", "selfhosted"} {
		if !seen[want] {
			t.Errorf("manifest %s is missing", want)
		}
	}
}

func TestMatchPicksTheClaimingDriver(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://hackerone.com/temu", "hackerone"},
		{"https://hackerone.com/temu/policy_scopes", "hackerone"},
		{"https://app.hackerone.com/api", "hackerone"},
		{"https://bugcrowd.com/tesla", "bugcrowd"},
		{"https://bugcrowd.com/engagements/tesla", "bugcrowd"},
		{"https://www.example.com/security", "selfhosted"},
		{"https://example.com/.well-known/security.txt", "selfhosted"},
	}
	for _, c := range cases {
		m, pat, ok := Match(c.url)
		if !ok {
			t.Errorf("%s: no driver claimed it", c.url)
			continue
		}
		if m.ID != c.want {
			t.Errorf("%s: claimed by %s (pattern %q), want %s", c.url, m.ID, pat, c.want)
		}
	}
}

// A wildcard must not be a suffix test on the whole host: a lookalike domain is
// a different program, and serving it another program's rules is the one error
// that matters here.
func TestLookalikeHostsDoNotMatch(t *testing.T) {
	for _, url := range []string{
		"https://hackerone.com.evil.example/x",
		"https://nothackerone.com/x",
		"https://evilbugcrowd.com/x",
		"https://bugcrowd.com.evil.example/x",
	} {
		m, pat, ok := Match(url)
		if ok && m.ID != "selfhosted" {
			t.Errorf("%s: claimed by %s via %q, want the fallback", url, m.ID, pat)
		}
	}
}

func TestMatchRejectsUnusableInput(t *testing.T) {
	for _, raw := range []string{"", "   ", "not a url", "/relative/path"} {
		if _, _, ok := Match(raw); ok {
			t.Errorf("%q should not match any driver", raw)
		}
	}
}

func TestGet(t *testing.T) {
	if _, ok := Get("hackerone"); !ok {
		t.Fatal("hackerone manifest missing")
	}
	if _, ok := Get("nope"); ok {
		t.Fatal("Get returned an unknown driver")
	}
}

func TestValidateRejectsBrokenManifests(t *testing.T) {
	base := func() Manifest {
		return Manifest{
			Version:         1,
			ID:              "x",
			Name:            "X",
			Parser:          "generic",
			IntakeURLs:      []string{"x.example/*"},
			PolicyFetch:     PolicyFetch{Kind: "html"},
			ScopeExtraction: ScopeExtraction{Kind: "html"},
			ReportFieldSet:  []string{"title"},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("the baseline manifest must validate: %v", err)
	}
	future := base()
	future.Version = ManifestVersion + 1
	if err := future.Validate(); err == nil {
		t.Error("a manifest from a newer schema must be refused, not guessed at")
	}
	noParser := base()
	noParser.Parser = ""
	if err := noParser.Validate(); err == nil {
		t.Error("a manifest with no parser must be refused")
	}
	badKind := base()
	badKind.PolicyFetch.Kind = "carrier-pigeon"
	if err := badKind.Validate(); err == nil {
		t.Error("an unknown policy_fetch kind must be refused")
	}
	noFields := base()
	noFields.ReportFieldSet = nil
	if err := noFields.Validate(); err == nil {
		t.Error("a manifest with no report field set must be refused")
	}
}
