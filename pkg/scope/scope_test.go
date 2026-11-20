package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func mustParse(t *testing.T, raw string) Target {
	t.Helper()
	tg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(%q): %v", raw, err)
	}
	return tg
}

func TestParseNormalizes(t *testing.T) {
	cases := map[string]string{
		"https://API.Example.com:443/path?q=1": "api.example.com",
		"api.example.com.":                     "api.example.com",
		"  Example.COM  ":                      "example.com",
	}
	for in, want := range cases {
		if got := mustParse(t, in).Value; got != want {
			t.Errorf("Parse(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseIP(t *testing.T) {
	for _, in := range []string{"203.0.113.7", "http://203.0.113.7:8080/", "::1"} {
		if got := mustParse(t, in).Kind; got != KindIP {
			t.Errorf("Parse(%q).Kind = %v, want KindIP", in, got)
		}
	}
}

func TestWildcardNeverMatchesApex(t *testing.T) {
	r := "*.example.com"
	for _, host := range []string{"a.example.com", "a.b.example.com"} {
		if !Matches(mustParse(t, host), r) {
			t.Errorf("%q should match %q", host, r)
		}
	}
	for _, host := range []string{"example.com", "notexample.com", "example.com.evil.test"} {
		if Matches(mustParse(t, host), r) {
			t.Errorf("%q must NOT match %q", host, r)
		}
	}
}

func TestCIDR(t *testing.T) {
	r := "203.0.113.0/24"
	if !Matches(mustParse(t, "203.0.113.200"), r) {
		t.Error("in-range IP should match CIDR")
	}
	if Matches(mustParse(t, "203.0.114.1"), r) {
		t.Error("out-of-range IP must not match CIDR")
	}
}

func TestOutOfScopeWins(t *testing.T) {
	g := Gate{In: []string{"*.example.com"}, Out: []string{"admin.example.com"}}
	if ok, _ := g.Check(mustParse(t, "api.example.com")); !ok {
		t.Error("api.example.com should be IN")
	}
	ok, reason := g.Check(mustParse(t, "admin.example.com"))
	if ok {
		t.Fatal("admin.example.com must be OUT")
	}
	if reason != "out-of-scope rule admin.example.com" {
		t.Errorf("reason = %q", reason)
	}
}

func TestUnknownHostIsOut(t *testing.T) {
	g := Gate{In: []string{"*.example.com"}}
	if ok, reason := g.Check(mustParse(t, "evil.test")); ok || reason != "no matching in-scope rule" {
		t.Errorf("got ok=%v reason=%q", ok, reason)
	}
}

func TestEmptyScopeRefuses(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scope.txt"), []byte("# only comments\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGate(dir); err != ErrEmptyScope {
		t.Fatalf("LoadGate err = %v, want ErrEmptyScope", err)
	}
}

func TestLoadStripsComments(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(p, []byte("API.Example.com.  # primary\n*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.com", "*.example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q want %q", i, got[i], want[i])
		}
	}
}
