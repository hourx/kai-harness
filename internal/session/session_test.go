package session

import (
	"strings"
	"testing"
)

func TestParseCookieHeader(t *testing.T) {
	got := ParseCookieHeader("sid=abc123; _ga=GA1.2; broken; empty=")
	if len(got) != 3 {
		t.Fatalf("got %d cookies, want 3: %+v", len(got), got)
	}
	want := map[string]string{"sid": "abc123", "_ga": "GA1.2", "empty": ""}
	for _, c := range got {
		if v, ok := want[c.Name]; !ok || v != c.Value {
			t.Errorf("unexpected cookie %+v", c)
		}
	}
}

func TestCookieHeaderRoundTrip(t *testing.T) {
	raw := "a=1; b=2"
	if got := CookieHeader(ParseCookieHeader(raw)); got != raw {
		t.Errorf("round trip = %q, want %q", got, raw)
	}
}

func TestImportHAR(t *testing.T) {
	har := `{"log":{"entries":[
		{"request":{"headers":[
			{"name":"Cookie","value":"sid=secret; theme=dark"},
			{"name":"Authorization","value":"Bearer tok_123"},
			{"name":"X-Noise","value":"drop me"}
		],"cookies":[]}},
		{"request":{"headers":[
			{"name":"cookie","value":"sid=secret"}
		],"cookies":[{"name":"extra","value":"1"}]}}
	]}}`

	s, err := ImportHAR([]byte(har))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Headers) != 1 || s.Headers["Authorization"] != "Bearer tok_123" {
		t.Errorf("headers = %v, want only Authorization", s.Headers)
	}
	if _, ok := s.Headers["X-Noise"]; ok {
		t.Error("unrelated headers must not be imported")
	}
	names := map[string]bool{}
	for _, c := range s.Cookies {
		names[c.Name] = true
	}
	for _, want := range []string{"sid", "theme", "extra"} {
		if !names[want] {
			t.Errorf("missing cookie %q in %+v", want, s.Cookies)
		}
	}
	if len(s.Cookies) != 3 {
		t.Errorf("cookies not de-duplicated: %+v", s.Cookies)
	}
}

func TestImportHARRejectsJunk(t *testing.T) {
	if _, err := ImportHAR([]byte("not json")); err == nil {
		t.Error("expected an error for a non-HAR file")
	}
	if _, err := ImportHAR([]byte(`{"log":{"entries":[{"request":{"headers":[]}}]}}`)); err == nil {
		t.Error("expected an error when nothing usable was found")
	}
}

func TestRedactedHidesValues(t *testing.T) {
	s := &Store{
		Source:  "har",
		Cookies: []Cookie{{Name: "sid", Value: "supersecretvalue"}},
		Headers: map[string]string{"Authorization": "Bearer tok_abcdef"},
	}
	out := s.Redacted()
	for _, leak := range []string{"supersecretvalue", "tok_abcdef"} {
		if strings.Contains(out, leak) {
			t.Errorf("redacted output leaks %q:\n%s", leak, out)
		}
	}
	for _, name := range []string{"sid", "Authorization"} {
		if !strings.Contains(out, name) {
			t.Errorf("redacted output should keep names, missing %q:\n%s", name, out)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := &Store{
		Source:  "manual",
		Cookies: []Cookie{{Name: "sid", Value: "v"}},
		Headers: map[string]string{"Authorization": "Bearer x"},
	}
	if err := Save(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Cookies) != 1 || out.Headers["Authorization"] != "Bearer x" {
		t.Errorf("round trip lost data: %+v", out)
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(t.TempDir()); err != ErrNone {
		t.Errorf("err = %v, want ErrNone", err)
	}
}
