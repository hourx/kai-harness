package netx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSessionAttached(t *testing.T) {
	var gotCookie, gotAuth, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := New("kai-test", 50, nil)
	defer c.Close()
	c.SetSession(Session{
		Cookies: "sid=abc; theme=dark",
		Headers: map[string]string{"Authorization": "Bearer tok", "Host": "evil.test"},
	})

	if _, err := c.Get(context.Background(), srv.URL, 1024); err != nil {
		t.Fatal(err)
	}
	if gotCookie != "sid=abc; theme=dark" {
		t.Errorf("Cookie = %q", gotCookie)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotUA != "kai-test" {
		t.Errorf("User-Agent = %q", gotUA)
	}
}

func TestSessionHostAllowList(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Cookie")
	}))
	defer srv.Close()

	c := New("kai-test", 50, nil)
	defer c.Close()
	c.SetSession(Session{Cookies: "sid=secret", Hosts: []string{"example.com"}})

	if _, err := c.Get(context.Background(), srv.URL, 1024); err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("cookie leaked to a host outside the allow-list: %q", got)
	}
}

func TestSessionNotSetByDefault(t *testing.T) {
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
	}))
	defer srv.Close()

	c := New("kai-test", 50, nil)
	defer c.Close()
	if _, err := c.Get(context.Background(), srv.URL, 1024); err != nil {
		t.Fatal(err)
	}
	if gotCookie != "" {
		t.Errorf("Cookie leaked without a session: %q", gotCookie)
	}
}

func TestRedirectOutOfScopeStops(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	targetURL, _ := url.Parse(target.URL)

	// A different host that is not allowed.
	elsewhere := "https://not-in-scope.test/next"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere, http.StatusFound)
	}))
	defer srv.Close()

	c := New("kai-test", 50, func(u *url.URL) bool {
		return u.Host == targetURL.Host
	})
	defer c.Close()

	if _, err := c.Get(context.Background(), srv.URL, 1024); err == nil {
		t.Fatal("redirect outside scope was followed instead of refused")
	}
}

func TestBodyCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 5000)))
	}))
	defer srv.Close()

	c := New("kai-test", 50, nil)
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Body) != 100 || !resp.Truncated {
		t.Errorf("body = %d bytes, truncated = %v", len(resp.Body), resp.Truncated)
	}
}
