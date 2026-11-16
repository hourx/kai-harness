// Package session stores the operator's authenticated context for one program.
//
// The file lives at data/<program>/session.json with mode 0600 and is never
// included in a pack unless the operator passes --include-session explicitly.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrNone means no session has been stored for the program.
var ErrNone = errors.New("no session stored")

// Cookie is one name/value pair captured from a browser or a HAR.
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"http_only,omitempty"`
}

// Store is the persisted session for a program.
type Store struct {
	CreatedAt time.Time         `json:"created_at"`
	Source    string            `json:"source"`
	Cookies   []Cookie          `json:"cookies"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// Path returns the session file location for a program directory.
func Path(dir string) string { return filepath.Join(dir, "session.json") }

// Load reads the stored session.
func Load(dir string) (*Store, error) {
	b, err := os.ReadFile(Path(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNone
		}
		return nil, err
	}
	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Save writes the session with mode 0600.
func Save(dir string, s *Store) error {
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := Path(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, Path(dir))
}

// CookieHeader renders "a=1; b=2" from the stored cookies.
func CookieHeader(cookies []Cookie) string {
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c.Name == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// ParseCookieHeader splits a Cookie header into cookies.
func ParseCookieHeader(raw string) []Cookie {
	var out []Cookie
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out = append(out, Cookie{Name: name, Value: value})
	}
	return out
}

type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Headers []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				Cookies []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"cookies"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

// ImportHAR extracts Cookie and Authorization headers from a HAR export.
// Only those two are taken: anything else is noise or another secret that
// belongs nowhere near a shared archive.
func ImportHAR(data []byte) (*Store, error) {
	var f harFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("not a HAR file: %w", err)
	}
	if len(f.Log.Entries) == 0 {
		return nil, errors.New("HAR has no entries")
	}
	s := &Store{Source: "har", CreatedAt: time.Now().UTC(), Headers: map[string]string{}}
	for _, e := range f.Log.Entries {
		for _, h := range e.Request.Headers {
			switch strings.ToLower(strings.TrimSpace(h.Name)) {
			case "cookie":
				s.Cookies = append(s.Cookies, ParseCookieHeader(h.Value)...)
			case "authorization":
				if h.Value != "" {
					s.Headers["Authorization"] = h.Value
				}
			}
		}
		for _, c := range e.Request.Cookies {
			if c.Name != "" {
				s.Cookies = append(s.Cookies, Cookie{Name: c.Name, Value: c.Value})
			}
		}
	}
	s.Cookies = dedupe(s.Cookies)
	if len(s.Cookies) == 0 && len(s.Headers) == 0 {
		return nil, errors.New("HAR contained no Cookie or Authorization header")
	}
	if len(s.Headers) == 0 {
		s.Headers = nil
	}
	return s, nil
}

func dedupe(in []Cookie) []Cookie {
	seen := map[string]struct{}{}
	var out []Cookie
	for _, c := range in {
		key := c.Name + "\x00" + c.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Merge adds cookies and headers from add into s, without duplicating.
func (s *Store) Merge(add *Store) {
	s.Cookies = dedupe(append(s.Cookies, add.Cookies...))
	if s.Headers == nil {
		s.Headers = map[string]string{}
	}
	for k, v := range add.Headers {
		s.Headers[k] = v
	}
}

// Redacted renders the session without exposing secret values.
func (s *Store) Redacted() string {
	var b strings.Builder
	fmt.Fprintf(&b, "source   %s\n", s.Source)
	fmt.Fprintf(&b, "created  %s\n", s.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "cookies  %d\n", len(s.Cookies))
	for _, c := range s.Cookies {
		fmt.Fprintf(&b, "  %-24s %s\n", c.Name, mask(c.Value))
	}
	if len(s.Headers) > 0 {
		fmt.Fprintf(&b, "headers  %d\n", len(s.Headers))
		keys := make([]string, 0, len(s.Headers))
		for k := range s.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %-24s %s\n", k, mask(s.Headers[k]))
		}
	}
	return b.String()
}

func mask(v string) string {
	if v == "" {
		return "(empty)"
	}
	if len(v) <= 4 {
		return "****"
	}
	return v[:4] + "…" + fmt.Sprintf("(%d chars)", len(v))
}
