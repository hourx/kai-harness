package recon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/hourx/kai-harness/internal/strutil"
)

// TLSInfo is the certificate data recorded for a host.
type TLSInfo struct {
	Subject  string   `json:"subject,omitempty"`
	Issuer   string   `json:"issuer,omitempty"`
	NotAfter string   `json:"not_after,omitempty"`
	Expired  bool     `json:"expired,omitempty"`
	SANs     []string `json:"sans,omitempty"`
}

// HostRecord is one discovered asset.
type HostRecord struct {
	Host      string    `json:"host"`
	IPs       []string  `json:"ips,omitempty"`
	CNAME     string    `json:"cname,omitempty"`
	URL       string    `json:"url,omitempty"`
	Status    int       `json:"status,omitempty"`
	Title     string    `json:"title,omitempty"`
	Tech      []string  `json:"tech,omitempty"`
	TLS       *TLSInfo  `json:"tls,omitempty"`
	Sources   []string  `json:"sources,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Runs      int       `json:"runs"`
}

// EndpointRecord is one path, with every query parameter seen on it.
type EndpointRecord struct {
	Path      string    `json:"path"`
	Params    []string  `json:"params,omitempty"`
	Sources   []string  `json:"sources,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// JSRecord tracks a bundle and its content hash across runs.
type JSRecord struct {
	URL       string    `json:"url"`
	SHA256    string    `json:"sha256"`
	Bytes     int       `json:"bytes"`
	Changed   bool      `json:"changed,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Store is the persistent state of a program's attack surface.
type Store struct {
	Program   string                     `json:"program"`
	Updated   time.Time                  `json:"updated"`
	Hosts     map[string]*HostRecord     `json:"hosts"`
	Endpoints map[string]*EndpointRecord `json:"endpoints"`
	JS        map[string]*JSRecord       `json:"js"`
}

// NewStore returns an empty store for a program.
func NewStore(program string) *Store {
	return &Store{
		Program:   program,
		Hosts:     map[string]*HostRecord{},
		Endpoints: map[string]*EndpointRecord{},
		JS:        map[string]*JSRecord{},
	}
}

func storePath(dir string) string { return filepath.Join(dir, "assets.json") }

// LoadStore reads assets.json, returning an empty store when absent.
func LoadStore(dir, program string) (*Store, error) {
	b, err := os.ReadFile(storePath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return NewStore(program), nil
		}
		return nil, err
	}
	s := NewStore(program)
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if s.Hosts == nil {
		s.Hosts = map[string]*HostRecord{}
	}
	if s.Endpoints == nil {
		s.Endpoints = map[string]*EndpointRecord{}
	}
	if s.JS == nil {
		s.JS = map[string]*JSRecord{}
	}
	s.Program = program
	return s, nil
}

// Save writes assets.json atomically.
func (s *Store) Save(dir string) error {
	s.Updated = time.Now().UTC()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := storePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, storePath(dir))
}

// Host returns the record for host, creating and stamping it when new.
func (s *Store) Host(host string, now time.Time) *HostRecord {
	h, ok := s.Hosts[host]
	if !ok {
		h = &HostRecord{Host: host, FirstSeen: now}
		s.Hosts[host] = h
	}
	h.LastSeen = now
	h.Runs++
	return h
}

// Endpoint returns the record for path, creating and stamping it when new.
func (s *Store) Endpoint(path string, now time.Time) *EndpointRecord {
	e, ok := s.Endpoints[path]
	if !ok {
		e = &EndpointRecord{Path: path, FirstSeen: now}
		s.Endpoints[path] = e
	}
	e.LastSeen = now
	return e
}

// Bundle returns the record for a JS url, marking it changed when the hash
// differs from the previous run.
func (s *Store) Bundle(url, sha string, size int, now time.Time) *JSRecord {
	j, ok := s.JS[url]
	if !ok {
		j = &JSRecord{URL: url, FirstSeen: now}
		s.JS[url] = j
	} else if j.SHA256 != "" && j.SHA256 != sha {
		j.Changed = true
	}
	j.SHA256 = sha
	j.Bytes = size
	j.LastSeen = now
	return j
}

// SortedHosts returns host names in lexical order.
func (s *Store) SortedHosts() []string {
	out := make([]string, 0, len(s.Hosts))
	for h := range s.Hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// SortedEndpoints returns endpoint paths in lexical order.
func (s *Store) SortedEndpoints() []string {
	out := make([]string, 0, len(s.Endpoints))
	for e := range s.Endpoints {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// SortedJS returns JS urls in lexical order.
func (s *Store) SortedJS() []string {
	out := make([]string, 0, len(s.JS))
	for u := range s.JS {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// Uniq merges values into a sorted, de-duplicated slice. The historical name is
// kept because callers rely on the sort (stable output depends on it); the
// implementation lives in strutil so there is one dedupe semantics in the tree.
func Uniq(values ...[]string) []string {
	var all []string
	for _, group := range values {
		all = append(all, group...)
	}
	return strutil.UniqueSorted(all)
}
