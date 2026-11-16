// Package workspace owns the on-disk state for one bug bounty program.
//
// bountykit keeps its own state under data/<program>/ and never writes into a
// Kairos checkout. The pack command is what bridges the two.
package workspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Meta is the machine-readable summary of a program.
type Meta struct {
	Name         string    `json:"name"`
	Platform     string    `json:"platform,omitempty"`
	ProgramURL   string    `json:"program_url,omitempty"`
	ScopeVerdict string    `json:"scope_verdict"`
	Domains      []string  `json:"domains,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Notes        string    `json:"notes,omitempty"`
}

// Program is an opened workspace.
type Program struct {
	Name string
	Dir  string
	Meta Meta
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrExists is returned when init targets an existing program directory.
var ErrExists = errors.New("program already exists")

// Home returns the state root. BOUNTYKIT_HOME overrides the default ./data.
func Home() string {
	if v := strings.TrimSpace(os.Getenv("BOUNTYKIT_HOME")); v != "" {
		return v
	}
	return "data"
}

// ValidateName rejects names that could escape the state root.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid program name %q: use lowercase letters, digits, dot, dash, underscore (max 64)", name)
	}
	return nil
}

// Dir returns the state directory for a program.
func Dir(name string) string { return filepath.Join(Home(), name) }

// List returns every program directory under Home, sorted by name.
func List() ([]string, error) {
	entries, err := os.ReadDir(Home())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || !nameRE.MatchString(e.Name()) {
			continue
		}
		// Only directories that actually hold a program are listed; a stray
		// dist/ or scratch directory under the state root is ignored.
		if _, err := os.Stat(filepath.Join(Home(), e.Name(), "meta.json")); err != nil {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}

// Create initializes a new program workspace. It refuses to reuse a name.
func Create(name string, m Meta) (*Program, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	dir := Dir(name)
	if _, err := os.Stat(dir); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrExists, dir)
	}
	for _, d := range []string{"", "state", "snapshots", "evidence", "findings", "passive", "recon"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	m.Name = name
	m.CreatedAt = now
	m.UpdatedAt = now
	if m.ScopeVerdict == "" {
		m.ScopeVerdict = "unknown"
	}
	p := &Program{Name: name, Dir: dir, Meta: m}
	files := map[string]string{
		"program.md":       programTemplate,
		"scope.txt":        scopeTemplate,
		"out-of-scope.txt": outOfScopeTemplate,
	}
	for f, body := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o600); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(p.auditPath(), nil, 0o600); err != nil {
		return nil, err
	}
	if err := p.SaveMeta(); err != nil {
		return nil, err
	}
	return p, nil
}

// Open loads an existing program.
func Open(name string) (*Program, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	dir := Dir(name)
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("unknown program %q (run: bountykit init %s)", name, name)
		}
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("corrupt meta.json for %s: %w", name, err)
	}
	return &Program{Name: name, Dir: dir, Meta: m}, nil
}

// SaveMeta writes meta.json atomically.
func (p *Program) SaveMeta() error {
	p.Meta.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(p.Meta, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(p.Dir, "meta.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(p.Dir, "meta.json"))
}

// AppendAudit appends a timestamped line to audit.log.
func (p *Program) AppendAudit(line string) error {
	f, err := os.OpenFile(p.auditPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), line)
	return err
}

func (p *Program) auditPath() string { return filepath.Join(p.Dir, "audit.log") }

// DeriveDomains returns enumeration seeds: meta.Domains when set, otherwise
// the bases of every wildcard rule in scope.txt.
func (p *Program) DeriveDomains() []string {
	if len(p.Meta.Domains) > 0 {
		return p.Meta.Domains
	}
	b, err := os.ReadFile(filepath.Join(p.Dir, "scope.txt"))
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		rule := strings.TrimRight(strings.ToLower(strings.TrimSpace(strings.SplitN(line, "#", 2)[0])), ".")
		if !strings.HasPrefix(rule, "*.") {
			continue
		}
		base := rule[2:]
		if base == "" {
			continue
		}
		if _, ok := seen[base]; ok {
			continue
		}
		seen[base] = struct{}{}
		out = append(out, base)
	}
	sort.Strings(out)
	return out
}

// ExactHosts returns host rules from scope.txt: concrete hosts that should be
// probed directly. Wildcards, CIDRs and path-scoped entries are excluded —
// wildcard bases are enumeration seeds handled by DeriveDomains.
func (p *Program) ExactHosts() []string {
	b, err := os.ReadFile(filepath.Join(p.Dir, "scope.txt"))
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		rule := strings.ToLower(strings.TrimSpace(strings.SplitN(line, "#", 2)[0]))
		if rule == "" || strings.HasPrefix(rule, "*.") || strings.ContainsAny(rule, "/ \t") {
			continue
		}
		if _, ok := seen[rule]; ok {
			continue
		}
		seen[rule] = struct{}{}
		out = append(out, rule)
	}
	sort.Strings(out)
	return out
}

// StatePath returns the path of a current-state artifact (subs.txt, live.txt…).
func (p *Program) StatePath(name string) string {
	return filepath.Join(p.Dir, "state", name)
}

// ReadState returns a state artifact, or (nil,false) when it does not exist.
func (p *Program) ReadState(name string) ([]byte, bool) {
	b, err := os.ReadFile(p.StatePath(name))
	if err != nil {
		return nil, false
	}
	return b, true
}

// CountLines returns the number of non-empty lines in a state artifact.
func (p *Program) CountLines(name string) int {
	b, ok := p.ReadState(name)
	if !ok {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

const programTemplate = `# Program

| Field | Value |
| --- | --- |
| Name | |
| Platform | HackerOne / Bugcrowd / Intigriti / direct |
| Program URL | |
| Authorized by | |
| Authorization date | |
| Expires | |
| Payout currency | |
| Contacts | |
| Safe harbor | yes / no / unknown |

## Rules of engagement

- Rate limit:
- Prohibited techniques:
- Test accounts:
- Required headers / user-agent:
- Disclosure window:

## Notes

<!-- Scope changes, triager feedback, payout terms, lessons. -->
`

const scopeTemplate = `# One rule per line. Hosts or CIDRs only — no scheme, path or port.
# Exact:        api.example.com
# Wildcard:     *.example.com   (subdomains only, not the apex)
# Network:      203.0.113.0/24
#
# bountykit refuses to test while this file has no rules.
`

const outOfScopeTemplate = `# Out-of-scope rules take precedence over scope.txt.
# status.example.com
# admin.example.com
# 203.0.113.128/25
`
