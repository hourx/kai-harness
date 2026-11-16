// Package scope implements the same scope semantics as
// Kairos/scripts/scope_check.py:
//
//   - exact host       api.example.com
//   - wildcard         *.example.com  (subdomains only, never the apex)
//   - CIDR             203.0.113.0/24
//   - out-of-scope always wins over scope.txt
//   - an empty scope.txt refuses to run
package scope

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Kind distinguishes a hostname target from an IP target.
type Kind int

const (
	KindHost Kind = iota
	KindIP
)

// Target is a normalized scope subject.
type Target struct {
	Kind  Kind
	Value string
}

func (t Target) String() string { return t.Value }

// ErrEmptyScope is returned when scope.txt is missing or has no rules.
var ErrEmptyScope = errors.New("scope.txt is missing or empty — refusing to test")

// Parse normalizes user input into a Target. Scheme, path and port are dropped.
func Parse(raw string) (Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Target{}, errors.New("cannot parse target: empty input")
	}
	// Bare IPs (including IPv6) never carry a scheme; handle them before URL
	// parsing, which needs brackets around an IPv6 host.
	if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
		return Target{Kind: KindIP, Value: ip.String()}, nil
	}
	if !strings.Contains(s, "://") {
		s = "//" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return Target{}, fmt.Errorf("cannot parse target %q: %w", raw, err)
	}
	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return Target{}, fmt.Errorf("cannot parse target: %q", raw)
	}
	if ip := net.ParseIP(host); ip != nil {
		return Target{Kind: KindIP, Value: ip.String()}, nil
	}
	return Target{Kind: KindHost, Value: host}, nil
}

// Load reads a rules file. Missing file yields an empty slice, not an error.
// Comments start at '#'; rules are lowercased and have trailing dots removed.
func Load(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.SplitN(line, "#", 2)[0]
		line = strings.TrimRight(strings.ToLower(strings.TrimSpace(line)), ".")
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// Matches reports whether rule applies to t.
func Matches(t Target, rule string) bool {
	if t.Kind == KindIP {
		if strings.Contains(rule, "/") {
			_, ipnet, err := net.ParseCIDR(rule)
			if err != nil {
				return false
			}
			ip := net.ParseIP(t.Value)
			return ip != nil && ipnet.Contains(ip)
		}
		rip := net.ParseIP(rule)
		return rip != nil && rip.Equal(net.ParseIP(t.Value))
	}
	if strings.HasPrefix(rule, "*.") {
		suffix := rule[2:]
		return strings.HasSuffix(t.Value, "."+suffix) && t.Value != suffix
	}
	return t.Value == rule
}

// Gate is a loaded scope.txt + out-of-scope.txt pair.
type Gate struct {
	In  []string
	Out []string
}

// LoadGate reads both rule files from a program directory.
func LoadGate(dir string) (Gate, error) {
	in, err := Load(filepath.Join(dir, "scope.txt"))
	if err != nil {
		return Gate{}, err
	}
	if len(in) == 0 {
		return Gate{}, ErrEmptyScope
	}
	out, err := Load(filepath.Join(dir, "out-of-scope.txt"))
	if err != nil {
		return Gate{}, err
	}
	return Gate{In: in, Out: out}, nil
}

// Check returns whether t is allowed and a human-readable reason.
// Out-of-scope rules are evaluated first and always win.
func (g Gate) Check(t Target) (allowed bool, reason string) {
	for _, r := range g.Out {
		if Matches(t, r) {
			return false, "out-of-scope rule " + r
		}
	}
	for _, r := range g.In {
		if Matches(t, r) {
			return true, "scope rule " + r
		}
	}
	return false, "no matching in-scope rule"
}
