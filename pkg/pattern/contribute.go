package pattern

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/archetype"
	"github.com/hourx/kai-harness/pkg/outcome"
)

// ContributeSchema tags the aggregate so a collector can reject anything it does
// not understand.
const ContributeSchema = "kai-contribute/1"

// Contribution is the tier-2 aggregate: pattern keys, their outcome counts, and
// salted host fingerprints. It is built to be publishable, and that property is
// checked rather than asserted — Audit refuses a payload that carries anything
// shaped like a target, and the caller can scan it against its own hostnames.
//
// What is never in here: URLs, hostnames, paths, parameter values, credentials,
// evidence, report text, notes, or anything the operator wrote by hand.
type Contribution struct {
	Schema           string    `json:"schema"`
	Generated        string    `json:"generated"`
	Archetype        string    `json:"archetype"`
	HostFingerprints []string  `json:"host_fingerprints"`
	Keys             []KeyStat `json:"keys"`
	WhatThisIs       string    `json:"what_this_is"`
}

// ContributeNotice is the one sentence a collector, and a reviewer, needs.
const ContributeNotice = "Class keys, outcome counts and salted host fingerprints only. No URLs, hostnames, paths, credentials, evidence or report text."

// Payload assembles the aggregate for one program. hosts are usually the scope
// entries; they are fingerprinted before they enter the payload and the raw
// value never appears in the result.
func Payload(program, arch string, records []outcome.Record, hosts []string, salt string, now time.Time) Contribution {
	d := BuildDelta(program, arch, records, now)
	c := Contribution{
		Schema:     ContributeSchema,
		Generated:  d.Generated,
		Archetype:  d.Archetype,
		Keys:       d.Keys,
		WhatThisIs: ContributeNotice,
	}
	// Empty, not null: a collector should read the shape it expects, and "null"
	// is a different fact from "none".
	if c.Keys == nil {
		c.Keys = []KeyStat{}
	}
	c.HostFingerprints = []string{}
	seen := map[string]bool{}
	for _, h := range hosts {
		fp := HostFingerprint(salt, h)
		if fp == "" || seen[fp] {
			continue
		}
		seen[fp] = true
		c.HostFingerprints = append(c.HostFingerprints, fp)
	}
	sort.Strings(c.HostFingerprints)
	return c
}

// HostFingerprint is a salted, truncated SHA-256 of a hostname: stable inside one
// workspace, useless outside it, and not reversible by dictionary attack without
// the salt. An empty salt or host yields "" — the caller cannot fingerprint by
// accident.
func HostFingerprint(salt, host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if salt == "" || host == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(salt + "\x00" + host))
	return hex.EncodeToString(sum[:8])
}

// SaltFile names the per-workspace salt.
const SaltFile = "patterns-salt"

// Salt returns the workspace's fingerprint salt, creating it on first use. The
// salt stays local: deleting it changes every fingerprint, which is the documented
// way to break the link between this workspace's contributions and the next one.
func Salt(programDir string) (string, error) {
	p := filepath.Join(programDir, "state", SaltFile)
	if b, err := os.ReadFile(p); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(programDir, "state"), 0o755); err != nil {
		return "", err
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	salt := hex.EncodeToString(buf)
	if err := os.WriteFile(p, []byte(salt+"\n"), 0o600); err != nil {
		return "", err
	}
	return salt, nil
}

var (
	keyNameOK     = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]*$`)
	hostShaped    = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)
	ipv4Shaped    = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	digitRun      = regexp.MustCompile(`\d{4,}`)
	fingerprintOK = regexp.MustCompile(`^[0-9a-f]{16}$`)
	// A URL that lost its punctuation survives canonicalisation as a pile of
	// hyphens, which is why the shape has to be caught by its words.
	schemeish = regexp.MustCompile(`(^|[-.])(https?|ftp|file|www)([-.]|$)`)
)

// Audit refuses a payload that could carry target data. It runs on every
// contribution, including --dry-run, so the check is part of producing the
// payload and not an afterthought.
func (c Contribution) Audit() error {
	if c.Schema != ContributeSchema {
		return fmt.Errorf("contribution: schema %q, want %q", c.Schema, ContributeSchema)
	}
	if c.Archetype != Any && !archetype.Known(c.Archetype) {
		return fmt.Errorf("contribution: unknown archetype %q", c.Archetype)
	}
	for _, s := range c.Keys {
		if s.Key.Family != FamilyClass {
			return fmt.Errorf("contribution: key %s is not a class key — only class keys are publishable", s.Key)
		}
		name := s.Key.Name
		switch {
		case !keyNameOK.MatchString(name):
			return fmt.Errorf("contribution: key name %q is not a plain name", name)
		case hostShaped.MatchString(name):
			return fmt.Errorf("contribution: key name %q is shaped like a hostname — rename it", name)
		case ipv4Shaped.MatchString(name):
			return fmt.Errorf("contribution: key name %q contains an address", name)
		case digitRun.MatchString(name):
			return fmt.Errorf("contribution: key name %q contains a long digit run (an id, a port, a year) — rename it", name)
		case schemeish.MatchString(name):
			return fmt.Errorf("contribution: key name %q is shaped like a URL or a host that lost its punctuation — rename it", name)
		}
	}
	for _, fp := range c.HostFingerprints {
		if !fingerprintOK.MatchString(fp) {
			return fmt.Errorf("contribution: %q is not a fingerprint", fp)
		}
	}
	return nil
}

// JSON marshals the payload for printing or sending.
func (c Contribution) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// AuditForbidden scans the marshalled payload for strings that must not appear —
// the program's own hosts, its recorded targets, the operator's notes. A payload
// that mentions where it came from is not anonymous, whatever the schema says.
func (c Contribution) AuditForbidden(needles []string) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	hay := strings.ToLower(string(b))
	for _, n := range needles {
		n = strings.ToLower(strings.TrimSpace(n))
		if len(n) < 4 {
			// Short strings match by accident inside hex and class names; the
			// structural audit already rejects them as keys.
			continue
		}
		if strings.Contains(hay, n) {
			return fmt.Errorf("contribution: payload contains %q — refusing to hand it out", n)
		}
	}
	return nil
}
