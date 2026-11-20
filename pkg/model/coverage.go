package model

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hourx/kai-harness/pkg/evidence"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/strutil"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// Exit states of an attempt as the coverage ledger records them.
const (
	TestedYes     = "yes"
	TestedPartial = "partial"
	TestedNo      = "no"

	OutcomeTried    = "tried"
	OutcomeProduced = "produced"
	OutcomeBlocked  = "blocked"
	OutcomeDead     = "dead"
)

// deriveCoverage answers "what has not been touched" for every in-scope asset.
//
// The asset list is deliberately wider than "the hosts in scope.txt": a wildcard
// base that was never enumerated, a contract nobody forked and a module with no
// outcome row are all places where work has not happened, and a list that hid
// them would let "never touched" stay invisible.
func deriveCoverage(p *workspace.Program, m *surface.Map, ev []evidence.Item, records []outcome.Record) []Coverage {
	assets := map[string]string{} // asset -> match token
	add := func(asset, token string) {
		if asset == "" || token == "" {
			return
		}
		assets[asset] = strings.ToLower(token)
	}
	for _, host := range p.ExactHosts() {
		add(host, host)
	}
	for _, base := range p.DeriveDomains() {
		add("*."+base, base)
	}
	for _, a := range m.NonWeb {
		add(a.Type+":"+a.Identifier, a.Identifier)
	}
	mods := make([]string, 0, len(m.Modules))
	for mod := range m.Modules {
		mods = append(mods, mod)
	}
	sort.Strings(mods)
	for _, mod := range mods {
		add("module:"+mod, mod)
	}

	names := make([]string, 0, len(assets))
	for name := range assets {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Coverage, 0, len(names))
	for _, asset := range names {
		token := assets[asset]
		row := Coverage{Asset: asset, Tested: TestedNo}

		// An outcome row is the strongest evidence that work happened: it means
		// someone tested and classified the result.
		for _, r := range records {
			if !matchesToken(token, r.Target) {
				continue
			}
			if r.TS > row.LastTS {
				row.LastTS = r.TS
				row.LastIntent = r.Class
				row.Tested = TestedYes
			}
		}
		// Traffic alone proves a request went out, not that anyone looked at the
		// answer — that is "partial".
		for _, it := range ev {
			if !matchesToken(token, it.Host+it.Path+it.Target) {
				continue
			}
			if row.EvidenceRef == "" {
				row.EvidenceRef = it.ID
			}
			if row.Tested == TestedNo {
				row.Tested = TestedPartial
				row.LastTS = it.TS
			}
		}
		if row.Tested == TestedYes && row.LastIntent == "" {
			row.LastIntent = "unclassified"
		}
		out = append(out, row)
	}
	return out
}

// deriveExploration answers "what was tried and why" from the outcome log. The
// log is the only place a human or an agent recorded an intent, so this is a
// transcription with one judgement: which of the four exits the record means.
func deriveExploration(records []outcome.Record, ev []evidence.Item) []Exploration {
	recs := append([]outcome.Record(nil), records...)
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].TS != recs[j].TS {
			return recs[i].TS < recs[j].TS
		}
		return recs[i].Target < recs[j].Target
	})

	var out []Exploration
	for _, r := range recs {
		if strings.TrimSpace(r.Target) == "" {
			continue
		}
		class := r.Class
		if class == "" {
			class = "unclassified"
		}
		row := Exploration{
			ID:          "exp:" + digest(r.TS, r.Target, r.Status),
			Intent:      class,
			Target:      r.Target,
			ActionClass: class,
			Outcome:     exitOf(r),
			TS:          r.TS,
		}
		if row.Outcome == OutcomeProduced {
			row.Produced = []string{class}
		}
		if r.Note != "" {
			row.Why = r.Note
		} else {
			row.Why = fmt.Sprintf("recorded %s with no note", r.Status)
		}
		for _, it := range ev {
			if matchesToken(it.Host, r.Target) && (it.Path == "" || matchesToken(it.Path, r.Target)) {
				row.EvidenceRef = it.ID
				break
			}
		}
		out = append(out, row)
	}
	return out
}

// exitOf maps a recorded status onto one of the four exits, using the note for
// the two that a status alone cannot express.
func exitOf(r outcome.Record) string {
	if outcome.Yields(r.Status) {
		return OutcomeProduced
	}
	note := strings.ToLower(r.Note)
	if containsAny(note, "block", "denied", "forbidden", "403", "401", "waf", "captcha", "rate limit", "challeng") {
		return OutcomeBlocked
	}
	if containsAny(note, "dead", "n/a", "retired", "gone", "not found", "no longer", "duplicate", "out of scope") {
		return OutcomeDead
	}
	return OutcomeTried
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// matchesToken reports whether a value mentions an asset's token. Tokens shorter
// than three characters are ignored: they match everything.
func matchesToken(token, value string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	value = strings.ToLower(strings.TrimSpace(value))
	if len(token) < 3 || value == "" {
		return false
	}
	return strings.Contains(value, token)
}

// CoverageGaps returns the assets with no coverage row at all, in case a caller
// holds a wider asset list than the derivation did.
func CoverageGaps(assets []string, rows []Coverage) []string {
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.Asset] = true
	}
	var out []string
	for _, a := range assets {
		if !seen[a] {
			out = append(out, a)
		}
	}
	return strutil.UniqueSorted(out)
}
