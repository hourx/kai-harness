package model

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hourx/kai-harness/pkg/strutil"
	"github.com/hourx/kai-harness/pkg/surface"
)

// Sweep tags, so a queue entry can always be traced back to the question that
// produced it.
const (
	TagCapability = "sweep:capability"
	TagTransition = "sweep:transition"
	TagInvariant  = "sweep:invariant"
	TagParity     = "sweep:parity"
	TagAnomaly    = "sweep:anomaly"
)

// Sweep reads only a derived model and emits hypotheses in the same shape the
// recon queue already uses, so nothing downstream needs a second format.
//
// The five sweeps are not interchangeable. Each one asks a question that the
// others cannot: permission (capability), order (transition), truth (invariant),
// consistency (parity) and convention (anomaly). A sweep that has no rows emits
// nothing — silence is the correct answer when the model has not learned enough,
// and the model's own Gaps list says what is missing.
func Sweep(m *Model) []surface.Hypothesis {
	if m == nil {
		return nil
	}
	var out []surface.Hypothesis
	out = append(out, capabilitySweep(m)...)
	out = append(out, transitionSweep(m)...)
	out = append(out, invariantSweep(m)...)
	out = append(out, paritySweep(m)...)
	out = append(out, anomalySweep(m)...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Class < out[j].Class
	})
	return out
}

// capabilitySweep: who may do what, and does the server agree?
func capabilitySweep(m *Model) []surface.Hypothesis {
	var out []surface.Hypothesis
	for _, c := range m.Capabilities {
		why := []string{fmt.Sprintf("capability: role %s is %s to %s %s (enforcement: %s)",
			c.Role, c.Allowed, c.Action, c.Object, c.Enforcement)}
		switch {
		case c.Allowed == "yes" && c.Enforcement == "none":
			out = append(out, surface.Hypothesis{
				Target:  c.Object,
				Class:   "access-control",
				Score:   74,
				Why:     why,
				Probe:   fmt.Sprintf("call %s as %s and as the lowest role that can reach the same object — if both succeed, the server trusts the client", c.Action, c.Role),
				Tags:    []string{TagCapability},
				Cluster: "mod:" + surface.Module(c.Object),
			})
		case c.Allowed == "yes" && c.Enforcement == "client":
			out = append(out, surface.Hypothesis{
				Target:  c.Object,
				Class:   "access-control",
				Score:   78,
				Why:     append(why, "the control is drawn in the UI, not enforced on the server"),
				Probe:   fmt.Sprintf("replay %s with the role that must not see it — a hidden button is not an authorization check", c.Action),
				Tags:    []string{TagCapability},
				Cluster: "mod:" + surface.Module(c.Object),
			})
		}
	}

	// Sibling disagreement: the same (action, object) allowed for one role and
	// denied for another is the shape of a real privilege bug, not a guess.
	type key struct{ action, object string }
	groups := map[key][]Capability{}
	keys := []key{}
	for _, c := range m.Capabilities {
		k := key{c.Action, c.Object}
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], c)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].action != keys[j].action {
			return keys[i].action < keys[j].action
		}
		return keys[i].object < keys[j].object
	})
	for _, k := range keys {
		rows := groups[k]
		var yes, no []string
		for _, r := range rows {
			switch r.Allowed {
			case "yes":
				yes = append(yes, r.Role)
			case "no":
				no = append(no, r.Role)
			}
		}
		if len(yes) == 0 || len(no) == 0 {
			continue
		}
		out = append(out, surface.Hypothesis{
			Target:  k.object,
			Class:   "access-control",
			Score:   70,
			Why:     []string{fmt.Sprintf("roles %s may %s this object while %s may not", strings.Join(strutil.UniqueSorted(yes), ","), k.action, strings.Join(strutil.UniqueSorted(no), ","))},
			Probe:   fmt.Sprintf("run %s as %s and compare with %s — the difference must come from the server, not the client", k.action, strings.Join(strutil.UniqueSorted(no), "/"), strings.Join(strutil.UniqueSorted(yes), "/")),
			Tags:    []string{TagCapability},
			Cluster: "mod:" + surface.Module(k.object),
		})
	}
	return out
}

// transitionSweep: any edge whose guard is unknown can be walked backwards, out
// of order, or twice.
func transitionSweep(m *Model) []surface.Hypothesis {
	var out []surface.Hypothesis
	seen := map[string]bool{}
	for _, t := range m.Transitions {
		id := t.From + "\x00" + t.Action + "\x00" + t.To
		if seen[id] {
			continue
		}
		seen[id] = true
		if !strings.Contains(strings.ToLower(t.Guard), "unknown") {
			continue
		}
		out = append(out, surface.Hypothesis{
			Target:  t.Action,
			Class:   "business-logic",
			Score:   64,
			Why:     []string{fmt.Sprintf("transition %s --[%s]--> %s carries no known guard", t.From, t.Action, t.To)},
			Probe:   fmt.Sprintf("walk the edge the wrong way: invoke %s while the object is still %s, then replay it twice — a second effect or a silent success means the guard is missing", t.Action, t.From),
			Tags:    []string{TagTransition},
			Cluster: "mod:" + surface.Module(t.Action),
		})
	}
	return out
}

// invariantSweep: a declared invariant with a check is already a probe; one
// without a check is a gap and stays in Model.Gaps.
func invariantSweep(m *Model) []surface.Hypothesis {
	var out []surface.Hypothesis
	for _, inv := range m.Invariants {
		if strings.TrimSpace(inv.Check) == "" {
			continue
		}
		out = append(out, surface.Hypothesis{
			Target: inv.ID,
			Class:  invariantClass(inv.Domain),
			Score:  66,
			Why:    []string{fmt.Sprintf("invariant [%s]: %s", inv.Domain, inv.Statement)},
			Probe:  inv.Check,
			Tags:   []string{TagInvariant},
		})
	}
	return out
}

func invariantClass(domain string) string {
	switch strings.ToLower(domain) {
	case "authz":
		return "access-control"
	case "tenancy":
		return "IDOR/BOLA"
	case "rate":
		return "business-logic"
	default:
		return "business-logic"
	}
}

// paritySweep: the same action served by two generations of the API is two
// implementations, and implementations drift.
func paritySweep(m *Model) []surface.Hypothesis {
	type group struct {
		prefixes map[string]string // prefix -> sample path
	}
	groups := map[string]*group{}
	order := []string{}
	for _, a := range m.Actions {
		key := parityKey(a.Path)
		if key == "" {
			continue
		}
		g, ok := groups[key]
		if !ok {
			g = &group{prefixes: map[string]string{}}
			groups[key] = g
			order = append(order, key)
		}
		p := apiPrefix(a.Path)
		if _, ok := g.prefixes[p]; !ok {
			g.prefixes[p] = a.Path
		}
	}
	sort.Strings(order)
	var out []surface.Hypothesis
	for _, key := range order {
		g := groups[key]
		if len(g.prefixes) < 2 {
			continue
		}
		prefixes := make([]string, 0, len(g.prefixes))
		for p := range g.prefixes {
			prefixes = append(prefixes, p)
		}
		sort.Strings(prefixes)
		first := g.prefixes[prefixes[0]]
		second := g.prefixes[prefixes[1]]
		out = append(out, surface.Hypothesis{
			Target:   first,
			Class:    "business-logic",
			Score:    68,
			Why:      []string{fmt.Sprintf("the same action is served by %s — %s and %s are separate implementations", strings.Join(prefixes, ", "), first, second)},
			Probe:    fmt.Sprintf("send %s and %s with the same identity and diff status, body and side effect — the older generation is usually the one that lost a check", first, second),
			Tags:     []string{TagParity},
			Cluster:  "mod:" + surface.Module(first),
			Variants: []string{second},
		})
	}
	return out
}

// anomalySweep turns the model's own oddities into probes. An anomaly without a
// target is reporting, not a probe, so it is skipped here.
func anomalySweep(m *Model) []surface.Hypothesis {
	var out []surface.Hypothesis
	for _, a := range m.Anomalies {
		if strings.TrimSpace(a.Target) == "" {
			continue
		}
		out = append(out, surface.Hypothesis{
			Target:  a.Target,
			Class:   anomalyClass(a.Kind),
			Score:   58,
			Why:     []string{fmt.Sprintf("anomaly %s: %s", a.Kind, a.Observation)},
			Probe:   anomalyProbe(a.Kind),
			Tags:    []string{TagAnomaly},
			Cluster: "mod:" + surface.Module(a.Target),
		})
	}
	return out
}

func anomalyClass(kind string) string {
	switch kind {
	case "dual-key-types":
		return "IDOR/BOLA"
	case "list-detail-filter":
		return "access-control"
	case "mixed-api-version":
		return "business-logic"
	default:
		return "surface-review"
	}
}

func anomalyProbe(kind string) string {
	switch kind {
	case "dual-key-types":
		return "take an object you own, then fetch it through the other key route — if the second route skips the ownership check, the two key types are not equivalent"
	case "list-detail-filter":
		return "page through the filtered list as the lowest role, then request the same objects directly by id — a filter is not an authorization boundary"
	case "mixed-api-version":
		return "replay the action on both generations with the same identity and compare enforcement"
	default:
		return "read the client code that drives this module and look for the call nobody documented"
	}
}

// parityKey normalises a path down to the action it names: version and transport
// prefixes dropped, object references collapsed.
func parityKey(path string) string {
	segs := strings.Split(strings.Trim(strings.ToLower(path), "/"), "/")
	var keep []string
	for _, s := range segs {
		if s == "" || isPrefixSegment(s) || isObjectSegment(s) {
			continue
		}
		keep = append(keep, s)
	}
	if len(keep) == 0 {
		return ""
	}
	return strings.Join(keep, "/")
}

// apiPrefix is the transport/version generation a path belongs to.
func apiPrefix(path string) string {
	for _, s := range strings.Split(strings.Trim(strings.ToLower(path), "/"), "/") {
		if isPrefixSegment(s) && !isObjectSegment(s) {
			return s
		}
	}
	return "web"
}

func isPrefixSegment(s string) bool {
	switch s {
	case "api", "apis", "rest", "graphql", "gql", "internal", "public", "external", "v1", "v2", "v3", "v4", "v5":
		return true
	}
	if len(s) == 2 && s[0] == 'v' && s[1] >= '0' && s[1] <= '9' {
		return true
	}
	return false
}

// isObjectSegment recognises a path segment that addresses one object rather than
// naming an action.
func isObjectSegment(s string) bool {
	if s == "" {
		return true
	}
	if s == "{" || s == "}" || strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		return true
	}
	digits := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r >= 'a' && r <= 'f', r == '-':
			// hex-ish / uuid-ish
		default:
			return false
		}
	}
	return digits > 0 && len(s) >= 6
}
