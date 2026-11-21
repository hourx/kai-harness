// Package pattern keeps knowledge keyed by the shape of a program — its
// archetype and what a row is about — never by a URL.
//
// Two layers, kept apart on purpose:
//
//   - the public layer (Public) ships with the binary: generic, reviewable, and
//     free of anything learned from a live campaign;
//   - the delta (Delta) is workspace-local: which keys fired here and what the
//     operator recorded against them.
//
// The layers meet in Delta.Boost, a deterministic ranking signal: what paid on
// this archetype outranks what nobody has tried. No database, no prompt, no
// network — a lookup and a sum.
package pattern

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hourx/kai-harness/pkg/archetype"
	"github.com/hourx/kai-harness/pkg/surface"
)

// Any is the archetype that applies to every shape.
const Any = "*"

// Family says what a key names.
type Family string

const (
	// FamilyEntity is a thing the program has (account, payment, token).
	FamilyEntity Family = "entity"
	// FamilyAction is a thing it does (login, upload, refund).
	FamilyAction Family = "action"
	// FamilyInvariant is something that has to stay true (supply conserved).
	FamilyInvariant Family = "invariant"
	// FamilyClass is a hypothesis class from the queue. It is the one family the
	// delta can observe on its own, because every recorded outcome carries a class.
	FamilyClass Family = "class"
)

// Families is the closed set, in the order reports print them.
var Families = []Family{FamilyClass, FamilyEntity, FamilyAction, FamilyInvariant}

// KnownFamily reports whether f is one of the four families.
func KnownFamily(f Family) bool {
	for _, k := range Families {
		if k == f {
			return true
		}
	}
	return false
}

// Key addresses one piece of pattern knowledge.
type Key struct {
	Archetype string `json:"archetype"`
	Family    Family `json:"family"`
	Name      string `json:"name"`
}

// NewKey canonicalises every part, so two spellings of one idea are one key.
func NewKey(a string, f Family, name string) Key {
	return Key{Archetype: canonArchetype(a), Family: f, Name: Canonical(name)}
}

// canonArchetype keeps Any as-is and folds every other spelling onto the closed set.
func canonArchetype(a string) string {
	a = strings.TrimSpace(a)
	if a == "" || a == Any {
		return Any
	}
	if n := archetype.Normalize(a); n != "" && archetype.Known(n) {
		return n
	}
	// A shape nothing recognises applies to every shape. A typo in a layer file is
	// caught earlier, by Key.Valid, which sees the string before this folding — so
	// this fallback widens scope for computed keys instead of hiding a mistake.
	return Any
}

// CanonicalArchetype folds an archetype spelling onto the closed set, or onto Any
// when nothing recognises it. Callers that must not fail on a stale name use this
// instead of hand-rolling the fallback.
func CanonicalArchetype(a string) string { return canonArchetype(a) }

// Canonical folds a name onto the form keys are stored in: lowercase, spaces and
// underscores as hyphens, slashes kept so class names such as IDOR/BOLA survive.
func Canonical(name string) string {
	var out []rune
	prevDash := false
	for _, r := range strings.TrimSpace(name) {
		switch {
		case r >= 'A' && r <= 'Z':
			out = append(out, r+('a'-'A'))
			prevDash = false
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			out = append(out, r)
			prevDash = false
		case r == '/' || r == '.' || r == '-':
			if prevDash && r != '/' {
				continue
			}
			out = append(out, r)
			prevDash = r != '/'
		default:
			// Spaces, underscores, anything else: one hyphen, never two.
			if !prevDash && len(out) > 0 {
				out = append(out, '-')
				prevDash = true
			}
		}
	}
	s := strings.Trim(string(out), "-")
	return strings.Trim(s, "/")
}

// Label renders a canonical name for humans: the acronyms an operator writes in
// caps come back in caps, everything else stays as stored, and the separators the
// name used are the separators it keeps.
func Label(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); {
		if c := name[i]; c == '/' || c == '-' || c == '.' {
			b.WriteByte(c)
			i++
			continue
		}
		j := i
		for j < len(name) {
			if c := name[j]; c == '/' || c == '-' || c == '.' {
				break
			}
			j++
		}
		w := name[i:j]
		if up, ok := acronyms[w]; ok {
			b.WriteString(up)
		} else {
			b.WriteString(w)
		}
		i = j
	}
	return b.String()
}

var acronyms = map[string]string{
	"idor": "IDOR", "bola": "BOLA", "ato": "ATO", "ssrf": "SSRF", "xss": "XSS",
	"csrf": "CSRF", "api": "API", "graphql": "GraphQL", "jwt": "JWT", "mfa": "MFA",
	"sql": "SQL", "rce": "RCE", "xxe": "XXE", "sso": "SSO", "otp": "OTP",
}

// String is the stable, greppable form: "graphql-api/class/idor/bola".
func (k Key) String() string {
	return k.Archetype + "/" + string(k.Family) + "/" + k.Name
}

// ParseKey reads the form Key.String writes.
func ParseKey(s string) (Key, error) {
	parts := strings.SplitN(strings.TrimSpace(s), "/", 3)
	if len(parts) != 3 {
		return Key{}, fmt.Errorf("pattern key %q must read <archetype>/<family>/<name>", s)
	}
	k := Key{Archetype: parts[0], Family: Family(parts[1]), Name: parts[2]}
	if err := k.Valid(); err != nil {
		return Key{}, err
	}
	canon := NewKey(k.Archetype, k.Family, k.Name)
	if canon.String() != s {
		return Key{}, fmt.Errorf("pattern key %q is not canonical — write %q", s, canon.String())
	}
	return canon, nil
}

// Valid reports whether the key can be stored and compared.
func (k Key) Valid() error {
	if k.Archetype == "" {
		return fmt.Errorf("pattern key %q: empty archetype", k.String())
	}
	if k.Archetype != Any && !archetype.Known(k.Archetype) {
		return fmt.Errorf("pattern key %q: unknown archetype %q (known: %s)", k.String(), k.Archetype, strings.Join(archetype.Names(), ", "))
	}
	if !KnownFamily(k.Family) {
		return fmt.Errorf("pattern key %q: unknown family %q (known: class, entity, action, invariant)", k.String(), k.Family)
	}
	if k.Name == "" {
		return fmt.Errorf("pattern key %q: empty name", k.String())
	}
	if NewKey(k.Archetype, k.Family, k.Name) != k {
		return fmt.Errorf("pattern key %q is not canonical — write %q", k.String(), NewKey(k.Archetype, k.Family, k.Name).String())
	}
	return nil
}

// Pattern is one piece of knowledge about a shape.
type Pattern struct {
	Key        Key     `json:"key"`
	Class      string  `json:"class,omitempty"` // the hypothesis class it feeds, when it feeds one
	Title      string  `json:"title"`
	Why        string  `json:"why"`
	Confidence float64 `json:"confidence"` // 0..1: how sure the layer that supplied it is
	Source     string  `json:"source"`
}

// Validate rejects a pattern that cannot be trusted or compared.
func (p Pattern) Validate() error {
	if err := p.Key.Valid(); err != nil {
		return err
	}
	if strings.TrimSpace(p.Title) == "" {
		return fmt.Errorf("pattern %s: empty title", p.Key)
	}
	if p.Confidence < 0 || p.Confidence > 1 {
		return fmt.Errorf("pattern %s: confidence %.2f is outside 0..1", p.Key, p.Confidence)
	}
	if p.Class != "" && !knownClass(p.Class) {
		return fmt.Errorf("pattern %s: class %q is not one the queue produces (see surface.Classes)", p.Key, p.Class)
	}
	return nil
}

// knownClass reports whether the queue can ever assign this class.
func knownClass(class string) bool {
	for _, c := range surface.Classes() {
		if Canonical(c) == class {
			return true
		}
	}
	return false
}

// Library is an ordered, deduplicated set of patterns.
type Library struct {
	items []Pattern
}

// New builds a library, rejecting anything that does not validate. A later
// pattern with the same key replaces an earlier one, which is how an operator's
// file corrects the public layer instead of duplicating it.
func New(ps ...Pattern) (Library, error) {
	return Library{}.With(ps...)
}

// With returns the library with ps merged in; the receiver is unchanged.
func (l Library) With(ps ...Pattern) (Library, error) {
	byKey := map[Key]int{}
	out := make([]Pattern, len(l.items))
	copy(out, l.items)
	for i, p := range out {
		byKey[p.Key] = i
	}
	for _, p := range ps {
		// The class field is a join key: canonicalise it here so a pattern that
		// writes IDOR/BOLA meets a delta that writes idor/bola.
		p.Class = Canonical(p.Class)
		if err := p.Validate(); err != nil {
			return Library{}, err
		}
		if i, ok := byKey[p.Key]; ok {
			out[i] = p
			continue
		}
		byKey[p.Key] = len(out)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.String() < out[j].Key.String() })
	return Library{items: out}, nil
}

// All returns every pattern, sorted by key.
func (l Library) All() []Pattern {
	out := make([]Pattern, len(l.items))
	copy(out, l.items)
	return out
}

// Len is the number of patterns held.
func (l Library) Len() int { return len(l.items) }

// Lookup finds the pattern for an exact key.
func (l Library) Lookup(k Key) (Pattern, bool) {
	for _, p := range l.items {
		if p.Key == k {
			return p, true
		}
	}
	return Pattern{}, false
}

// For returns the patterns that apply to an archetype, most specific first: the
// ones written for this shape, then the ones written for the shape it descends
// from, then the ones written for every shape.
func (l Library) For(a string) []Pattern {
	want := canonArchetype(a)
	parent := archetype.Parent(want)
	tier := func(k Key) int {
		switch {
		case k.Archetype == want:
			return 0
		case k.Archetype == Any:
			return 2
		case parent != "" && k.Archetype == parent:
			return 1
		}
		return -1
	}
	var out []Pattern
	for t := 0; t <= 2; t++ {
		for _, p := range l.items { // l.items is sorted by key, so each tier is sorted
			if tier(p.Key) == t {
				out = append(out, p)
			}
		}
	}
	return out
}

// Origin says where a pattern comes from relative to an archetype: the shape
// itself, the shape it descends from, or every shape. A report that cannot say
// which tier a pattern came from makes an inheritance look like a coincidence.
func Origin(p Pattern, a string) string {
	want := canonArchetype(a)
	switch {
	case p.Key.Archetype == Any:
		// An unclassified program matches this tier by construction, and calling
		// it "this shape" would claim the library knows something about it.
		return "every shape"
	case p.Key.Archetype == want:
		return "this shape"
	case p.Key.Archetype != "" && p.Key.Archetype == archetype.Parent(want):
		return "inherited from `" + p.Key.Archetype + "`"
	}
	return "does not apply to `" + want + "`"
}

// Covered reports whether a class key is explained for this archetype, and by
// which tier.
func (l Library) Covered(a, class string) (string, bool) {
	class = Canonical(class)
	if class == "" {
		return "", false
	}
	for _, p := range l.For(a) {
		if p.Key.Family == FamilyClass && p.Key.Name == class {
			return Origin(p, a), true
		}
	}
	return "", false
}

// Coverage reports which of the wanted class keys the library explains. It is how
// a report says "the queue asks this question and no pattern has an opinion" —
// printed as a question rather than invented.
func (l Library) MissingClasses(a string, classes []string) []string {
	have := map[string]bool{}
	for _, p := range l.For(a) {
		if p.Key.Family == FamilyClass {
			have[p.Key.Name] = true
		}
	}
	var missing []string
	for _, c := range classes {
		if c = Canonical(c); c == "" || have[c] {
			continue
		}
		missing = append(missing, c)
	}
	sort.Strings(missing)
	return dedupe(missing)
}

// Classes returns the canonical class keys the library knows for an archetype.
func (l Library) Classes(a string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range l.For(a) {
		if p.Key.Family != FamilyClass || seen[p.Key.Name] {
			continue
		}
		seen[p.Key.Name] = true
		out = append(out, p.Key.Name)
	}
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	out := in[:0]
	prev := ""
	for i, s := range in {
		if i > 0 && s == prev {
			continue
		}
		out = append(out, s)
		prev = s
	}
	return out
}
