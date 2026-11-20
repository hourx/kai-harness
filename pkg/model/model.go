// Package model derives the operational model of a program — what exists, who
// can act on it, and what has already been tried — from the artifacts kai
// already holds: the recon store, the evidence index and the outcome log.
//
// The model describes; it never sends a request. Every row carries a source, so
// a reader can tell an operator declaration ("spec") from something collected
// ("observed") from a naming heuristic ("inferred"). A question the artifacts
// cannot answer becomes an explicit gap instead of a fabricated row: an invented
// invariant is worse than a missing one, because every sweep would then hunt a
// bug that only exists in the model.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/evidence"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/recon"
	"github.com/hourx/kai-harness/pkg/strutil"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// Provenance vocabulary. One word set is used for both Source and Confidence so
// a row never claims more than it can show.
const (
	ProvSpec     = "spec"     // operator declared it (program.yaml, meta.json)
	ProvObserved = "observed" // collected artifact (recon store, evidence, outcomes)
	ProvInferred = "inferred" // naming heuristic — verify before relying on it
)

// Entity is an object the program keeps: a user, an order, a repo.
type Entity struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	AddressForm string   `json:"address_form"` // path | query | path+query
	KeyTypes    []string `json:"key_types,omitempty"`
	Notes       string   `json:"notes,omitempty"`
	Source      string   `json:"source"`
	Confidence  string   `json:"confidence,omitempty"`
}

// Actor is a class of principal: anonymous, a user, an admin, a service.
type Actor struct {
	ID         string `json:"id"`
	Role       string `json:"role"`
	Auth       string `json:"auth"` // anon | user | admin | service
	Tenancy    string `json:"tenancy,omitempty"`
	Source     string `json:"source"`
	Confidence string `json:"confidence,omitempty"`
}

// Capability is one cell of the (role, action, object) matrix.
type Capability struct {
	Role        string `json:"role"`
	Action      string `json:"action"`
	Object      string `json:"object"`
	Allowed     string `json:"allowed"`     // yes | no | unknown
	Enforcement string `json:"enforcement"` // server | client | none | unknown
	Source      string `json:"source"`
	Confidence  string `json:"confidence,omitempty"`
}

// Action is something a client can ask the program to do.
type Action struct {
	ID           string   `json:"id"`
	Method       string   `json:"method"` // "unknown" until a request is observed
	Path         string   `json:"path_or_selector"`
	AuthRequired string   `json:"auth_required"` // yes | no | unknown
	Inputs       []string `json:"inputs,omitempty"`
	SideEffect   string   `json:"side_effect"` // read | write | value | auth
	Source       string   `json:"source"`
	Confidence   string   `json:"confidence,omitempty"`
}

// Transition is an edge between two states of an entity.
type Transition struct {
	From       string `json:"from_state"`
	Action     string `json:"action"`
	To         string `json:"to_state"`
	Guard      string `json:"guard"` // what must be true; "unknown" is a real answer
	Source     string `json:"source"`
	Confidence string `json:"confidence,omitempty"`
}

// Invariant is a rule that must hold for every request that touches an entity.
type Invariant struct {
	ID         string `json:"id"`
	Statement  string `json:"statement"`
	Check      string `json:"check,omitempty"` // how a probe falsifies it; empty = gap
	Domain     string `json:"domain"`          // state | authz | value | rate | tenancy
	Source     string `json:"source"`
	Confidence string `json:"confidence,omitempty"`
}

// Boundary is a place where trust changes: a session edge, a tenant edge, a
// service edge, a client edge.
type Boundary struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"` // auth | tenancy | chain | service | client
	Inside     string `json:"inside"`
	Outside    string `json:"outside"`
	Source     string `json:"source"`
	Confidence string `json:"confidence,omitempty"`
}

// ValueFlow is something worth stealing or redirecting, and who may move it.
type ValueFlow struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Asset      string `json:"asset"`
	FeeRule    string `json:"fee_rule,omitempty"`
	Source     string `json:"source"`
	Confidence string `json:"confidence,omitempty"`
}

// Anomaly is a place where the surface disagrees with the program's own
// convention. Anomalies are where other hunters have stopped looking.
type Anomaly struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Observation string `json:"observation"`
	Target      string `json:"target,omitempty"` // what a probe would point at
	EvidenceRef string `json:"evidence_ref,omitempty"`
	Source      string `json:"source"`
}

// Coverage answers "what has not been touched" for one in-scope asset.
type Coverage struct {
	Asset       string `json:"asset"`
	Tested      string `json:"tested"` // yes | partial | no
	LastIntent  string `json:"last_intent,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	LastTS      string `json:"last_ts,omitempty"`
}

// Exploration answers "what was tried and why" for one attempt.
type Exploration struct {
	ID          string   `json:"id"`
	Intent      string   `json:"intent"`
	Target      string   `json:"target"`
	ActionClass string   `json:"action_class,omitempty"`
	Outcome     string   `json:"outcome"` // tried | produced | blocked | dead
	Produced    []string `json:"produced,omitempty"`
	Why         string   `json:"why,omitempty"`
	EvidenceRef string   `json:"evidence_ref,omitempty"`
	TS          string   `json:"ts,omitempty"`
}

// Model is the whole picture: facts with provenance, plus the gaps the
// artifacts could not fill.
type Model struct {
	Program      string        `json:"program"`
	Archetype    string        `json:"archetype"`
	Source       string        `json:"source"`
	Generated    string        `json:"generated"`
	Entities     []Entity      `json:"entities,omitempty"`
	Actors       []Actor       `json:"actors,omitempty"`
	Capabilities []Capability  `json:"capabilities,omitempty"`
	Actions      []Action      `json:"actions,omitempty"`
	Transitions  []Transition  `json:"transitions,omitempty"`
	Invariants   []Invariant   `json:"invariants,omitempty"`
	Boundaries   []Boundary    `json:"boundaries,omitempty"`
	ValueFlows   []ValueFlow   `json:"value_flows,omitempty"`
	Anomalies    []Anomaly     `json:"anomalies,omitempty"`
	Coverage     []Coverage    `json:"coverage,omitempty"`
	Exploration  []Exploration `json:"exploration,omitempty"`
	Gaps         []string      `json:"gaps,omitempty"`
}

// Options is everything Derive is allowed to read. Passing artifacts in instead
// of paths keeps the derivation testable and keeps the package free of I/O.
type Options struct {
	Program         *workspace.Program
	Store           *recon.Store
	NonWeb          []surface.NonWebAsset
	Evidence        []evidence.Item
	Outcomes        *outcome.Table
	Records         []outcome.Record
	Archetype       string // verdict name; empty leaves it blank for the caller to fill
	ArchetypeSource string
	Now             time.Time
}

// Derive builds the model. It is deterministic: the same artifacts always
// produce the same bytes, so a diff between two runs means reality moved.
func Derive(o Options) (*Model, error) {
	p := o.Program
	if p == nil {
		return nil, errors.New("model: a program is required")
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	eps := map[string][]string{}
	if o.Store != nil {
		for path, rec := range o.Store.Endpoints {
			if rec == nil {
				continue
			}
			eps[path] = append([]string(nil), rec.Params...)
		}
	}
	m := surface.BuildWithNonWeb(p.Name, eps, o.NonWeb, now)

	out := &Model{
		Program:   p.Name,
		Archetype: o.Archetype,
		Source:    o.ArchetypeSource,
		Generated: now.UTC().Format(time.RFC3339),
	}

	out.Entities = deriveEntities(m)
	out.Actions = deriveActions(m)
	out.Transitions = deriveTransitions(out.Entities, out.Actions)
	out.Anomalies = deriveAnomalies(m)
	out.Boundaries = deriveBoundaries(p, o.NonWeb)
	out.ValueFlows = deriveValueFlows(out.Actions)
	out.Actors = []Actor{{
		ID:         "actor:anon",
		Role:       "unauthenticated",
		Auth:       "anon",
		Tenancy:    "unknown",
		Source:     ProvInferred,
		Confidence: ProvInferred,
	}}
	out.Coverage = deriveCoverage(p, m, o.Evidence, o.Records)
	out.Exploration = deriveExploration(o.Records, o.Evidence)

	// The gaps are the honest half of the model: what the artifacts cannot
	// answer. Each sweep prints them instead of guessing.
	out.Gaps = append(out.Gaps, fmt.Sprintf(
		"capabilities: 0 rows — the (role, action, object) matrix needs an authenticated walk; the capability sweep stays empty until someone records what each role can do"))
	for _, d := range []string{"state", "authz", "value", "rate", "tenancy"} {
		out.Gaps = append(out.Gaps, fmt.Sprintf(
			"invariants[%s]: none declared — needs operator knowledge; write the statement and a falsifiable check, then the invariant sweep turns into probes", d))
	}
	if len(out.ValueFlows) > 0 {
		out.Gaps = append(out.Gaps, "value_flows: fee and balance rules are unknown — a value bug needs the rule the program believes it enforces")
	}
	if len(out.Anomalies) == 0 {
		out.Gaps = append(out.Gaps, "anomalies: none found — either the surface is uniform or the recon has not reached the interesting modules yet")
	}
	sort.Strings(out.Gaps)
	return out, nil
}

type entityDraft struct {
	path  bool
	query bool
	keys  []string
}

func deriveEntities(m *surface.Map) []Entity {
	drafts := map[string]*entityDraft{}
	touch := func(name string) *entityDraft {
		if d, ok := drafts[name]; ok {
			return d
		}
		d := &entityDraft{}
		drafts[name] = d
		return d
	}
	for _, r := range m.Refs {
		d := touch(surface.Module(r.Endpoint))
		d.path = true
		d.keys = append(d.keys, r.Kind)
	}
	params := make([]string, 0, len(m.IDParams))
	for p := range m.IDParams {
		params = append(params, p)
	}
	sort.Strings(params)
	for _, param := range params {
		for _, path := range m.IDParams[param] {
			d := touch(surface.Module(path))
			d.query = true
			d.keys = append(d.keys, "param:"+strings.ToLower(param))
		}
	}
	names := make([]string, 0, len(drafts))
	for name := range drafts {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Entity, 0, len(names))
	for _, name := range names {
		d := drafts[name]
		form := "path"
		switch {
		case d.path && d.query:
			form = "path+query"
		case d.query:
			form = "query"
		}
		keys := strutil.UniqueSorted(d.keys)
		notes := ""
		if len(keys) > 1 {
			notes = "addressed by more than one key type"
		}
		out = append(out, Entity{
			ID:          "ent:" + name,
			Name:        name,
			AddressForm: form,
			KeyTypes:    keys,
			Notes:       notes,
			Source:      ProvObserved,
			Confidence:  ProvObserved,
		})
	}
	return out
}

func deriveActions(m *surface.Map) []Action {
	mods := make([]string, 0, len(m.Modules))
	for mod := range m.Modules {
		mods = append(mods, mod)
	}
	sort.Strings(mods)
	var out []Action
	for _, mod := range mods {
		paths := append([]string(nil), m.Modules[mod]...)
		sort.Strings(paths)
		for _, path := range paths {
			class := surface.Class(path)
			out = append(out, Action{
				ID:           "act:" + path,
				Method:       "unknown",
				Path:         path,
				AuthRequired: authRequired(class),
				Inputs:       strutil.UniqueSorted(paramsOf(m, path)),
				SideEffect:   sideEffect(class),
				Source:       ProvObserved,
				Confidence:   ProvInferred,
			})
		}
	}
	return out
}

// paramsOf recovers a path's parameters from the module listing's sibling data.
// The map keeps params on IDParams and loose names; everything else has to be
// re-read from the store, so only id params are attached here.
func paramsOf(m *surface.Map, path string) []string {
	var out []string
	params := make([]string, 0, len(m.IDParams))
	for p := range m.IDParams {
		params = append(params, p)
	}
	sort.Strings(params)
	for _, p := range params {
		for _, seen := range m.IDParams[p] {
			if seen == path {
				out = append(out, p)
			}
		}
	}
	return out
}

// authRequired: a login route is reachable without a session; nothing else can
// be claimed without observing a request.
func authRequired(class string) string {
	if class == "auth" {
		return "no"
	}
	return "unknown"
}

// sideEffect maps a business area onto the kind of state change it implies.
var sideEffectByClass = map[string]string{
	"auth":    "auth",
	"billing": "value",
	"upload":  "write",
	"admin":   "write",
	"account": "write",
	"graphql": "read",
	"generic": "read",
}

func sideEffect(class string) string {
	if v, ok := sideEffectByClass[class]; ok {
		return v
	}
	return "read"
}

var (
	createVerbs = map[string]bool{"create": true, "new": true, "add": true, "register": true,
		"signup": true, "order": true, "submit": true, "upload": true, "invite": true,
		"start": true, "init": true, "request": true, "send": true}
	updateVerbs = map[string]bool{"update": true, "edit": true, "patch": true, "set": true,
		"change": true, "modify": true, "confirm": true, "verify": true, "approve": true,
		"activate": true, "complete": true, "finish": true, "accept": true, "pay": true,
		"refund": true, "cancel": true, "reset": true}
	deleteVerbs = map[string]bool{"delete": true, "remove": true, "destroy": true, "revoke": true, "close": true}
)

// verbOf returns the first verb-like word in a path.
func verbOf(path string) (string, string) {
	for _, seg := range strings.Split(strings.ToLower(path), "/") {
		for _, word := range strings.FieldsFunc(seg, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
			switch {
			case createVerbs[word]:
				return "create", word
			case updateVerbs[word]:
				return "update", word
			case deleteVerbs[word]:
				return "delete", word
			}
		}
	}
	return "", ""
}

// deriveTransitions reads the verbs an entity's own endpoints use and writes the
// edges they imply. The guards are almost always a question — which is exactly
// what the transition sweep asks next.
func deriveTransitions(entities []Entity, actions []Action) []Transition {
	byMod := map[string][]Action{}
	for _, a := range actions {
		mod := surface.Module(a.Path)
		byMod[mod] = append(byMod[mod], a)
	}
	var out []Transition
	for _, e := range entities {
		group := byMod[e.Name]
		sort.Slice(group, func(i, j int) bool { return group[i].Path < group[j].Path })
		var create, update, del []Action
		for _, a := range group {
			switch kind, _ := verbOf(a.Path); kind {
			case "create":
				create = append(create, a)
			case "update":
				update = append(update, a)
			case "delete":
				del = append(del, a)
			}
		}
		for _, c := range create {
			for _, u := range update {
				out = append(out, Transition{From: "absent", Action: c.Path, To: "exists", Guard: "unknown", Source: ProvInferred, Confidence: ProvInferred})
				out = append(out, Transition{From: "exists", Action: u.Path, To: "exists", Guard: "owner check unknown", Source: ProvInferred, Confidence: ProvInferred})
				break
			}
		}
		for _, u := range update {
			for _, d := range del {
				out = append(out, Transition{From: "exists", Action: d.Path, To: "absent", Guard: "owner check unknown", Source: ProvInferred, Confidence: ProvInferred})
				_ = u
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		return out[i].To < out[j].To
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func deriveAnomalies(m *surface.Map) []Anomaly {
	var out []Anomaly
	add := func(id, kind, target, obs string) {
		out = append(out, Anomaly{ID: id, Kind: kind, Target: target, Observation: obs, Source: ProvObserved})
	}

	// 1. One entity addressed by more than one key type: the route that is
	//    guarded by an owner check usually sits next to one that is not.
	byMod := map[string][]string{}
	for _, r := range m.Refs {
		byMod[surface.Module(r.Endpoint)] = append(byMod[surface.Module(r.Endpoint)], r.Kind)
	}
	// A brace segment ({order_id}) is a reference too, but the map keeps it as a
	// query-style id param instead of a literal ref. Both shapes count as a key.
	for _, param := range sortedKeys(m.IDParams) {
		for _, path := range m.IDParams[param] {
			mod := surface.Module(path)
			byMod[mod] = append(byMod[mod], "param:"+strings.ToLower(param))
		}
	}
	mods := make([]string, 0, len(byMod))
	for mod := range byMod {
		mods = append(mods, mod)
	}
	sort.Strings(mods)
	for _, mod := range mods {
		kinds := strutil.UniqueSorted(byMod[mod])
		if len(kinds) > 1 {
			add("ano:keys:"+mod, "dual-key-types", "module:"+mod, fmt.Sprintf(
				"module %s addresses objects by %s — same entity, different key shapes", mod, strings.Join(kinds, "+")))
		}
	}

	// 2. A list endpoint that filters by an object id while a sibling endpoint
	//    addresses the object directly. If the filter is only applied to the
	//    list, the detail route is the way around it (and vice versa).
	refs := append([]surface.Ref(nil), m.Refs...)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Endpoint != refs[j].Endpoint {
			return refs[i].Endpoint < refs[j].Endpoint
		}
		return refs[i].Segment < refs[j].Segment
	})
	for _, p := range refs {
		mod := surface.Module(p.Endpoint)
		for _, param := range sortedKeys(m.IDParams) {
			for _, listPath := range m.IDParams[param] {
				if listPath == p.Endpoint || surface.Module(listPath) != mod {
					continue
				}
				add("ano:filter:"+param+":"+listPath, "list-detail-filter", listPath, fmt.Sprintf(
					"%s filters by %s while %s addresses the object directly — check which of the two enforces ownership",
					listPath, param, p.Endpoint))
			}
		}
	}

	// 3. Two API generations on one surface.
	if len(m.APIVersions) > 1 {
		add("ano:versions", "mixed-api-version", "", fmt.Sprintf(
			"surface spans %s — run the same action on both generations and compare enforcement", strings.Join(m.APIVersions, ", ")))
	}

	// 4. A module with a lot of endpoints and no object reference at all: the
	//    interesting call is usually in the JavaScript nobody read yet.
	for mod, paths := range m.Modules {
		if len(paths) < 5 {
			continue
		}
		if _, ok := byMod[mod]; ok {
			continue
		}
		hasParam := false
		for _, param := range sortedKeys(m.IDParams) {
			for _, path := range m.IDParams[param] {
				if surface.Module(path) == mod {
					hasParam = true
				}
			}
		}
		if hasParam {
			continue
		}
		add("ano:orphan:"+mod, "orphan-module", "module:"+mod, fmt.Sprintf(
			"module %s has %d endpoints and no object reference — read the bundle that drives it", mod, len(paths)))
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func deriveBoundaries(p *workspace.Program, nonWeb []surface.NonWebAsset) []Boundary {
	inside := append(p.ExactHosts(), p.DeriveDomains()...)
	for _, a := range nonWeb {
		inside = append(inside, a.Identifier)
	}
	outside := rules(filepath.Join(p.Dir, "out-of-scope.txt"))
	out := []Boundary{{
		ID:         "bnd:scope",
		Kind:       "service",
		Inside:     strings.Join(strutil.UniqueSorted(inside), ", "),
		Outside:    strings.Join(outside, ", "),
		Source:     ProvObserved,
		Confidence: ProvObserved,
	}}
	return out
}

// rules reads a one-rule-per-line file, dropping comments and blanks.
func rules(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			out = append(out, strings.ToLower(line))
		}
	}
	return strutil.UniqueSorted(out)
}

func deriveValueFlows(actions []Action) []ValueFlow {
	var out []ValueFlow
	for _, a := range actions {
		if a.SideEffect != "value" {
			continue
		}
		out = append(out, ValueFlow{
			From:       "client",
			To:         a.Path,
			Asset:      "value",
			FeeRule:    "unknown",
			Source:     ProvInferred,
			Confidence: ProvInferred,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].To < out[j].To })
	return out
}

// Path is where a program's model lives.
func Path(pDir string) string { return filepath.Join(pDir, "state", "model.json") }

// Load reads the model an earlier run wrote.
func Load(pDir string) (*Model, error) {
	b, err := os.ReadFile(Path(pDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no model yet (%s) — run: kai model <program>", Path(pDir))
	}
	if err != nil {
		return nil, err
	}
	var m Model
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("model %s: %w", Path(pDir), err)
	}
	return &m, nil
}

// Save writes the model atomically: a half-written model must never be read by a
// sweeps run.
func (m *Model) Save(pDir string) error {
	if err := os.MkdirAll(filepath.Dir(Path(pDir)), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := Path(pDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, Path(pDir)); err != nil {
		return err
	}
	// Read back: a successful write is not the same as a readable model.
	back, err := Load(pDir)
	if err != nil {
		return fmt.Errorf("model written but not readable back: %w", err)
	}
	if back.Program != m.Program || len(back.Coverage) != len(m.Coverage) {
		return errors.New("model written but read back different")
	}
	return nil
}

// JSON renders the model exactly as Save would write it, for callers that print
// instead of persisting.
func (m *Model) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// NeverTested lists the in-scope assets with nothing recorded against them.
//
// Partial coverage counts as touched: one exchange against an asset is enough to
// say someone has started, and calling that "never touched" would hide work that
// has already been done.
func (m *Model) NeverTested() []string {
	var out []string
	for _, c := range m.Coverage {
		if c.Tested == TestedNo || c.Tested == "" {
			out = append(out, c.Asset)
		}
	}
	return out
}

// Markdown renders the model for a human or an agent reading the workspace.
func (m *Model) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Program model — %s\n\n", m.Program)
	fmt.Fprintf(&b, "Archetype **%s** (%s) · generated %s\n\n", m.Archetype, m.Source, m.Generated)
	fmt.Fprintf(&b, "%d entities · %d actions · %d transitions · %d invariants · %d anomalies · %d coverage rows · %d explorations\n\n",
		len(m.Entities), len(m.Actions), len(m.Transitions), len(m.Invariants), len(m.Anomalies), len(m.Coverage), len(m.Exploration))

	if len(m.Entities) > 0 {
		b.WriteString("## Entities\n\n| entity | addressed by | key types |\n| --- | --- | --- |\n")
		for _, e := range m.Entities {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", e.Name, e.AddressForm, strings.Join(e.KeyTypes, ", "))
		}
		b.WriteString("\n")
	}
	if len(m.Anomalies) > 0 {
		b.WriteString("## Anomalies\n\n")
		for _, a := range m.Anomalies {
			fmt.Fprintf(&b, "- **%s** — %s\n", a.Kind, a.Observation)
		}
		b.WriteString("\n")
	}
	if len(m.Transitions) > 0 {
		b.WriteString("## Transitions\n\n| from | action | to | guard |\n| --- | --- | --- | --- |\n")
		for _, t := range m.Transitions {
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", t.From, t.Action, t.To, t.Guard)
		}
		b.WriteString("\n")
	}
	if len(m.Coverage) > 0 {
		b.WriteString("## Coverage — what has not been touched\n\n| asset | tested | last intent | last seen |\n| --- | --- | --- | --- |\n")
		rows := append([]Coverage(nil), m.Coverage...)
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Tested != rows[j].Tested {
				return rows[i].Tested < rows[j].Tested
			}
			return rows[i].Asset < rows[j].Asset
		})
		for _, c := range rows {
			intent := c.LastIntent
			if intent == "" {
				intent = "—"
			}
			ts := c.LastTS
			if ts == "" {
				ts = "—"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", c.Asset, c.Tested, intent, ts)
		}
		b.WriteString("\n")
	}
	if len(m.Exploration) > 0 {
		b.WriteString("## Exploration\n\n")
		for _, e := range m.Exploration {
			fmt.Fprintf(&b, "- `%s` **%s** %s — %s\n", e.Target, e.Outcome, e.ActionClass, e.Why)
		}
		b.WriteString("\n")
	}
	if len(m.Gaps) > 0 {
		b.WriteString("## Gaps — questions the artifacts could not answer\n\n")
		for _, g := range m.Gaps {
			fmt.Fprintf(&b, "- %s\n", g)
		}
	}
	return b.String()
}

// digest is the short content hash used for row ids.
func digest(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%s\x00", p)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
