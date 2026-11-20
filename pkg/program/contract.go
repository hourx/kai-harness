package program

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/driver"
	"github.com/hourx/kai-harness/pkg/scope"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// ContractVersion is the schema version of state/program.yaml. Bump it only for
// a change a reader must know about; consumers refuse a version they do not
// understand rather than guessing at the missing field.
const ContractVersion = 1

// Contract is the contract of record for one program: what the platform allows,
// where that was read from, and which actions the operator has authorised.
//
// Every later command reads this file instead of re-deriving policy, so a
// verdict can always be traced back to the intake snapshot it came from.
//
// It is written as JSON. JSON is a subset of YAML 1.2, so the file is valid
// YAML for any reader (`yq`, PyYAML, an editor) while kai stays free of a YAML
// dependency. Human-readable output is `kai contract <program>`.
type Contract struct {
	ContractVersion int    `json:"contract_version"`
	Driver          string `json:"driver"`
	DriverVersion   int    `json:"driver_version"`
	DriverName      string `json:"driver_name"`
	Platform        string `json:"platform"`
	// Archetype is the operator's own name for the shape of this program. When
	// empty the model infers it; when set it is never overridden, because a
	// human who has read the policy outranks a heuristic.
	Archetype    string `json:"archetype,omitempty"`
	Name         string `json:"name"`
	Handle       string `json:"handle,omitempty"`
	URL          string `json:"url"`
	RequiresAuth bool   `json:"requires_auth"`

	Intake    Snapshot           `json:"intake"`
	Scope     []Rule             `json:"scope"`
	Out       []Rule             `json:"out_of_scope"`
	PathOnly  []AssetRef         `json:"path_scoped"`
	NonWeb    []AssetRef         `json:"non_web"`
	Mandatory []driver.Condition `json:"mandatory_conditions"`

	Actions       Actions  `json:"actions"`
	ReportFields  []string `json:"report_field_set"`
	RewardFields  []string `json:"reward_fields"`
	SubmitChannel string   `json:"submit_channel,omitempty"`
	SubmitURL     string   `json:"submit_url,omitempty"`

	WrittenAt time.Time `json:"written_at"`
}

// Snapshot records where the contract's facts came from, so a rule can always
// be traced back to the intake that produced it.
type Snapshot struct {
	Hash         string    `json:"hash,omitempty"`
	PolicyHash   string    `json:"policy_hash,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
	Confidence   string    `json:"confidence,omitempty"`
	Score        int       `json:"score,omitempty"`
	Verdict      string    `json:"verdict,omitempty"`
	OffersBounty bool      `json:"offers_bounty"`
}

// Rule is one scope rule plus where it came from. A rule with no source is a
// contract violation: an unattributable rule cannot be defended.
type Rule struct {
	Rule   string `json:"rule"`
	Source string `json:"source"`
}

// AssetRef is an asset that cannot be expressed as a host rule.
type AssetRef struct {
	Identifier string `json:"identifier"`
	Reason     string `json:"reason"`
}

// Actions is the action-class table: what may run unattended, what needs the
// operator, and what never runs. It is doctrine plus what the policy forces.
type Actions struct {
	ReadOnly      []string `json:"read_only"`
	NeedsApproval []string `json:"needs_approval"`
	Forbidden     []string `json:"forbidden"`
}

// BuildContract turns an intake plus its driver into the contract of record.
func BuildContract(in *Intake, m driver.Manifest) Contract {
	sc := in.Scope()
	c := Contract{
		ContractVersion: ContractVersion,
		Driver:          m.ID,
		DriverVersion:   m.Version,
		DriverName:      m.Name,
		Platform:        in.Platform,
		Name:            in.Name,
		Handle:          in.Handle,
		URL:             in.URL,
		RequiresAuth:    m.RequiresAuth,
		// Empty tables are empty, not absent: a reader of this file should
		// never have to tell "no rules" from "field missing".
		Scope:         []Rule{},
		Out:           []Rule{},
		PathOnly:      []AssetRef{},
		NonWeb:        []AssetRef{},
		Mandatory:     append([]driver.Condition{}, m.MandatoryConditions...),
		RewardFields:  append([]string{}, m.RewardFields...),
		ReportFields:  append([]string{}, m.ReportFieldSet...),
		SubmitChannel: m.SubmitChannel,
		SubmitURL:     m.SubmitURL,
		Actions:       actionsFor(in.Boundaries, m),
		WrittenAt:     time.Now().UTC(),
		Intake: Snapshot{
			Hash:         intakeHash(in),
			PolicyHash:   in.PolicyHash,
			FetchedAt:    in.FetchedAt,
			Confidence:   in.Confidence,
			Score:        in.Scorecard.Total,
			Verdict:      in.Scorecard.Verdict,
			OffersBounty: in.OffersBounty,
		},
	}
	for _, r := range sc.In {
		c.Scope = append(c.Scope, Rule{Rule: r, Source: ruleSource(in, r)})
	}
	for _, r := range sc.Out {
		c.Out = append(c.Out, Rule{Rule: r, Source: "structured scope (not eligible)"})
	}
	for _, a := range sc.PathOnly {
		c.PathOnly = append(c.PathOnly, AssetRef{Identifier: a.Identifier, Reason: "path-restricted asset: a host-only gate would be broader than the program allows"})
	}
	for _, a := range sc.NonWeb {
		c.NonWeb = append(c.NonWeb, AssetRef{Identifier: a.Identifier, Reason: "non-web asset: the HTTP gate cannot reach it"})
	}
	return c
}

// ruleSource names where an in-scope rule came from, so the operator can tell
// a platform fact from a promotion he performed with --trust-scope.
func ruleSource(in *Intake, rule string) string {
	if !in.TrustScope {
		return "structured scope (eligible)"
	}
	for _, a := range in.Assets {
		if a.Eligible && normalizeRuleValue(a) == rule {
			return "structured scope (eligible)"
		}
	}
	return "page text, promoted by --trust-scope"
}

func normalizeRuleValue(a Asset) string {
	r, kind := normalizeRule(a)
	if kind == "path" || kind == "non-web" || kind == "unparsed" {
		return ""
	}
	return r
}

// intakeHash is a short stable digest of the facts the contract rests on. It is
// compared by `kai rules-diff` and printed by `kai contract`.
func intakeHash(in *Intake) string {
	if in == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(in.Platform + "|" + in.Handle + "|" + in.URL + "|")
	b.WriteString(fmt.Sprintf("%v|", in.OffersBounty))
	for _, a := range in.Assets {
		fmt.Fprintf(&b, "%s=%v;", a.Identifier, a.Eligible)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// actionsFor is doctrine plus policy: the read-only / approval / forbidden
// split, with anything the policy forbids added explicitly.
func actionsFor(b Boundaries, m driver.Manifest) Actions {
	a := Actions{
		ReadOnly: []string{
			"passive HTTP reads of in-scope assets",
			"endpoint and directory discovery inside the program's stated rate limit",
			"reissuing your own requests to confirm a result",
			"reading the public policy and reporting pages",
		},
		NeedsApproval: []string{
			"any request that changes state on the target, even against an object you own",
			"creating an account or resource on the target",
			"file upload, including innocuous test files",
			"submitting a report (kai drafts; the operator submits)",
		},
		Forbidden: []string{
			"denial of service, load or stress testing of any kind",
			"social engineering of staff, contractors or users",
			"testing an asset the contract does not list as in scope",
			"accessing third-party data, even when it is reachable",
			"scanning beyond the program's stated rate limit or outside its allowed window",
		},
	}
	if b.PoCRequired {
		a.NeedsApproval = append(a.NeedsApproval, "running the proof of concept end to end (the program requires a PoC)")
	}
	if b.KYCRequired {
		a.NeedsApproval = append(a.NeedsApproval, "any step that requires identity verification (the program requires KYC)")
	}
	if b.DepositRequired {
		a.NeedsApproval = append(a.NeedsApproval, "any step that requires a deposit or spends funds")
		a.Forbidden = append(a.Forbidden, "spending funds to obtain a finding")
	}
	if strings.Contains(strings.ToLower(b.MainnetTesting), "do not") || strings.Contains(strings.ToLower(b.MainnetTesting), "not ") {
		a.Forbidden = append(a.Forbidden, "testing against mainnet: the policy forbids it")
	}
	if m.RequiresAuth {
		a.NeedsApproval = append(a.NeedsApproval, "the policy is behind a login; reading it requires an authenticated session")
	}
	return a
}

// Marshal renders the contract the way it is stored.
func (c Contract) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// SaveContract writes state/program.yaml.
func SaveContract(p *workspace.Program, c Contract) error {
	b, err := c.Marshal()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.StatePath(""), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p.StatePath("program.yaml"), b, 0o600)
}

// LoadContract reads state/program.yaml. The boolean is false when no contract
// has been written yet, which is a normal state for a workspace from `kai init`
// that has not been through intake.
func LoadContract(p *workspace.Program) (Contract, bool, error) {
	b, err := os.ReadFile(p.StatePath("program.yaml"))
	if err != nil {
		if os.IsNotExist(err) {
			return Contract{}, false, nil
		}
		return Contract{}, false, err
	}
	var c Contract
	if err := json.Unmarshal(b, &c); err != nil {
		return Contract{}, false, fmt.Errorf("state/program.yaml is not readable: %w", err)
	}
	if c.ContractVersion > ContractVersion {
		return Contract{}, false, fmt.Errorf("state/program.yaml is version %d, this build understands %d — upgrade kai", c.ContractVersion, ContractVersion)
	}
	return c, true, nil
}

// InScopeSet returns the contract's in-scope rules as a set.
func (c Contract) InScopeSet() map[string]bool {
	s := make(map[string]bool, len(c.Scope))
	for _, r := range c.Scope {
		s[r.Rule] = true
	}
	return s
}

// OutOfScopeSet returns the contract's out-of-scope rules as a set.
func (c Contract) OutOfScopeSet() map[string]bool {
	s := make(map[string]bool, len(c.Out))
	for _, r := range c.Out {
		s[r.Rule] = true
	}
	return s
}

// ContractAudit compares the contract against the artifacts actually on disk.
// The dangerous direction is a gate that is BROADER than the contract: that is
// what lets recon touch an asset the program never authorised. A narrower gate
// only means recon skips work, so it is reported as a note.
func ContractAudit(p *workspace.Program, c Contract) []string {
	var problems []string
	inGate, err := scope.Load(p.Dir + "/scope.txt")
	if err != nil && !os.IsNotExist(err) {
		problems = append(problems, "scope.txt cannot be read: "+err.Error())
	}
	outGate, _ := scope.Load(p.Dir + "/out-of-scope.txt")

	contractIn := c.InScopeSet()
	contractOut := c.OutOfScopeSet()

	for _, rule := range inGate {
		if contractOut[rule] {
			problems = append(problems, fmt.Sprintf("contradiction: %s is in scope.txt and in the contract's out-of-scope table", rule))
			continue
		}
		if !contractIn[rule] {
			problems = append(problems, fmt.Sprintf("scope.txt is broader than the contract: %s is not authorised by %s", rule, c.Driver))
		}
	}
	for _, rule := range outGate {
		if contractIn[rule] {
			problems = append(problems, fmt.Sprintf("contradiction: %s is out of scope and authorised by the contract", rule))
		}
	}
	for _, r := range c.Scope {
		if !contains(inGate, r.Rule) {
			problems = append(problems, fmt.Sprintf("note: the contract authorises %s but scope.txt does not list it (recon will skip it)", r.Rule))
		}
	}
	if p.Meta.Platform != "" && c.Platform != "" && p.Meta.Platform != c.Platform {
		// The workspace may record the platform under its short name ("h1" for
		// the driver "hackerone"). That is a label, not a disagreement.
		if m, ok := driver.Get(strings.ToLower(p.Meta.Platform)); !ok || m.ID != c.Driver {
			problems = append(problems, fmt.Sprintf("note: meta.json says platform %s, the contract says %s", p.Meta.Platform, c.Platform))
		}
	}
	sort.Strings(problems)
	return problems
}

// Markdown is the human view `kai contract <program>` prints.
func (c Contract) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Program contract — %s\n\n", c.Name)
	fmt.Fprintf(&b, "- driver: %s (manifest v%d)\n", c.Driver, c.DriverVersion)
	fmt.Fprintf(&b, "- platform: %s\n", c.Platform)
	fmt.Fprintf(&b, "- url: %s\n", c.URL)
	fmt.Fprintf(&b, "- intake fetched: %s", c.Intake.FetchedAt.Format(time.RFC3339))
	var facts []string
	if s := strings.TrimSpace(c.Intake.Confidence); s != "" {
		facts = append(facts, "confidence "+s)
	}
	if s := strings.TrimSpace(c.Intake.Verdict); s != "" {
		facts = append(facts, "verdict "+s)
	}
	facts = append(facts, fmt.Sprintf("score %d", c.Intake.Score))
	fmt.Fprintf(&b, " (%s)\n", strings.Join(facts, ", "))
	if c.Intake.Hash != "" {
		fmt.Fprintf(&b, "- intake snapshot: %s\n", c.Intake.Hash)
	}
	if c.RequiresAuth {
		fmt.Fprintln(&b, "- policy requires an authenticated session")
	}
	fmt.Fprintf(&b, "- written: %s\n\n", c.WrittenAt.Format(time.RFC3339))

	fmt.Fprintf(&b, "## Scope (%d rules)\n\n", len(c.Scope))
	for _, r := range c.Scope {
		fmt.Fprintf(&b, "- `%s` — %s\n", r.Rule, r.Source)
	}
	fmt.Fprintf(&b, "\n## Out of scope (%d rules)\n\n", len(c.Out))
	if len(c.Out) == 0 {
		fmt.Fprintln(&b, "none published as host rules")
	}
	for _, r := range c.Out {
		fmt.Fprintf(&b, "- `%s`\n", r.Rule)
	}
	if len(c.PathOnly) > 0 {
		fmt.Fprintf(&b, "\n## Path-restricted, not enabled (%d)\n\n", len(c.PathOnly))
		for _, a := range c.PathOnly {
			fmt.Fprintf(&b, "- `%s` — %s\n", a.Identifier, a.Reason)
		}
	}
	if len(c.NonWeb) > 0 {
		fmt.Fprintf(&b, "\n## Non-web, out of the HTTP gate (%d)\n\n", len(c.NonWeb))
		for _, a := range c.NonWeb {
			fmt.Fprintf(&b, "- `%s` — %s\n", a.Identifier, a.Reason)
		}
	}
	if len(c.Mandatory) > 0 {
		fmt.Fprintf(&b, "\n## Mandatory conditions (not scope rules)\n\n")
		for _, m := range c.Mandatory {
			fmt.Fprintf(&b, "- **%s** — %s\n", m.ID, m.Text)
		}
	}
	fmt.Fprintf(&b, "\n## Actions\n\n")
	fmt.Fprintln(&b, "Read-only (runs unattended):")
	for _, s := range c.Actions.ReadOnly {
		fmt.Fprintf(&b, "- %s\n", s)
	}
	fmt.Fprintln(&b, "\nNeeds operator approval:")
	for _, s := range c.Actions.NeedsApproval {
		fmt.Fprintf(&b, "- %s\n", s)
	}
	fmt.Fprintln(&b, "\nForbidden:")
	for _, s := range c.Actions.Forbidden {
		fmt.Fprintf(&b, "- %s\n", s)
	}
	fmt.Fprintf(&b, "\n## Report field set (%s)\n\n", c.Driver)
	for _, f := range c.ReportFields {
		fmt.Fprintf(&b, "- %s\n", f)
	}
	if len(c.RewardFields) > 0 {
		fmt.Fprintf(&b, "\n## Reward fields\n\n")
		for _, f := range c.RewardFields {
			fmt.Fprintf(&b, "- %s\n", f)
		}
	}
	if c.SubmitChannel != "" {
		fmt.Fprintf(&b, "\nSubmission: %s", c.SubmitChannel)
		if c.SubmitURL != "" {
			fmt.Fprintf(&b, " — %s", c.SubmitURL)
		}
		fmt.Fprintln(&b)
	}
	return b.String()
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
