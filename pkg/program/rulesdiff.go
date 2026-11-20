package program

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RulesDiff is the delta between two intakes. A change in scope or policy is
// as important as a new host: a program that silently narrows its scope can
// turn yesterday's in-scope test into today's unauthorised request.
type RulesDiff struct {
	From                   string   `json:"from"`
	To                     string   `json:"to"`
	Baseline               bool     `json:"baseline"`
	NewScopeRules          []string `json:"new_scope_rules,omitempty"`
	RemovedScopeRules      []string `json:"removed_scope_rules,omitempty"`
	NewOutOfScopeRules     []string `json:"new_out_of_scope_rules,omitempty"`
	RemovedOutOfScopeRules []string `json:"removed_out_of_scope_rules,omitempty"`
	NewAssets              []string `json:"new_assets,omitempty"`
	RemovedAssets          []string `json:"removed_assets,omitempty"`
	NewCandidates          []string `json:"new_candidates,omitempty"`
	ConstraintsAdded       []string `json:"constraints_added,omitempty"`
	ConstraintsRemoved     []string `json:"constraints_removed,omitempty"`
	RewardChanged          bool     `json:"reward_changed,omitempty"`
	OldRewardTop           int      `json:"old_reward_top,omitempty"`
	NewRewardTop           int      `json:"new_reward_top,omitempty"`
	StateChanged           string   `json:"state_changed,omitempty"`
	PolicyChanged          bool     `json:"policy_changed,omitempty"`
}

func intakesDir(dir string) string { return filepath.Join(dir, "intakes") }

// SnapshotAndDiff archives this intake and compares it with the previous one.
func SnapshotAndDiff(pDir string, in *Intake) (RulesDiff, error) {
	var d RulesDiff
	ts := in.FetchedAt.UTC().Format("20060102T150405Z")
	dir := filepath.Join(intakesDir(pDir), ts)
	for n := 2; ; n++ {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			break
		}
		dir = filepath.Join(intakesDir(pDir), fmt.Sprintf("%s-%d", ts, n))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return d, err
	}
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return d, err
	}
	if err := os.WriteFile(filepath.Join(dir, "intake.json"), b, 0o600); err != nil {
		return d, err
	}
	if err := os.WriteFile(filepath.Join(dir, "boundaries.md"), []byte(in.BoundariesMarkdown()), 0o600); err != nil {
		return d, err
	}
	if in.Policy != "" {
		if err := os.WriteFile(filepath.Join(dir, "policy.md"), []byte(in.Policy), 0o600); err != nil {
			return d, err
		}
	}

	d.From = lastIntake(pDir, filepath.Base(dir))
	d.To = filepath.Base(dir)
	if d.From == "" {
		d.Baseline = true
	} else {
		prev, err := loadIntakeSnapshot(pDir, d.From)
		if err != nil {
			return d, err
		}
		d = compareIntakes(prev, in, d)
	}
	if err := writeRulesDiff(pDir, d); err != nil {
		return d, err
	}
	return d, nil
}

func lastIntake(pDir, current string) string {
	entries, err := os.ReadDir(intakesDir(pDir))
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != current {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[len(names)-1]
}

func loadIntakeSnapshot(pDir, name string) (*Intake, error) {
	b, err := os.ReadFile(filepath.Join(intakesDir(pDir), name, "intake.json"))
	if err != nil {
		return nil, err
	}
	var in Intake
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, err
	}
	return &in, nil
}

func compareIntakes(prev, cur *Intake, d RulesDiff) RulesDiff {
	ps, cs := prev.Scope(), cur.Scope()
	d.NewScopeRules = diffStrings(ps.In, cs.In)
	d.RemovedScopeRules = diffStrings(cs.In, ps.In)
	d.NewOutOfScopeRules = diffStrings(ps.Out, cs.Out)
	d.RemovedOutOfScopeRules = diffStrings(cs.Out, ps.Out)
	d.NewAssets = diffStrings(assetKeys(prev.Assets), assetKeys(cur.Assets))
	d.RemovedAssets = diffStrings(assetKeys(cur.Assets), assetKeys(prev.Assets))
	d.NewCandidates = diffStrings(candidateKeys(prev.Candidates), candidateKeys(cur.Candidates))
	d.ConstraintsAdded = diffStrings(prev.Constraints, cur.Constraints)
	d.ConstraintsRemoved = diffStrings(cur.Constraints, prev.Constraints)
	if prev.TopUpper != cur.TopUpper {
		d.RewardChanged = true
		d.OldRewardTop, d.NewRewardTop = prev.TopUpper, cur.TopUpper
	}
	if prev.State != cur.State || prev.Submission != cur.Submission {
		d.StateChanged = fmt.Sprintf("%s/%s → %s/%s", prev.State, prev.Submission, cur.State, cur.Submission)
	}
	ph, ch := prev.PolicyHash, cur.PolicyHash
	d.PolicyChanged = ph != "" && ch != "" && ph != ch
	return d
}

func diffStrings(from, to []string) []string {
	have := map[string]bool{}
	for _, v := range from {
		have[v] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, v := range to {
		if !have[v] && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func assetKeys(assets []Asset) []string {
	out := make([]string, 0, len(assets))
	for _, a := range assets {
		out = append(out, a.Type+": "+a.Identifier)
	}
	return out
}

func candidateKeys(c []Candidate) []string {
	out := make([]string, 0, len(c))
	for _, x := range c {
		out = append(out, x.Type+": "+x.Identifier)
	}
	return out
}

func hashPolicy(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func writeRulesDiff(pDir string, d RulesDiff) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(pDir, "rules-diff.json"), b, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(pDir, "rules-diff.md"), []byte(d.Markdown()), 0o600)
}

// LoadRulesDiff reads the last rule diff.
func LoadRulesDiff(pDir string) (*RulesDiff, error) {
	b, err := os.ReadFile(filepath.Join(pDir, "rules-diff.json"))
	if err != nil {
		return nil, err
	}
	var d RulesDiff
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Changed reports whether anything meaningful moved since the last intake.
func (d RulesDiff) Changed() bool {
	return len(d.NewScopeRules)+len(d.RemovedScopeRules)+len(d.NewOutOfScopeRules)+
		len(d.RemovedOutOfScopeRules)+len(d.NewAssets)+len(d.RemovedAssets)+
		len(d.NewCandidates)+len(d.ConstraintsAdded)+len(d.ConstraintsRemoved) > 0 ||
		d.RewardChanged || d.StateChanged != "" || d.PolicyChanged
}

// Markdown renders the rule diff for the operator and the agent brief.
func (d RulesDiff) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Rule changes\n\n`%s` → `%s`\n\n", d.From, d.To)
	if d.Baseline {
		b.WriteString("**Baseline.** No earlier intake to compare against — every rule below is new by definition.\n")
		return b.String()
	}
	section := func(title string, values []string) {
		if len(values) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s (%d)\n\n", title, len(values))
		for _, v := range values {
			fmt.Fprintf(&b, "- `%s`\n", v)
		}
		b.WriteString("\n")
	}
	section("New scope rules", d.NewScopeRules)
	section("Removed scope rules", d.RemovedScopeRules)
	section("New out-of-scope rules", d.NewOutOfScopeRules)
	section("Removed out-of-scope rules", d.RemovedOutOfScopeRules)
	section("New assets", d.NewAssets)
	section("Removed assets", d.RemovedAssets)
	section("New host candidates", d.NewCandidates)
	section("Constraints added", d.ConstraintsAdded)
	section("Constraints removed", d.ConstraintsRemoved)
	if d.RewardChanged {
		fmt.Fprintf(&b, "## Reward changed\n\n%s → %s\n\n", money(d.OldRewardTop), money(d.NewRewardTop))
	}
	if d.StateChanged != "" {
		fmt.Fprintf(&b, "## Program state changed\n\n%s\n\n", d.StateChanged)
	}
	if d.PolicyChanged {
		b.WriteString("## Policy text changed\n\nThe policy itself was edited. Re-read `policy.md` before testing.\n\n")
	}
	if len(d.NewScopeRules)+len(d.RemovedScopeRules)+len(d.NewOutOfScopeRules)+len(d.RemovedOutOfScopeRules)+
		len(d.NewAssets)+len(d.RemovedAssets)+len(d.NewCandidates)+len(d.ConstraintsAdded)+
		len(d.ConstraintsRemoved) == 0 && !d.RewardChanged && d.StateChanged == "" && !d.PolicyChanged {
		b.WriteString("**No rule changes since the previous intake.**\n")
	}
	return b.String()
}
