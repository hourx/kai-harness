package program

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hourx/kai-harness/internal/scope"
	"github.com/hourx/kai-harness/internal/strutil"
)

// CompactBrief renders a context card small enough to inject into an agent
// prompt (~300 tokens). It stays deliberately factual: no prose, no advice.
func CompactBrief(pDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(pDir, "intake.json"))
	if err != nil {
		return "", fmt.Errorf("no intake — run: kai intake <url> --name %s", filepath.Base(pDir))
	}
	var in Intake
	if err := json.Unmarshal(b, &in); err != nil {
		return "", err
	}
	s := in.Scorecard
	var out strings.Builder
	fmt.Fprintf(&out, "# %s — context card\n", in.Name)
	fmt.Fprintf(&out, "platform=%s confidence=%s verdict=%s (%d/100) money=%d crowding=%d\n",
		in.Platform, in.confidenceLabel(), s.Verdict, s.Total, s.Money, s.Crowding)

	// Operator-approved `scope.txt` is the source of truth for the gate; prefer
	// it over intake-derived rules so the card matches `kai boundaries` and the
	// gate. Prose-only programs often have no intake assets at all.
	var rules []string
	var outRules []string
	if g, err := scope.LoadGate(pDir); err == nil {
		rules = g.In
		outRules = g.Out
	} else {
		for _, a := range in.Assets {
			if !a.Eligible {
				continue
			}
			if r, kind := normalizeRule(a); r != "" && kind != "non-web" && kind != "unparsed" {
				rules = append(rules, r)
			}
		}
		rules = strutil.Unique(rules)
	}
	fmt.Fprintf(&out, "scope(%d): %s\n", len(rules), strings.Join(rules, ", "))
	if len(outRules) > 0 {
		fmt.Fprintf(&out, "out(%d): %s\n", len(outRules), strings.Join(outRules, ", "))
	}

	bd := in.Boundaries
	fmt.Fprintf(&out, "mainnet=%s env=%s\n", strutil.Dash(bd.MainnetTesting), strutil.Dash(bd.TestingEnvironment))
	if bd.SubmissionChannel != "" {
		fmt.Fprintf(&out, "submit=%s\n", bd.SubmissionChannel)
	}
	if len(bd.RequiredHeaders) > 0 {
		fmt.Fprintf(&out, "headers=%s\n", strings.Join(bd.RequiredHeaders, ","))
	}
	if len(bd.SubmissionContact) > 0 {
		fmt.Fprintf(&out, "contacts=%s (contacts, not the channel)\n", strings.Join(bd.SubmissionContact, ","))
	}

	if raw, err := os.ReadFile(filepath.Join(pDir, "next.json")); err == nil {
		var plan struct {
			Items []struct {
				Target string `json:"target"`
				Class  string `json:"class"`
				Score  int    `json:"score"`
			} `json:"items"`
		}
		if json.Unmarshal(raw, &plan) == nil {
			out.WriteString("top:\n")
			for i, it := range plan.Items {
				if i >= 5 {
					break
				}
				fmt.Fprintf(&out, "- [%d] %s — %s\n", it.Score, it.Target, it.Class)
			}
		}
	}

	// ~300 tokens at 4 chars/token. Keep the mandatory lines; trim targets.
	const max = 1200
	if len(out.String()) <= max {
		return out.String(), nil
	}
	text := out.String()
	if idx := strings.Index(text, "top:\n"); idx >= 0 {
		head := text[:idx]
		targets := strings.Split(strings.TrimSpace(text[idx:]), "\n")
		var kept []string
		for _, line := range targets {
			candidate := head + "top:\n" + strings.Join(append(kept, line), "\n") + "\n"
			if len(candidate) > max {
				break
			}
			kept = append(kept, line)
		}
		return head + "top:\n" + strings.Join(kept, "\n") + "\n", nil
	}
	return text[:max], nil
}
