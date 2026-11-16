package program

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hourx/bountykit/internal/workspace"
)

// Apply writes the intake artifacts into an existing workspace. It replaces
// the scope files that `init` created with rules derived from the platform.
func Apply(p *workspace.Program, in *Intake) error {
	sc := in.Scope()
	in.Scorecard = in.Score()

	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	if err := write(filepath.Join(p.Dir, "intake.json"), b); err != nil {
		return err
	}
	if err := write(filepath.Join(p.Dir, "program.md"), []byte(in.Markdown())); err != nil {
		return err
	}
	if err := write(filepath.Join(p.Dir, "boundaries.md"), []byte(in.BoundariesMarkdown())); err != nil {
		return err
	}
	if in.Policy != "" {
		if err := write(filepath.Join(p.Dir, "policy.md"), []byte(strings.TrimSpace(in.Policy)+"\n")); err != nil {
			return err
		}
	}

	var scope strings.Builder
	fmt.Fprintf(&scope, "# Scope — imported from %s\n", in.URL)
	fmt.Fprintf(&scope, "# Fetched %s. Out-of-scope always wins.\n", in.FetchedAt.Format(time.RFC3339))
	if len(sc.PathOnly) > 0 {
		fmt.Fprintf(&scope, "# WARNING: %d path-scoped asset(s) are NOT enabled here.\n", len(sc.PathOnly))
		fmt.Fprintln(&scope, "# A host-only gate would be broader than the program allows. Read policy.md.")
	}
	if len(sc.In) == 0 {
		fmt.Fprintln(&scope, "# No host-level scope was published. Read policy.md and add rules manually.")
		fmt.Fprintln(&scope, "# Recon refuses to run while this file has no rules — that is deliberate.")
	}
	for _, r := range sc.In {
		fmt.Fprintln(&scope, r)
	}
	if in.TrustScope {
		fmt.Fprintln(&scope, "")
		fmt.Fprintln(&scope, "# The host rules above were promoted from page text by --trust-scope.")
		fmt.Fprintln(&scope, "# VERIFY each one against policy.md before relying on it.")
		for _, c := range in.Candidates {
			if c.Path != "" {
				fmt.Fprintf(&scope, "#   %s (path-restricted, not enabled)\n", c.Identifier)
			}
		}
	} else if len(in.Candidates) > 0 {
		fmt.Fprintf(&scope, "# %d candidate host(s) from page text are NOT enabled. See intake.json.\n", len(in.Candidates))
		fmt.Fprintln(&scope, "# Use --trust-scope only after verifying each one against the policy.")
	}
	if err := write(filepath.Join(p.Dir, "scope.txt"), []byte(scope.String())); err != nil {
		return err
	}

	var out strings.Builder
	fmt.Fprintf(&out, "# Out of scope — imported from %s\n", in.URL)
	fmt.Fprintln(&out, "# Host rules only. Vulnerability classes, prohibited actions and headers")
	fmt.Fprintln(&out, "# are in boundaries.md and policy.md — a host gate cannot enforce them.")
	fmt.Fprintln(&out, "# Host rules here come only from the platform's structured scope.")
	for _, r := range sc.Out {
		fmt.Fprintln(&out, r)
	}
	if len(sc.PathOnly) > 0 {
		fmt.Fprintln(&out, "")
		fmt.Fprintln(&out, "# Path-restricted assets (NOT enabled in scope.txt):")
		for _, a := range sc.PathOnly {
			fmt.Fprintf(&out, "#   %s\n", a.Identifier)
		}
	}
	if err := write(filepath.Join(p.Dir, "out-of-scope.txt"), []byte(out.String())); err != nil {
		return err
	}

	if _, err := SnapshotAndDiff(p.Dir, in); err != nil {
		return err
	}

	p.Meta.Notes = fmt.Sprintf("intake from %s (%s)", in.URL, in.FetchedAt.Format("2006-01-02"))
	return p.SaveMeta()
}

func write(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
