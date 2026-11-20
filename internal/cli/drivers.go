package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hourx/kai-harness/pkg/driver"
	"github.com/hourx/kai-harness/pkg/program"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// resolveDriver picks the driver that claims an intake argument. A pasted URL is
// matched against the manifests; a bare handle has no host to match, so it goes
// to HackerOne, whose shorthand it is. Anything else falls to the self-hosted
// driver. The returned pattern is the manifest rule that won, and is printed so
// the choice is auditable.
func resolveDriver(arg string) (driver.Manifest, string) {
	arg = strings.TrimSpace(arg)
	if m, pat, ok := driver.Match(arg); ok {
		return m, pat
	}
	if !strings.Contains(arg, ".") {
		if m, ok := driver.Get("hackerone"); ok {
			return m, "bare handle → hackerone shorthand"
		}
	}
	if m, ok := driver.Get("selfhosted"); ok {
		return m, "fallback"
	}
	// Unreachable while the embedded manifests are present, but a missing
	// fallback must not silently pick a platform.
	panic("driver: no manifests loaded")
}

func cmdDrivers(args []string) int {
	fs := flag.NewFlagSet("drivers", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "emit the manifests as JSON")
	pos, rest := split(args, nil)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) > 1 {
		return fail(errors.New("usage: kai drivers [<url>] [--json]"))
	}

	if len(pos) == 1 {
		m, pat, ok := driver.Match(pos[0])
		if !ok {
			return fail(fmt.Errorf("no driver claims %s", pos[0]))
		}
		fmt.Printf("%s claims %q via pattern %q\n", m.ID, pos[0], pat)
		fmt.Printf("parser     %s\n", m.Parser)
		fmt.Printf("policy     %s\n", m.PolicyFetch.Kind)
		fmt.Printf("scope      %s\n", m.ScopeExtraction.Kind)
		fmt.Printf("fields     %d report fields\n", len(m.ReportFieldSet))
		if m.RequiresAuth {
			fmt.Println("auth       policy requires a session")
		}
		return 0
	}

	all := driver.All()
	if *asJSON {
		b, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			return fail(err)
		}
		fmt.Println(string(b))
		return 0
	}
	fmt.Printf("drivers  %d (manifest v%d)\n\n", len(all), driver.ManifestVersion)
	for _, m := range all {
		fmt.Printf("%-12s %s\n", m.ID, m.Name)
		fmt.Printf("  %-10s %s\n", "matches", strings.Join(m.IntakeURLs, ", "))
		fmt.Printf("  %-10s %s · policy %s · scope %s\n", "reader", m.Parser, m.PolicyFetch.Kind, m.ScopeExtraction.Kind)
		fmt.Printf("  %-10s %d report fields", "contract", len(m.ReportFieldSet))
		if len(m.RewardFields) > 0 {
			fmt.Printf(", %d reward fields", len(m.RewardFields))
		}
		if len(m.MandatoryConditions) > 0 {
			fmt.Printf(", %d mandatory condition(s)", len(m.MandatoryConditions))
		}
		fmt.Println()
	}
	fmt.Printf("\nreaders registered: %s\n", strings.Join(program.ParserIDs(), ", "))
	return 0
}

func cmdContract(args []string) int {
	fs := flag.NewFlagSet("contract", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	raw := fs.Bool("json", false, "print the stored file verbatim")
	audit := fs.Bool("audit", false, "compare the contract against scope.txt and out-of-scope.txt")
	pos, rest := split(args, nil)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai contract <program> [--json] [--audit]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	c, ok, err := program.LoadContract(p)
	if err != nil {
		return fail(err)
	}
	if !ok {
		return fail(fmt.Errorf("no contract yet — run: kai intake <url> --name %s", p.Name))
	}

	if *raw {
		b, err := c.Marshal()
		if err != nil {
			return fail(err)
		}
		os.Stdout.Write(b)
		return 0
	}
	fmt.Print(c.Markdown())

	if !*audit {
		return 0
	}
	problems := program.ContractAudit(p, c)
	if len(problems) == 0 {
		fmt.Println("\naudit: scope.txt and out-of-scope.txt agree with the contract")
		return 0
	}
	contradictions := 0
	fmt.Printf("\naudit: %d finding(s)\n", len(problems))
	for _, s := range problems {
		if !strings.HasPrefix(s, "note:") {
			contradictions++
		}
		fmt.Printf("  %s\n", s)
	}
	if contradictions > 0 {
		return 1
	}
	return 0
}
