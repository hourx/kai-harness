package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hourx/kai-harness/internal/audit"
	"github.com/hourx/kai-harness/internal/backup"
	"github.com/hourx/kai-harness/internal/doctor"
	"github.com/hourx/kai-harness/internal/nonweb"
	"github.com/hourx/kai-harness/internal/pack"
	"github.com/hourx/kai-harness/internal/session"
	"github.com/hourx/kai-harness/pkg/netx"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/program"
	"github.com/hourx/kai-harness/pkg/progress"
	"github.com/hourx/kai-harness/pkg/recon"
	"github.com/hourx/kai-harness/pkg/scope"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/triage"
	"github.com/hourx/kai-harness/pkg/version"
	"github.com/hourx/kai-harness/pkg/workspace"
)

const usageText = `kai — deterministic context packs for bug bounty

Usage:
  kai <command> [arguments]

Commands:
  run     <url> [--name slug] [--step] [--clone] [--no-session] [--rps N]
                    [--max-links N] [--no-follow] [-o dist] [--force]
                                                             full guided workflow
  audit   <program|file.zip>                                 check handoff consistency
  doctor  [--no-net]                                         check local environment
  init    <program> [--platform P] [--url U] [--verdict V] [--domain d,d]
                                                             create workspace
  intake  <url|handle> [--name slug] [--dry-run] [--force] [--trust-scope]
                    [--max-links N] [--no-follow]                Phase 0: read program
  drivers [<url>] [--json]                                   which platform claims this target
  contract <program> [--json] [--audit]                       the contract of record (state/program.yaml)
  boundaries <program>                                      print scope limits & rules
  brief    <program> [--out file]                            compact context card (~300 tokens)
  track    <program> list|submit|status|payout|retest        submission & triage ledger
  backup   [--out file] [--include-session] [--include-repos]
                                                             snapshot data/ + dist/
  restore  <file.tar.gz> [--dest dir]                        restore a snapshot
  analyze   <program> [--clone] [--refresh]                 inspect in-scope repos/contracts
  rules-diff <program>                                      what changed since last intake
  scope   <program> <host|cidr>                              scope gate (IN/OUT)
  recon   <program> [--domain d] [--rps N] [--max-hosts N]
                    [--max-bundles N] [--nuclei] [--no-session] [--step]
                                                             discover surface
  session <program> [show|set|clear] [--har f] [--cookie s] [--header 'K: V']
                                                             auth for recon
  model   <program> [--json] [--write] [--archetype NAME]     what kind of program this is + the facts and gaps
  map     <program>                                          structure endpoints
  next    <program>                                          ranked test queue
  outcome <program> --status S [--class C] [--note T] <target...>
                                                             record what a target turned out to be
  patterns <program> [--json] [--write] [--dir D] [--archetype NAME]
                                                             what applies to this shape + what paid here before
  contribute <program> [--json] [--out f]                     build the anonymous pattern payload (never sent)
  plan    <program>                                          queue -> waves by what each step needs
  board   [<program>]                                        what is worth doing today (all programs)
  evidence <program> [list|add|import|show|attach] [--har f]  capture the raw proof behind a finding
  report-draft <program> <evidence-id> [--platform P]        draft a submission in the platform's fields
  diff    <program>                                          show last surface diff
  pack    <program> [-o dist] [--include-raw] [--include-session]
                                                             build handoff ZIP
  export  <program> --to <dir>                               write agent context files
                                                             into a campaign dir
  status  [<program>]                                        show state
  tui     [<program>] [--demo] [--frames N]                  split-pane workspace (bare kai on a terminal)
  serve   [--addr host:port] [--token T|auto]                read-only HTTP/JSON view of the workspace
  version                                                    print version

Exit codes for scope:
  0  in scope      1  out of scope      2  usage or empty scope

Environment:
  KAI_HOME   state root (default: ./data)
`

// Run dispatches a command and returns the process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		// On a terminal, the bare command opens the workspace. Everywhere else
		// (pipes, cron, CI) it stays the usage text it always was.
		if tuiWanted() {
			return tuiInteractive("")
		}
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}
	switch args[0] {
	case "tui":
		return tuiCmd(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "version", "-v", "--version":
		fmt.Println("kai " + version.String())
		return 0
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return 0
	case "run":
		return cmdRun(args[1:])
	case "audit":
		return cmdAudit(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "init":
		return cmdInit(args[1:])
	case "intake":
		return cmdIntake(args[1:])
	case "drivers":
		return cmdDrivers(args[1:])
	case "contract":
		return cmdContract(args[1:])
	case "scope":
		return cmdScope(args[1:])
	case "boundaries":
		return cmdBoundaries(args[1:])
	case "brief":
		return cmdBrief(args[1:])
	case "track":
		return cmdTrack(args[1:])
	case "backup":
		return cmdBackup(args[1:])
	case "restore":
		return cmdRestore(args[1:])
	case "analyze":
		return cmdAnalyze(args[1:])
	case "rules-diff":
		return cmdRulesDiff(args[1:])
	case "recon":
		return cmdRecon(args[1:])
	case "session":
		return cmdSession(args[1:])
	case "model":
		return cmdModel(args[1:])
	case "map":
		return cmdMap(args[1:])
	case "next":
		return cmdNext(args[1:])
	case "outcome":
		return cmdOutcome(args[1:])
	case "patterns":
		return cmdPatterns(args[1:])
	case "contribute":
		return cmdContribute(args[1:])
	case "plan":
		return cmdPlan(args[1:])
	case "board":
		return cmdBoard(args[1:])
	case "evidence":
		return cmdEvidence(args[1:])
	case "report-draft":
		return cmdReportDraft(args[1:])
	case "diff":
		return cmdDiff(args[1:])
	case "pack":
		return cmdPack(args[1:])
	case "export":
		return cmdExport(args[1:])
	case "status":
		return cmdStatus(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "kai: unknown command %q\n\n", args[0])
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "kai:", err)
	return 2
}

// split separates positional arguments from flags so commands accept both
// `init acme --platform h1` and `init --platform h1 acme`. The standard flag
// package stops at the first positional, which is a poor CLI experience.
// valueFlags lists flag names that consume the following argument.
func split(args []string, valueFlags map[string]bool) (pos, rest []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			rest = append(rest, a)
			name := strings.TrimLeft(a, "-")
			if strings.ContainsRune(name, '=') {
				continue
			}
			if valueFlags[name] && i+1 < len(args) {
				i++
				rest = append(rest, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return pos, rest
}

func cmdBrief(args []string) int {
	pos, rest := split(args, map[string]bool{"out": true})
	fs := flag.NewFlagSet("brief", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outFlag := fs.String("out", "", "write to this file instead of <program>/brief-compact.md")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai brief <program> [--out file]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	text, err := program.CompactBrief(p.Dir)
	if err != nil {
		return fail(err)
	}
	dest := *outFlag
	if dest == "" {
		dest = filepath.Join(p.Dir, "brief-compact.md")
	}
	if err := os.WriteFile(dest, []byte(text), 0o600); err != nil {
		return fail(err)
	}
	fmt.Print(text)
	return 0
}

// writeCompact refreshes the agent-facing card after state changes.
func writeCompact(p *workspace.Program) {
	text, err := program.CompactBrief(p.Dir)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(p.Dir, "brief-compact.md"), []byte(text), 0o600)
}

func cmdBackup(args []string) int {
	pos, rest := split(args, map[string]bool{"out": true})
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outFlag := fs.String("out", "", "archive path (default: kai-backup-<ts>.tar.gz)")
	withSession := fs.Bool("include-session", false, "include session.json (contains live credentials)")
	withRepos := fs.Bool("include-repos", false, "include cloned repositories")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 0 {
		return fail(errors.New("usage: kai backup [--out file] [--include-session] [--include-repos]"))
	}
	root, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	path, err := backup.Create(root, backup.Options{
		Out:            *outFlag,
		DataDir:        workspace.Home(),
		DistDir:        filepath.Join(root, "dist"),
		IncludeSession: *withSession,
		IncludeRepos:   *withRepos,
	})
	if err != nil {
		return fail(err)
	}
	info, _ := os.Stat(path)
	fmt.Printf("backup  %s", path)
	if info != nil {
		fmt.Printf(" (%d bytes)", info.Size())
	}
	fmt.Println()
	if !*withSession {
		fmt.Println("session.json excluded — restore it separately with: kai session <program> set --har ...")
	}
	return 0
}

func cmdRestore(args []string) int {
	pos, rest := split(args, map[string]bool{"dest": true})
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	destFlag := fs.String("dest", ".", "directory to restore into")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai restore <file.tar.gz> [--dest dir]"))
	}
	n, err := backup.Restore(pos[0], *destFlag)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("restored %d file(s) into %s\n", n, *destFlag)
	fmt.Println("next    kai doctor && kai status")
	return 0
}

func cmdTrack(args []string) int {
	pos, rest := split(args, map[string]bool{"platform": true, "note": true, "amount": true})
	fs := flag.NewFlagSet("track", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	platformFlag := fs.String("platform", "", "platform used for submission")
	noteFlag := fs.String("note", "", "triager note / reason")
	amountFlag := fs.Int("amount", 0, "payout amount")
	forceFlag := fs.Bool("force", false, "allow payout on a finding marked duplicate/informative")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) < 2 {
		return fail(errors.New("usage: kai track <program> list|submit|status|payout|retest ..."))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	ledger, err := triage.Load(p.Dir)
	if err != nil {
		return fail(err)
	}
	action := pos[1]

	switch action {
	case "list":
		fmt.Print(ledger.Markdown())
		return 0
	case "submit":
		if len(pos) < 3 {
			return fail(errors.New("usage: kai track <program> submit <queue-number|target>"))
		}
		target, class, probe, index := pos[2], "", "", 0
		if idx, e := strconv.Atoi(pos[2]); e == nil {
			b, e := os.ReadFile(filepath.Join(p.Dir, "next.json"))
			if e != nil {
				return fail(errors.New("no next.json — run: kai next " + p.Name))
			}
			var plan struct {
				Items []struct {
					Target string `json:"target"`
					Class  string `json:"class"`
					Probe  string `json:"probe"`
				} `json:"items"`
			}
			if e := json.Unmarshal(b, &plan); e != nil || idx < 1 || idx > len(plan.Items) {
				return fail(fmt.Errorf("no queue item %d (run: kai next %s)", idx, p.Name))
			}
			it := plan.Items[idx-1]
			target, class, probe, index = it.Target, it.Class, it.Probe, idx
		}
		platform := *platformFlag
		if platform == "" {
			platform = p.Meta.Platform
		}
		f, err := ledger.Add(target, class, probe, platform, index)
		if err != nil {
			return fail(err)
		}
		if err := ledger.Save(p.Dir); err != nil {
			return fail(err)
		}
		fmt.Printf("submitted %s — %s\n", f.ID, f.Target)
		return 0
	case "status":
		if len(pos) < 4 {
			return fail(errors.New("usage: kai track <program> status <id> <duplicate|informative|needs-info|...> [--note text]"))
		}
		if err := ledger.SetStatus(pos[2], pos[3], *noteFlag); err != nil {
			return fail(err)
		}
	case "payout":
		if len(pos) < 3 || *amountFlag <= 0 {
			return fail(errors.New("usage: kai track <program> payout <id> --amount N [--force]"))
		}
		if err := ledger.Payout(pos[2], *amountFlag, *forceFlag); err != nil {
			return fail(err)
		}
	case "retest":
		if len(pos) < 3 {
			return fail(errors.New("usage: kai track <program> retest <id>"))
		}
		snapshot := ""
		if b, err := os.ReadFile(filepath.Join(p.Dir, "diff.json")); err == nil {
			var d struct {
				To string `json:"to"`
			}
			if json.Unmarshal(b, &d) == nil {
				snapshot = d.To
			}
		}
		if err := ledger.Retest(pos[2], snapshot); err != nil {
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("unknown track action %q", action))
	}
	if err := ledger.Save(p.Dir); err != nil {
		return fail(err)
	}
	fmt.Print(ledger.Markdown())
	return 0
}

func cmdRun(args []string) int {
	pos, rest := split(args, map[string]bool{"name": true, "rps": true, "max-links": true, "o": true})
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	nameFlag := fs.String("name", "", "workspace slug (default: derived from URL)")
	stepMode := fs.Bool("step", false, "pause before each phase")
	cloneRepos := fs.Bool("clone", false, "git clone in-scope repositories")
	noSession := fs.Bool("no-session", false, "ignore stored session")
	rps := fs.Int("rps", 10, "requests per second during recon")
	maxLinks := fs.Int("max-links", 8, "documentation links to follow during intake")
	noFollow := fs.Bool("no-follow", false, "do not follow documentation links")
	out := fs.String("o", "dist", "output directory for the handoff ZIP")
	force := fs.Bool("force", false, "replace an existing workspace's scope files")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai run <url> [--name slug] [--step] [--clone] [--no-session] [--rps N] [--max-links N] [--no-follow] [-o dist] [--force]"))
	}

	programURL := pos[0]
	name := *nameFlag
	if name == "" {
		name = program.SuggestName(programURL)
	}
	gate := func(title, detail string) bool {
		if *stepMode {
			return promptConfirm(title, detail)
		}
		fmt.Printf("\n── %s ── %s\n", title, detail)
		return true
	}

	// 1. Intake.
	iargs := []string{programURL, "--name", name}
	if _, err := workspace.Open(name); err == nil {
		iargs = append(iargs, "--force")
	}
	if *force {
		iargs = append(iargs, "--force")
	}
	if *maxLinks != 8 {
		iargs = append(iargs, "--max-links", strconv.Itoa(*maxLinks))
	}
	if *noFollow {
		iargs = append(iargs, "--no-follow")
	}
	if !gate("intake", "read program page + relevant documentation") {
		return 0
	}
	if code := cmdIntake(iargs); code != 0 {
		return code
	}

	// 2. Boundaries.
	if !gate("boundaries", "read scope limits and rules") {
		return 0
	}
	if code := cmdBoundaries([]string{name}); code != 0 {
		return code
	}

	// 3. Session.
	if !gate("session", "decide whether to use stored credentials") {
		return 0
	}
	if *noSession {
		fmt.Println("session  skipped (--no-session)")
	} else if s, err := session.Load(workspace.Dir(name)); err == nil {
		fmt.Printf("session  stored (%d cookies, %d headers) — will be used for in-scope hosts only\n", len(s.Cookies), len(s.Headers))
	} else {
		fmt.Println("session  none — unauthenticated surface only")
	}

	p, err := workspace.Open(name)
	if err != nil {
		return fail(err)
	}

	// 4. Recon, skipped for programs with no host-level scope.
	if len(p.ExactHosts()) == 0 && len(p.DeriveDomains()) == 0 {
		fmt.Println("\n── recon ── skipped: no host-level scope; non-web targets go through analyze")
	} else {
		if !gate("recon", fmt.Sprintf("probe %d in-scope seed host(s)", len(p.ExactHosts()))) {
			return 0
		}
		rargs := []string{name, "--rps", strconv.Itoa(*rps)}
		if *noSession {
			rargs = append(rargs, "--no-session")
		}
		if code := cmdRecon(rargs); code != 0 {
			return code
		}
	}

	// 5. Non-web analysis.
	aargs := []string{name}
	if *cloneRepos {
		aargs = append(aargs, "--clone")
	}
	if !gate("analyze", "inspect in-scope repositories and contracts") {
		return 0
	}
	if code := cmdAnalyze(aargs); code != 0 {
		return code
	}

	// 6. Queue.
	if !gate("next", "build the ranked test queue") {
		return 0
	}
	if code := cmdNext([]string{name}); code != 0 {
		return code
	}

	// 7. Pack.
	if !gate("pack", "build the handoff ZIP") {
		return 0
	}
	if code := cmdPack([]string{name, "-o", *out}); code != 0 {
		return code
	}

	// 8. Audit.
	if !gate("audit", "verify the handoff is internally consistent") {
		return 0
	}
	code := cmdAudit([]string{name, "-dir", *out})
	if code == 0 {
		fmt.Printf("\ndone. ZIP: %s/<program>_*.zip -> workspace/%s/\n", *out, name)
		fmt.Println("note: no session was packed. The agent needs its own session.")
	}
	return code
}

func cmdAudit(args []string) int {
	pos, rest := split(args, map[string]bool{"dir": true})
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", "dist", "directory containing the handoff ZIP")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai audit <program|file.zip> [-dir dist]"))
	}

	target := pos[0]
	if !strings.HasSuffix(strings.ToLower(target), ".zip") {
		matches, _ := filepath.Glob(filepath.Join(*dir, target+"_*.zip"))
		if len(matches) == 0 {
			return fail(fmt.Errorf("no ZIP for %s in %s — run: kai pack %s", target, *dir, target))
		}
		sort.Strings(matches)
		target = matches[len(matches)-1]
	}

	res, err := audit.RunZip(target)
	if err != nil {
		return fail(err)
	}
	fmt.Print(res.Text())
	if res.Failed() > 0 {
		return 1
	}
	return 0
}

func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	noNet := fs.Bool("no-net", false, "skip the public network check")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return fail(errors.New("usage: kai doctor [--no-net]"))
	}
	report := doctor.Run(context.Background(), doctor.Options{Net: !*noNet})
	fmt.Print(report.Text())
	if report.Failures() > 0 {
		return 1
	}
	return 0
}

func cmdIntake(args []string) int {
	pos, rest := split(args, map[string]bool{"name": true, "max-links": true})
	fs := flag.NewFlagSet("intake", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	nameFlag := fs.String("name", "", "workspace slug (default: HackerOne handle)")
	dryRun := fs.Bool("dry-run", false, "print the scorecard without creating a workspace")
	force := fs.Bool("force", false, "overwrite an existing workspace's scope files")
	trustScope := fs.Bool("trust-scope", false, "promote hosts found in page text into scope.txt (verify first)")
	maxLinks := fs.Int("max-links", 8, "follow up to N relevant documentation links (0 = off)")
	noFollow := fs.Bool("no-follow", false, "do not follow reference links")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai intake <url|handle> [--name slug] [--dry-run] [--force] [--trust-scope]"))
	}

	platform, err := program.DetectPlatform(pos[0])
	if err != nil {
		return fail(err)
	}
	m, pat := resolveDriver(pos[0])
	parse, ok := program.ParserFor(m.Parser)
	if !ok {
		return fail(fmt.Errorf("driver %s names reader %q, which is not registered", m.ID, m.Parser))
	}
	client := netx.New(program.UserAgent(), 5, nil)
	defer client.Close()
	n := *maxLinks
	if *noFollow {
		n = 0
	}
	var in *program.Intake
	in, err = parse(context.Background(), client, pos[0], program.FetchOptions{Follow: n > 0, MaxLinks: n})
	if err != nil {
		// Name the driver and its reader: when a platform page is a JavaScript
		// shell the driver can be right about the claim and still have no reader
		// that can read it, and that gap must be visible in the failure.
		return fail(fmt.Errorf("driver %s (reader %s) could not read %s: %w", m.ID, m.Parser, pos[0], err))
	}
	in.TrustScope = *trustScope
	if *dryRun {
		fmt.Print(in.Markdown())
		return 0
	}

	slug := *nameFlag
	if slug == "" {
		slug = in.Handle
	}
	if err := workspace.ValidateName(slug); err != nil {
		return fail(err)
	}
	verdict := "vdp"
	if in.OffersBounty {
		verdict = "bounty"
	}
	p, err := workspace.Create(slug, workspace.Meta{
		Platform:     platform,
		ProgramURL:   in.URL,
		ScopeVerdict: verdict,
	})
	if errors.Is(err, workspace.ErrExists) {
		if !*force {
			return fail(fmt.Errorf("workspace %s exists — pass --force to replace its scope files", slug))
		}
		p, err = workspace.Open(slug)
	}
	if err != nil {
		return fail(err)
	}
	if err := program.Apply(p, in); err != nil {
		return fail(err)
	}
	_ = p.AppendAudit(fmt.Sprintf("intake from %s (%s, %s), %d assets, %d candidates",
		in.URL, platform, in.FetchedAt.Format(time.RFC3339), len(in.Assets), len(in.Candidates)))

	c := program.BuildContract(in, m)
	if err := program.SaveContract(p, c); err != nil {
		return fail(err)
	}
	_ = p.AppendAudit(fmt.Sprintf("contract from driver %s v%d (matched %q): %d in scope, %d out of scope, %d path-restricted",
		m.ID, m.Version, pat, len(c.Scope), len(c.Out), len(c.PathOnly)))

	fmt.Print(in.Markdown())
	if rd, err := program.LoadRulesDiff(p.Dir); err == nil && rd.Changed() {
		fmt.Println("\nwarning rules changed since the last intake — run: kai rules-diff " + slug)
	}
	fmt.Printf("\nworkspace  %s\n", p.Dir)
	fmt.Printf("driver     %s (matched %s)\n", m.ID, pat)
	fmt.Printf("contract   %s\n", p.StatePath("program.yaml"))
	sc := in.Scope()
	if len(sc.In) > 0 {
		fmt.Printf("next       kai recon %s   # %d seed host(s)\n", slug, len(sc.In))
	} else if len(in.Candidates) > 0 {
		fmt.Printf("next       verify %d candidate host(s) in policy.md, then rerun with --trust-scope\n", len(in.Candidates))
	} else {
		fmt.Printf("next       read %s/policy.md — this program has no host-based scope\n", p.Dir)
	}
	fmt.Printf("contract   kai contract %s --audit   # the contract vs scope.txt\n", slug)
	return 0
}

func cmdInit(args []string) int {
	pos, rest := split(args, map[string]bool{"platform": true, "url": true, "verdict": true, "domain": true})
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	platform := fs.String("platform", "", "h1 | bugcrowd | intigriti | direct")
	programURL := fs.String("url", "", "program URL")
	verdict := fs.String("verdict", "unknown", "bounty | vdp | none | unknown")
	domains := fs.String("domain", "", "comma-separated enumeration seeds (e.g. example.com)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai init <program> [--platform P] [--url U] [--verdict V] [--domain d]"))
	}
	p, err := workspace.Create(pos[0], workspace.Meta{
		Platform:     *platform,
		ProgramURL:   *programURL,
		ScopeVerdict: *verdict,
		Domains:      parseList(*domains),
	})
	if err != nil {
		return fail(err)
	}
	fmt.Printf("created  %s\n", p.Dir)
	fmt.Printf("next     edit %s/scope.txt and %s/out-of-scope.txt\n", p.Dir, p.Dir)
	fmt.Printf("         kai scope %s <host>   # gate must pass before any request\n", p.Name)
	return 0
}

func cmdBoundaries(args []string) int {
	if len(args) != 1 {
		return fail(errors.New("usage: kai boundaries <program>"))
	}
	p, err := workspace.Open(args[0])
	if err != nil {
		return fail(err)
	}
	b, err := os.ReadFile(filepath.Join(p.Dir, "boundaries.md"))
	if err != nil {
		return fail(fmt.Errorf("no boundaries yet — run: kai intake <url> --name %s", p.Name))
	}
	fmt.Print(string(b))
	return 0
}

func cmdAnalyze(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	clone := fs.Bool("clone", false, "git clone in-scope repositories into data/<program>/repos/")
	refresh := fs.Bool("refresh", false, "git pull already-cloned repositories")
	pos, rest := split(args, nil)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai analyze <program> [--clone] [--refresh]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	rep, err := nonweb.Analyze(context.Background(), p, nonweb.Options{
		Clone: *clone, Refresh: *refresh, Log: func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
	})
	if err != nil {
		return fail(err)
	}
	if err := nonweb.Save(p, rep); err != nil {
		return fail(err)
	}
	fmt.Print(rep.Markdown())
	if plan, err := buildSurface(p); err != nil {
		fmt.Fprintf(os.Stderr, "kai: queue refresh skipped (%v)\n", err)
	} else if len(plan.Items) > 0 {
		fmt.Printf("queue     %d hypotheses refreshed in next.md\n", len(plan.Items))
	}
	return 0
}

func cmdRulesDiff(args []string) int {
	if len(args) != 1 {
		return fail(errors.New("usage: kai rules-diff <program>"))
	}
	p, err := workspace.Open(args[0])
	if err != nil {
		return fail(err)
	}
	d, err := program.LoadRulesDiff(p.Dir)
	if err != nil {
		return fail(fmt.Errorf("no rule diff yet — run: kai intake <url> --name %s", p.Name))
	}
	fmt.Print(d.Markdown())
	return 0
}

func cmdScope(args []string) int {
	if len(args) != 2 {
		return fail(errors.New("usage: kai scope <program> <host|cidr>"))
	}
	p, err := workspace.Open(args[0])
	if err != nil {
		return fail(err)
	}
	gate, err := scope.LoadGate(p.Dir)
	if err != nil {
		return fail(err)
	}
	target, err := scope.Parse(args[1])
	if err != nil {
		return fail(err)
	}
	allowed, reason := gate.Check(target)
	result, code := "OUT", 1
	if allowed {
		result, code = "IN", 0
	}
	line := fmt.Sprintf("%-3s %-40s %s", result, target.Value, reason)
	fmt.Println(line)
	_ = p.AppendAudit(line)
	return code
}

func cmdRecon(args []string) int {
	pos, rest := split(args, map[string]bool{
		"domain": true, "rps": true, "max-hosts": true,
		"max-bundles": true, "user-agent": true,
	})
	fs := flag.NewFlagSet("recon", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	domainFlag := fs.String("domain", "", "comma-separated domains (default: derived from scope.txt)")
	rps := fs.Int("rps", 10, "global requests per second")
	maxHosts := fs.Int("max-hosts", 500, "probe at most N hosts")
	maxBundles := fs.Int("max-bundles", 100, "download at most N JavaScript bundles")
	nuclei := fs.Bool("nuclei", false, "run nuclei against live hosts (slow)")
	step := fs.Bool("step", false, "pause before each phase")
	noSession := fs.Bool("no-session", false, "ignore the stored session for this run")
	ua := fs.String("user-agent", "", "override User-Agent")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai recon <program> [--domain d] [--rps N] [--step]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	domains := parseList(*domainFlag)
	if len(domains) == 0 {
		domains = p.DeriveDomains()
	}
	if len(domains) == 0 && len(p.ExactHosts()) == 0 {
		return fail(errors.New("no domains: pass --domain example.com, or import scope with: kai intake <hackerone-url>"))
	}

	adapters := recon.Adapters()
	if len(adapters) > 0 {
		names := make([]string, 0, len(adapters))
		for n := range adapters {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Printf("adapters %s\n", strings.Join(names, ", "))
	} else {
		fmt.Println("adapters none — crt.sh and direct HTTP only")
	}

	// A front-end (the split-pane workspace) may be watching this run and able to
	// stop it. When none is attached the run is still recorded, so a watcher
	// (`kai serve`) can follow it and a later replay can read it.
	bus, fctx := frontEnd()
	front := bus != nil
	if bus == nil {
		bus = progress.NewBus(2048)
	}
	ctx := context.Background()
	if fctx != nil {
		ctx = fctx
	}
	sink := progress.NewWriter(bus)
	logw := io.Writer(io.MultiWriter(os.Stdout, sink))
	if rec, err := progress.NewRecorder(p.StatePath("progress.jsonl")); err == nil {
		stop := progress.Record(bus, rec)
		defer func() {
			sink.Flush()
			stop()
		}()
	} else {
		fmt.Fprintf(os.Stderr, "kai: progress log unavailable (%v)\n", err)
	}

	opts := recon.Options{
		Domains:    domains,
		SeedHosts:  p.ExactHosts(),
		RPS:        *rps,
		MaxHosts:   *maxHosts,
		MaxBundles: *maxBundles,
		Nuclei:     *nuclei,
		UserAgent:  *ua,
		Adapters:   adapters,
		Log:        logw,
	}
	sessUsed, sessCookies, sessHeaders := false, 0, 0
	if !*noSession {
		sess, err := session.Load(p.Dir)
		switch {
		case err == nil:
			cookies := session.CookieHeader(sess.Cookies)
			opts.Session = cookies
			opts.SessionHeaders = sess.Headers
			sessUsed, sessCookies, sessHeaders = true, len(sess.Cookies), len(sess.Headers)
			fmt.Printf("session  stored (%d cookies, %d headers)\n", sessCookies, sessHeaders)
		case errors.Is(err, session.ErrNone):
			fmt.Println("session  none — unauthenticated surface only")
		default:
			fmt.Fprintf(os.Stderr, "kai: session unreadable (%v), continuing unauthenticated\n", err)
		}
	} else {
		fmt.Println("session  skipped (--no-session)")
	}
	if front {
		// The workspace draws phases as they start; the kernel never waits on a
		// keyboard here, it just reports. Cancelling the context aborts the run.
		opts.Confirm = func(name, detail string) bool {
			sink.SetPhase(name)
			bus.Emit(progress.Event{Kind: progress.KindPhase, Phase: name, Text: detail})
			return ctx.Err() == nil
		}
	} else if *step {
		if !isTerminal(os.Stdin) {
			fmt.Fprintln(os.Stderr, "kai: --step ignored (stdin is not a terminal)")
		} else {
			opts.Confirm = promptConfirm
		}
	}

	// Record how recon was performed. Counts only — never cookie values.
	// The pack uses this to warn the receiving agent that the mapped surface
	// is authenticated even though the session itself is not shipped.
	_ = writeJSON(filepath.Join(p.Dir, "session-used.json"), map[string]any{
		"used": sessUsed, "cookies": sessCookies, "headers": sessHeaders,
		"at": time.Now().UTC().Format(time.RFC3339),
	})

	sum, err := recon.Run(ctx, p, opts)
	if sink != nil {
		sink.Flush()
	}
	if err != nil {
		return fail(err)
	}
	fmt.Println()
	fmt.Printf("done in %s\n", sum.Elapsed.Round(time.Second))
	fmt.Printf("  discovered %d  in-scope %d  resolved %d  live %d\n", sum.Discovered, sum.Gated, sum.Resolved, sum.Live)
	fmt.Printf("  urls %d  bundles %d  endpoints %d\n", sum.URLs, sum.Bundles, sum.Endpoints)
	if sum.Baseline {
		fmt.Printf("  diff: baseline snapshot (no previous run to compare)\n")
	} else {
		fmt.Printf("  diff: +%d hosts  +%d endpoints  %d js changed\n", sum.NewHosts, sum.NewEndpoints, sum.ChangedJS)
	}

	if plan, err := buildSurface(p); err != nil {
		fmt.Fprintf(os.Stderr, "kai: map/next failed (%v)\n", err)
	} else if len(plan.Items) > 0 {
		fmt.Printf("  queue: %d hypotheses, top %s (%s)\n", len(plan.Items), plan.Items[0].Target, plan.Items[0].Class)
	}
	fmt.Printf("next    kai next %s\n", p.Name)
	return 0
}

// buildSurface writes map.json/map.md and next.json/next.md from current state.
// A missing assets.json (no recon yet) is reported, not invented.
func buildSurface(p *workspace.Program) (*surface.Plan, error) {
	store, err := recon.LoadStore(p.Dir, p.Name)
	if err != nil {
		return nil, err
	}
	nonWeb, constraints := intakeSurface(p)
	if len(store.Endpoints) == 0 && len(store.Hosts) == 0 && len(nonWeb) == 0 {
		return nil, errors.New("no assets yet — run: kai recon " + p.Name + " (or kai intake <url>)")
	}
	now := time.Now().UTC()

	endpoints := map[string][]string{}
	for path, e := range store.Endpoints {
		endpoints[path] = e.Params
	}
	m := surface.BuildWithNonWeb(p.Name, endpoints, nonWeb, now)
	if err := os.WriteFile(filepath.Join(p.Dir, "map.md"), []byte(m.Markdown()), 0o600); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(p.Dir, "map.json"), m); err != nil {
		return nil, err
	}

	d, _ := recon.LoadDiff(p.Dir)
	plan := surface.BuildPlan(p.Name, m, endpoints, d, store.Hosts, now)
	surface.AddNonWeb(plan, nonWeb, constraints)
	surface.ApplyConstraints(plan, constraints)
	// Ranking feedback (T1.2): the recorded outcomes decide which of these
	// targets is still worth a slot. Deterministic — same log, same surface,
	// same plan, so a diff between runs means the surface or the history moved.
	tbl, err := outcome.Load(p.Dir)
	if err != nil {
		return nil, err
	}
	if dropped := surface.ApplyOutcomes(plan, tbl, outcome.SurfaceTS(p.Dir)); dropped > 0 {
		fmt.Fprintf(os.Stderr, "outcomes: %d target(s) already classified — dropped from the queue\n", dropped)
	}
	if err := os.WriteFile(filepath.Join(p.Dir, "next.md"), []byte(plan.Markdown()), 0o600); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(p.Dir, "next.json"), plan); err != nil {
		return nil, err
	}
	return plan, nil
}

// scopeHosts is the host allow-list used when importing a browser HAR.
func scopeHosts(p *workspace.Program) []string {
	hosts := append([]string{}, p.ExactHosts()...)
	hosts = append(hosts, p.DeriveDomains()...)
	return recon.Uniq(hosts)
}

// intakeSurface converts Phase 0 assets into surface hints. Out-of-scope
// assets are deliberately dropped: they must never reach a test queue.
func intakeSurface(p *workspace.Program) ([]surface.NonWebAsset, []string) {
	b, err := os.ReadFile(filepath.Join(p.Dir, "intake.json"))
	if err != nil {
		return nil, nil
	}
	var in program.Intake
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, nil
	}
	sc := in.Scope()
	var out []surface.NonWebAsset
	for _, a := range sc.NonWeb {
		out = append(out, surface.NonWebAsset{Identifier: a.Identifier, Type: a.Type, Detail: a.Instruction})
	}
	for _, a := range sc.PathOnly {
		out = append(out, surface.NonWebAsset{Identifier: a.Identifier, Type: a.Type, Detail: "path-restricted, no host rule"})
	}
	for _, c := range in.Candidates {
		// A bare GitHub organisation URL is not a repo; don't rank it above
		// the concrete repositories enumerated by analyze.
		orgURL := false
		if strings.HasPrefix(c.Identifier, "https://github.com/") || strings.HasPrefix(c.Identifier, "http://github.com/") {
			rest := strings.TrimPrefix(strings.TrimPrefix(c.Identifier, "https://"), "http://")
			rest = strings.TrimSuffix(rest, "/")
			parts := strings.Split(rest, "/")
			orgURL = len(parts) == 2
		}
		out = append(out, surface.NonWebAsset{Identifier: c.Identifier, Type: c.Type, Detail: "section: " + c.Section, Unverified: !in.TrustScope || orgURL})
	}
	// Repositories enumerated from an organisation URL live in nonweb.json,
	// not in intake.json. Fold the most recent ones into the queue too.
	if rep, err := nonweb.Load(p); err == nil {
		seen := map[string]bool{}
		for _, a := range out {
			seen[strings.TrimSuffix(a.Identifier, "/")] = true
		}
		added := 0
		for _, r := range rep.Repos {
			key := strings.TrimSuffix(r.URL, "/")
			if key == "" || seen[key] {
				continue
			}
			detail := r.Description
			if r.Origin != "" {
				detail = r.Origin + " — " + detail
			}
			out = append(out, surface.NonWebAsset{Identifier: key, Type: "SOURCE_CODE", Detail: detail})
			seen[key] = true
			added++
			if added >= 12 {
				break
			}
		}
	}
	enrichNonWeb(p, out)
	return out, in.Boundaries.Notes
}

// enrichNonWeb folds opt-in repository/contract findings into the queue.
func enrichNonWeb(p *workspace.Program, out []surface.NonWebAsset) {
	rep, err := nonweb.Load(p)
	if err != nil {
		return
	}
	repos := map[string]nonweb.Repo{}
	for _, r := range rep.Repos {
		repos[r.URL] = r
	}
	contracts := map[string]nonweb.Contract{}
	for _, c := range rep.Contracts {
		contracts[c.Address] = c
	}
	for i := range out {
		a := &out[i]
		if r, ok := repos[strings.TrimSuffix(a.Identifier, "/")]; ok {
			if len(r.Risks) > 0 {
				a.Detail += " | CI risks: " + strings.Join(r.Risks[:min(3, len(r.Risks))], "; ")
				a.Boost += nonweb.RiskScore(r.Risks)
				a.Hint = "Review the flagged CI workflow first (" + nonweb.TopRisk(r.Risks) + ")."
			} else if r.Status == "local" {
				a.Detail += " | repo scanned locally, no flagged CI pattern"
			}
			continue
		}
		if c, ok := contracts[a.Identifier]; ok {
			a.Detail += " | chain " + c.Chain
			if c.Explorer != "" {
				a.Detail += " (" + c.Explorer + ")"
			}
			a.Boost += 5
		}
	}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func cmdMap(args []string) int {
	if len(args) != 1 {
		return fail(errors.New("usage: kai map <program>"))
	}
	p, err := workspace.Open(args[0])
	if err != nil {
		return fail(err)
	}
	if _, err := buildSurface(p); err != nil {
		return fail(err)
	}
	b, err := os.ReadFile(filepath.Join(p.Dir, "map.md"))
	if err != nil {
		return fail(err)
	}
	fmt.Print(string(b))
	return 0
}

func cmdNext(args []string) int {
	if len(args) != 1 {
		return fail(errors.New("usage: kai next <program>"))
	}
	p, err := workspace.Open(args[0])
	if err != nil {
		return fail(err)
	}
	if _, err := buildSurface(p); err != nil {
		return fail(err)
	}
	b, err := os.ReadFile(filepath.Join(p.Dir, "next.md"))
	if err != nil {
		return fail(err)
	}
	fmt.Print(string(b))
	return 0
}

func cmdSession(args []string) int {
	pos, rest := split(args, map[string]bool{"har": true, "cookie": true, "header": true})
	fs := flag.NewFlagSet("session", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	harPath := fs.String("har", "", "HAR export from the browser or Burp")
	rawCookie := fs.String("cookie", "", "'a=1; b=2' cookie header")
	header := fs.String("header", "", "'Authorization: Bearer …' header, repeatable")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) == 0 {
		return fail(errors.New("usage: kai session <program> [show|set|clear] [--har f] [--cookie s]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	action := "show"
	if len(pos) > 1 {
		action = pos[1]
	}

	switch action {
	case "show":
		s, err := session.Load(p.Dir)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", p.Name, err))
		}
		fmt.Print(s.Redacted())
		return 0
	case "clear":
		if err := os.Remove(session.Path(p.Dir)); err != nil && !os.IsNotExist(err) {
			return fail(err)
		}
		fmt.Printf("cleared session for %s\n", p.Name)
		return 0
	case "set":
		var add *session.Store
		switch {
		case *harPath != "":
			b, err := os.ReadFile(*harPath)
			if err != nil {
				return fail(err)
			}
			add, err = session.ImportHARForHosts(b, scopeHosts(p))
			if err != nil {
				return fail(err)
			}
		case *rawCookie != "" || *header != "":
			add = &session.Store{
				Source:    "manual",
				CreatedAt: time.Now().UTC(),
				Cookies:   session.ParseCookieHeader(*rawCookie),
				Headers:   map[string]string{},
			}
			if *header != "" {
				name, value, ok := strings.Cut(*header, ":")
				if !ok || strings.TrimSpace(name) == "" {
					return fail(errors.New("--header must look like 'Authorization: Bearer …'"))
				}
				add.Headers[strings.TrimSpace(name)] = strings.TrimSpace(value)
			}
		default:
			return fail(errors.New("nothing to import: pass --har, --cookie or --header"))
		}
		existing, err := session.Load(p.Dir)
		if err != nil && !errors.Is(err, session.ErrNone) {
			return fail(err)
		}
		if existing == nil {
			existing = add
		} else {
			existing.Merge(add)
			existing.Source = add.Source
		}
		if err := session.Save(p.Dir, existing); err != nil {
			return fail(err)
		}
		fmt.Printf("stored session for %s\n", p.Name)
		fmt.Print(existing.Redacted())
		fmt.Println("\nrecon will use it automatically; pack will not include it unless --include-session")
		return 0
	default:
		return fail(fmt.Errorf("unknown session action %q (show|set|clear)", action))
	}
}

var stdinReader = bufio.NewReader(os.Stdin)

func promptConfirm(step, detail string) bool {
	fmt.Printf("\n── %s ── %s\n   Enter=lanjut, q=berhenti: ", step, detail)
	line, _ := stdinReader.ReadString('\n')
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans != "q" && ans != "quit"
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func cmdDiff(args []string) int {
	if len(args) != 1 {
		return fail(errors.New("usage: kai diff <program>"))
	}
	p, err := workspace.Open(args[0])
	if err != nil {
		return fail(err)
	}
	d, err := recon.LoadDiff(p.Dir)
	if err != nil {
		return fail(fmt.Errorf("no diff yet — run: kai recon %s", p.Name))
	}
	fmt.Print(d.Markdown())
	return 0
}

func parseList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		part = strings.TrimPrefix(part, "*.")
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func cmdPack(args []string) int {
	pos, rest := split(args, map[string]bool{"o": true})
	fs := flag.NewFlagSet("pack", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("o", "dist", "output directory")
	includeRaw := fs.Bool("include-raw", false, "include data/<program>/raw/")
	includeSession := fs.Bool("include-session", false, "include the stored session (secrets!)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: kai pack <program> [-o dist] [--include-raw] [--include-session]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	writeCompact(p)
	res, err := pack.Build(p, pack.Options{
		OutDir:         *out,
		IncludeRaw:     *includeRaw,
		IncludeSession: *includeSession,
	})
	if err != nil {
		return fail(err)
	}
	fmt.Printf("packed  %s\n", res.Path)
	fmt.Printf("        %d files, %d bytes\n", res.Files, res.Bytes)
	if *includeSession {
		fmt.Println("warning session included — the archive contains live credentials")
	}
	fmt.Printf("next    unzip into the agent workspace as workspace/%s/\n", p.Name)
	return 0
}

func cmdStatus(args []string) int {
	if len(args) == 1 {
		p, err := workspace.Open(args[0])
		if err != nil {
			return fail(err)
		}
		fmt.Printf("program   %s\n", p.Name)
		fmt.Printf("dir       %s\n", p.Dir)
		fmt.Printf("platform  %s\n", orDash(p.Meta.Platform))
		fmt.Printf("verdict   %s\n", p.Meta.ScopeVerdict)
		fmt.Printf("updated   %s\n", p.Meta.UpdatedAt.Format("2006-01-02 15:04 MST"))
		fmt.Println("artifacts")
		for _, name := range pack.Artifacts {
			fmt.Printf("  %-16s %d\n", name, p.CountLines(name))
		}
		return 0
	}
	if len(args) > 1 {
		return fail(errors.New("usage: kai status [<program>]"))
	}

	names, err := workspace.List()
	if err != nil {
		return fail(err)
	}
	if len(names) == 0 {
		fmt.Println("no programs yet — run: kai init <program>")
		return 0
	}
	fmt.Printf("%-20s %-10s %-10s %6s %6s %6s %6s\n", "PROGRAM", "PLATFORM", "VERDICT", "SUBS", "LIVE", "URLS", "ENDS")
	for _, name := range names {
		p, err := workspace.Open(name)
		if err != nil {
			fmt.Printf("%-20s %s\n", name, "unreadable meta.json")
			continue
		}
		fmt.Printf("%-20s %-10s %-10s %6d %6d %6d %6d\n",
			name,
			truncate(orDash(p.Meta.Platform), 10),
			truncate(p.Meta.ScopeVerdict, 10),
			p.CountLines("subs.txt"),
			p.CountLines("live.txt"),
			p.CountLines("urls.txt"),
			p.CountLines("endpoints.txt"),
		)
	}
	return 0
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
