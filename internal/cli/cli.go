package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hourx/bountykit/internal/netx"
	"github.com/hourx/bountykit/internal/pack"
	"github.com/hourx/bountykit/internal/program"
	"github.com/hourx/bountykit/internal/recon"
	"github.com/hourx/bountykit/internal/scope"
	"github.com/hourx/bountykit/internal/session"
	"github.com/hourx/bountykit/internal/surface"
	"github.com/hourx/bountykit/internal/version"
	"github.com/hourx/bountykit/internal/workspace"
)

const usageText = `bountykit — deterministic context packs for bug bounty

Usage:
  bountykit <command> [arguments]

Commands:
  init    <program> [--platform P] [--url U] [--verdict V] [--domain d,d]
                                                             create workspace
  intake  <url|handle> [--name slug] [--dry-run] [--force] [--trust-scope]
                                                             Phase 0: read program
  scope   <program> <host|cidr>                              scope gate (IN/OUT)
  recon   <program> [--domain d] [--rps N] [--max-hosts N]
                    [--max-bundles N] [--nuclei] [--no-session] [--step]
                                                             discover surface
  session <program> [show|set|clear] [--har f] [--cookie s] [--header 'K: V']
                                                             auth for recon
  map     <program>                                          structure endpoints
  next    <program>                                          ranked test queue
  diff    <program>                                          show last surface diff
  pack    <program> [-o dist] [--include-raw] [--include-session]
                                                             build handoff ZIP
  status  [<program>]                                        show state
  version                                                    print version

Exit codes for scope:
  0  in scope      1  out of scope      2  usage or empty scope

Environment:
  BOUNTYKIT_HOME   state root (default: ./data)
`

// Run dispatches a command and returns the process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}
	switch args[0] {
	case "version", "-v", "--version":
		fmt.Println("bountykit " + version.String())
		return 0
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return 0
	case "init":
		return cmdInit(args[1:])
	case "intake":
		return cmdIntake(args[1:])
	case "scope":
		return cmdScope(args[1:])
	case "recon":
		return cmdRecon(args[1:])
	case "session":
		return cmdSession(args[1:])
	case "map":
		return cmdMap(args[1:])
	case "next":
		return cmdNext(args[1:])
	case "diff":
		return cmdDiff(args[1:])
	case "pack":
		return cmdPack(args[1:])
	case "status":
		return cmdStatus(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "bountykit: unknown command %q\n\n", args[0])
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "bountykit:", err)
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

func cmdIntake(args []string) int {
	pos, rest := split(args, map[string]bool{"name": true})
	fs := flag.NewFlagSet("intake", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	nameFlag := fs.String("name", "", "workspace slug (default: HackerOne handle)")
	dryRun := fs.Bool("dry-run", false, "print the scorecard without creating a workspace")
	force := fs.Bool("force", false, "overwrite an existing workspace's scope files")
	trustScope := fs.Bool("trust-scope", false, "promote hosts found in page text into scope.txt (verify first)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) != 1 {
		return fail(errors.New("usage: bountykit intake <url|handle> [--name slug] [--dry-run] [--force] [--trust-scope]"))
	}

	platform, err := program.DetectPlatform(pos[0])
	if err != nil {
		return fail(err)
	}
	client := netx.New(program.UserAgent(), 5, nil)
	defer client.Close()
	var in *program.Intake
	if platform == "h1" {
		handle, _, err := program.HackerOneHandle(pos[0])
		if err != nil {
			return fail(err)
		}
		in, err = program.FetchHackerOne(context.Background(), client, handle)
	} else {
		in, err = program.FetchWeb(context.Background(), client, pos[0])
	}
	if err != nil {
		return fail(err)
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

	fmt.Print(in.Markdown())
	fmt.Printf("\nworkspace  %s\n", p.Dir)
	sc := in.Scope()
	if len(sc.In) > 0 {
		fmt.Printf("next       bountykit recon %s   # %d seed host(s)\n", slug, len(sc.In))
	} else if len(in.Candidates) > 0 {
		fmt.Printf("next       verify %d candidate host(s) in policy.md, then rerun with --trust-scope\n", len(in.Candidates))
	} else {
		fmt.Printf("next       read %s/policy.md — this program has no host-based scope\n", p.Dir)
	}
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
		return fail(errors.New("usage: bountykit init <program> [--platform P] [--url U] [--verdict V] [--domain d]"))
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
	fmt.Printf("         bountykit scope %s <host>   # gate must pass before any request\n", p.Name)
	return 0
}

func cmdScope(args []string) int {
	if len(args) != 2 {
		return fail(errors.New("usage: bountykit scope <program> <host|cidr>"))
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
		return fail(errors.New("usage: bountykit recon <program> [--domain d] [--rps N] [--step]"))
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
		return fail(errors.New("no domains: pass --domain example.com, or import scope with: bountykit intake <hackerone-url>"))
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

	opts := recon.Options{
		Domains:    domains,
		SeedHosts:  p.ExactHosts(),
		RPS:        *rps,
		MaxHosts:   *maxHosts,
		MaxBundles: *maxBundles,
		Nuclei:     *nuclei,
		UserAgent:  *ua,
		Adapters:   adapters,
		Log:        os.Stdout,
	}
	if !*noSession {
		sess, err := session.Load(p.Dir)
		switch {
		case err == nil:
			cookies := session.CookieHeader(sess.Cookies)
			opts.Session = cookies
			opts.SessionHeaders = sess.Headers
			fmt.Printf("session  stored (%d cookies, %d headers)\n", len(sess.Cookies), len(sess.Headers))
		case errors.Is(err, session.ErrNone):
			fmt.Println("session  none — unauthenticated surface only")
		default:
			fmt.Fprintf(os.Stderr, "bountykit: session unreadable (%v), continuing unauthenticated\n", err)
		}
	} else {
		fmt.Println("session  skipped (--no-session)")
	}
	if *step {
		if !isTerminal(os.Stdin) {
			fmt.Fprintln(os.Stderr, "bountykit: --step ignored (stdin is not a terminal)")
		} else {
			opts.Confirm = promptConfirm
		}
	}

	sum, err := recon.Run(context.Background(), p, opts)
	if err != nil {
		return fail(err)
	}
	fmt.Println()
	fmt.Printf("done in %s\n", sum.Elapsed.Round(time.Second))
	fmt.Printf("  discovered %d  in-scope %d  resolved %d  live %d\n", sum.Discovered, sum.Gated, sum.Resolved, sum.Live)
	fmt.Printf("  urls %d  bundles %d  endpoints %d\n", sum.URLs, sum.Bundles, sum.Endpoints)
	fmt.Printf("  diff: +%d hosts  +%d endpoints  %d js changed\n", sum.NewHosts, sum.NewEndpoints, sum.ChangedJS)

	if plan, err := buildSurface(p); err != nil {
		fmt.Fprintf(os.Stderr, "bountykit: map/next failed (%v)\n", err)
	} else if len(plan.Items) > 0 {
		fmt.Printf("  queue: %d hypotheses, top %s (%s)\n", len(plan.Items), plan.Items[0].Target, plan.Items[0].Class)
	}
	fmt.Printf("next    bountykit next %s\n", p.Name)
	return 0
}

// buildSurface writes map.json/map.md and next.json/next.md from current state.
// A missing assets.json (no recon yet) is reported, not invented.
func buildSurface(p *workspace.Program) (*surface.Plan, error) {
	store, err := recon.LoadStore(p.Dir, p.Name)
	if err != nil {
		return nil, err
	}
	if len(store.Endpoints) == 0 && len(store.Hosts) == 0 {
		return nil, errors.New("no assets yet — run: bountykit recon " + p.Name)
	}
	now := time.Now().UTC()

	endpoints := map[string][]string{}
	for path, e := range store.Endpoints {
		endpoints[path] = e.Params
	}
	m := surface.Build(p.Name, endpoints, now)
	if err := os.WriteFile(filepath.Join(p.Dir, "map.md"), []byte(m.Markdown()), 0o600); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(p.Dir, "map.json"), m); err != nil {
		return nil, err
	}

	d, _ := recon.LoadDiff(p.Dir)
	plan := surface.BuildPlan(p.Name, m, endpoints, d, store.Hosts, now)
	if err := os.WriteFile(filepath.Join(p.Dir, "next.md"), []byte(plan.Markdown()), 0o600); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(p.Dir, "next.json"), plan); err != nil {
		return nil, err
	}
	return plan, nil
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
		return fail(errors.New("usage: bountykit map <program>"))
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
		return fail(errors.New("usage: bountykit next <program>"))
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
		return fail(errors.New("usage: bountykit session <program> [show|set|clear] [--har f] [--cookie s]"))
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
			add, err = session.ImportHAR(b)
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
		return fail(errors.New("usage: bountykit diff <program>"))
	}
	p, err := workspace.Open(args[0])
	if err != nil {
		return fail(err)
	}
	d, err := recon.LoadDiff(p.Dir)
	if err != nil {
		return fail(fmt.Errorf("no diff yet — run: bountykit recon %s", p.Name))
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
		return fail(errors.New("usage: bountykit pack <program> [-o dist] [--include-raw] [--include-session]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
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
	fmt.Printf("next    unzip into the Kairos box as workspace/%s/\n", p.Name)
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
		return fail(errors.New("usage: bountykit status [<program>]"))
	}

	names, err := workspace.List()
	if err != nil {
		return fail(err)
	}
	if len(names) == 0 {
		fmt.Println("no programs yet — run: bountykit init <program>")
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
