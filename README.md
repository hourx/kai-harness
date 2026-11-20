# kai

[![ci](https://github.com/hourx/kai-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/hourx/kai-harness/actions/workflows/ci.yml)

> Know the boundary. Prepare the context.

`kai` is a deterministic context harness for bug-bounty work, written in Go with
the standard library only. It runs the front of an engagement — read the program,
gate scope, reconnaissance, map endpoints, rank a test queue — and keeps its state
across runs. It never calls an LLM and never touches the network except through its
explicit `intake`, `recon` and `analyze` commands. Its output is a compact,
self-contained handoff (a small ZIP plus a one-page brief) that an agent can consume
without re-deriving the engagement from scratch. New in this release: it records a
per-target outcome ledger, so the ranked queue converges instead of re-proposing
targets that were already classified negative.

**Who it is not for.** `kai` is not a scanner. It does not exploit anything, does not
confirm vulnerabilities, and does not submit reports. It prepares the ground; the
hunting happens downstream. If you want an automated vuln scanner, this is the wrong
tool.

---

## Why use it

| Problem | How `kai` answers it |
|---|---|
| An agent keeps re-testing the same surface and produces duplicates | `first_seen` / `last_seen` snapshots plus `kai diff`: only what changed is prioritised |
| Program rules are spread across many pages | `boundaries.md`: in-scope, out-of-scope, prohibited actions and submission channel, quoted verbatim |
| Long policies get truncated by downstream tooling | `BRIEF.md`: one page, ordered Phase 0 -> Boundaries -> Scope -> Start here |
| Every run produces different results | Deterministic extraction with explicit confidence and run snapshots |
| The queue keeps proposing targets already ruled out | `state/outcomes.jsonl` + `kai next`: classified targets are dropped or demoted, never re-proposed blindly |

---

## Install

With Go installed:

```bash
go install github.com/hourx/kai-harness/cmd/kai@latest
kai version
```

From source:

```bash
git clone https://github.com/hourx/kai-harness.git
cd kai-harness
go build -o bin/kai ./cmd/kai
go test ./...
install -m 0755 bin/kai /usr/local/bin/kai
```

**State root.** `kai` stores everything under a state root: one directory per
program, plus the `dist/` output directory. The root defaults to `./data` relative to
the current working directory, which is easy to get wrong when you change folders.
Set `KAI_HOME` explicitly instead:

```bash
mkdir -p ~/.kai
echo 'export KAI_HOME="$HOME/.kai/data"' >> ~/.bashrc   # or ~/.zshrc
source ~/.bashrc
```

`BOUNTYKIT_HOME` is still accepted as a legacy alias for `KAI_HOME`.

Check the environment once after install:

```bash
kai doctor
```

This reports git, Go, any recon adapters present (`subfinder`, `gau`, `nuclei`, ...),
proxy configuration, the resolved state root, every known program with its session
state, and public connectivity.

---

## Quickstart

A full pass over one program, one command per phase:

```bash
kai init acme --platform h1 --url https://hackerone.com/acme --verdict bounty
# edit the scope files before doing anything else
$EDITOR "$KAI_HOME/acme/scope.txt" "$KAI_HOME/acme/out-of-scope.txt"

kai scope acme acme.example.com     # gate must print IN before any request
kai intake https://hackerone.com/acme --name acme   # Phase 0: read the program
kai boundaries acme                 # scope limits and rules, verbatim
kai recon acme --rps 10             # discover the surface
kai map acme                        # structure endpoints
kai next acme                       # ranked test queue

# after testing a target, record what it turned out to be
kai outcome acme --status negation "GET /api/v1/orders"
kai next acme                       # the queue now converges

kai pack acme                       # handoff ZIP: dist/acme_<ts>.zip
kai audit acme                      # consistency check before handing off
```

`kai run <url>` chains all of this in one command (intake -> boundaries -> session
check -> recon -> analyze -> next -> pack -> audit). Use `--step` to pause before each
phase, and note that `recon` is skipped automatically for programs with no host-level
scope (impact-based or on-chain programs go through `analyze`).

`kai intake --trust-scope` promotes hosts found in page text into `scope.txt`. Use it
only for text sources and only after you have verified each host in `policy.md`.

---

## Command reference

| Command | What it does |
|---|---|
| `run <url> [--name slug] [--step] [--clone] [--no-session] [--rps N] [--max-links N] [--no-follow] [-o dist] [--force]` | full guided workflow |
| `audit <program\|file.zip>` | check handoff consistency |
| `doctor [--no-net]` | check local environment |
| `init <program> [--platform P] [--url U] [--verdict V] [--domain d,d]` | create workspace |
| `intake <url\|handle> [--name slug] [--dry-run] [--force] [--trust-scope] [--max-links N] [--no-follow]` | Phase 0: read program |
| `boundaries <program>` | print scope limits & rules |
| `brief <program> [--out file]` | compact context card (~300 tokens) |
| `track <program> list\|submit\|status\|payout\|retest` | submission & triage ledger |
| `backup [--out file] [--include-session] [--include-repos]` | snapshot `data/` + `dist/` |
| `restore <file.tar.gz> [--dest dir]` | restore a snapshot |
| `analyze <program> [--clone] [--refresh]` | inspect in-scope repos/contracts |
| `rules-diff <program>` | what changed since last intake |
| `scope <program> <host\|cidr>` | scope gate (IN/OUT) |
| `recon <program> [--domain d] [--rps N] [--max-hosts N] [--max-bundles N] [--nuclei] [--no-session] [--step]` | discover surface |
| `session <program> [show\|set\|clear] [--har f] [--cookie s] [--header 'K: V']` | auth for recon |
| `map <program>` | structure endpoints |
| `next <program>` | ranked test queue |
| `outcome <program> --status S [--class C] [--note T] <target...>` | record what a target turned out to be |
| `plan <program> [--out file]` | turn the ranked queue into waves by precondition |
| `board [<program>]` | what is worth doing today, across every program |
| `evidence <program> [list\|add\|show\|attach]` | capture the raw proof behind a finding |
| `report-draft <program> <evidence-id> [--platform hackerone\|bugcrowd\|yandex]` | render a submission draft in the platform's fields |
| `diff <program>` | show last surface diff |
| `pack <program> [-o dist] [--include-raw] [--include-session]` | build handoff ZIP |
| `export <program> --to <dir>` | write agent context files into a campaign directory |
| `status [<program>]` | show state |
| `version` | print version |

Running `kai` with no arguments prints this list to stderr and exits `2`. An unknown
command does the same.

### Notes on individual commands

- `brief` prints a compact context card (~300 tokens) to stdout or to `--out file`.
  It is regenerated automatically during `pack`.
- `track` is a manual ledger: submit -> needs-info -> duplicate/informative ->
  resolved -> paid. It never contacts the platform. Rejection reasons accumulate
  into a lessons file and are summarised in `BRIEF.md`.
- `backup` copies `data/` and `dist/` into a single `.tar.gz`. By default it excludes
  `session.json` and any cloned repositories; keep the archive on a separate machine.
- `session set` imports cookies and headers from a HAR file, a `--cookie` string, or
  repeatable `--header 'K: V'` values. `analyze --clone` pulls in-scope repositories;
  `--refresh` pulls already-cloned ones.
- `export` writes the agent-facing context files (brief, validation gate, map, queue,
  boundaries, scope, diff, policy pages) into a target directory.

---

## The outcome loop

`kai outcome` records what happened to a target that `kai next` proposed:

```
kai outcome <program> --status negation|informational|finding|reported|paid \
            [--class C] [--note T] <target...>
```

Each call appends one JSON record per target to `state/outcomes.jsonl` (written mode
`0600`). The five statuses mean: `negation` (tested, not a bug), `informational`
(tested, no security impact), `finding` (proven bug, not yet submitted), `reported`
(submitted to the program), `paid` (rewarded).

The next `kai next` (or `map`, or `recon`) folds that ledger back into the ranking:

- A target classified **after** the last surface change is **dropped** from the queue:
  it was tested against the current surface, so re-proposing it would just duplicate
  work.
- A target classified **before** the last surface change is only **demoted**, with a
  note explaining why. A recon run that changes the surface can therefore never hide
  untested work — freshness is decided by comparing the outcome timestamp against the
  last surface change, and a record written in the same second still counts as fresh.
- A target classified `finding` is **lifted**, and its cluster siblings are lifted with
  it, so a promising area rises to the top.
- An unparseable or missing timestamp is treated as **stale**, so a corrupt log cannot
  silently suppress a target.

The loop is deterministic by design: the same inputs always produce the same queue.
There is no model, no randomness, and no hidden weight re-trained between runs.

---

## From queue to submission draft

Four commands close the loop between "the tool found something" and "a triager can
read it". None of them decides anything for you.

```
kai plan acme                       # queue -> waves: what needs no session, what needs a login
kai board                           # every program, ranked into today's list
kai evidence acme add --kind response --host api.example.com --method GET \
    --path /v1/orders/7 --status 200 --file raw.json --note "other tenant's order"
kai evidence acme list              # ids, hashes, blobs
kai report-draft acme 4f2a1c9b0e77 --platform hackerone --title "IDOR on /v1/orders/7"
```

- `plan` groups the queue by what each hypothesis needs (`none`, `session`,
  `two-sessions`) and keeps one step per class — several paths asking the same question
  collapse into the highest-scoring one, and the rest are listed under `merged_hypotheses`
  so nothing disappears. `plan.json` is plain data: disagree with a precondition and edit it.
- `board` reads state only, so the same disk produces the same board: findings waiting on
  your hand rank above hunting work, stale surfaces ask for a refresh, and every row's
  blockers are printed. `board.json` / `board.md` land in `KAI_HOME`.
- `evidence` stores the raw bytes with a SHA-256 and a permissions-restricted index, so a
  report drafted later can be tied to bytes that cannot silently change. Capturing identical
  bytes twice is a no-op.
- `report-draft` fills the platform's own fields (HackerOne, Bugcrowd, Yandex), prefills the
  target, class and evidence list, and leaves description/impact/steps blank on purpose. It
  runs the scope gate on the evidence's host and refuses to look confident when the gate says
  OUT: the draft carries a warning banner instead.

`kai` never sends a request while planning, never asserts scope on its own, and never submits.

## Scope gate and exit codes

`kai scope <program> <host|cidr>` is the single source of truth for whether a target
may be touched. Check it before every request.

| Exit code | Meaning |
|---|---|
| `0` | in scope |
| `1` | out of scope |
| `2` | usage error, or the scope list is empty |

An empty `scope.txt` is treated as "nothing is authorised", not as "everything is".

---

## Artifacts

Inside a program directory (`$KAI_HOME/<program>/`):

| Artifact | Contents |
|---|---|
| `boundaries.md` | scope limits, prohibited actions and submission channel, quoted verbatim |
| `scope.txt` | in-scope hosts and CIDRs |
| `out-of-scope.txt` | explicit exclusions (these always win) |
| `map.json` / `map.md` | structured endpoint map |
| `next.json` / `next.md` | ranked test queue with reasons and probes |
| `diff.json` / `diff.md` | surface delta since the previous recon run |
| `state/outcomes.jsonl` | appended outcome ledger, mode `0600` |

Produced outputs:

| Artifact | Contents |
|---|---|
| `BRIEF.md` | one-page ordered brief; the pack also carries a ~300-token `brief-compact.md` card |
| Pack ZIP | `dist/<program>_<ts>.zip` — the self-contained handoff archive |
| Export directory | files written by `kai export --to <dir>` for a downstream agent |

---

## Hard rules / design contract

1. **Deterministic.** Same inputs, same output. No LLM calls, no randomness.
2. **English-only files.** Every generated artifact is written in English.
3. **No target data committed.** `data/`, `dist/` and `*.zip` are gitignored. Nothing
   collected about a target belongs in the repository.
4. **Credentials never live in plain files.** A stored session (`session.json`, mode
   `0600`) is strictly opt-in and is only ever included inside a `0600` archive when
   you explicitly pass `--include-session`. By default the pack excludes it.
5. **`out-of-scope.txt` always wins.** An explicit exclusion beats any in-scope match.
6. **Path-scoped rules are not widened.** A rule like `example.com/api/*` is not
   promoted to a host-wide rule.
7. **Unpublished is `unknown`, not permission.** If a program does not say a thing is
   allowed, treat it as not allowed.
8. **Heuristic sources never authorise.** Hosts guessed from prose stay candidates
   until verified and imported with `--trust-scope`.
9. **Intake reads public pages only.** It does not log in and does not attack the
   target; credentials are only ever sent to in-scope hosts.
10. **No network except explicit commands.** Only `intake`, `recon` and `analyze`
    reach the network. Everything else is local.

---

## Background: how to read a bug-bounty program

The knowledge below is what makes `kai`'s output useful. It is general field guidance
for anyone starting an engagement.

### Bounded scope

A program's scope is a whitelist, not a suggestion. Two rules decide almost every
dispute:

- **Wildcards do not cover the apex.** `*.example.com` does not include `example.com`.
  Read the scope entry literally.
- **Path-scoped entries are traps.** `example.com/api/*` authorises testing under
  `/api/`, not the whole host. Widening it yourself is testing outside the grant.

Scope can also be **impact-based rather than host-based**: some programs (commonly
on-chain ones) publish no host list at all and instead describe which impacts they
pay for. That is not a missing scope file — it is a different kind of boundary. `kai`
refuses to run host reconnaissance in that case and routes you to `analyze` instead,
which is the correct behaviour rather than a bug.

### Prohibited actions, quoted verbatim

The most important lines in any policy are the ones telling you what **not** to do:
no denial-of-service, no automated scanning at volume, no testing of third parties or
employees, no touching production data beyond proof, no social engineering. These are
usually buried as bullets with no heading, so `kai` extracts them by keyword and
records them **verbatim** — never paraphrased — so the exact wording survives into the
handoff. Treat a verbatim prohibition as an absolute rule.

### Mainnet and on-chain boundaries

For on-chain programs, "in scope" often means a deployed contract address on a
specific network, with a hard boundary between testnet and mainnet. Never assume a
mainnet contract is in scope just because a testnet copy is; never assume you may
deploy exploits or move real funds; and remember that an impact-based policy may
include or exclude specific asset types (bridges, oracles, governance) explicitly.
Read the address and network lists literally, exactly as you would read a host list.

### Submission channel vs contact email

An email address in a policy is usually a contact, not the submission channel. On a
hosted platform, reports still go through the platform's own form. `kai` records the
submission channel and any contact address separately so they are never confused.

### Reconnaissance and surface

- On a busy program, **the diff matters more than the endpoint count**. Re-walking old
  paths on a program with thousands of prior reports is almost always a duplicate;
  what changed since the last run is where the fresh surface is.
- **A session is often the difference between a thin and a full map.** Areas behind a
  login cannot be mapped from the outside; with stored credentials the reachable
  surface can grow by orders of magnitude.
- **JavaScript bundles often live on out-of-scope CDNs.** Fetching such a public
  bundle is fine, but credentials must only be sent to in-scope hosts, and those CDN
  hosts must not enter the in-scope URL list.
- **Regex over JavaScript produces false paths** (`/412`, `${e}`, `:app_id`).
  Placeholders are normalised and bare numbers discarded.
- **Scores that are all equal carry no information.** A queue of identically-scored
  endpoints does not tell you where to start; weighting is applied toward
  credential-, recovery-, export-, balance- and transfer-like paths.

### Sessions and access

- A HAR export can be **sanitized**: hundreds of requests but zero cookies means the
  export excluded sensitive data, not that the tool failed. Re-export with sensitive
  data included.
- Some anti-bot cookies (for example Cloudflare's clearance cookie) are **bound to the
  originating IP**. A cookie captured from a laptop may not work from a server; a
  persistent challenge page in that case is the anti-bot layer, not a broken session.
- HAR files contain **third-party cookies**. Only cookies for in-scope hosts should be
  imported; analytics and CDN entries are dropped.
- **Never store a session in a repository or in a shared archive.** Rotate credentials
  once you are done.

---

## Troubleshooting

| Symptom | Meaning / action |
|---|---|
| `no domains` | scope is empty; fill it in, or re-run `intake` |
| `crt.sh(status 502)` | public CT service is down; a parallel source still runs |
| verdict `review` | heuristic source; verify before `--trust-scope` |
| `bundles 0` | no scripts in the HTML, or all bundles are out of scope |
| `session none` | the HAR had no cookies, or the path is wrong |
| anti-bot challenge (`403`) | session is bound to another IP; capture it from the same host |
| `audit FAIL` | do not hand off; read the failing lines |
| `unknown program` | wrong state root; check `KAI_HOME` and your current directory |
| machine replaced | `kai restore backup.tar.gz`, then re-import the session |

---

## Two faces

The CLI is the reference implementation. Two other faces read the same workspace
and never change what a run does.

`kai` on a terminal (or `kai tui <program>`) opens the workspace itself: steps on the
left, the process output, the ranked queue, and a command line at the bottom. `/help`,
`/enum`, `/map`, `/next`, `/plan`, `/board`, `/status`, `/evidence`, `/scope` go
through the same dispatcher as the headless commands, so the panes cannot show
something the CLI would not print. `ctrl-c` aborts the running command, it does not
kill the workspace. `kai tui --demo` draws the layout without needing a terminal.

`kai serve` publishes the same state over HTTP for a phone or any other UI:

| Endpoint | Returns |
|---|---|
| `GET /` | single-file dashboard — no build step, no external assets |
| `GET /healthz` | liveness; the only route that needs no token |
| `GET /api/v1/board` | cross-program board, including `do today` |
| `GET /api/v1/programs` | every program with surface counts and scope verdict |
| `GET /api/v1/programs/<n>` | queue, plan, findings, outcomes, evidence, scope samples |
| `GET /api/v1/programs/<n>/queue?limit=N` | ranked queue (`limit` is clamped) |
| `GET /api/v1/programs/<n>/scope?host=X` | the gate's verdict for one host, and why |
| `GET /api/v1/programs/<n>/{brief,outcomes,evidence}` | brief, outcome ledger, evidence index |

It is read-only by construction: no endpoint runs a command or writes a file, so a
published port cannot become a remote scan surface. Mutations stay in the CLI, where a
scope gate and a printed artifact are attached to them. The default bind is loopback;
anything else requires a token (`--token auto` generates one, or set `KAI_SERVE_TOKEN`)
and the check happens before the listener opens, so a misconfiguration fails loudly
instead of quietly serving a campaign to the network. `--addr 127.0.0.1:0` asks the
kernel for a free port.

---

## FAQ

**Is there an `npx` package?** No. `npx` runs npm/Node.js packages, and `kai` is a Go
binary. Making `npx kai` work would only require a thin wrapper package that downloads
the release binary; it would not turn `kai` into a library. For now, use
`go install github.com/hourx/kai-harness/cmd/kai@latest`.

**Does it need an API key or a model?** No. `kai` is stdlib-only Go with no LLM calls.

---

## Status

Current line: `kai 0.12.0`.

| Version | Contents |
|---|---|
| v0.1–v0.3 | scope gate, pack, recon, diff, session, map, next |
| v0.4–v0.6 | multi-source intake, verbatim boundaries |
| v0.7–v0.8 | rule diff, non-web assets, repo/contract analysis |
| v0.9 | `kai` identity, `run` / `audit` / `doctor` |
| v0.10 | backup/restore, compact brief, triage ledger |
| v0.11 | per-target outcome ledger and a convergent `next` queue |
| v0.12 | engagement plan (`plan`), cross-program board (`board`), evidence capture, submission drafts, engine packages under `pkg/` |
| v0.13 (unreleased) | split-pane terminal workspace, read-only `kai serve` service face |

`kai` is a context preparer and an evidence bookkeeper, not a hunting agent. The full design
lives in [`SPEC.md`](SPEC.md); the improvement roadmap in [`IMPROVEMENT-PLAN.md`](IMPROVEMENT-PLAN.md).

### Using the engine from Go

The deterministic core lives under `pkg/` and is importable:

| Package | Purpose |
|---|---|
| `pkg/scope` | rule parsing and the scope gate |
| `pkg/program` | intake, boundaries, validation |
| `pkg/recon` | surface store (hosts, endpoints, bundles) |
| `pkg/surface` | structure, ranking, outcomes |
| `pkg/hypothesis` | queue → engagement plan |
| `pkg/evidence` | hashed evidence capture |
| `pkg/report` | platform field sets |
| `pkg/outcome`, `pkg/triage`, `pkg/workspace` | ledgers and state |
| `pkg/serve` | read-only HTTP/JSON face over the workspace |
| `pkg/progress` | run events the terminal workspace renders |

`internal/` keeps the CLI wiring and operator conveniences. Anything under `pkg/` is
covered by tests and safe to depend on; the AGPL applies to both.

## License

AGPL-3.0. The core is free to use, modify and self-host; anyone who offers it as
a network service must publish their changes. See [`LICENSE`](LICENSE).
