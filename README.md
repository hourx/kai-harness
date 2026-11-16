# bountykit

Deterministic context packs for bug bounty work.

bountykit does the mechanical phases — program intake (Phase 0), recon, surface
mapping, test queue — and emits a ZIP that drops straight into a Kairos
workspace. The agent then hunts with real context instead of re-discovering the
surface from zero.

Design rationale: [`SPEC.md`](SPEC.md).

## Why

Automation alone produces duplicates, because it only ever finds the shallowest
layer, and every other hunter's automation scans that layer first. bountykit
adds the two things automation normally lacks:

- **State across runs** — `first_seen` / `last_seen` per asset, so the pack can
  say what is *new*. New surface is the only reliable anti-duplicate lever.
- **A distilled handoff** — one page (`BRIEF.md`), not a 100k-line skill dump.
  The agent reads the brief, not the universe.

## Build

```bash
go build -o bin/bountykit ./cmd/bountykit
go test ./...
```

Go 1.21+. No cgo, no third-party modules.

## Use

```bash
# 1. Phase 0 — read the public program page (HackerOne today)
bountykit intake 'https://hackerone.com/temu?type=team' --dry-run   # scorecard only
bountykit intake temu                              # create workspace + scope + policy
bountykit boundaries temu                          # aturan, batasan, out-of-scope (verbatim)
bountykit rules-diff temu                          # aturan/scope berubah sejak intake terakhir?

# 2. fill in / verify scope (intake writes what the platform publishes)
$EDITOR data/temu/scope.txt data/temu/out-of-scope.txt

# 3. gate every host before touching it
bountykit scope temu www.temu.com   # exit 0 = IN, 1 = OUT, 2 = error

# 4. discover the surface (exact hosts are probed directly, wildcards get CT/adapters)
bountykit recon acme
bountykit recon acme --step          # learn mode: pause before each phase

# 5. map it and rank what to test
bountykit map acme                   # modules, object refs, id params, GraphQL
bountykit next acme                  # evidence-weighted test queue
bountykit diff acme                  # what is new since the previous run

# 6. authenticated surface (optional)
bountykit session acme set --har ~/burp.har     # or --cookie 'sid=…'
bountykit session acme show                     # values are masked
bountykit recon acme                            # uses it automatically
bountykit session acme clear

# 7. build the handoff archive
bountykit pack acme -o dist
bountykit pack acme -o dist --include-session   # only if the agent needs auth

# 8. on the Kairos box
unzip dist/acme_*.zip -d workspace/
```

## Phase 0 intake

`bountykit intake <url-or-handle>` reads **public program pages only** — it does
not log in and does not touch target assets. Supported readers:

| Source | How it is read | Confidence |
| --- | --- | --- |
| `hackerone.com/<handle>` | public GraphQL: scope, rewards, policy, report metrics, paginated | `structured` |
| `*.gitbook.io/...` | the page's `.md` variant | `heuristic` |
| `cantina.xyz/bounties/<uuid>` | server-rendered page text | `heuristic` |
| `immunefi.com/bug-bounty/<slug>/information/` | page text (+ use `/scope/` for asset list) | `heuristic` |
| `bugbounty.meta.com/payout-guidelines/<slug>` | page text (400-with-body tolerated) | `heuristic` |
| `ethereum.org/bug-bounty/` and any other URL | page text | `heuristic` |

Outputs: reward table, severity distribution where published, report/payout
counters, testing constraints (no-mainnet, PoC, KYC, disclosure), a scorecard
(money / crowding / speed / surface), `scope.txt`, `out-of-scope.txt`,
`policy.md`, `program.md` and `intake.json`.

Heuristic sources return verdict **`review`**, never `go`. Hosts mentioned near
an in-scope heading are recorded as `candidate_assets` in `intake.json` but are
**not** written into `scope.txt` by default — a regex cannot tell an in-scope
host from an example. Verify them and rerun with `--trust-scope` if you want
them promoted:

```
bountykit intake cantina.xyz/bounties/... --name uniswap --dry-run
bountykit intake cantina.xyz/bounties/... --name uniswap --trust-scope
```

Scope is derived conservatively:

| Platform scope | Result |
| --- | --- |
| `URL` / bare host | exact host rule |
| `WILDCARD` | `*.domain` rule |
| `CIDR` | CIDR rule |
| URL with a path | **excluded** — a host-only gate would be broader than allowed |
| app ID / contract / source / hardware | listed in the scorecard, never guessed as a host |

Out-of-scope rules from the platform are written to `out-of-scope.txt`. Rules
that cannot be expressed as hosts stay in `policy.md`.

`boundaries.md` is the single authoritative "what may I touch" document:
enforceable IN/OUT host rules, path-restricted and non-web assets, mainnet /
test policy, PoC/KYC/deposit, required research headers, and **verbatim**
in-scope, out-of-scope, prohibited, eligibility, submission and disclosure
excerpts. `bountykit boundaries <program>` prints it; it is also in the ZIP and
summarised at the top of `BRIEF.md`. Anything not published is rendered as
"unknown / not stated", never as "allowed".

Every intake is snapshotted under `intakes/<ts>/`. `bountykit rules-diff <program>`
compares it with the previous one and flags new/removed scope rules, new or
removed assets and candidates, reward changes, program state changes and edits
to the policy text. A program that silently removes `api.example.com` from
scope produces "Removed scope rules" — yesterday's test target is not
automatically safe today. The diff is also summarised in `BRIEF.md`.

`map` and `next` now consume Phase 0 non-web assets too: source repositories,
contract addresses, API paths, app IDs and AI/model surfaces get their own
hypotheses with class-specific probes. Verbatim boundaries are carried into
those probes — a program that forbids mainnet testing says so in the first
probe. Out-of-scope assets are never queued.

## Scope semantics

Identical to `Kairos/scripts/scope_check.py`:

| Rule | Meaning |
| --- | --- |
| `api.example.com` | exact host |
| `*.example.com` | subdomains only — never the apex |
| `203.0.113.0/24` | CIDR containment |
| `out-of-scope.txt` | always wins |
| empty `scope.txt` | refuses to run (exit 2) |

Every decision is appended to `data/<program>/audit.log`.

## Layout

```
data/<program>/          state (gitignored)
  meta.json
  scope.txt  out-of-scope.txt  program.md  policy.md  boundaries.md
  intake.json            structured Phase 0 data + scorecard + boundaries
  audit.log
  intakes/<ts>/          intake + boundaries + policy snapshots
  rules-diff.json  rules-diff.md   rule changes vs previous intake
  session.json           cookies + headers, mode 0600, never packed by default
  assets.json            hosts, endpoints, JS hashes + first_seen/last_seen
  diff.json  diff.md     delta vs previous snapshot
  map.json  map.md       modules, object refs, id params
  next.json  next.md     ranked test queue with reasons
  state/                 current artifacts: subs, live, urls, js, endpoints, nuclei
  snapshots/             per-run history for diff

dist/<program>_<ts>.zip  handoff archive
  <program>/
    BRIEF.md             one page for the agent
    program.md  scope.txt  out-of-scope.txt  LEDGER.md
    recon/               what bugbounty-pipeline already reads
    bountykit/
      MANIFEST.json      files + sha256
      intake.json        Phase 0 data + boundaries
      rules-diff.md      rule changes
      diff.md            what is new
      map.md  map.json   surface map
      next.md  next.json ranked queue
      session.json       only with --include-session
```

`BOUNTYKIT_HOME` overrides the `./data` state root.

## Status

| Version | State |
| --- | --- |
| v0.1 | `init`, `scope`, `pack`, `status` — done |
| v0.2 | `recon`, `diff`, snapshots — done |
| v0.3 | `map`, `next`, session import — done |
| v0.4 | `intake` (Phase 0), exact-host recon — done |
| v0.5 | multi-source intake (H1, Cantina, Immunefi, GitBook, self-hosted) |
| v0.6 | `boundaries` — structured limits + verbatim out-of-scope |
| v0.7 | rule diff across intakes + non-web assets in `map`/`next` |
| v0.8 | `report`, full adapters |

## Rules

1. Empty scope refuses to run. No exceptions.
2. Out-of-scope always wins.
3. No credentials, cookies or tokens in a pack unless `--include-session` is passed, and the tool says so loudly when it is.
4. `data/` and `dist/` never enter git.
5. `intake` reads public pages only. Never log in, never touch a target asset.
6. Path-scoped platform assets are never widened into host rules.
7. A host found in prose stays a candidate until the operator verifies it and passes `--trust-scope`.
8. Missing rules are `unknown` / "not stated". Absence of a prohibition is never treated as permission.
