# kai — SPEC v0.8

Deterministic context-pack builder for bug bounty.
Phases the tool works on: **Program Selection (assist) → Pre-Hunt (collect) → Recon → Mapping**.
The rest (hunting, validation, report) is handed to the downstream agent.

---

## 1. Problem

Evidence from the two existing repos:

| Fact | Consequence |
|---|---|
| The skill pack = 276 SKILL.md, 104,442 lines, with no orchestrator / pool-picker / re-verify scripts | The pack is a **library**, not a pipeline. The agent infers the order itself → every run differs → cannot be improved |
| Targets drawn from a pool of 35,550 domains, breadth-first | Only finds the shallowest layer = the layer everyone has already scanned → **structurally duplicate** |
| Downstream campaigns: 411 attempts / 0 findings, 29 / 0 | Lots of effort, zero results: not a lack of tools, but a lack of per-target context |
| There is no cross-run state for raw assets | The agent does not know what is **new** → it repeats surface that is already stale |

**Conclusion:** what is missing is not a new recon tool. What is missing is a **deterministic, small context artifact that carries a diff**.

---

## 2. Scope

### Done in v0.1
- `init` — program intake: scope, out-of-scope, policy, verdict
- `scope` — IN/OUT gate identical to the downstream agent's `scripts/scope_check.py`
- `pack` — build a ZIP ready to be absorbed into `workspace/<program>/`
- `status` — summary of all programs

### Done in v0.2
- `recon` — subdomains, DNS, HTTP probe, TLS/SAN, URL harvest, JS harvest
- `diff` — compare the current snapshot against the previous one (`first_seen` / `last_seen`)

### Done in v0.3
- `session` — import cookie/header from HAR or manually, used by recon, **not** included in the pack unless `--include-session`
- `map` — modules, object references, ID parameters, GraphQL, loose parameters from JS
- `next` — test queue ordered per vuln class, with evidence and a first probe
- `outcome` — record what a target turned out to be into `state/outcomes.jsonl`; `next` reads it back and re-ranks (see 4.5)

### Done in v0.4
- `intake` — Phase 0: read the HackerOne program page over the public GraphQL, score go/careful/skip, scope + policy
- `recon` accepts exact hosts from `scope.txt` (a program without wildcards can still be recon'd)

### Done in v0.5
- multi-source `intake`: H1 (GraphQL), Cantina, Immunefi, GitBook, meta, standalone pages
- `structured` vs `heuristic` confidence; a `review` verdict for heuristic results

### Done in v0.6
- `boundaries` — a single document with the rules, constraints and verbatim in/out-of-scope quotes

### Done in v0.8
- `analyze` — in-scope repos (optionally cloned) + contracts; CI workflows, manifests, entry points
- analysis results feed `map`/`next` with probes that respect the constraints

### Done in v0.9
- `report` — markdown/HTML report per program

### Out of scope (forever)
- Automated hunting (that is the downstream agent's job, together with its hunting skills)
- Automatic report submission to the platform
- Storing target credentials in the repo

---

## 3. Integration contract with the downstream agent

The tool must produce output that the downstream pipeline can use **directly**, with no translation.

### 3.1 Scope semantics (must be identical)

Copied from the downstream agent's `scripts/scope_check.py`:

| Input | Rule |
|---|---|
| `api.example.com` | exact match |
| `*.example.com` | matches `a.example.com` and `a.b.example.com`, does **not** match `example.com` |
| `203.0.113.0/24` | CIDR containment |
| `out-of-scope.txt` | **always wins** over `scope.txt` |
| `scope.txt` empty / missing | **refuse** (exit 2) |

Exit code: `0` = IN, `1` = OUT, `2` = misuse.

Every decision is written append-only to `audit.log`.

### 3.2 Workspace layout expected by the downstream agent

```
workspace/<program>/
├── program.md
├── scope.txt
├── out-of-scope.txt
├── boundaries.md
├── passive/
├── recon/
├── evidence/
└── findings/
```

Artifact filenames read by the downstream pipeline:

```
recon/subs.txt      recon/live.txt      recon/urls.txt
recon/js.ts         recon/endpoints.txt recon/nuclei.txt
recon/ranked.txt    recon/smuggling.txt
LEDGER.md
```

Note: the pipeline calls the folder `targets-<name>/`; kai uses `recon/` (the bug-bounty runbook's convention) and **maps the name in `BRIEF.md`**.

### 3.3 VPS toolchain (from the bug-bounty runbook)

If present, used as an adapter. If not, an internal fallback.

```
subfinder assetfinder dnsx httpx naabu katana gau waybackurls
ffuf nuclei dalfox anew notify interactsh-client
SecLists: /opt/wordlists/SecLists
```

### 3.4 Phase 0 contract (intake)

Source: `POST https://hackerone.com/graphql` ( public, no login ). One query for
metadata + policy + reward, one scope query paginated by 100.

| Platform data | Used for |
|---|---|
| `handle`, `name`, `state`, `submission_state`, `offers_bounties` | identity + verdict |
| `top/average_bounty_*`, `bounty_table_rows` | money component |
| `reports_received_last_90_days`, `resolved_report_count`, `profile_metrics_snapshot` | crowding component + "where reports land" |
| `response_efficiency_percentage` | speed component |
| `structured_scopes` (asset_type, eligibility, max_severity, instruction) | scope.txt + scope + surface component |
| `policy` | policy.md — rules that cannot be represented as a host |

The scope mapping is deliberately conservative: `URL` → host, `WILDCARD` → `*.`,
`CIDR` → CIDR. **A URL with a path is not turned into a host rule** because the
gate only understands hosts; widening `example.com/api/*` to `example.com` would
allow testing outside the program's permission. Non-web assets (app ID, contract,
source, hardware) are recorded in intake.json and the scorecard, not guessed as a host.

Non-H1 sources are read from page text (GitBook uses the `.md` variant). Because a
regex cannot tell an example from a rule, the result is labelled
`confidence: heuristic` and its verdict is always `review`. Hosts found
near an "in scope" heading go into `candidate_assets`, **not** directly into
`scope.txt`. The operator verifies them and then uses `--trust-scope` to
promote them; this is recorded in a comment in `scope.txt`.

Non-H1 sources also follow relevant document links from the main page (testnet,
reward, submission, security, faucet) on the same domain, at most 8 pages.
The combined text is used for all extraction. Hosts found on reference pages
stay candidates until verified by the operator.

Data extracted from the text: reward per severity (including `<1M USDC`),
"Maximum Bounty/Max payout", number of findings/paid reports, testing constraints
(no-mainnet, PoC, KYC, disclosure), and the assets mentioned in the scope section.
If the number of reports is not published, the crowding component is scored
"unknown" (17/35), not "zero competition".

---

## 4. Architecture

### 4.1 Two modes

| Mode | Behaviour |
|---|---|
| `--auto` | runs straight through `init → recon → map → pack`, no prompt. For VPS/cron |
| `--step` | stops at each stage, shows findings + reasoning + the next command, waits for Enter. Learning mode |

### 4.2 Self-contained + adapters

The core is written with the **Go standard library only** (no cgo, no external dependencies):

- scope parsing, HTTP client, TLS handshake, DNS, JS parsing via regex, ZIP writing, JSONL state

Optional adapters: if an external binary is on `PATH`, it is used for richer results:

```
subfinder → subs.txt        httpx → live.txt        katana → urls.txt
gau       → urls.txt (historical)   nuclei → nuclei.txt
```

If none are present, the tool still runs on internal sources (crt.sh, HTTP GET, a simple crawl).

### 4.3 Repo structure

```
kai/
├── cmd/kai/main.go
├── internal/
│   ├── cli/          per-command dispatch
│   ├── scope/        parse + match + gate
│   ├── workspace/    program layout, meta, audit log
│   ├── pack/         zip builder + BRIEF + MANIFEST
│   └── version/
├── SPEC.md
└── data/             (gitignored) per-program state
```

State lives in `data/<program>/`, separate from the downstream agent's repo. `pack` is the bridge.

### 4.4 Data model per program

```
data/<program>/
├── meta.json         name, platform, url, domains, verdict, timestamps
├── program.md
├── scope.txt
├── out-of-scope.txt
├── audit.log
├── intake.json       Phase 0 data + scorecard + boundaries (structured)
├── boundaries.md     rules + constraints + verbatim in/out-of-scope quotes
├── nonweb.json       analyze results (repos + contracts)
├── nonweb.md         non-web analysis summary
├── rules-diff.json   rule delta vs the previous intake
├── rules-diff.md     delta read by the agent
├── intakes/<ts>/     intake + boundaries + policy snapshot
├── policy.md         program policy (out-of-scope classes, required headers)
├── session.json      cookie + header (0600, not packed unless requested)
├── assets.json       hosts, endpoints, JS hashes (with first_seen/last_seen)
├── repos/            cloned repos (only via analyze --clone)
├── diff.json         delta vs the previous snapshot
├── diff.md           delta in the form the agent reads
├── map.json  map.md  modules, object references, ID parameters, GraphQL
├── next.json next.md test queue + reasons + first probe
├── state/
│   ├── subs.txt      live.txt  live_urls.txt  urls.txt
│   ├── js.ts         endpoints.txt  ranked.txt  nuclei.txt
│   └── (current condition, ready to pack)
└── snapshots/
    └── <ts>/assets.json
```

### 4.5 Queue score (`next`)

`next` does not send requests. It only weighs evidence that already exists:

| Signal | Weight | Reason |
|---|---:|---|
| endpoint new since the previous snapshot | +100 | least likely to have been scanned by others |
| object reference in the path or an ID parameter | +50 | IDOR/BOLA candidates, the most common paid bug |
| business class (billing/auth/admin/upload) | +45...60 | money and identity flows |
| has parameters | +15 | something can be changed |
| host 401/403 + a sensitive subdomain name | +45...65 | areas that clearly require login |
| loose parameters from JS | +30...55 | a hint at which request to read |

Lower bound: `surface-review` items scoring < 30 are dropped. If nothing passes, `next.md` says plainly that this is the result, not a failed run.

Outcome-driven re-ranking (current spec). `next` also reads the outcome log
`state/outcomes.jsonl` written by `kai outcome`, and re-ranks the queue
deterministically — same log, same surface, same plan:

- a target classified **after** the last surface change is dropped from the queue, not merely demoted: a `negation` or `informational` is not worth a slot;
- a stale classification (the surface changed since) stays with a penalty and a note — `negation` -20, `informational` -10 — so a change can never hide untested work;
- a target that yielded (`finding` / `reported` / `paid`) is lifted +40, and its cluster siblings +20 — the same object root usually means the same bug;
- an unparseable timestamp counts as stale, so a corrupt log cannot hide anything.

Freshness is measured against the last surface change (the newest mtime among the recon artifacts), not the wall clock.

---

## 5. ZIP contents

```
<program>_<ts>.zip
└── <program>/
    ├── BRIEF.md               ← 1 page for the agent: scope, pack contents, what's missing, next action
    ├── program.md
    ├── scope.txt
    ├── out-of-scope.txt
    ├── boundaries.md          ← rules + constraints, verbatim quotes
    ├── policy.md              ← program rules that are not host-based
    ├── LEDGER.md              ← the tool's decision log
    ├── recon/                 ← only the files that exist
    │   ├── subs.txt
    │   ├── live.txt
    │   ├── urls.txt
    │   ├── js.ts
    │   ├── endpoints.txt
    │   └── nuclei.txt
    └── bountykit/           ← internal contract, not a product name
        ├── MANIFEST.json      ← file list + sha256
        ├── intake.json        ← Phase 0 (score + reasons)
        ├── rules-diff.md      ← rule changes
        ├── nonweb.md  nonweb.json  ← repo/contract analysis
        ├── diff.md            ← what is new
        ├── map.md  map.json   ← surface map
        ├── next.md next.json  ← ordered test queue
        └── session.json       ← only with --include-session
```

Principle: **distilled by default**. The downstream agent has limited RAM and `RTK` truncates output >500 characters — a raw dump ruins the context. `--include-raw` only on request.

---

## 6. Anti-duplicate design

Three mechanisms, all in the tool:

1. **`first_seen` / `last_seen` per asset.** An asset that appears in snapshot N and was absent in N-1 = **fresh** surface → top priority.
2. **JS bundle hash.** A changed bundle = new endpoints most likely live there.
3. **`diff` must go into BRIEF.md.** The agent reads "WHAT IS NEW", not the whole asset universe.

Reason: automation always loses the speed race on old surface. Diff is the only lever that makes automation produce something nobody else has scanned.

---

## 7. Commands

```
kai version
kai init   <program> [--platform h1|bugcrowd|direct] [--url U] [--verdict bounty|vdp|none]
kai scope  <program> <host|cidr>          # exit 0 IN / 1 OUT / 2 error
kai status [<program>]
kai pack   <program> [-o dist] [--include-raw]
```

v0.2:

```
kai recon  <program> [--auto|--step]
kai diff   <program>
```

v0.3:

```
kai session <program> [show|set|clear] [--har f] [--cookie s] [--header 'K: V']
kai map    <program>
kai next   <program>
kai outcome <program> --status negation|informational|finding|reported|paid [--class C] [--note T] <target...>
kai pack   <program> [--include-session]
```

v0.4:

```
kai intake <hackerone-url|handle> [--name slug] [--dry-run] [--force]
kai analyze <program> [--clone] [--refresh]        # in-scope repos + contracts
kai rules-diff <program>                   # rule delta between intakes
kai boundaries <program>                   # rules + constraints + verbatim
kai intake <url> [--name slug] [--dry-run] [--force] [--trust-scope]
                      [--max-links N] [--no-follow]
```

v0.5:

```
kai report <program>
```

v0.16 (see README for the commands added between v0.6 and v0.15):

```
kai model  <program> [--json] [--write] [--archetype NAME] [--top N]
kai evidence <program> import --har capture.har [--limit N] [--label name] [--keep-secrets]
```

---

## 8. Hard rules

1. Empty `scope.txt` → refuse. No exceptions.
2. Out-of-scope always wins.
3. Every host to be touched must pass through `scope` first; every result goes into `audit.log`.
4. No credential, cookie or token inside the ZIP except via `--include-session`; the tool prints a warning when that happens.
5. The ZIP never goes into git. `data/` and `dist/` are gitignored.
6. `session.json` is mode 0600, and `session show` always masks secret values.
7. Session cookies/headers are sent only to hosts that pass the gate — not to CT services, CDNs or reference hosts.
7. `intake` only reads the platform's public API: no login, it does not touch the target's assets.
8. Path-scoped assets are never widened into host rules.
9. Hosts from page text stay candidates until the operator verifies them and uses `--trust-scope`.
10. An unpublished rule = `unknown` / "not stated", not permission. Out-of-scope quotes must go into `boundaries.md` verbatim.
11. Every intake is snapshotted. Any change to scope or policy must show up in `rules-diff.md` and `BRIEF.md`.
12. Out-of-scope non-web assets never enter the `next` queue.
13. `analyze --clone` only touches repos listed in scope; clones are stored in `data/` and never packed.
14. `intake` only follows relevant links on the same domain, at most `--max-links` pages (default 8). Additional references still yield unverified candidates.

---

## 9. Roadmap

| Version | Contents | Definition of done |
|---|---|---|
| v0.1 | `init`, `scope`, `pack`, `status` | A ZIP can be built, the gate is identical to the downstream agent's (tested), the agent can read BRIEF |
| v0.2 | `recon`, `diff`, snapshots | One run produces `subs/live/urls/js/endpoints`; diff is filled — **done** |
| v0.3 | `map`, `next`, session import | Ordered test queue + a hypothesis per vuln class, the auth surface is mapped too — **done** |
| v0.8 | `analyze` repos/contracts | CI workflow + manifest enter the queue, probes respect the constraints — **done** |
| v0.9 | `report`, full adapters | Markdown/HTML report per program |
