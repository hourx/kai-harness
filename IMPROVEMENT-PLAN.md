# kai — Improvement Plan

Date: 2026-11-20 (v2, same day). Baseline commit: 89980d1. Binary installed: kai 0.11.3-dev (89980d1).
Repo renamed `hourx/kai` → **`hourx/kai-harness`**; module `github.com/hourx/kai-harness`; working dir
`kai-harness`. CLI binary keeps the name `kai` (ripgrep/rg precedent) so existing docs and
`KAI_HOME` paths stay valid. Sections 9–13 carry the design agreed with the operator on 2026-11-20.

Status: sections 0–8 = audit + tiered plan. Sections 9–13 = design of record. Sprint 1 (Tier 0 +
T1.1/T1.2) is implemented in this commit; everything else here is still PLAN ONLY.

---

## 0. Baseline (verified)

| Metric | Value |
|---|---|
| Go source | 12,276 lines (≈8.2k production, ≈4k test) |
| Packages | 15 internal + cmd/kai |
| External deps | 0 (stdlib only, go 1.21) |
| go build ./... | OK |
| go vet ./... | clean |
| Tests | 87 test funcs, all pass |
| CI | none (.github absent) |
| Repo size | 796 KB .git (bin/, dist/, data/ gitignored) |

Coverage by package: surface 85.6 · session 84.7 · backup 78.0 · scope 74.6 · triage 72.6 ·
nonweb 70.6 · program 61.0 · netx 59.8 · pack 54.6 · workspace 48.4 · recon 23.4 · audit 14.1 ·
cli 0.0 (1,488 lines) · doctor 0.0 · version 0.0 · cmd 0.0

Command surface (20): run, audit, doctor, init, intake, boundaries, brief, track, backup, restore,
analyze, rules-diff, scope, recon, session, map, next, diff, pack, export, status, version.

---

## 1. Design contract (must not break)

From IDEAS.md / SPEC.md:

- kai is a **deterministic context packer**, frozen. It does not hunt, does not validate, does not
  submit, and contains **no LLM**.
- Every outbound request goes through the scope gate. Out-of-scope always wins. Empty scope refuses
  to run.
- stdlib-only. Same input → same output. Artifacts are predictable and machine-readable.
- Everything kai emits is a **hypothesis for an agent**, never a claim.

Every improvement below preserves: determinism, the scope gate, no LLM, no external deps, no
auto-submit, no auto-exploit.

---

## 2. Tier 0 — correctness debt (effort S, do first)

**F1 — `internal/audit/audit.go:402` tautological check.**
`!strings.Contains(brief, "mainnet testing is forbidden") || strings.Contains(brief, "forbidden")`.
The right operand is implied by the left (the left string contains "forbidden"), so the condition is
always true and the check can never fail. Replace with an explicit comparison against
`Intake.MainnetTesting`: the brief must not claim mainnet is forbidden when intake says it is allowed.

**F2 — `internal/audit/audit.go:307-322` shared accumulator.**
`missing` is created once and reused by two assertions ("BRIEF ranked table == next.json top 12",
then "next.md top 10 == next.json") with no reset. If the first check fails, the second fails too and
its detail lists carry-over entries. Use a fresh slice per assertion.

**F3 — duplicated helpers with divergent behaviour.**
`dash` ×3 (program/intake.go:650, pack/pack.go:545, triage/triage.go:216); `uniqueStrings` ×2
(program/generic.go:526, nonweb/nonweb.go:466); dedupers `uniq` (program/intake.go:252) vs `Uniq`
(recon/store.go:189) vs `UniqLoose` (surface/map.go). Semantics already differ — intake/generic keep
empty strings, recon/surface drop them and sort. Consolidate into one `internal/strutil` with
documented semantics and delete the copies.

**F4 — `min`/`max` shadow Go 1.21 builtins.**
`func min` at audit.go:406 and cli.go:1031, `func max` at nonweb.go:264. Delete, use the builtins.

**F5 — `internal/pack/pack.go` archive permissions.**
The tar.gz is created with `os.Create` (0644). With `--include-session` it carries credentials
readable by other local users. Write 0600 and print a warning line whenever a session is included.

**F6 — `internal/netx/client.go` global `InsecureSkipVerify: true`.**
Correct for target probing (expired/mismatched certs must be visible in the pack), but the same
client is used for GitHub API and CT queries, so recon traffic is MITM-able. Add `--verify-tls`
(on for non-target endpoints, off for targets) or a second client for non-target hosts.

**F7 — silent error discards (12 total in non-test code).** The ones that matter:
`internal/triage/triage.go:77-78` ignores failures writing lessons.md / dupes.md;
`internal/cli/export.go:126` ignores an intake unmarshal error.
Also `internal/nonweb/nonweb.go:354` (scanRepo) truncates workflow YAML at 200,000 chars with **no
marker**, unlike crawl.go:74 and pack.go:415/493 which do annotate their truncation.

---

## 3. Tier 1 — close the loop (effort M/L, highest leverage)

Today kai is one-way: policy + surface in, ranked queue out. Nothing that happens after `next` ever
flows back, so the ranking cannot improve and every session re-walks targets already classified
NEGATIVE in a previous one.

**T1.1 Outcome log — DONE (verified end-to-end).** `kai outcome <program> --status
negation|informational|finding|reported|paid [--class C] [--note T] <target...>` appends to
`state/outcomes.jsonl` (0600) and reads the record back before reporting success. The command
writes the line itself, so a successful exit means the next `kai next` will see it. Pure data,
no LLM, no network.

**T1.2 Ranking feedback — DONE (verified end-to-end).** `next` reads outcomes.jsonl and applies
deterministic modifiers: a target classified *after* the last surface change (negation or
informational) is dropped from the queue; the same classification *before* the last surface
change only demotes it and adds a note, so a recon run can never hide untested work; a target
that produced a finding is lifted, and so are its cluster siblings (excluding the proven target
itself); an unparseable timestamp counts as stale. Determinism gotcha found while wiring it:
surface freshness must be read from the artifacts a *recon run* produces (`assets.json`,
`recon/*.txt`) — using the derived `map.json`/`next.json` makes every outcome look stale forever,
because `kai next` rewrites them on every invocation. A same-second record also needs a 1s
tolerance: second-precision timestamps truncate below the recon mtime and would read as stale.
Results on a 150-item real queue: recording one informational = 150 → 149 items with a stderr
note; a finding lifts itself by 40 and its sibling by 20 with both reasons written into `why`.

**T1.3 `kai plan <program>` — hypotheses, not URLs.** For each ranked item emit
`{endpoint, class, params, method_pointer, oracle}` where `method_pointer` references a skill
reference file; dedupe per `(host, class)` so the queue matches the operator's one-target-one-probe
protocol. Output `plan.json` + `plan.md`.

**T1.4 `kai board` — cross-program board.** Aggregate every program under KAI_HOME: scope verdict,
surface counts, open hypotheses, age of last recon, last outcome. One ranked "what to do today" list.
Serves the income-priority use case; reads meta.json + state dirs only.

**T1.5 Evidence capture.** `kai evidence <program> --host H --path P --method M [--har f | --raw f]`
writes `{id, ts, status, headers, body_sha256, raw_path}` into `evidence/`. Deterministic id from
(host, path, method, ts).

**T1.6 `kai report-draft <program> <evidence-id> --platform hackerone|yandex|bugcrowd`** renders the
platform's exact field set from evidence + scope. The report forms have fixed fields; templating
removes a whole class of formatting errors. kai produces a draft file and never submits it.

---

## 4. Tier 2 — recon depth (effort M)

Current recon: subfinder/assetfinder + crt.sh + certspotter → resolve → scheme probe (title/tech/TLS)
→ crawl JS bundles → regex endpoints → optional nuclei.

**T2.1 `recon --deep`**
- sourcemap discovery (`.map`) plus a pointer to the unminified source
- framework hydration data: `__NEXT_DATA__`, `__NUXT__`, `window.__INITIAL_STATE__`, `__APOLLO_STATE__`
- webpack/vite chunk-graph walk (follow chunk ids, not just `<script src>`)
- inline secret/key/anomaly pass over JS (api keys, tokens, internal hosts, debug flags) — reported as
  markers, never exercised

**T2.2 Param discovery** on live endpoints (wordlist + reflection heuristic) → `recon/params.txt`, fed
to `plan` as additional hypothesis axes.

**T2.3 Resumable recon.** Checkpoint `state/recon.progress.json` per phase; `--resume` continues
instead of restarting a ~20-minute run.

**T2.4 `kai scope-audit <program>`** — detect: a rule present in both scope.txt and out-of-scope.txt;
wildcard base also listed as exact; path/port-scoped rules kai silently drops; duplicate rules;
scope.txt drift against the last intake policy snapshot (extends `rules-diff` from "policy changed"
to "your scope file and the live policy disagree").

---

## 5. Tier 3 — reliability, structure, distribution (effort M/L)

**T3.1 Tests.** Table-driven flag-parsing + exit-code tests for all 20 commands (KAI_HOME →
`t.TempDir()`); round-trip tests for recon state files; audit tests that assert a deliberately broken
pack **fails** (permanently guards F1/F2).

**T3.2 CI** (`.github/workflows`): build, vet, `test -race`, staticcheck, gosec, coverage gate.

**T3.3 Split `internal/cli/cli.go`** (1,488 lines, 20 handlers) into one file per command group
(cmd_recon.go, cmd_pack.go, cmd_intake.go, …) leaving cli.go as dispatch + usage text.

**T3.4 Pack contract.** `pack/kai.toml` manifest with schema_version + artifact list; `audit` validates
the pack against the declared schema; the bb-* skills read the manifest instead of guessing filenames.

**T3.5 Ops niceties.** `doctor --fix` (create missing dirs / fix permissions), shell completions,
`kai self-update` from GitHub releases, `npx` wrapper (README already raises "Instalasi lewat npx?").

---

## 6. What NOT to change

- No LLM inside kai. Intelligence stays in the agent.
- No auto-submit, no auto-exploit. kai stops at a draft.
- No breaking determinism (no network- or clock-dependent ranking unless the input is recorded).
- No external Go deps. stdlib-only is a supply-chain feature on a box that holds credentials.
- The scope gate stays mandatory on every request path, including new ones.

---

## 7. Suggested sequence

1. **Sprint 1** — Tier 0 + T1.1/T1.2 → the queue stops repeating itself.
2. **Sprint 2** — T1.3/T1.4 + T2.3 → hypotheses + board + resumable recon.
3. **Sprint 3** — T2.1/T2.4 + T1.5/T1.6 → deeper recon + report bridge.
4. **Sprint 4** — Tier 3 → tests, CI, split, pack contract.

### Locked build order (operator approved 2026-11-20)

1. Rename (`kai-harness`) — done before anything else because it is free while there are no consumers.
2. **Sprint 1** (Tier 0 + T1.1/T1.2) — trust debt first: a ranking loop that cannot remember is the
   single biggest waste in the current tool.
3. `pkg/` promotion (§10) — a library nobody can import is not a product.
4. Sprint 2, then Sprint 3, then Sprint 4.
5. Platform drivers + `state/program.yaml` (§11): HackerOne → Bugcrowd → self-hosted (security.txt).
6. `model.json` + the five sweeps (§9), spiked on one real program before it generalises.
7. Pattern library, two layers (§9.3) + external adapter seam (§12).
8. LLM seam last (§12) — the kernel must be useful with the LLM switched off.

End state: kai becomes the deterministic spine of the pipeline —
intake → scope → recon (deep, resumable) → plan (hypotheses) → [agent tests] → evidence →
report-draft → outcome → board — while staying frozen on everything that makes it trustworthy.

---

## 8. Long-term vision — from context packer to hunter / validator with an LLM decision layer

Feasible. One architecture decision determines whether it works.

**Do not put the LLM inside the deterministic kernel.** Split kai into two halves:

- **Kernel (`kai`, Go, stdlib-only, deterministic):** scope gate, recon, pattern execution, evidence
  capture, ledger, validation harness, budgets, kill switch. Every outbound request passes through it
  and is logged together with the decision that authorised it.
- **Planner (`kai-agent`, LLM):** reads kernel state + pattern library + outcomes and proposes a
  *plan* (YAML: target, action class, pattern id, expected oracle). It never touches the network.

Flow is plan/apply: the planner proposes, the kernel validates the plan against scope + action-class
policy, then executes. Replayable, auditable, and the model can be swapped or run offline.

### Layers

- **L0 — context packer** (today).
- **L1 — kernel capabilities:** outcomes, plan, board, evidence, report-draft. Prerequisite for
  everything below — the Tier 1/2 work is already on this path.
- **L2 — pattern library + rule engine, still no LLM.** Each pattern is data:
  `signal -> hypothesis -> probe (read-only template) -> oracle (differential check) -> confidence /
  source / cvss_hint`. Adding a pattern is adding a row, not compiling code. Sourced from own campaign
  history plus public writeups. Commands: `kai patterns`, `kai test --pattern <id> --target <t>`.
- **L3 — decision layer.** `kai decide` / `kai hunt`: LLM plans, kernel executes. Action classes:
  read-only (auto), state-changing (operator approval), destructive (never). Per-program token and
  request budget.
- **L4 — validator.** Differential harness (baseline vs payload, state-change checks, reflection
  context) plus LLM adjudication; emits a verdict and a reproducible proof script. Replaces the manual
  Skeptic pass.
- **L5 — learning loop.** Outcomes re-weight patterns by observed yield per (shape, class).
  Deterministic scoring; optional LLM summary of what works where.

### Hard constraints

- The scope gate stays the only authority on what may be requested. The planner may propose; it can
  never widen scope.
- Determinism survives as: the plan is a recorded artifact, so any run can be replayed with the LLM
  disabled.
- Budgets: tokens per program/day, requests per pattern, and a kill switch.
- kai never submits a report; a human does.
- The kernel keeps zero external deps and full test coverage. Only the planner depends on an LLM
  endpoint (a self-hosted router).

### Why this ordering

Value concentrates in (a) the pattern library, (b) validation rigour, (c) the loop that stops
forgetting. The LLM is only the planner. Tools that put the LLM in the execution path produce
unaccountable request spam and cannot be reproduced; tools that keep it at the decision boundary stay
auditable.

### Pieces already on this box

Model routing, memory, campaign history (the pattern source), the evidence/ledger conventions, and
the role skills that already encode tester / skeptic / reporter. The vision is assembly, not
invention.

---

## 9. Depth > Variety — the program model is the core artifact

Operator principle (2026-11-20): kai must go **deep, not wide**. Three obligations: understand the
program's **logic**, understand its **patterns**, and **notice what others miss**.

Consequence for the architecture: the primary artifact moves from *a ranked URL queue* to *a model of
the program*. The queue becomes a derived view of the model. A tool that ranks URLs can only re-find
what was already crawled; a tool that models the program can state what the program *allows* and then
look for the place where reality disagrees with the model.

### 9.1 `state/model.json` — shape

```
program: <name>
archetype: web-app | api | chain | mobile-api | exchange | saas-tenant
entities:     [{id, name, address_form: path|query|body|graphql|contract|id, key_types[], notes, source}]
actors:       [{id, role, auth: anon|user|admin|service, tenancy, source}]
capabilities: [{role, action, object, allowed: yes|no|unknown,
                enforcement: server|client|none|unknown, source, confidence}]
actions:      [{id, method, path_or_selector, auth_required, inputs[], side_effect: read|write|value|auth, source}]
transitions:  [{from_state, action, to_state, guard, source}]
invariants:   [{id, statement, check, domain: state|authz|value|rate|tenancy, source}]
boundaries:   [{id, kind: auth|tenancy|chain|service|client, inside, outside, source}]
value_flows:  [{from, to, asset, fee_rule, source}]
anomalies:    [{id, kind, observation, evidence_ref}]
```

Every row carries `source` and `confidence` (`spec` | `observed` | `inferred`). A row with no source is
a hypothesis, not part of the model, and the sweeps must treat it that way.

### 9.2 The five deterministic sweeps — this is "notice what others miss"

All five read only `model.json` (+ evidence refs) and emit hypotheses in the existing T1.3 shape
(`{endpoint, class, params, method_pointer, oracle}`). No network access in the derivation step.

1. **Capability-matrix sweep** — cells where a `(role, action, object)` is allowed with no visible
   control, where enforcement is `client`, or where sibling cells in the same row/column disagree
   (role A blocked, role B not; object X protected by owner check, object Y of the same entity not).
2. **Transition-edge sweep** — illegal edges: skip a step, replay a step, re-enter a terminal state,
   run a transition out of order, or two transitions racing on one object.
3. **Invariant sweep** — every invariant with a falsifiable `check` becomes a planned probe
   (baseline vs payload differential). Invariants without a check are printed as *needs operator
   knowledge* — an explicit gap, never a guess.
4. **Cross-surface parity sweep** — the same action exercised over two surfaces (web vs mobile API,
   v1 vs v2, off-chain vs on-chain, tenant view vs admin view). Divergence is the candidate finding;
   this is where enforcement differences live and where other hunters stop looking.
5. **Model-anomaly sweep** — endpoints that do not follow the program's own convention, objects
   addressed by two different key types, list endpoints filtered while the detail endpoint is not,
   undocumented verbs/verbs with no matching action row.

### 9.3 Pattern knowledge, keyed by shape — not by URL

The pattern library is keyed by `(archetype, entity|action|invariant-class)`. Each program also keeps a
*delta*: which keys fired, and how the operator classified the outcome (from `outcomes.jsonl`). On
program N+1, ranking is driven by what actually paid on the same archetype. That is the "kai
understands the pattern of every program" requirement — implemented as data + deterministic scoring,
not as a prompt.

### 9.4 How the model gets built without lying

Inputs, in order: **spec** (policy page, docs, OpenAPI/GraphQL SDL, ABI, mobile manifest) →
**observed** (surface/recon artifacts, evidence captures) → **inferred** (folds and pattern matches).
Provenance is preserved per row; sweeps weight hypotheses by confidence; every output prints the
confidence of the rows it relied on, so the operator can see which part is a guess.

### 9.5 Spike target (chosen 2026-11-20)

**A live, evidence-first program** — chosen because:

- its artifacts already exist locally (recon logs, JS bundles) — the spike needs **zero new requests**;
- it has **two known findings** that are exactly capability-matrix / invariant violations, so the
  spike has a real acceptance test: *the model, built only from local artifacts, must place both
  findings in its top-ranked hypotheses*. Back-testing a model against a known bug is the only honest
  way to know the model works;
- the program is live, so a working model immediately improves a pending submission.

Secondary (free, but not the primary): spec-first micro-run on the Claude MCP connector surface
(stored JSON tool schemas = machine-readable spec, no network) and on the Coinbase registry
(`recon/registry_final.json`, ABI/selector tables) — both are pure-spec inputs that cost nothing.

---

## 10. Distribution — library first, then CLI, then service

- **`internal/` cannot be imported by third parties.** The engine must be promoted to `pkg/` with a
  documented API before "kai as a library" is real: `scope`, `program`, `surface`, `model`, `plan`,
  `evidence`, `outcome`. `internal/` keeps only CLI glue. Nothing else in this plan is worth as much
  to a paying user as an importable engine.
- **Binary stays `kai`**; the repo/product name is `kai-harness`.
- **CLI = local face.** `kai serve` = service face: HTTP + JSON, binds loopback by default, refuses
  non-loopback without an explicit auth token.
- **Multi-tenant layout:** `KAI_HOME/tenants/<tenant>/<program>/…`. Single-user layout
  (`KAI_HOME/<program>/…`) stays valid — the tenant dir is an added level, not a migration.

## 11. Platform drivers + the program contract

- **Driver = data + a tiny manifest** (`drivers/<platform>/manifest.json`): id, display name, intake
  URL patterns, policy fetch plan, scope / out-of-scope extraction rules, mandatory conditions (e.g.
  HackerOne's username-based reporting address), report field set, reward fields, requires-auth flag.
- Adding a platform = adding a driver directory. The core is untouched for normal HTML policy pages;
  a driver may ship one small Go file if it needs a non-HTML parser. That is a **registry seam, not a
  plugin loader** — no dynamic loading, no external deps.
- **`state/program.yaml` = the contract of record:** platform, intake snapshot hash, scope verdict
  table, mandatory conditions, allowed / required / forbidden actions, report field set. Every later
  command reads the contract, and `audit` asserts that no artifact contradicts it.
- Order: HackerOne → Bugcrowd → self-hosted (Relay-style, discovered via RFC 9116 `security.txt`).

## 12. Data loop (3 tiers) + the LLM seam

**Tiers.** T1 public: drivers, generic patterns, schemas. T2 opt-in anonymous aggregates: pattern keys
+ outcome labels + hashed host fingerprint — **never** URLs, reports, credentials, or target data.
T3 private: tenant-local, never uploaded. `kai contribute --dry-run` prints the exact payload; nothing
leaves without the operator seeing it first.

**LLM seam (deliberately last).** Four roles, all at the edge: (1) plan adjudicator — rank/verify the
hypothesis queue; (2) evidence adjudicator — the Skeptic replacement; (3) unstructured→structured
translator — policy pages, PDFs, JS; (4) report drafter. Requirement: with the LLM disabled, kai still
produces a complete, useful output (deterministic fallback). No LLM ever sits in the request path.

## 13. Decisions locked with the operator (2026-11-20)

- **Name:** repo + module `kai-harness`; CLI binary stays `kai`. Applied to repo, module path, working
  dir, the operator's provisioning defaults and the operator's internal skills.
- **Public release:** open-core **split** (recommendation, operator to confirm the exact boundary):
  public repo = engine (`pkg/`), CLI, driver interface, public pattern layer, docs; private = pattern
  layer derived from live campaigns, hosted/service layer (tenancy, billing), and anything carrying a
  live-hunting advantage. Public from day one is correct precisely because the pattern library is
  supposed to be fed by contributions — but a pattern that encodes an unfolding campaign stays out.
- **Licence: AGPL-3.0 — decided and applied** (LICENSE + README). Rationale: the plan sells a hosted
  tier, and a permissive licence lets a competitor host this as a service without contributing back,
  which directly undercuts that tier; AGPL forces them to publish or buy. Third-party material
  (humanize CC-BY-4.0, Cybermes Apache-2.0, Claude-BugHunter split `LICENSE`/`LICENSE-CONTENT`)
  stays reference data with attribution — never re-licensed text.
- **Pattern extraction from operator campaigns: APPROVED**, destination = the **private** layer.
  Publishing the invariant that a live program is currently being hunted with would hand over the edge.
- **Spike target:** the live evidence-first program, with the back-test against its two known findings
  as the acceptance test (§9.5).
- **Determinism, scope gate, no-auto-submit, stdlib-only:** unchanged. Every section above preserves
  them.
