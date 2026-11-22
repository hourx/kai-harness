# KAI-REFERENCES.md

Assessment of 10 reference repositories as initial learning material for kai.
Read on 2026-11-20. All findings below come from the actual repository contents
(clone metadata + raw file reads), not from repository descriptions alone.

Working copies of everything fetched during this assessment live in a pruneable
scratch directory outside the repo.

---

## 1. Ranking — what each repo is actually worth to kai

| # | Repo | What it really is | Take | kai layer | Verdict |
|---|---|---|---|---|---|
| 1 | The-XSS-Rat/SecurityTesting | Human methodology prose + checklists + tool lists + WAF bypass + real delivered pentest report (PDF) + report templates (PDF) | Structured check templates, param→class mapping, report templates | Pattern library + report module | **High** (structure only, not prose) |
| 2 | elementalsouls/Claude-BugHunter | 83 `hunt-*` skills, 15 commands, 681 disclosed-report patterns (433 cited), working HackerOne MCP driver, Python engine with memory | Vuln taxonomy, H1 driver shape, disclosed-report corpus, engagement-folder model | Platform driver + pattern library | **Highest** |
| 3 | awarexone/Agentic-Bug-Hunter | 25 skills, 43 commands, `rules/hunting.md` + `rules/reporting.md` (policy + report language rules) | The rules layer: gates, kill signals, report language constraints | Gate contract semantics + report module | **High, cheap** (text) |
| 4 | aicodeking/leanrea | One 8 KB RE router skill, no MCP, CLI-only, with benchmarks | Tool router table + evidence discipline (seen/inferred/unknown) | RE path + model confidence rules | **High** (tiny, dense) |
| 5 | KeygraphHQ/shannon | Autonomous web/API pentester: source → attack path → real exploit, Docker + Temporal worker | Confirmation gate design, source-analysis-before-exploit sequencing | Gate 1 semantics + planner ordering | **Medium-high** (heavy infra) |
| 6 | lightpanda-io/browser | Headless browser in Zig, 16x less RAM / 9x faster than Chrome, CDP server on :9222 | Drop-in CDP for bulk fetch/crawl | Browser layer (read-only) | **Medium** (caveats below) |
| 7 | Zyrexnn/Cybermes | Go+Python aggregator: 209 skills, 2960-file knowledge base, `pkg/scope/scope.go`, MCP server, ships a Hermes Agent launcher | Scope-engine design, `pkg/` public layout, catalogue names | Service face reference + catalog | **Medium** (it is an aggregator) |
| 8 | gencharitaci/humanize-skills | Anti-formula prose rulebook, 10 modes, 20 languages (incl. `id.md`), no-edit gate | Report layer — call it, do not reimplement | Report module | **Adopt as-is** (already in use) |
| 9 | monsifhmouri/SubMonsif | Small Go subdomain enumerator (crt.sh, HackerTarget, VirusTotal, OTX, Shodan + bruteforce) | Go provider abstraction pattern for recon | Recon module reference | **Low-medium** (reference only) |
| 10 | zhaoxuya520/reverse-skill | 49 skill dirs, 412 skill files, CTF chains, Burp MCP | Not-yet-converted parts: CTF-Sandbox-Orchestrator chains | Already converted | **Already adopted** |
| 11 | Ignitetechnologies (all 34 repos) | The GitHub mirror of hackingarticles.in: 33 of 34 repos are one README that is a table of links to blog posts; 724 MB of that is mindmap images; 33 of 34 have no licence | Names only — tool vocabulary, 22 privesc check names, product→class seed list | Adapter-list cross-check; future post-exploitation phase | **Low** (an hour of name extraction, never a clone) |

---

## 2. What repeats across the good ones (the actual signal)

Every high-value repo in this list converges on the same seven ideas.
That convergence is the strongest evidence that kai's planned shape is right.

1. **Scope first, before any request.** `Agentic-Bug-Hunter/rules/hunting.md`
   opens with "READ FULL SCOPE FIRST" and lists exactly four things to read:
   in-scope assets, out-of-scope exclusions, excluded bug classes, safe harbor.
   This is the same four-field contract proposed for `program.yaml`.
2. **Never report without demonstrated impact.** "No exploit, no report"
   (shannon), "PoC || GTFO" (SecurityTesting), "NEVER USE THEORETICAL LANGUAGE"
   (Agentic rules). Three independent repos, same rule.
3. **Kill weak findings fast.** 7-Question Gate, 5-minute rule, kill signals
   (all 403, static pages, no ID params, no interesting JS, nuclei silent).
4. **Automation for recon only; manual for hunting.** "AUTOMATION = HIGHEST DUP
   RATE". This matches kai's deterministic-kernel / LLM-planner split.
5. **Evidence discipline.** leanrea: mark every claim **seen** (cite file:offset)
   or **inferred**; a fact you did not find is **unknown**, not "absent".
   That is exactly the `confidence` field proposed for `model.json`.
6. **Explicit confirmation before active testing.** shannon refuses to start
   without the operator confirming ownership and non-production, and refuses to
   infer either from the URL.
7. **A workspace per engagement with defined deliverables.** Claude-BugHunter
   `engagement.json` + `engine/`; Cybermes "target workspace & deliverables".

Every one of these is a *gate or an artifact discipline*, not a vulnerability
trick. Which is the point: the repos that get this right are the ones that hold
up. The value is in the discipline, not the payload list.

---

## 3. Per-repo detail

### 3.1 The-XSS-Rat/SecurityTesting (1747 stars, 271 files, 15 MB)

`Checklists/` — all 12 text files read:

| File | Bytes | Shape |
|---|---|---|
| 2026-bug-bounty-guide.md | 34,571 | 11-section guide: mindset → platform → recon → manual → Burp → vuln classes → WAF → chaining → reporting → tools |
| HuntingCheckList.md | 19,560 | Per-class checklists with *Tips* + video links |
| Main app methodology.md | 16,933 | "Uncle Rat's attack strategy" — leftovers over firsts |
| 100-bounty-tools.txt | 9,717 | Categorised tool catalogue |
| webAppSec.md | 6,267 | Info gathering + login + input validation + general exploits |
| 100-web-exploits.md | 4,798 | Flat list of ~120 exploit classes |
| WAF-bypass-checklist.md | 3,089 | Generic bypass list + named-WAF payloads (Airlock, Barracuda) |
| FAQ.md | 2,713 | — |
| web app pentesting checklist.txt | 2,739 | — |
| OSINT.md | 1,675 | Sources + dork operators |
| Multi target recon.md | 993 | Tool-per-stage recon chain |
| CSRFTools.txt | 678 | 7 links |
| NetworkHacking.drawio (1).png | 64,398 | Diagram |
| PEN-82804737-250323-0957.pdf | 236,089 | **A real delivered pentest report** |

Highest-value extract, verbatim from the guide — a deterministic
parameter→class mapping that kai can implement without an LLM:

| Parameter pattern | Class |
|---|---|
| `url=`, `src=`, `dest=`, `feed=`, `webhook=` | SSRF |
| `file=`, `page=`, `template=`, `path=`, `include=` | LFI/RFI |
| `id=`, `user_id=`, `order=`, `invoice=`, `doc=` | IDOR |
| `redirect=`, `next=`, `returnTo=`, `goto=` | Open redirect |
| `q=`, `search=`, `name=`, `title=`, `comment=` | XSS / SSTI / SQLi |
| `cmd=`, `exec=`, `shell=`, `ping=`, `host=` | Command injection |
| XML body, or DOCX/XLSX/SVG upload | XXE |

Second-highest extract: the model-level moves in Phase 3 — infer `v2` → `v1`,
tamper HTTP methods even when undocumented, add non-UI params
(`role=admin`, `isAdmin=true`, `plan=enterprise`) for mass assignment. These are
the depth operations, not surface enumeration.

Also present but outside `Checklists/`: `pentesting/` holds 10 PDFs including
`GENERAL-TPL-Bugtemplate`, `GENERAL-TPL-Pentestingreport`,
`GENERAL-SOP-WebEndpointReportTemplate` and a test-plan template. That is a ready
skeleton set for kai's report module — worth mining when the report layer is built.

**Verdict:** take the structure and the mappings as machine-readable data.
Do not vendor the prose. Do not clone the 15 MB repo — the relevant text is
about 100 KB plus two PDFs.

### 3.2 elementalsouls/Claude-BugHunter (13,338 stars, 343 files) — the best reference here

- 83 `hunt-*` skills forming a clean vuln-class taxonomy (idor, ssrf, xss, sqli,
  ssti, xxe, jwt-crypto, oauth, saml, mfa-bypass, race-condition, cache-poison,
  http-smuggling, websocket, grpc, graphql, shadow-api, source-leak, subdomain,
  tls-network, business-logic, file-upload, host-header, ldap, lfi, nosqli,
  open-redirect, rce, session, dom, html-injection, captcha-bypass, nextjs,
  laravel, springboot, aspnet, nodejs, sharepoint, k8s, cicd, cloud-misconfig,
  cors, csrf, deserialization, llm-ai, rag-vector, fintech-graphql, apk, ios,
  m365-entra, enterprise-vpn, meme-coin).
- 15 commands: `autopilot, chain, hunt, intel, memory-gc, pickup, recon,
  remember, report, scope, surface, token-scan, triage, validate, web3-audit`.
  Compare with kai's current surface (`intake, scope, map, next, recon`) —
  `chain` (chaining), `validate`/`triage` (gates), `memory-gc`/`pickup`/`remember`
  (session memory) are the gaps.
- **`mcp/hackerone/` — a working platform driver, standard library only.** Tools:
  `get_program_scope` (structured in/out scope + policy text),
  `get_program`, `search_disclosed_reports`, plus logged-in variants
  (`list_my_programs`, `get_my_program`, `list_my_reports`) gated on
  `HACKERONE_API_USERNAME` + `HACKERONE_API_TOKEN` (Settings → API Token).
  Read-only Hacker API; nothing submits. This is the exact shape proposed for
  kai's platform adapters, and it is a live implementation to copy from.
- **681 disclosed-report patterns (433 individually cited) across 24 classes**,
  in `docs/disclosed-reports/` and `research/`. This is the missing piece for
  "notice what others miss": a corpus of what has *already* been found tells kai
  both what to avoid (dupes) and what the remaining space looks like.
- `engine/` — Python, with `agent.py`, `memory.py`, `closure.py`,
  `engagement.example.json`. Engagement-scoped state + memory.

**Verdict:** the single highest-value repo in the list. Cherry-pick the taxonomy,
the H1 driver shape, and the disclosed-report corpus idea. Do not adopt the
prompt packs wholesale — kai's value is determinism, and the LLM seam is separate.

### 3.3 awarexone/Agentic-Bug-Hunter (6,011 stars, 454 files) — the rules layer

25 skills, 43 commands, and three rule files that are better than anything else
in this list:

- `rules/hunting.md` — engagement context (operator is a bounty hunter, not a
  pentester); READ FULL SCOPE FIRST; NEVER HUNT THEORETICAL BUGS; KILL WEAK
  FINDINGS FAST (7-Question Gate); CHECK SCOPE EXPLICITLY FOR EVERY ASSET
  (third-party service = out of scope); 5-MINUTE RULE with concrete kill signals;
  AUTOMATION = HIGHEST DUP RATE.
- `rules/reporting.md` — "NEVER USE THEORETICAL LANGUAGE" with a banned-phrase
  list (`could potentially`, `may allow`, `might be possible`, `could lead to`)
  and the required form: "An attacker can [exact action] by [exact method]".
- `docs/CAPABILITY-GAPS.md` — a template for kai's own gaps document.

**Verdict:** adopt the rules as kai's policy text templates. Cheap, and it is
exactly the "boleh / wajib / tidak" layer the gate needs.

### 3.4 aicodeking/leanrea (4,387 stars, 12 files, 24 KB) — RE without MCP

One 8 KB skill that replaces an RE MCP server with plain CLI tools, plus a
`bench/` folder with real benchmark scripts, tasks and results.

Its rules are the important part:

- Work on a copy; one extraction dir per target; reuse existing extractions.
- Route by `file -b` and magic bytes first, then cheapest inventory, then code.
- Never `cat` a big or minified file — slice around the needle.
- Batch independent probes into ONE shell call; cap every output.
- **Answer from evidence: mark each claim `seen` (cite file:offset or a
  symbol/string) or `inferred`. A fact you did not find is `unknown`, not
  "absent". Static reading is not observed execution.**
- Turns cost more than bytes: aim for 2-4 tool calls.

Router table covers Electron/asar, web bundles, Hermes/bytenode, Mach-O, native
logic (otool/objdump/Ghidra/r2), ELF/PE, Go, Rust, .NET, APK, Flutter snapshot
hash, WASM, SQLite, plist/nib/car, pcap/HAR, firmware, website, running app.

**Verdict:** the tiny file with the highest density of reusable rules. Its
evidence discipline maps 1:1 onto `model.json`'s `confidence` field. Since the
operator already has an RE MCP + skill, this is a candidate to complement or
replace it — decide after reading `bench/results/final.jsonl`, not before.

### 3.5 KeygraphHQ/shannon (52,117 stars, 393 files, 92 MB)

Source → attack path → executed exploit. Docs include `platforms.md`,
`ai-providers.md`, `configuration.md`, `coverage-roadmap.md`, and an
`exp-php2shell` probe.

The reusable part is not the Docker/Temporal worker — it is the gate:

- Before the first start, ask the operator to confirm two things: they own the
  target or are authorised, and it is not production. **Do not infer either from
  a URL, a repository name, or the target being local.**
- If the target looks like production, say so and do not start.
- Never run `reset`. Do not run interactive `setup` from an agent shell, and
  never ask the user to paste a provider key into chat.

**Verdict:** take the confirmation-gate semantics and the "source analysis before
exploitation" ordering. The runtime stack is far too heavy for kai. Note the
operator already has a `shannon-pentest-framework` skill — do not duplicate.

### 3.6 lightpanda-io/browser (42,263 stars, Zig)

| Metric | Lightpanda | Headless Chrome |
|---|---|---|
| Peak memory (100 pages) | 123 MB | ~2 GB |
| Execution time (100 pages) | 5 s | 46 s |

Verified from the README: it exposes a **CDP server on port 9222** and works with
`puppeteer-core` / Playwright via `browserWSEndpoint: "ws://127.0.0.1:9222"`.
It also speaks WebDriver BiDi. JS support is V8. Install: brew, AUR, or the
nightly binary for linux/macOS x86_64 and aarch64.

**Verdict:** usable as a lighter replacement for bulk read-only fetch/crawl. Two
caveats that matter for security work: (a) it is a new, incomplete browser, so
feature coverage is narrower than Chrome — verify per target before trusting a
JS-heavy SPA result; (b) it is not Chrome, so anything that fingerprints the
client, or any flow where the app behaves differently under a nonstandard
engine, is unsafe to test through it. Keep a real Chrome for anything that
touches auth, state, or anti-bot.

### 3.7 Zyrexnn/Cybermes (1,047 stars, 4,732 files, 173 MB)

Go + Python aggregator: 209 skill dirs, a 2,960-file `knowledge/` tree (which
contains a vendored copy of Claude-BugHunter), 1,292 tool files, an MCP server,
an npx wrapper, and — relevant to this stack — **it ships a Hermes Agent
launcher (`.hermes/SOUL.md`, `hermes`, `hermes.ps1`) with an image titled
`cybermes_hermes_workflow.jpeg`.**

Concrete reusable pieces:

- `pkg/scope/scope.go` + `scope.yaml` — a scope engine written in Go, plus tests.
- `pkg/` as the public package layout (the thing kai currently lacks entirely).
- `pkg/mcp/tools_*.go` (recon, nmap, nuclei, fuzz, knowledge), `pkg/crawl`,
  `pkg/fuzz`.
- `cmd/`: `aggregate_reports`, `cybermes-mcp`, `search_knowledge`, `secret_scan`,
  `smart_pipe`.
- Its own roadmap puts scope safety in Phase 2, before automation — same ordering
  as kai.

**Verdict:** medium. It is an aggregator, which is what the operator is already
doing by hand — so its catalogue is more useful than its code. Its two real
lessons: a Go scope engine is a solved problem with a reference implementation,
and a `pkg/` layout is what makes Go code reusable by others.

### 3.8 gencharitaci/humanize-skills (38 stars, 98 files)

Already in use for write-ups. Structure: `skills/humanize-skills/SKILL.md` plus
`references/` with 10 modes (general, academic, medical, legal, business, resume,
ux, creative, social, technical), 20 language files including **`id.md`**, tone
profiles, a cultural matrix, `structural-pass.md`, `prose-benchmarks.md`,
`voice-calibration.md`, and per-language example corpora.

The rule that matters most is the **no-edit gate**: an independent blind test
found a humanizer's edits to genuinely human-written paragraphs were identified
as tampered 83% of the time, from a median change of only 8-9% of tokens. So the
skill assesses whether the input already reads as human *before* editing, and the
skill's own text says to treat it as a prose-quality tool rather than a detector
workaround and to say so plainly.

**Verdict:** adopt as-is for the report layer. kai calls it; kai does not
reimplement it. Do not humanise an already-human report, and do not claim the
output evades detectors.

### 3.9 monsifhmouri/SubMonsif (11 stars, Go)

~4 files of logic: `main.go`, `core/engine.go`, `core/results.go`,
`providers/passive.go`, `providers/bruteforce.go`. Sources: crt.sh,
HackerTarget, VirusTotal, OTX, Shodan; multi-threaded; dedupe; wordlist
bruteforce; `-d/-dl/-t/-brute/-v/-o` flags.

**Verdict:** low-medium. Do not vendor it — it is small and thin. Its one real
use is as a Go-language reference for the passive/bruteforce provider split,
readable in a few minutes and written in the same language as kai.

### 3.10 zhaoxuya520/reverse-skill (44,966 stars, 633 files)

Already converted into this environment's skills (`api-security`, `attack-chain`,
`llm-security`, `code-audit`, `pentest-tools` were built from it).

What has not been taken yet:

- `CTF-Sandbox-Orchestrator/` — 136 files of **chained** recipes:
  `competition-ad-certificate-abuse`, `competition-agent-cloud`,
  `competition-android-hooking`, `competition-browser-persistence`,
  `competition-bundle-sourcemap-recovery`, `competition-cloud-metadata-path`,
  `competition-container-runtime`, `competition-crypto-mobile`,
  `competition-custom-protocol-replay`, `competition-dpapi-credential-chain`,
  `competition-file-parser-chain`, and more.
- `skills/MASTER-ROUTING.md` and `skills/INDEX.md` — a routing model over 49
  skills, worth reading as a design reference for kai's dispatch.
- `burp-mcp-full/` — a Burp MCP implementation.

**Verdict:** already adopted; the chains are the remaining cherry-pick.

### 3.11 Ignitetechnologies — all 34 repos (surveyed 2026-11-23, API only, no clone)

The GitHub mirror of `hackingarticles.in`, a training/consulting brand. 34 public
repos, 6,065 followers, account opened 2016. 824 MB total, of which **724 MB is
Mindmap images**. **33 of 34 repos have no licence file** (default: all rights
reserved); the one MIT repo is a fork. Seven repos are forks of other people's
work — `Outpacket`→n00py, `OSCP_Tools`→hanzobite, `awesome-tunneling`→anderspitman,
`precompiled-binaries`→jakobfriedl, `cheatsheets`→cipher387, `myfiles`→MSaroeval,
`PayloadsAllTheThings`→swisskyrepo. Go upstream, never to the mirror.

**Shape of the content.** 19 of the 34 repos are link tables: **732 article rows,
881 distinct URLs, 731 of them blog posts on `www.hackingarticles.in`** (the rest:
57 exploit-db, 14 rapid7, 4 github, plus social). Every one is a `README.md` that is a
`| # | Topic | Description | Read Article |` table, 0 code fences. Android-Penetration-Testing (2 KB), Nmap-For-Pentester
(3 KB), AI-Pentest (2 KB), Command-Control (1 KB), `bugbounty` (4 KB),
Credential-Dumping, ADCS-Attack, Abusing-DACL, AWS-Pentest, MSSQL, Wireless,
Privacy-Protection, Linux/Windows privesc, and the HTB/Vulnhub/TryHackMe writeup
repos are all this shape: indexes of links, not references. Whole account is 8.4 MB
of text, and ~4.2 MB of that is fork noise (OSCP_Tools, precompiled-binaries,
the PayloadsAllTheThings index).

**The three things worth taking — names and structure only, no prose, no images:**

1. `Mindmap/` — 77 top-level dirs, 424 images. The images are worthless to a text
   pipeline; the **directory names are a free capability vocabulary**, one per tool
   or topic: nmap, ffuf, gobuster, httpx, wfuzz, feroxbuster, sqlmap, hydra, medusa,
   hashcat, wpscan, aircrack, nxc/crackmapexec, impacket, mimikatz, john, gtfobin,
   IDAPro, empire, metasploit, tcpdump/tshark/wireshark — plus a governance branch
   (FISMA, GDPR, HIPPA, ISO Control, SOC 2, NIST) and an ATT&CK branch. Useful as a
   cross-check when extending `pkg/recon`'s adapter list (currently subfinder,
   assetfinder, gau, waybackurls, nuclei); it confirms the set and adds no data.
2. `Privilege-Escalation/` — the only dense repo: 22 files, 304 table rows, still 0
   code fences. One section per local technique: SUID, sudo rights, capabilities,
   crontab, kernel, Docker group, LXD, NFS, Redis, MySQL, PATH, wildcard injection,
   writable `/etc/passwd`, shadow cracking, chkrootkit. Take the **check names** as
   a post-exploitation enumeration checklist (a phase kai does not have); leave the
   payload prose.
3. `Web-Application-Cheatsheet/` — 84 table rows, one section per product: Drupal,
   Jenkins, Joomla, Webmin, WordPress, Moodle, CouchDB, PHP Mailer, PlaySMS,
   Simple PHP Blog. kai has no product branch at all (`grep -ri
   'wordpress|drupal|jenkins' pkg/` returns nothing; surface classification stops at
   graphql/api). Take as a **product fingerprint → known vuln class** seed list —
   the same shape as SecurityTesting's param→class table, so an extension of an
   existing axis, not a new one.

**Rejected:** every link-table repo (a link is not a check — nothing to convert),
all 7 forks, the three binary repos (kai ships one binary and zero dependencies),
`Persistence-Accessibility-Features` and `Windows-…-SeImpersonation` (payloads),
`view2akill` (CTF exploit scripts), `CTF-Difficulty`, and Mindmap's 424 images.

**Licence rule, restated because this account is the strongest case yet:** no
licence file means all rights reserved. Reading it to learn is fine; shipping its
text or images inside a released product is not. Convert to (check|probe|oracle|
rule), write kai's own words, and keep `source: Ignitetechnologies/<repo>` +
`confidence` only where the claim was independently verified.

**Verdict: low.** A marketing funnel with one usable table. An hour of name
extraction, never a clone — and everything valuable here already exists in the
corpus from licensed sources (Claude-BugHunter's taxonomy beats their `bugbounty`
list; SecurityTesting's checklists beat their Burp and Web-App tables).

---

## 4. What NOT to take

- **Do not vendor whole repositories.** Cybermes shows the cost: 173 MB and 4,732
  files to deliver a catalogue that is mostly other people's material.
- **Do not copy prose checklists as prompt text.** Their value is as structured
  checks — `{class, precondition, probe, oracle}` — not as paragraphs.
- **Do not adopt heavy runtimes.** Shannon's Docker + Temporal stack buys
  coverage kai cannot use at this stage.
- **Do not duplicate existing skills.** shannon, reverse-skill and
  humanize-skills are already integrated here. Adding them again is pure cost.
- **Licensing must be checked before any of this ships inside a paid product.**
  humanize-skills is CC-BY-4.0 (attribution required), Cybermes is Apache-2.0
  (NOTICE required), and Claude-BugHunter carries both `LICENSE` and
  `LICENSE-CONTENT`, which usually means code and content are licensed
  separately. Recommendation: keep third-party material as *ingested reference
  data* with attribution, write kai's own rules and taxonomy from scratch, and
  never re-license someone else's text as kai's own.

---

## 5. How this corpus feeds kai's learning loop

These repositories are **human-authored prose**, not machine-readable data. The
conversion step is kai's, and it is the same step for all of them:

```
source text  ->  extract checks/patterns/rules  ->  normalise  ->  pattern library / policy templates
                 (with source + confidence)        (one schema)     (keyed to archetype, entity, invariant)
```

Concretely, per source type:

| Source | Extraction target | Output artifact |
|---|---|---|
| Param→class tables (SecurityTesting) | Class + precondition + probe + oracle | `patterns/*.yaml` |
| Per-class checklists (SecurityTesting, HuntingCheckList) | Atomic test steps with pass/fail signal | `checks/*.yaml` |
| `rules/*.md` (Agentic-Bug-Hunter) | Policy rules and banned phrasing | `policy/*.yaml` + report lint rules |
| `hunt-*` skill names (Claude-BugHunter, Cybermes) | Taxonomy → pattern key namespace | pattern key registry |
| Disclosed-report corpus (Claude-BugHunter) | Already-found map per class | dupe-avoidance index + negative-space map |
| Report templates (SecurityTesting PDFs) | Section schema per platform | `report/*.md` skeletons |
| leanrea router + rules | Tool-per-target routing, evidence markers | RE path config + confidence vocabulary |
| humanize-skills | Prose rules, no-edit gate | report layer call (no reimplementation) |

The one structural rule: **every extracted item keeps its source and its
confidence.** Anything that cannot be traced to a source stays `inferred` and is
never presented as fact. That is what separates a pattern library from a rumour
mill — and it is the same rule the reference repos themselves apply to their own
findings.

---

## 6. Submission patterns — platforms and self-hosted

The operator plans to add submit patterns for multiple platforms; the plan is
consistent with what is in this corpus.

Per-platform driver fetch targets (from the H1 MCP driver read here, plus the
gate rule from Agentic-Bug-Hunter):

| Platform type | Fetch | Contract fields |
|---|---|---|
| HackerOne | GraphQL: program, structured scope, policy text, disclosed reports | scope in/out, bounty table, exclusions, required headers/identity, submission fields |
| Bugcrowd / Intigriti / Cantina / Immunefi | platform adapter per driver | same normalised contract |
| Self-hosted (e.g. Relay) | `/.well-known/security.txt` → `Policy:` URL → docs page | reward model, out-of-scope, PoC requirements, submission channel, identity/KYC requirements |

Relay is a good worked example of why self-hosted needs its own driver: its
policy encodes a severity×likelihood payout matrix with modifiers, a $500 floor
and $100k cap, "admin-only = S1", "theft outranks freeze", **runnable PoC required
for S3/S4**, an explicit out-of-scope list that names individual contracts
(Relay Vaults), submission by email (`support@relay.link`, one finding per email),
and KYC/KYB plus tax documents before payment. None of that is inferable from a
generic scan of the site — it is in the policy text and in
`/.well-known/security.txt` (RFC 9116, with `Policy:` and `Expires:`).

Because the reward model is machine-readable once extracted, kai can rank
hypotheses by **expected value in dollars** (severity × likelihood × modifiers)
instead of by a technical score. That is a direct consequence of this data being
part of the contract rather than part of the docs.

---

## 7. Immediate next step

Nothing here should be built before the operator gives the go. When that happens,
the cheapest useful first move is:

1. Extract the two param→class tables and the per-class checklists into
   `patterns/*.yaml` + `checks/*.yaml` with source citations (pure data work, no
   requests, no LLM).
2. Extract `rules/hunting.md` + `rules/reporting.md` into `policy/*.yaml`.
3. Build the MCP-style HackerOne driver against `get_program_scope` +
   `search_disclosed_reports`, using the existing `internal/program/hackerone.go`
   as the base.

All three are offline, testable without touching any target, and each one makes
the next stage cheaper.
