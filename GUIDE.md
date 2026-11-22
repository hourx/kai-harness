# Using kai — from install to a finished program

`README.md` is the reference. This is the walkthrough: get the binary onto the box, point it
at one bug-bounty program, and run the loop that turns a policy page into a ranked queue, a
trail of evidence, and a draft submission.

The mental model is one sentence: **kai is a bookkeeper, not a hunter.** It reads a program,
tells you what the surface is, remembers what you tested, and refuses to let you wander out of
scope. It never sends an attack. You do that — and you tell it what happened.

---

## 0. Install

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

There are no prebuilt binaries in the releases — a tag is the source, and Go is the build. To
put kai on a box that has no Go, build once elsewhere and copy the binary over:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o kai-linux-amd64 ./cmd/kai
scp kai-linux-amd64 box:/usr/local/bin/kai
```

### Make it callable from anywhere

`go install` drops the binary in `$(go env GOPATH)/bin`, which is not on the PATH of a fresh
root shell. Put it where the shell already looks:

```bash
install -m 0755 "$(go env GOPATH)/bin/kai" /usr/local/bin/kai
which kai && kai version
```

### Pin the state root, once

kai keeps one directory per program under a **state root**, plus a `dist/` output directory.
The root defaults to `./data` — relative to the directory you happen to be standing in, which
means `kai next acme` works in one terminal and says `unknown program` in the next. Pin it:

```bash
mkdir -p ~/.kai
echo 'export KAI_HOME="$HOME/.kai/data"' >> ~/.bashrc
source ~/.bashrc
echo "$KAI_HOME"          # /root/.kai/data
```

Every program now lives in `$KAI_HOME/<slug>/`, no matter where you run kai from. `KAI_HOME` is
the **only** environment variable that changes where things go, and it is the answer to almost
every "unknown program" error.

### Check the box before you trust it

```bash
kai doctor            # git, go, recon adapters, proxy, state root, per-program, network
kai doctor --no-net   # skip the network probe
```

It prints `OK`/`FAIL` per check and exits non-zero if anything failed, so it is safe to put in a
provisioning script.

---

## 1. Open the workspace

On a terminal, with no arguments:

```bash
kai
```

That is the split-pane face: panes over the deterministic state — what the program is, the ranked
queue, evidence, and the live process output — with a command line at the bottom of the screen.

Commands typed there run in place: `/enum [--rps N]` `/map` `/next` `/queue` `/plan` `/board`
`/status` `/evidence` `/scope <host>` `/programs` `/probe` `/harvest` `/help` `/clear` `/abort`
`/quit`. The panes only ever show state a command actually wrote, so an empty pane means
"nothing recorded yet", not "loading".

- `kai` (no args, real terminal) → the workspace, no program attached
- `kai tui acme` → the same workspace, focused on one program
- `kai tui acme --demo` → a canned screen, no workspace needed (good for seeing the layout)
- piped or redirected stdout (a script, a CI box, this agent) → not a TTY, so kai prints help
  instead of trying to draw. Every command works the same either way; only the bare `kai` case
  changes.

If you would rather not have panes, use the CLI directly — the panes are a pure view over the
same artifacts, never a second source of truth.

---

## 2. Phase 0 — teach it the program

One program, one slug. Give it the policy URL:

```bash
kai intake https://hackerone.com/acme --name acme
kai intake https://acme.com/security --name acme --dry-run   # look first, write nothing
```

This reads the program page and its linked documentation and writes the workspace:

| Artifact | What it is |
|---|---|
| `state/scope.txt` | hosts, wildcards, CIDRs that are in scope, one per line |
| `state/out-of-scope.txt` | the explicit exclusions |
| `state/program.yaml` | the contract of record: platform, rules, provenance for every line |
| `policy.md` | the raw policy text it read, kept verbatim |

**Now open `state/scope.txt` and `out-of-scope.txt` and fix them by hand.** Intake is a first
draft from a machine-readable page, and policy pages lie in the details — a wildcard that does
not cover the apex, an exclusion buried in prose, a second domain mentioned in a footnote.

Then confirm the gate agrees with you:

```bash
kai boundaries acme                 # the scope limits and rules, as kai understands them
kai scope acme api.acme.com         # exit 0 = in scope, 1 = out of scope, 2 = empty scope
kai contract acme --audit           # does the contract match the workspace?
kai drivers https://acme.com        # which platform driver claims this target
```

`kai scope` is the gate everything else obeys — recon, the queue, `kai decide` — so a wrong
`scope.txt` quietly poisons every later step. Spend the two minutes.

> Wildcard rule: `*.acme.com` does **not** cover `acme.com`. If the apex is in scope, list it as
> its own line. This is the single most common intake mistake.

---

## 3. Discover the surface

The full chain, one command, with a pause before each phase:

```bash
kai run https://hackerone.com/acme --step
```

`run` is intake → boundaries → session → recon → analyze → next → pack → audit. Without
`--step` it does not stop to ask. Useful flags: `--name slug`, `--rps 10` (be polite),
`--max-hosts N`, `--clone` (git clone in-scope repos), `--no-session`, `-o dist`.

Or drive the phases yourself, which is what you want once you know the program:

```bash
kai recon acme                       # walk the surface: hosts, live check, JS bundles
kai recon acme --domain acme.com --rps 5 --max-hosts 40
kai recon acme --nuclei              # slow; run it when you mean it
```

Authenticated recon — do it if the interesting surface is behind a login:

```bash
kai session acme set --har capture.har
kai session acme set --cookie 'session=...'
kai session acme set --header 'Authorization: Bearer ...'
kai session acme show                # what is stored
kai session acme clear
```

Then structure it and rank it:

```bash
kai map acme                         # endpoints → parameters, shapes, hypotheses
kai next acme                        # the ranked test queue: what to try, in order
kai diff acme                        # what moved since the last pass
```

`kai next` is the deliverable of phase 1: a ranked list where every row names a target, a class,
an action, and the evidence that would settle it. Work top-down.

---

## 4. Record what you learn — the outcome loop

Every time you finish with a target, tell kai what happened. This is the habit that makes the
tool worth using: the queue re-ranks on real results instead of guessing twice at the same thing.

```bash
kai outcome acme --status negation --class IDOR/BOLA api.acme.com/orders/123 --note "A cannot read B"
kai outcome acme --status finding  --class XSS       acme.com/search?q=  --note "stored via profile name"
```

Statuses (closed set): `negation` (tested, not a bug) · `informational` (works, no security
impact) · `finding` (proven bug, not yet submitted) · `reported` (submitted) · `paid`.

```bash
kai board                            # every program, what is worth doing today
kai board acme
kai status acme
kai audit acme                       # is the handoff internally consistent?
```

---

## 5. Decide what to do next

```bash
kai model acme                       # archetype, entities, anomalies, coverage, gaps
kai model acme --json
kai patterns acme                    # what applies to this shape, and what paid here before
kai shadow acme                      # lessons this workspace's outcomes propose (nothing applied)
kai shadow acme --adopt <id>         # adopt one, recorded in state/pattern-overrides.json
kai decide acme                      # ask the planner for the next steps (scope-gated)
kai plan acme                        # queue → waves by what each step needs
```

Three of those deserve a sentence:

- **`kai model`** answers "what have I *not* touched". The gaps list is the most honest to-do
  list in the tool — it is derived from coverage, not from vibes.
- **`kai patterns`** is the knowledge layer keyed by the shape of the program (archetype),
  adjusted by what actually paid in this workspace. `kai shadow` is the same idea one level up:
  it reads outcomes across your workspaces and *proposes* a lesson. Nothing is applied until you
  `--adopt` it, and `--revert` takes it back.
- **`kai decide`** is the only place a model is allowed to help. It writes
  `state/proposal.json`; every step in it has been re-checked against the scope gate and the
  action policy first. No endpoint configured → the deterministic proposer builds the same plan
  from the ranked queue. See the README section *The planner seam*.

---

## 6. Turn a finding into a submission

```bash
kai evidence acme add --kind screenshot --file shot.png \
  --host api.acme.com --method GET --path /orders/123 --status 200 \
  --note "A's session returns B's order" --target /orders/{id}
kai evidence acme import --har capture.har --label "run 1"   # bulk-import a browser/Burp capture
kai evidence acme list
kai evidence acme show <id>
kai evidence acme attach <id> --finding F-3                 # tie it to a findings/ledger.json id

kai report-draft acme <evidence-id> --platform hackerone
kai track acme submit <id> --url https://hackerone.com/reports/...
kai track acme list
kai track acme status <id>
kai track acme payout <id>
kai track acme retest <id>
```

`--kind` is one of `response | request | screenshot | poc | note | log`. `import` takes
`--limit N` to cap entries and `--keep-secrets` to store credential header values verbatim —
by default they become a length marker, so a capture can be filed without filing the session.

`evidence` stores hashed raw proof; `report-draft` fills the **platform's** field set from it
(that is why the platform matters — the fields differ). `track` is the ledger of what you sent,
what came back, and what got paid. Draft, review, then submit yourself.

---

## 7. Watch it from anywhere

```bash
kai serve                                     # http://127.0.0.1:8789
kai serve --addr 0.0.0.0:8789 --token auto    # non-loopback requires a token
```

A read-only HTTP/JSON view of the workspace, with a single-file dashboard: program list,
queue, findings, evidence, and a `watch live` panel (SSE over the recorded run events) so a
long recon can be watched from a phone instead of a terminal. It never mutates anything.

---

## 8. Keep the work, move the work

```bash
kai backup --out acme-$(date +%F).tar.gz     # snapshot state/ (+ --include-session, --include-repos)
kai restore acme-2026-11-23.tar.gz --dest ~/.kai/data
kai pack acme -o dist                        # handoff ZIP (+ --include-raw, --include-session)
kai export acme --to ~/Bug/acme              # agent context files into a campaign dir
```

`backup` is the durable copy of state; `pack` is what you hand to a teammate or an agent;
`export` drops the context files a campaign workspace expects.

---

## The daily loop, condensed

```bash
kai board                          # 1. what is worth doing today
kai next acme                      # 2. the ranked queue for the program you picked
#    ... test the top row, by hand ...
kai outcome acme --status <s> --class <c> <target>   # 3. record the result
kai model acme                     # 4. what is still untouched (the gaps)
kai board                          # 5. back to the top
```

Everything else (`recon`, `map`, `decide`, `patterns`, `evidence`, `report-draft`) is code you
run when the state has moved — a new program, a new auth session, a proven finding. The loop is
five commands and one honest line about what happened.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `unknown program` | `KAI_HOME` differs between shells | `echo $KAI_HOME`; pin it in `~/.bashrc` |
| `kai next` is empty | nothing ranked yet | run `kai map` then `kai next` (and check auth via `session show`) |
| intake found nothing | the page is a JS app, not server-rendered | paste the policy text into `state/scope.txt` by hand; `kai intake --dry-run` to see what it saw |
| a host is "out of scope" but is not | wildcard does not cover the apex | add the apex as its own line in `state/scope.txt` |
| the gate lets junk through | empty or wrong `scope.txt` | `kai scope acme <host>` must exit 0; exit 2 means the scope file is empty, so the check means nothing |
| bare `kai` prints help | stdout is not a TTY | use `kai tui acme`, or just use the CLI |

**Design contract, in one line:** kai runs nothing against a target on its own, and no LLM sits
in the request path. When a run with the model switched off is not a complete run, that is a bug.
