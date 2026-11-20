# Deferred ideas

This file is not a roadmap for kai. kai is **frozen** as a context harness: no hunting, no
validation, no report writing, no submission inside the binary. The ideas below **may** be
implemented as long as they stay deterministic *context artifacts*.

## Status

- [x] 1. `validation-gate.md` generated automatically — consumed by `kai export`.
- [x] 2. Hypothesis clusters — `clusters` + `variants` in `next.json`.
- [x] 3. `tags` in `next.json` — `api`, `auth`, `idor`, `logic`, and so on.
- [x] 4. `kai export <program> --to <dir>` — a bridge into a campaign folder.

## 1. Automatic `validation-gate.md`

**Source:** `awarexone/Agentic-Bug-Hunter` (7-question gate),
`elementalsouls/Claude-BugHunter` (triage validation).

The gate questions are pre-filled from kai's own data:

- did the target pass `scope.txt`
- is the impact class accepted by the program (from `boundaries.md`)
- is there a PoC or reproducible evidence
- is it already in `findings/dupes.md`

kai can produce this file deterministically from `intake.json` + `boundaries` + the ledger. It is
consumed by the downstream validator, not by kai.

## 2. Hypothesis clusters in `next`

**Source:** `KeygraphHQ/shannon` (finding reconciliation: merge + dedupe).

Dozens of endpoints with the same root, for example `/api/organizations/{id}/...`, still show up as
separate hypotheses. They are merged into one hypothesis plus a list of variants, so an agent does
not re-test the same surface.

## 3. `tags` in `next.json`

**Source:** `zhaoxuya520/reverse-skill`, `aegisxresearch/AegisX-Skills`
(a router plus an index, instead of dumping every skill).

Tags such as `["api", "auth-required", "idor", "priority-high"]` let an agent retrieve by tag instead
of loading 150 hypotheses at once. This matches the index-first pattern: read the index, load the
detail only on a match.

## Philosophy kai already follows

- `aicodeking/leanrea`: small skills, an agent driving real tools — cheaper and faster than an MCP
  server with hundreds of tools.
- `DietrichGebert/ponytail`: write only what is needed, but never cut validation, error handling or
  safety.
- `blader/humanizer`: matters for report drafts, not for kai.

## Note

Do not implement any of this before a downstream skill actually needs it. Otherwise kai only gets
fatter with nobody using the new parts.
