# Ide yang ditunda (deferred)

Catatan ini bukan roadmap kai. Kai **difreeze** di v0.10.x sebagai context
packer. Ide di bawah dipakai **saat fase skill Hermes**, bukan ditambahkan ke
binari kai.

## 1. `validation-gate.md` otomatis

**Sumber:** `awarexone/Agentic-Bug-Hunter` (7-Question Gate),
`elementalsouls/Claude-BugHunter` (triage-validation).

Isi 7 pertanyaan Skeptic sudah di-prefill dari data kai:

- apakah target lolos `scope.txt`
- apakah kelas dampaknya diterima program (dari `boundaries.md`)
- apakah ada PoC / bukti reproducible
- apakah sudah ada di `findings/dupes.md`

Kai bisa menghasilkan file ini secara deterministik dari `intake.json` +
`boundaries` + ledger. Dipakai agen Skeptic, bukan kai.

## 2. Cluster hipotesis di `next`

**Sumber:** `KeygraphHQ/shannon` (finding reconciliation: merge + dedupe).

Puluhan endpoint dengan akar sama, misalnya
`/api/organizations/{id}/...`, masih muncul sebagai hipotesis terpisah.
Digabung menjadi satu hipotesis + daftar varian supaya agen tidak
menguji ulang permukaan yang sama.

## 3. `tags` di `next.json`

**Sumber:** `zhaoxuya520/reverse-skill`, `aegisxresearch/AegisX-Skills`
(router + index, bukan dump semua skill).

Menambahkan tag seperti `["api", "auth-required", "idor", "priority-high"]`
 supaya agen bisa retrieval by tag tanpa memuat 150 hypotheses sekaligus.
Selaras dengan pola Maus/Hermes: index dulu, baca detail hanya saat cocok.

## Filosofi yang sudah dipakai kai

- `aicodeking/leanrea`: skill kecil, agen yang menjalankan tool nyata —
  lebih murah & cepat dari MCP dengan ratusan tool
- `DietrichGebert/ponytail`: tulis hanya yang perlu, tapi jangan pangkas
  validasi, error handling, atau keamanan
- `blader/humanizer`: penting untuk draft laporan, bukan untuk kai

## Catatan

Jangan implementasi ini sebelum ada skill Hermes yang benar-benar
membutuhkannya. Kalau tidak, kai cuma bertambah gemuk tanpa pemakai.
