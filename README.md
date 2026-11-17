# kai

> **Tahu batasnya, siapkan konteksnya.**

`kai` adalah context packer deterministik untuk bug bounty. Ia mengerjakan
Fase 0–3 (pemahaman program → recon → pemetaan → antrian tes), lalu
menghasilkan **satu ZIP kecil** yang langsung bisa dipakai agen **Kairos**.

Bukan tool recon baru. Nilainya ada pada **state lintas-run**, **batasan yang
terdokumentasi**, dan **brief yang sudah disaring**.

---

## Kenapa perlu kai

Masalah yang dijawab:

| Masalah | Jawaban kai |
|---|---|
| Agent mengulang permukaan yang sama → duplikat | `first_seen` / `last_seen` + `diff`: yang baru saja yang diprioritaskan |
| Aturan program tersebar di banyak halaman | `boundaries.md`: scope + out-of-scope + prohibited + submission, verbatim |
| Policy panjang, RTK Kairos memotong output >500 char | `BRIEF.md`, satu halaman, urut: Phase 0 → Boundaries → Scope → Start here |
| Hasil tiap run berbeda-beda | Ekstraksi deterministik + confidence + snapshot |

---

## Peta fase

| Fase | Perintah | Keluaran |
|---|---|---|
| 0 — Program | `kai intake <url>` | `intake.json`, `program.md`, `boundaries.md`, `policy.md` |
| 1 — Batasan | `kai boundaries <program>` | aturan main, email/kanal submit, header wajib |
| 2 — Permukaan | `kai recon <program>` / `kai analyze <program>` | `assets.json`, `state/`, `nonweb.*` |
| 3 — Antrian | `kai next <program>` | `map.json`, `next.json` + alasan & probe |
| Serah | `kai pack <program>` | `dist/<program>_<ts>.zip` |
| QA | `kai audit <program>` | 30 pengecekan konsistensi |

`kai run <url>` menjalankan semuanya sekaligus.

---

## Setup awal

### Opsi 1 — Go terpasang

```bash
go install github.com/hourx/kai/cmd/kai@latest
kai version
```

### Opsi 2 — dari source

```bash
git clone https://github.com/hourx/kai.git
cd kai
go build -o bin/kai ./cmd/kai
go test ./...
install -m 0755 bin/kai /usr/local/bin/kai
```

### State root

Secara default kai memakai `./data` **relatif terhadap direktori saat ini**.
Itu sering bikin bingung kalau kamu pindah folder. Lebih baik eksplisit:

```bash
mkdir -p ~/.kai
echo 'export KAI_HOME="$HOME/.kai/data"' >> ~/.bashrc   # atau ~/.zshrc
source ~/.bashrc
```

`BOUNTYKIT_HOME` masih diterima sebagai alias lama.

### Cek lingkungan

```bash
kai doctor
```

Menampilkan: git, Go, adapter recon (`subfinder`, `gau`, `nuclei`, …), proxy,
state root, semua program + status session, dan konektivitas.

---

## Pemakaian sehari-hari

```bash
kai doctor                                      # sekali saat setup
kai run 'https://hackerone.com/anthropic'       # alur lengkap, satu perintah
kai run 'https://hackerone.com/anthropic' --step  # berhenti tiap fase
kai audit anthropic                             # cek ZIP sebelum diserahkan
```

`kai run` melakukan: intake → boundaries → session check → recon → analyze →
next → pack → audit. Kalau program tidak punya scope host (web3 / on-chain),
`recon` otomatis dilewati dan jalur non-web yang dipakai.

### Contoh sumber

```bash
# HackerOne
kai run 'https://hackerone.com/temu?type=team'

# GitBook di domain sendiri (varian .md terbaca otomatis)
kai run 'https://docs.ticko.xyz/resources/ticko-bug-bounty' --trust-scope

# Platform lain
kai run 'https://immunefi.com/bug-bounty/beanstalk/information/'
kai run 'https://bugbounty.meta.com/payout-guidelines/muse'
```

`--trust-scope` hanya untuk sumber teks (heuristic), dan **hanya setelah** kamu
memverifikasi host di `policy.md`. Untuk HackerOne tidak perlu.

---

## Daftar perintah

| Perintah | Fungsi |
|---|---|
| `run <url> [--step] [--clone] [--no-session] [--rps N] [-o dist] [--force]` | workflow lengkap |
| `intake <url> [--dry-run] [--name slug] [--force] [--trust-scope] [--max-links N]` | baca program + referensi |
| `boundaries <program>` | aturan & kutipan verbatim |
| `brief <program> [--out file]` | kartu konteks ~300 token (auto saat `pack`) |
| `track <program> list\|submit\|status\|payout\|retest` | ledger submit → triage → payout |
| `backup [--out file] [--include-session] [--include-repos]` | salinan state di luar repo |
| `restore <file.tar.gz> [--dest dir]` | pulihkan state |
| `rules-diff <program>` | perubahan aturan antar-intake |
| `scope <program> <host\|cidr>` | gate IN/OUT (exit 0/1/2) |
| `session <program> [show\|set\|clear] [--har f] [--cookie s] [--header 'K: V']` | sesi untuk recon |
| `recon <program> [--rps N] [--nuclei] [--step] [--no-session]` | discover → probe → harvest → diff |
| `diff <program>` | permukaan baru sejak run terakhir |
| `analyze <program> [--clone] [--refresh]` | repo & kontrak in-scope |
| `map <program>` / `next <program>` | peta & antrian tes |
| `pack <program> [-o dist] [--include-raw] [--include-session]` | ZIP handoff |
| `audit <program\|file.zip> [-dir dist]` | cek konsistensi (30 pengecekan) |
| `doctor [--no-net]` | cek lingkungan |
| `status [<program>]` | ringkasan program |
| `version` | versi + commit |

---

## State, kartu konteks & triage

- **`brief-compact.md`** dibuat otomatis saat `pack`, berisi maksimal ~300 token:
  platform, verdict, scope, boundary, kanal submit, dan 5 target teratas.
  Ini untuk Orchestrator agent. Detail tetap ada di `BRIEF.md` dan `next.md`.
- **`kai backup`** menyalin `data/` + `dist/` ke satu `.tar.gz` di luar repo.
  Default **tidak** menyertakan `session.json` dan repo hasil clone. Simpan
  arsip ini di mesin lain — VPS yang mati tidak membawa state bersamanya.
- **`kai track`** mencatat lifecycle temuan: submit → needs-info → duplicate/
  informative → resolved → paid. Alasan penolakan otomatis masuk
  `findings/dupes.md` dan `findings/lessons.md`, lalu ringkasannya tampil di
  `BRIEF.md`. Ini catatan manual — tool tidak menghubungi platform.

Contoh:

```bash
kai track anthropic submit 1                       # ambil target #1 dari next.json
kai track anthropic status f-001 needs-info --note 'butuh akun kedua'
kai track anthropic status f-001 duplicate --note 'akar sama dengan laporan lama'
kai track anthropic payout f-001 --amount 250
kai backup --out ~/bountykit-state.tar.gz
```

---

## Artefak

```
$KAI_HOME/<program>/
  meta.json  program.md  scope.txt  out-of-scope.txt
  boundaries.md   aturan + kutipan verbatim
  brief-compact.md  kartu ~300 token untuk agen
  policy.md       policy asli
  intake.json     data Phase 0 + scorecard
  rules-diff.*    perubahan aturan
  intakes/<ts>/   snapshot intake
  assets.json     host + endpoint + hash JS
  diff.json/.md   delta permukaan
  session.json    cookie, mode 0600
  nonweb.json/.md hasil analyze
  findings/       ledger.json + lessons.md + dupes.md
  map.*  next.*
  state/          subs, live, urls, js, endpoints, ranked
  snapshots/<ts>/
  repos/          clone (hanya dengan --clone)

dist/<program>_<ts>.zip
  <program>/
    BRIEF.md  program.md  boundaries.md  brief-compact.md  policy.md  LEDGER.md
    scope.txt  out-of-scope.txt
    recon/                    konvensi Kairos
    bountykit/                ← kontrak internal, tetap walau produk bernama kai
      MANIFEST.json  intake.json  rules-diff.md
      diff.md  map.*  next.*  nonweb.*
      ledger.json  lessons.md  dupes.md
      session.json            hanya dengan --include-session
```

> `bountykit/` di dalam ZIP **bukan** nama produk. Itu kontrak dengan
> `bugbounty-pipeline` di Kairos. Jangan diganti.

---

## Aturan keras

1. `scope.txt` kosong → recon menolak.
2. `out-of-scope.txt` selalu menang.
3. URL dengan path (`/api/*`) tidak dilebarkan jadi aturan host.
4. Host dari teks prose tetap kandidat sampai diverifikasi + `--trust-scope`.
5. Yang tidak dipublikasikan = `unknown`, bukan izin.
6. Sumber heuristic selalu verdict `review`, tidak pernah `go`.
7. Session tidak pernah masuk ZIP kecuali `--include-session` (dan tool memperingatkan).
8. Cookie/header session hanya dikirim ke host in-scope — bukan CT service/CDN.
9. `intake` hanya baca halaman publik. Tidak login, tidak menyerang target.
10. `data/`, `dist/`, `*.zip` gitignored — tidak ada data target di repo.

---

## Pengetahuan lapangan

Hal-hal yang nyata ditemukan saat membangun dan menguji kai:

### Batasan & aturan

- **Scope bisa berbasis dampak, bukan host.** Program seperti Ticko/Hyperliquid
  tidak punya daftar host; `recon` akan menolak, dan itu benar. Pakai `analyze`.
- **Wildcard ≠ apex.** `*.example.com` tidak mencakup `example.com`.
- **Path-scoped itu jebakan.** `example.com/api/*` kalau dilebarkan jadi
  `example.com` berarti mengizinkan pengujian di luar izin program.
- **Email di policy bukan kanal submit.** Untuk HackerOne, laporan tetap lewat
  form H1; email di policy hanya kontak. kai mencatat keduanya terpisah.
- **Out-of-scope butuh kata kunci, bukan heading.** Banyak policy menaruh
  aturan di bullet tanpa judul khusus; kai mengambil baris per kata kunci.

### Recon & permukaan

- **Program padat = diff lebih penting dari jumlah endpoint.** Anthropic:
  5.282 laporan/90 hari. Mengulang jalur lama hampir pasti duplikat.
- **Session adalah pembeda hasil.** Recon Anthropic tanpa session: 2 endpoint.
  Dengan session: **728 endpoint, 72 bundle JS**. Area ber-login tidak bisa
  dipetakan dari luar.
- **JS sering di CDN luar scope.** kai mengambil bundle publik itu tanpa
  mengirim cookie, dan tidak memasukkannya ke `urls.txt`.
- **Regex JS menghasilkan path palsu** (`/412`, `${e}`, `:app_id`). kai
  menormalisasi placeholder jadi `{id}` dan membuang angka murni.
- **Repo organisasi bisa diuraikan.** `github.com/org` kini diambil daftar
  repo publiknya lewat GitHub API (max 30 terbaru); repo archived/fork dilewati
  sesuai kebanyakan policy. Tanpa token, API publik rate-limited ~60/jam.
- **Skor yang semua sama = nol informasi.** 14 endpoint IDOR skor 200 tidak
  membantu; kai menambah bobot untuk `key_material`, `recovery`, `export`,
  `balance`, `transfer`, dll.

### Sesi & akses

- **HAR bisa sanitized.** 576 request tapi 0 `Cookie` — itu export browser,
  bukan bug kai. Cari opsi *Export HAR (with sensitive data)*.
- **`cf_clearance` terikat IP.** Cookie Cloudflare dari Mac tidak otomatis
  dipakai VPS. Kalau masih `403 Just a moment...`, itu Cloudflare, bukan session.
- **Cookie HAR mengandung pihak ketiga.** kai hanya mengimpor cookie untuk host
  in-scope; analytics/CDN dibuang.
- **Jangan pernah simpan session di repo atau ZIP.** Setelah selesai, rotasi.

### Workflow

- **`KAI_HOME` lebih aman daripada `./data`.** Tanpa itu, `kai run` dari `/root`
  membuat workspace baru di `/root/data` dan session lama tidak ketemu.
- **Audit sebelum serah.** `kai audit` menangkap masalah yang tidak terlihat:
  hash manifest, score yang beda antarfile, ranked table yang tidak cocok,
  session yang tanpa sadar ikut ter-pack.
- **Nama internal tetap.** Produk bernama `kai`, tapi folder `bountykit/` di ZIP
  tidak boleh diganti.

---

## Trouble cepat

| Gejala | Arti / tindakan |
|---|---|
| `no domains` | scope kosong; isi manual atau ulangi `intake` |
| `crt.sh(status 502)` | CT publik gangguan; Cert Spotter jalan paralel |
| verdict `review` | sumber heuristic; verifikasi dulu sebelum `--trust-scope` |
| `bundles 0` | tidak ada script di HTML, atau semua di luar scope |
| `session none` | HAR belum punya cookie / path salah |
| `403 Just a moment...` | Cloudflare; butuh session dari browser/IP yang sama |
| `audit FAIL` | jangan diserahkan ke Kairos; baca baris FAIL |
| `unknown program` | state root salah → cek `KAI_HOME` / `pwd` |
| VPS mati / ganti VPS | `kai restore backup.tar.gz`, lalu impor session ulang |

---

## Instalasi lewat npx?

Belum. `npx` adalah runner paket **npm/Node.js**, sedangkan kai adalah biner
**Go**. Supaya `npx kai` jalan, perlu paket pembungkus kecil (mis.
`@hourx/kai`) yang mengunduh biner dari GitHub Releases. Itu bisa dibuat
belakangan — bukan mengubah kai jadi library.

Sekarang: `go install github.com/hourx/kai/cmd/kai@latest`.

---

## Status

`kai 0.9.0-dev` — Phase 0–3 lengkap, workflow satu perintah, audit otomatis.

| Versi | Isi |
|---|---|
| v0.1–v0.3 | scope gate, pack, recon, diff, session, map, next |
| v0.4–v0.6 | intake multi-sumber, boundaries verbatim |
| v0.7–v0.8 | rule diff, aset non-web, analisis repo/kontrak |
| v0.9 | identitas `kai`, `run` / `audit` / `doctor` |
| v0.10 | backup/restore, compact brief, triage ledger |

Fitur selesai. Setelah ini **freeze** — kai adalah penyiap konteks, bukan agen hunting.
| v1.0 | config file, penguraian repo organisasi, wrapper npm |

Desain lengkap: [`SPEC.md`](SPEC.md).
