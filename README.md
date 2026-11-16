# kai

Pembantu Phase 0–3 bug bounty: membaca aturan program, memetakan permukaan,
lalu menghasilkan satu ZIP yang langsung bisa dipakai Kairos (`bugbounty-pipeline`).

Bukan tool recon baru. Nilainya ada di **state lintas-run** (`first_seen` /
`last_seen` + diff), **batasan yang terdokumentasi**, dan **brief kecil** yang
dibaca agent sebelum mulai hunting.

Desain: [`SPEC.md`](SPEC.md).

---

## Mulai dari sini (satu perintah)

```bash
kai doctor                  # cek lingkungan sekali jalan
kai run 'https://hackerone.com/anthropic'
kai run 'https://hackerone.com/anthropic' --step    # mode belajar: berhenti tiap fase
```

`kai run` melakukan urutan di bawah otomatis: intake → boundaries → session check →
recon → analyze → next → pack → audit. Kalau tidak ada scope host (program web3),
recon dilewati dan jalur non-web yang dipakai.

Di bawah ini urutan **manual** — berguna kalau mau mengawasi tiap tahap atau
sedang mempelajari alurnya.

Contoh memakai program HackerOne. Ganti `temu` dengan programmu.

### 0. Cek dulu layak tidaknya (tanpa bikin apa-apa)

```bash
kai intake 'https://hackerone.com/temu?type=team' --dry-run
```

Keluar scorecard: reward, jumlah report 90 hari, efficiency, dan scope yang
publish. Verdict `go` / `careful` / `skip` / `vdp-only` / `review`.

### 1. Buat workspace

```bash
kai intake 'https://hackerone.com/temu?type=team'
```

Terbuat `data/temu/` berisi `scope.txt`, `out-of-scope.txt`, `policy.md`,
`boundaries.md`, `program.md`, `intake.json`.

Secara default `intake` juga **mengikuti link dokumentasi yang relevan** dari
halaman utama (maksimal 8 halaman, domain yang sama saja): guide testnet,
halaman reward, cara submit, dan sejenisnya. Semua teksnya digabung sebelum
aturan diekstrak, jadi email submission, host testnet, dan aturan tambahan
masuk dalam satu kali jalan. Daftar halaman yang dibaca ada di `intake.json`
dan di scorecard. Matikan dengan `--no-follow`, atau ubah batasnya dengan
`--max-links 12`.

### 2. Baca batasan sebelum apa pun

```bash
kai boundaries temu
```

Ini **kontrak program**: aturan mainnet/testnet, PoC, KYC, header wajib, dan
kutipan verbatim bagian in-scope / out-of-scope / prohibited / disclosure.
Yang tidak dipublikasikan ditulis `unknown` / "not stated" — bukan izin.

### 3. Periksa scope, lalu gate tiap host

```bash
cat data/temu/scope.txt data/temu/out-of-scope.txt
kai scope temu www.temu.com     # exit 0=IN, 1=OUT, 2=error
kai scope temu evil.temu.com.evil.test
```

`out-of-scope.txt` selalu menang. Empty `scope.txt` membuat recon menolak jalan.

### 4. (Opsional) Impor session kalau mau petakan area login

```bash
kai session temu set --har ~/Downloads/burp.har
kai session temu show                      # nilai disembunyikan
kai recon temu                             # otomatis pakai session
kai session temu clear
```

Tanpa session, yang dipetakan hanya permukaan unauth. `--no-session` untuk
memaksa recon tanpa session.

### 5A. Jalur web — recon

```bash
kai recon temu                 # crt.sh + Cert Spotter (+adapter kalau ada)
kai recon temu --step          # mode belajar: berhenti tiap fase
kai diff temu                  # apa yang baru sejak run terakhir
```

Host eksak dari `scope.txt` diprobes langsung. Wildcard baru di-enumerasi
subdomainnya. Semua host lolos gate dulu sebelum ada request keluar.

### 5B. Jalur non-web — repo & kontrak

Untuk program seperti Uniswap (Cantina), Beanstalk (Immunefi), Hyperliquid,
Ethereum, atau Muse:

```bash
kai analyze uniswap             # tanpa clone: lihat daftar aset dulu
kai analyze uniswap --clone     # clone repo in-scope ke data/<program>/repos/
kai analyze uniswap --refresh   # git pull repo yang sudah ada
```

`analyze` membaca workflow CI (mis. `pull_request_target`, `${{ github.event.* }}`,
`write-all`), install-time scripts, manifest, entry point kontrak, dan alamat
kontrak beserta explorer-nya. Hasilnya `nonweb.md` / `nonweb.json`.

### 6. Bangun peta dan antrian tes

```bash
kai map temu                   # modul, object ref, parameter, aset non-web
kai next temu                  # antrian terurut + alasan + probe pertama
```

`recon` dan `analyze` otomatis menyegarkan keduanya. `next` memasukkan aset
non-web, dan probe-nya mewarisi batasan — program yang melarang mainnet akan
bilang "use testnet or a local fork only" di probe pertamanya.

### 7. Cek perubahan aturan

```bash
kai rules-diff temu
```

Tiap intake di-snapshot ke `intakes/<ts>/`. Kalau program mencabut host dari
scope, mengubah reward, atau mengedit policy, ini muncul di sini dan di
`BRIEF.md`.

### 8. Pack untuk Kairos

```bash
kai pack temu -o dist
kai pack temu -o dist --include-session   # HANYA kalau agent perlu auth
```

Lalu di mesin Kairos:

```bash
unzip dist/temu_*.zip -d workspace/
```

ZIP berisi `BRIEF.md` yang dibuka dengan Phase 0 → Boundaries → perubahan
aturan → scope → Start here (ranked) → diff permukaan.

---

## Contoh singkat: sumber non-HackerOne

```bash
# 1. baca (verdict selalu "review" untuk sumber teks)
kai intake cantina.xyz/bounties/f9df94db-c7b1-434b-bb06-d1360abdd1be --dry-run

# 2. buat workspace
kai intake cantina.xyz/bounties/f9df94db-c7b1-434b-bb06-d1360abdd1be \
  --name uniswap

# 3. baca batasan
kai boundaries uniswap

# 4. host dari teks prose MASIH kandidat, belum aktif.
#    Verifikasi di policy.md, lalu aktifkan kalau setuju:
kai intake cantina.xyz/bounties/f9df94db-c7b1-434b-bb06-d1360abdd1be \
  --name uniswap --force --trust-scope

# 5. lanjut seperti biasa
kai analyze uniswap --clone
kai next uniswap
kai pack uniswap -o dist
```

Sumber yang didukung: HackerOne (GraphQL terstruktur), Cantina, Immunefi,
GitBook (varian `.md`), `bugbounty.meta.com`, `ethereum.org`, dan halaman
mandiri lain.

---

## Daftar perintah

| Perintah | Fungsi |
|---|---|
| `run <url> [--step] [--clone] [--no-session] [--rps N] [-o dist]` | workflow lengkap satu perintah |
| `audit <program\|file.zip> [-dir dist]` | cek konsistensi ZIP / handoff |
| `doctor [--no-net]` | cek git, Go, adapter, proxy, session, konektivitas |
| `init <program> [--platform P] [--url U] [--domain d,d]` | workspace kosong manual |
| `intake <url\|handle> [--name slug] [--dry-run] [--force] [--trust-scope] [--max-links N] [--no-follow]` | Phase 0 dari halaman program + referensinya |
| `boundaries <program>` | aturan, batasan, kutipan verbatim |
| `rules-diff <program>` | perubahan aturan vs intake sebelumnya |
| `scope <program> <host\|cidr>` | gate IN/OUT (exit 0/1/2) |
| `session <program> [show\|set\|clear] [--har f] [--cookie s] [--header 'K: V']` | session untuk recon |
| `recon <program> [--domain d] [--rps N] [--nuclei] [--step] [--no-session]` | discover → probe → harvest → diff |
| `diff <program>` | permukaan baru sejak run terakhir |
| `analyze <program> [--clone] [--refresh]` | repo & kontrak in-scope |
| `map <program>` | peta endpoint + aset non-web |
| `next <program>` | antrian tes terurut |
| `pack <program> [-o dist] [--include-raw] [--include-session]` | ZIP handoff |
| `status [<program>]` | ringkasan semua program |
| `version` | versi + commit |

---

## Aturan keras

1. `scope.txt` kosong → recon menolak. Tidak ada pengecualian.
2. `out-of-scope.txt` selalu menang.
3. Host dari teks prose tetap kandidat sampai diverifikasi + `--trust-scope`.
4. Aset berskope path tidak pernah dilebarkan jadi aturan host.
5. Aturan yang tidak dipublikasikan = `unknown`, bukan izin.
6. Sumber heuristic selalu verdict `review`, tidak pernah `go`.
7. Session tidak pernah masuk ZIP kecuali `--include-session` (dan tool memperingatkan). Cookie/header session hanya dikirim ke host in-scope, bukan ke crt.sh/CDN.
8. `intake` hanya baca halaman publik. Tidak login, tidak menyentuh aset target.
9. `data/`, `dist/`, `*.zip` tidak pernah masuk git.

Semantik gate identik dengan `Kairos/scripts/scope_check.py`:

| Rule | Arti |
|---|---|
| `api.example.com` | exact host |
| `*.example.com` | subdomain saja, apex tidak ikut |
| `203.0.113.0/24` | CIDR |
| out-of-scope | selalu menang |

---

## Artefak

```
data/<program>/
  meta.json  program.md  scope.txt  out-of-scope.txt
  boundaries.md            aturan + batasan + kutipan verbatim
  policy.md                policy asli
  intake.json              data Phase 0 + scorecard + boundaries
  rules-diff.json/.md      perubahan aturan
  intakes/<ts>/            snapshot intake
  assets.json              host, endpoint, hash JS + first_seen/last_seen
  diff.json/.md            delta permukaan
  session.json             cookie (0600, tidak ikut pack by default)
  nonweb.json/.md          hasil analyze
  map.json/.md  next.json/.md
  state/                   subs, live, urls, js, endpoints, ranked
  snapshots/<ts>/          riwayat aset
  repos/                   clone repo (hanya dengan --clone)
  audit.log

dist/<program>_<ts>.zip
  <program>/
    BRIEF.md  program.md  scope.txt  out-of-scope.txt
    boundaries.md  policy.md  LEDGER.md
    recon/                   sesuai konvensi Kairos
    kai/
      MANIFEST.json  intake.json  rules-diff.md
      diff.md  map.json/.md  next.json/.md  nonweb.json/.md
      session.json           hanya dengan --include-session
```

`KAI_HOME` mengganti root `./data`.

Pipeline memakai folder `targets-<name>/`; pack ini memakai `recon/`
(konvensi `docs/BUG-BOUNTY.md`). Pemetaan namanya ditulis di `BRIEF.md`.

---

## Masalah umum

| Gejala | Arti / tindakan |
|---|---|
| `no domains` di recon | scope.txt tidak punya host atau wildcard. Isi manual atau ulangi `intake`. |
| `crt.sh(status 502)` | CT publik sedang gangguan. Cert Spotter jalan paralel; cakupan mungkin kurang lengkap. |
| verdict `review` | Sumber bukan H1 terstruktur. Verifikasi scope di `policy.md` sebelum `--trust-scope`. |
| `no host-level scope` | Program web3 / non-HTTP. Pakai `analyze`, bukan `recon`. |
| GitBook di domain sendiri (`docs.*`) | Tetap dibaca lewat varian `.md` di sebelah halaman. |
| `mainnet testing is forbidden` | Jangan kirim request ke produksi. Pakai testnet/local fork. |
| `session none` | Area login belum dipetakan. Impor HAR dulu kalau program mengizinkan. |
| `rules-diff` baseline | Baru intake pertama; belum ada pembanding. |

---

## Install

```bash
# paling cepat kalau Go sudah ada
go install github.com/hourx/kai/cmd/kai@latest

# dari source
git clone https://github.com/hourx/kai.git
cd kai
go build -o bin/kai ./cmd/kai
go test ./...
```

Go 1.21+. Tanpa cgo, tanpa dependency eksternal. Biner bisa juga diunduh dari
GitHub Releases (rencana).

### Soal `npx kai`

Belum tersedia, dan itu bukan satu hal yang sama dengan tool ini:

- **npm** = package manager untuk ekosistem **Node.js**
- **npx** = runner yang mengunduh lalu menjalankan paket npm
- **kai** = biner **Go**, bukan paket npm / bukan library

Supaya `npx kai` bisa dipakai, perlu paket npm kecil (mis. `@hourx/kai`) yang
cuma mengunduh biner Go dari GitHub Releases lalu memanggilnya. Itu bisa
dibuat belakangan setelah rilis stabil — bukan mengubah kai jadi library.

| Versi | Isi |
|---|---|
| v0.1–v0.3 | scope gate, pack, recon, diff, session, map, next |
| v0.4–v0.6 | intake H1 + multi-sumber, boundaries verbatim |
| v0.7–v0.8 | rule diff, aset non-web, analisis repo/kontrak, referensi dokumentasi |
| v0.9 | rename identitas `kai`, module & remote GitHub |
| v1.0 | `run`, `audit`, `doctor` — satu perintah untuk alur penuh |
