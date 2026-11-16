# bountykit

Pembantu Phase 0–3 bug bounty: membaca aturan program, memetakan permukaan,
lalu menghasilkan satu ZIP yang langsung bisa dipakai Kairos (`bugbounty-pipeline`).

Bukan tool recon baru. Nilainya ada di **state lintas-run** (`first_seen` /
`last_seen` + diff), **batasan yang terdokumentasi**, dan **brief kecil** yang
dibaca agent sebelum mulai hunting.

Desain: [`SPEC.md`](SPEC.md).

---

## Mulai dari sini (urutan lengkap)

Contoh memakai program HackerOne. Ganti `temu` dengan programmu.

### 0. Cek dulu layak tidaknya (tanpa bikin apa-apa)

```bash
bountykit intake 'https://hackerone.com/temu?type=team' --dry-run
```

Keluar scorecard: reward, jumlah report 90 hari, efficiency, dan scope yang
publish. Verdict `go` / `careful` / `skip` / `vdp-only` / `review`.

### 1. Buat workspace

```bash
bountykit intake 'https://hackerone.com/temu?type=team'
```

Terbuat `data/temu/` berisi `scope.txt`, `out-of-scope.txt`, `policy.md`,
`boundaries.md`, `program.md`, `intake.json`.

### 2. Baca batasan sebelum apa pun

```bash
bountykit boundaries temu
```

Ini **kontrak program**: aturan mainnet/testnet, PoC, KYC, header wajib, dan
kutipan verbatim bagian in-scope / out-of-scope / prohibited / disclosure.
Yang tidak dipublikasikan ditulis `unknown` / "not stated" — bukan izin.

### 3. Periksa scope, lalu gate tiap host

```bash
cat data/temu/scope.txt data/temu/out-of-scope.txt
bountykit scope temu www.temu.com     # exit 0=IN, 1=OUT, 2=error
bountykit scope temu evil.temu.com.evil.test
```

`out-of-scope.txt` selalu menang. Empty `scope.txt` membuat recon menolak jalan.

### 4. (Opsional) Impor session kalau mau petakan area login

```bash
bountykit session temu set --har ~/Downloads/burp.har
bountykit session temu show                      # nilai disembunyikan
bountykit recon temu                             # otomatis pakai session
bountykit session temu clear
```

Tanpa session, yang dipetakan hanya permukaan unauth. `--no-session` untuk
memaksa recon tanpa session.

### 5A. Jalur web — recon

```bash
bountykit recon temu                 # crt.sh + Cert Spotter (+adapter kalau ada)
bountykit recon temu --step          # mode belajar: berhenti tiap fase
bountykit diff temu                  # apa yang baru sejak run terakhir
```

Host eksak dari `scope.txt` diprobes langsung. Wildcard baru di-enumerasi
subdomainnya. Semua host lolos gate dulu sebelum ada request keluar.

### 5B. Jalur non-web — repo & kontrak

Untuk program seperti Uniswap (Cantina), Beanstalk (Immunefi), Hyperliquid,
Ethereum, atau Muse:

```bash
bountykit analyze uniswap             # tanpa clone: lihat daftar aset dulu
bountykit analyze uniswap --clone     # clone repo in-scope ke data/<program>/repos/
bountykit analyze uniswap --refresh   # git pull repo yang sudah ada
```

`analyze` membaca workflow CI (mis. `pull_request_target`, `${{ github.event.* }}`,
`write-all`), install-time scripts, manifest, entry point kontrak, dan alamat
kontrak beserta explorer-nya. Hasilnya `nonweb.md` / `nonweb.json`.

### 6. Bangun peta dan antrian tes

```bash
bountykit map temu                   # modul, object ref, parameter, aset non-web
bountykit next temu                  # antrian terurut + alasan + probe pertama
```

`recon` dan `analyze` otomatis menyegarkan keduanya. `next` memasukkan aset
non-web, dan probe-nya mewarisi batasan — program yang melarang mainnet akan
bilang "use testnet or a local fork only" di probe pertamanya.

### 7. Cek perubahan aturan

```bash
bountykit rules-diff temu
```

Tiap intake di-snapshot ke `intakes/<ts>/`. Kalau program mencabut host dari
scope, mengubah reward, atau mengedit policy, ini muncul di sini dan di
`BRIEF.md`.

### 8. Pack untuk Kairos

```bash
bountykit pack temu -o dist
bountykit pack temu -o dist --include-session   # HANYA kalau agent perlu auth
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
bountykit intake cantina.xyz/bounties/f9df94db-c7b1-434b-bb06-d1360abdd1be --dry-run

# 2. buat workspace
bountykit intake cantina.xyz/bounties/f9df94db-c7b1-434b-bb06-d1360abdd1be \
  --name uniswap

# 3. baca batasan
bountykit boundaries uniswap

# 4. host dari teks prose MASIH kandidat, belum aktif.
#    Verifikasi di policy.md, lalu aktifkan kalau setuju:
bountykit intake cantina.xyz/bounties/f9df94db-c7b1-434b-bb06-d1360abdd1be \
  --name uniswap --force --trust-scope

# 5. lanjut seperti biasa
bountykit analyze uniswap --clone
bountykit next uniswap
bountykit pack uniswap -o dist
```

Sumber yang didukung: HackerOne (GraphQL terstruktur), Cantina, Immunefi,
GitBook (varian `.md`), `bugbounty.meta.com`, `ethereum.org`, dan halaman
mandiri lain.

---

## Daftar perintah

| Perintah | Fungsi |
|---|---|
| `init <program> [--platform P] [--url U] [--domain d,d]` | workspace kosong manual |
| `intake <url\|handle> [--name slug] [--dry-run] [--force] [--trust-scope]` | Phase 0 dari halaman program |
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
7. Session tidak pernah masuk ZIP kecuali `--include-session` (dan tool memperingatkan).
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
    bountykit/
      MANIFEST.json  intake.json  rules-diff.md
      diff.md  map.json/.md  next.json/.md  nonweb.json/.md
      session.json           hanya dengan --include-session
```

`BOUNTYKIT_HOME` mengganti root `./data`.

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
| `mainnet testing is forbidden` | Jangan kirim request ke produksi. Pakai testnet/local fork. |
| `session none` | Area login belum dipetakan. Impor HAR dulu kalau program mengizinkan. |
| `rules-diff` baseline | Baru intake pertama; belum ada pembanding. |

---

## Build

```bash
go build -o bin/bountykit ./cmd/bountykit
go test ./...
```

Go 1.21+. Tanpa cgo, tanpa dependency eksternal.

| Versi | Isi |
|---|---|
| v0.1–v0.3 | scope gate, pack, recon, diff, session, map, next |
| v0.4–v0.6 | intake H1 + multi-sumber, boundaries verbatim |
| v0.7–v0.8 | rule diff, aset non-web, analisis repo/kontrak |
| v0.9 | `report`, adapter penuh |
