# bountykit — SPEC v0.4

Deterministic context-pack builder for bug bounty.
Fase yang dikerjakan tool: **Program Selection (bantu) → Pre-Hunt (kumpulkan) → Recon → Mapping**.
Sisanya (hunting, validasi, report) diserahkan ke Kairos.

---

## 1. Masalah

Bukti dari dua repo yang ada:

| Fakta | Konsekuensi |
|---|---|
| `bounty-pack` = 276 SKILL.md, 104.442 baris, tanpa `audit-pipeline-orchestrator.py` / `pool_pick.py` / `reverify.py` | Pack itu **perpustakaan**, bukan pipeline. Agent menyimpulkan urutan sendiri → tiap run beda → tidak bisa diperbaiki |
| Target diputar dari pool 35.550 domain, breadth-first | Hanya menemukan lapisan paling dangkal = lapisan yang sudah dipindai semua orang → **duplikat secara struktural** |
| Kairos: `google-vrp` 411 attempts / 0 findings, `ticko` 29 / 0 | Usaha banyak, hasil nol: bukan kurang alat, tapi kurang konteks per target |
| Tidak ada state lintas-run untuk aset mentah | Agent tidak tahu apa yang **baru** → mengulang permukaan yang sudah usang |

**Kesimpulan:** yang hilang bukan tool recon baru. Yang hilang adalah **artefak konteks yang deterministik, kecil, dan membawa diff**.

---

## 2. Ruang lingkup

### Dikerjakan v0.1
- `init` — intake program: scope, out-of-scope, policy, verdict
- `scope` — gate IN/OUT identik dengan `Kairos/scripts/scope_check.py`
- `pack` — bangun ZIP siap-serap ke `workspace/<program>/`
- `status` — ringkasan semua program

### Dikerjakan v0.2
- `recon` — subdomain, DNS, HTTP probe, TLS/SAN, URL harvest, JS harvest
- `diff` — bandingkan snapshot sekarang vs sebelumnya (`first_seen` / `last_seen`)

### Dikerjakan v0.3
- `session` — impor cookie/header dari HAR atau manual, dipakai recon, **tidak** masuk pack kecuali `--include-session`
- `map` — modul, object reference, ID parameter, GraphQL, parameter liar dari JS
- `next` — antrian tes terurut per kelas vuln, dengan bukti dan probe pertama

### Dikerjakan v0.4
- `intake` — Phase 0: baca halaman program HackerOne lewat GraphQL publik, skor go/careful/skip, scope + policy
- `recon` menerima host eksak dari `scope.txt` (program tanpa wildcard tetap bisa direcon)

### Dikerjakan v0.5
- `report` — laporan markdown/HTML per program
- adapter penuh (katana, smuggling check)

### Bukan scope (selamanya)
- Hunting otomatis (itu tugas Kairos + skill `hunt-*`)
- Submit laporan otomatis ke platform
- Menyimpan credential target di repo

---

## 3. Kontrak integrasi dengan Kairos

Tool ini harus menghasilkan output yang **langsung** bisa dipakai `bugbounty-pipeline` tanpa penerjemahan.

### 3.1 Semantik scope (wajib identik)

Disalin dari `Kairos/scripts/scope_check.py`:

| Input | Aturan |
|---|---|
| `api.example.com` | exact match |
| `*.example.com` | cocok untuk `a.example.com` dan `a.b.example.com`, **tidak** cocok untuk `example.com` |
| `203.0.113.0/24` | CIDR containment |
| `out-of-scope.txt` | **selalu menang** atas `scope.txt` |
| `scope.txt` kosong / tidak ada | **refuse** (exit 2) |

Exit code: `0` = IN, `1` = OUT, `2` = salah pakai.

Setiap keputusan ditulis append ke `audit.log`.

### 3.2 Layout workspace yang diharapkan Kairos

```
workspace/<program>/
├── program.md
├── scope.txt
├── out-of-scope.txt
├── passive/
├── recon/
├── evidence/
└── findings/
```

Nama file artefak yang dibaca `bugbounty-pipeline`:

```
recon/subs.txt      recon/live.txt      recon/urls.txt
recon/js.ts         recon/endpoints.txt recon/nuclei.txt
recon/ranked.txt    recon/smuggling.txt
LEDGER.md
```

Catatan: pipeline menyebut folder `targets-<name>/`; bountykit memakai `recon/` (konvensi `docs/BUG-BOUNTY.md`) dan **memetakan namanya di `BRIEF.md`**.

### 3.3 Toolchain VPS (dari `docs/BUG-BOUNTY.md`)

Kalau ada, dipakai sebagai adapter. Kalau tidak, fallback internal.

```
subfinder assetfinder dnsx httpx naabu katana gau waybackurls
ffuf nuclei dalfox anew notify interactsh-client
SecLists: /opt/wordlists/SecLists
```

### 3.4 Kontrak Phase 0 (intake)

Sumber: `POST https://hackerone.com/graphql` ( publik, tanpa login ). Satu query
metadata + policy + reward, satu query scope dengan paginasi 100.

| Data platform | Dipakai untuk |
|---|---|
| `handle`, `name`, `state`, `submission_state`, `offers_bounties` | identitas + verdict |
| `top/average_bounty_*`, `bounty_table_rows` | komponen money |
| `reports_received_last_90_days`, `resolved_report_count`, `profile_metrics_snapshot` | komponen crowding + "di mana report jatuh" |
| `response_efficiency_percentage` | komponen speed |
| `structured_scopes` (asset_type, eligibility, max_severity, instruction) | scope.txt + scope + komponen surface |
| `policy` | policy.md — aturan yang tidak bisa diwakili host |

Pemetaan scope sengaja konservatif: `URL` → host, `WILDCARD` → `*.`, `CIDR` →
CIDR. **URL dengan path tidak dijadikan aturan host** karena gate hanya
memahami host; melebarkan `example.com/api/*` menjadi `example.com` akan
mengizinkan pengujian di luar izin program. Aset non-web (app ID, source,
hardware) tercatat di intake.json dan scorecard, tidak ditebak sebagai host.

---

## 4. Arsitektur

### 4.1 Dua mode

| Mode | Perilaku |
|---|---|
| `--auto` | jalan lurus `init → recon → map → pack`, tanpa prompt. Untuk VPS/cron |
| `--step` | berhenti tiap tahap, tampilkan temuan + alasan + perintah berikutnya, tunggu Enter. Mode belajar |

### 4.2 Self-contained + adapter

Inti ditulis dengan **stdlib Go saja** (tanpa cgo, tanpa dependency eksternal):

- parsing scope, HTTP client, TLS handshake, DNS, parse JS via regex, tulis ZIP, state JSONL

Adapter opsional: kalau binary eksternal ada di `PATH`, dipakai untuk hasil yang lebih kaya:

```
subfinder → subs.txt        httpx → live.txt        katana → urls.txt
gau       → urls.txt (historis)   nuclei → nuclei.txt
```

Kalau tidak ada, tool tetap jalan dengan sumber internal (crt.sh, HTTP GET, crawl sederhana).

### 4.3 Struktur repo

```
bountykit/
├── cmd/bountykit/main.go
├── internal/
│   ├── cli/          dispatch perintah
│   ├── scope/        parse + match + gate
│   ├── workspace/    layout program, meta, audit log
│   ├── pack/         zip builder + BRIEF + MANIFEST
│   └── version/
├── SPEC.md
└── data/             (gitignored) state tiap program
```

State di `data/<program>/`, terpisah dari repo Kairos. `pack` yang menjembatani.

### 4.4 Data model per program

```
data/<program>/
├── meta.json         name, platform, url, domains, verdict, timestamps
├── program.md
├── scope.txt
├── out-of-scope.txt
├── audit.log
├── intake.json       data Phase 0 + scorecard (terstruktur)
├── policy.md         kebijakan program (class out-of-scope, header wajib)
├── session.json      cookie + header (0600, tidak ikut pack kecuali diminta)
├── assets.json       hosts, endpoints, JS hash (dengan first_seen/last_seen)
├── diff.json         delta vs snapshot sebelumnya
├── diff.md           delta dalam bentuk yang dibaca agent
├── map.json  map.md  modul, object reference, ID parameter, GraphQL
├── next.json next.md antrian tes + alasan + probe pertama
├── state/
│   ├── subs.txt      live.txt  live_urls.txt  urls.txt
│   ├── js.ts         endpoints.txt  ranked.txt  nuclei.txt
│   └── (kondisi terkini, siap di-pack)
└── snapshots/
    └── <ts>/assets.json
```

### 4.5 Skor antrian (`next`)

`next` tidak mengirim request. Ia hanya menimbang bukti yang sudah ada:

| Sinyal | Bobot | Alasan |
|---|---:|---|
| endpoint baru sejak snapshot sebelumnya | +100 | paling kecil kemungkinan sudah dipindai orang lain |
| object reference di path atau ID parameter | +50 | kandidat IDOR/BOLA, bug berbayar paling umum |
| kelas bisnis (billing/auth/admin/upload) | +45…60 | alur uang dan identitas |
| punya parameter | +15 | ada yang bisa diubah |
| host 401/403 + nama subdomain sensitif | +45…65 | area yang jelas butuh login |
| parameter liar dari JS | +30…55 | petunjuk request mana yang harus dibaca |

Batas bawah: item `surface-review` dengan skor < 30 dibuang. Kalau tidak ada yang lolos, `next.md` bilang terus terang bahwa itu hasil, bukan kegagalan run.

---

## 5. Isi ZIP

```
<program>_<ts>.zip
└── <program>/
    ├── BRIEF.md               ← 1 halaman untuk agent: scope, isi pack, yang hilang, next action
    ├── program.md
    ├── scope.txt
    ├── out-of-scope.txt
    ├── policy.md              ← aturan program yang bukan host
    ├── LEDGER.md              ← log keputusan tool
    ├── recon/                 ← hanya file yang ada
    │   ├── subs.txt
    │   ├── live.txt
    │   ├── urls.txt
    │   ├── js.ts
    │   ├── endpoints.txt
    │   └── nuclei.txt
    └── bountykit/
        ├── MANIFEST.json      ← daftar file + sha256
        ├── intake.json        ← Phase 0 (skor + alasan)
        ├── diff.md            ← apa yang baru
        ├── map.md  map.json   ← peta permukaan
        ├── next.md next.json  ← antrian tes terurut
        └── session.json       ← hanya dengan --include-session
```

Prinsip: **distilled by default**. Agent Kairos punya RAM terbatas dan `RTK` memotong output >500 karakter — dump mentah merusak konteks. `--include-raw` hanya kalau diminta.

---

## 6. Desain anti-duplikat

Tiga mekanisme, semuanya di tool:

1. **`first_seen` / `last_seen` per aset.** Aset yang muncul di snapshot ke-N dan tidak ada di N-1 = permukaan **segar** → prioritas tertinggi.
2. **Hash JS bundle.** Bundle yang berubah = endpoint baru kemungkinan besar ada di sana.
3. **`diff` wajib masuk BRIEF.md.** Agent membaca "APA YANG BARU", bukan seluruh semesta aset.

Alasan: automation selalu kalah cepat pada permukaan lama. Diff adalah satu-satunya lever yang membuat automation menghasilkan sesuatu yang belum dipindai orang lain.

---

## 7. Perintah

```
bountykit version
bountykit init   <program> [--platform h1|bugcrowd|direct] [--url U] [--verdict bounty|vdp|none]
bountykit scope  <program> <host|cidr>          # exit 0 IN / 1 OUT / 2 error
bountykit status [<program>]
bountykit pack   <program> [-o dist] [--include-raw]
```

v0.2:

```
bountykit recon  <program> [--auto|--step]
bountykit diff   <program>
```

v0.3:

```
bountykit session <program> [show|set|clear] [--har f] [--cookie s] [--header 'K: V']
bountykit map    <program>
bountykit next   <program>
bountykit pack   <program> [--include-session]
```

v0.4:

```
bountykit intake <hackerone-url|handle> [--name slug] [--dry-run] [--force]
```

v0.5:

```
bountykit report <program>
```

---

## 8. Aturan keras

1. `scope.txt` kosong → refuse. Tidak ada pengecualian.
2. Out-of-scope selalu menang.
3. Setiap host yang akan disentuh wajib lewat `scope` dulu; setiap hasil masuk `audit.log`.
4. Tidak ada credential, cookie, atau token di dalam ZIP kecuali lewat `--include-session`; tool mencetak peringatan saat itu terjadi.
5. ZIP tidak pernah masuk git. `data/` dan `dist/` gitignored.
6. `session.json` mode 0600, dan `session show` selalu menutupi nilai rahasia.
7. `intake` hanya membaca API publik platform: tidak login, tidak menyentuh aset target.
8. Aset berskope path tidak pernah dilebarkan jadi aturan host.

---

## 9. Roadmap

| Versi | Isi | Definisi selesai |
|---|---|---|
| v0.1 | `init`, `scope`, `pack`, `status` | ZIP bisa dibuat, gate identik dengan Kairos (diuji), agent bisa membaca BRIEF |
| v0.2 | `recon`, `diff`, snapshot | Satu run menghasilkan `subs/live/urls/js/endpoints`; diff terisi — **selesai** |
| v0.3 | `map`, `next`, session import | Antrian tes terurut + hipotesis per kelas vuln, permukaan auth ikut terpetakan — **selesai** |
| v0.4 | `intake`, host eksak | Skor Phase 0 + scope terisi otomatis dari halaman publik — **selesai** |
| v0.5 | `report`, adapter penuh | Laporan markdown/HTML per program |
