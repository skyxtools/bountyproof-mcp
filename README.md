# BountyProof MCP

MCP server minimal untuk bug bounty dengan urutan kerja yang ketat:

```text
session(scope + rules) → preflight → surface import/discovery → high-signal or authorization checks → verification → evidence
```

Pemeriksaan WAF bukan finding. Ia hanya bagian dari **preflight gate** untuk mengetahui apakah live testing layak diteruskan atau kemungkinan membuang waktu karena challenge, rate limit, respons tidak stabil, redirect keluar host, atau proteksi edge lainnya.

## Mengapa minimal

BountyProof memakai HTTP client internal dan hanya dua binary eksternal:

- **Katana** untuk discovery URL yang dibatasi ke hostname yang lolos preflight.
- **Nuclei** untuk template HTTP severity high/critical; fuzz, DoS, brute-force, dan headless selalu dikecualikan.

Tidak ada shell tool generik, payload kustom, mass scanning, subdomain brute force, credential attack, atau automatic exploitation.

## Dua belas tool MCP

1. `start_session(...)` — menyimpan program, scope, out-of-scope, rules, aktivitas yang diizinkan, larangan, rate limit, dan otorisasi tanpa traffic.
2. `scope_check(session_id, url)` — validasi scope sesi tanpa request HTTP.
3. `preflight_target(session_id, url)` — menilai target sebagai `clear`, `guarded`, atau `blocked`.
4. `discover_surface(...)` — discovery Katana setelah preflight.
5. `scan_high_signal(...)` — Nuclei HTTP high/critical dengan rate limit ketat.
6. `verify_finding(...)` — menjalankan ulang satu template yang sama 2-3 kali.
7. `find_origin_candidates(...)` — mencari kandidat origin melalui DNS hint yang tetap in-scope dan historical A record opsional.
8. `verify_origin_candidate(...)` — setelah persetujuan baru, membandingkan satu respons edge dan satu direct-IP HTTPS.
9. `import_surface(...)` — mengimpor HAR, OpenAPI, atau Postman dengan scope filtering dan redaksi nilai.
10. `register_auth_profiles(...)` — menyimpan role dan nama environment variable, bukan credential.
11. `compare_authorization(...)` — membandingkan satu GET yang sama sebagai owner dan identitas lain selama 2-3 putaran.
12. `get_report(...)` — membaca laporan JSON aman atau Markdown.

Semua tool selain `start_session` wajib memakai `session_id`. Out-of-scope diperiksa sebelum in-scope, termasuk URL path prefix. Aktivitas ditolak jika tidak tercantum dalam `allowed_activities` sesi (`preflight`, `discovery`, `nuclei-scan`, `verification`, `origin-discovery`, `origin-verification`, `surface-import`, `authorization-testing`). Live discovery, scan, dan authorization comparison juga wajib menyertakan `preflight_run_id`. Scheme, host, dan port harus sama dengan target preflight. Gate `blocked` tidak dapat dilewati. Gate `guarded` memerlukan review manual dan `override_guarded=true`.

## Makna gate preflight

| Gate | Makna | Aksi |
|---|---|---|
| `clear` | Baseline stabil, tidak ada friction jelas | Lanjut secara terukur |
| `guarded` | Ada WAF/CDN, redirect, latency tinggi, atau respons tidak stabil | Review policy dan strategi |
| `blocked` | Challenge/block berulang, rate limit, atau target gagal diakses | Hentikan automasi live |

Deteksi Cloudflare, Akamai, Imperva, CloudFront, F5, Sucuri, Fastly, atau Azure edge hanya metadata keputusan. Tidak pernah dibuat sebagai laporan vulnerability.

## Instalasi

Persyaratan:

- Python 3.11+
- Katana
- Nuclei dan nuclei-templates

```bash
git clone https://github.com/skyxtools/bountyproof-mcp.git
cd bountyproof-mcp
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -e .
```

Konfigurasi runtime PowerShell:

```powershell
$env:BOUNTYPROOF_ALLOWED_PORTS = "443"
$env:BOUNTYPROOF_CONTACT = "researcher@example.com"
bountyproof-mcp
```

Jika binary tidak berada di `PATH`:

```powershell
$env:BOUNTYPROOF_KATANA_BIN = "C:\Tools\katana.exe"
$env:BOUNTYPROOF_NUCLEI_BIN = "C:\Tools\nuclei.exe"
```

## OpenCode

Salin [opencode.jsonc.example](opencode.jsonc.example) menjadi `opencode.jsonc` di project OpenCode Anda, lalu ganti absolute path executable. Atur `BOUNTYPROOF_WORKSPACE` serta credential variables di shell sebelum OpenCode dijalankan. OpenCode melakukan substitusi `{env:VARIABLE}` dan meneruskannya melalui opsi `environment` ke proses MCP; secret tidak perlu ditulis langsung di config.

Salin `.opencode/commands/bounty-start.md` ke project tempat OpenCode dijalankan, atau ke `~/.config/opencode/commands/bounty-start.md` agar tersedia global. Mulai setiap engagement dengan:

```text
/bounty-start
```

Command tersebut memaksa OpenCode bertanya tentang program, in-scope, out-of-scope, rules, aktivitas yang benar-benar diizinkan, larangan, rate limit, dan konfirmasi otorisasi. Setelah ringkasan dikonfirmasi, OpenCode memanggil `bountyproof_start_session` dan mengembalikan `session_id`. MCP tidak dapat membuka dialog secara sepihak hanya karena proses server baru menyala; interaksi harus dimulai oleh request client, sehingga custom command adalah entrypoint yang tepat.

Konfigurasi MCP client generik selain OpenCode:

```json
{
  "mcpServers": {
    "bountyproof": {
      "command": "/absolute/path/to/.venv/bin/bountyproof-mcp",
      "args": [],
      "env": {
        "BOUNTYPROOF_ALLOWED_PORTS": "443",
        "BOUNTYPROOF_CONTACT": "researcher@example.com"
      }
    }
  }
}
```

Di Windows, gunakan `.venv\\Scripts\\bountyproof-mcp.exe`.

## Workflow

### 1. Buat sesi

Jalankan `/bounty-start` di OpenCode. Scope yang didukung:

- Exact host: `api.example.com`
- Wildcard subdomain: `*.example.com`
- URL/path prefix: `https://app.example.com/api/`

Out-of-scope selalu menang. Contoh: in-scope `https://app.example.com/api/` dengan out-of-scope `https://app.example.com/api/admin/` akan menolak seluruh path admin.

### 2. Preflight

```text
scope_check(session_id="session-...", url="https://app.example.com/")
preflight_target(session_id="session-...", url="https://app.example.com/", samples=3)
```

Preflight mengirim 2-5 GET ke URL yang sama. Tidak ada payload serangan.

### 3. Discovery

```text
discover_surface(
  session_id="session-...",
  url="https://app.example.com/",
  preflight_run_id="preflight-...",
  depth=2
)
```

Katana dipaksa ke scope `fqdn`, concurrency 1, dan rate limit sesi (maksimum 2 request/detik).

### 4. High-signal scan

```text
scan_high_signal(
  session_id="session-...",
  urls=["https://app.example.com/api"],
  preflight_run_id="preflight-...",
  profile="high-signal"
)
```

Profil `high-signal` hanya high/critical. Profil `critical-only` lebih sempit. Hasil Nuclei tetap disebut candidate.

### 5. Verification

```text
verify_finding(
  session_id="session-...",
  scan_run_id="scan-...",
  finding_index=0,
  rounds=2
)
```

Status `repeatable-candidate` berarti template yang sama match pada setiap putaran. Dampak bisnis dan kepatuhan terhadap policy program tetap harus divalidasi manual.

### 6. Origin discovery dan verification

`find_origin_candidates` menggunakan dua sumber:

- Resolusi DNS terhadap hostname berlabel `origin`, `direct`, `backend`, `server`, `dev`, atau `staging`, tetapi hanya jika hostname itu sendiri cocok dengan wildcard in-scope dan tidak cocok dengan out-of-scope.
- Historical A record SecurityTrails bila `BOUNTYPROOF_SECURITYTRAILS_API_KEY` tersedia. Dokumentasi resmi SecurityTrails memang menyebut endpoint historical DNS ini dapat digunakan untuk mencari IP asli di balik proxy seperti Cloudflare.

Hasil tahap ini selalu `unverified-origin-candidate`. Agent tidak boleh langsung menjalankan scanner terhadap IP tersebut.

```text
find_origin_candidates(
  session_id="session-...",
  target_url="https://app.example.com/",
  preflight_run_id="preflight-..."
)
```

Jika activity `origin-verification` diizinkan rules, agent harus menunjukkan kandidat IP kepada pengguna dan meminta konfirmasi baru. Setelah itu, tool mengirim tepat dua request: satu ke edge dan satu langsung ke kandidat IP menggunakan TLS SNI serta HTTP `Host` target.

```text
verify_origin_candidate(
  session_id="session-...",
  origin_run_id="origin-...",
  candidate_index=0,
  direct_request_confirmed=true
)
```

Setelah verification, automasi selalu berhenti. Agent harus menampilkan bukti, memeriksa ownership/provider serta apakah IP mentah memang masuk scope, dan tidak boleh meneruskan IP ke `scan_high_signal`. Pengujian tambahan memerlukan keputusan eksplisit baru dari pengguna.

### 7. Surface import dan authorization comparison

Surface dapat diimpor dari HAR, OpenAPI JSON/YAML, atau Postman Collection. File wajib berada di `BOUNTYPROOF_IMPORT_ROOT`. Header value dan request body tidak disimpan; hanya header name, parameter name, dan body field name. Endpoint out-of-scope dibuang. Replay URL lengkap hanya berada di laporan lokal yang gitignored, sedangkan output MCP menyamarkan query value dan object-like path segment.

```text
import_surface(
  session_id="session-...",
  file_path="captures/app.har",
  input_format="auto"
)
```

Credential tidak boleh dikirim melalui chat atau parameter MCP. Atur token/cookie sebagai environment variable pada proses MCP, lalu register referensinya:

```powershell
$env:BOUNTY_USER_A_TOKEN = "<SET_OUTSIDE_CHAT>"
$env:BOUNTY_USER_B_TOKEN = "<SET_OUTSIDE_CHAT>"
```

```text
register_auth_profiles(
  session_id="session-...",
  profiles=[
    {"name":"user_a", "role":"owner", "auth_type":"bearer", "credential_env":"BOUNTY_USER_A_TOKEN"},
    {"name":"user_b", "role":"other-user", "auth_type":"bearer", "credential_env":"BOUNTY_USER_B_TOKEN"},
    {"name":"anonymous", "role":"anonymous", "auth_type":"anonymous"}
  ]
)
```

`compare_authorization` hanya menerima endpoint GET replayable. Tool tidak mengganti ID, parameter, method, atau body. Respons owner dan comparison profile diambil 2-3 kali. Candidate hanya dibuat bila comparison profile berulang kali mendapat 2xx dengan body identik atau canonical JSON stabil yang sama dengan owner.

```text
compare_authorization(
  session_id="session-...",
  surface_run_id="surface-...",
  endpoint_index=0,
  preflight_run_id="preflight-...",
  owner_profile="user_a",
  comparison_profiles=["user_b", "anonymous"],
  expected_policy="owner-only",
  rounds=2
)
```

Setelah differential candidate ditemukan, agent berhenti. Ia tidak boleh mengenumerasi atau mengganti object ID secara otomatis. User harus mengonfirmasi bahwa comparison profile memang seharusnya tidak dapat mengakses object tersebut sebelum validasi dampak tambahan.

## Evidence dan privasi

Sesi disimpan di `.bountyproof/sessions/`, auth profile metadata di `.bountyproof/auth-profiles/`, dan laporan di `.bountyproof/reports/`; semuanya dikecualikan dari Git. Auth profile hanya menyimpan nama environment variable, bukan nilainya. Raw request/response Nuclei tetap lokal dan tidak dikembalikan melalui MCP. Field `authorization`, `cookie`, dan `set-cookie` diperintahkan untuk direduksi oleh Nuclei.

## Konfigurasi

| Variabel | Default | Fungsi |
|---|---:|---|
| `BOUNTYPROOF_ALLOWED_PORTS` | `443` | Port yang diizinkan |
| `BOUNTYPROOF_ALLOW_HTTP` | `false` | Izinkan HTTP tanpa TLS |
| `BOUNTYPROOF_ALLOW_PRIVATE` | `false` | Izinkan IP non-publik untuk lab |
| `BOUNTYPROOF_VERIFY_TLS` | `true` | Verifikasi sertifikat TLS |
| `BOUNTYPROOF_DELAY_MS` | `350` | Jeda preflight |
| `BOUNTYPROOF_MAX_URLS` | `100` | Batas hasil discovery |
| `BOUNTYPROOF_NUCLEI_RATE_LIMIT` | `2` | Maksimum request Nuclei/detik |
| `BOUNTYPROOF_REPORT_DIR` | `.bountyproof/reports` | Evidence lokal |
| `BOUNTYPROOF_SECURITYTRAILS_API_KEY` | kosong | Historical A records opsional; tidak ditulis ke laporan |
| `BOUNTYPROOF_IMPORT_ROOT` | current directory | Root yang diizinkan untuk HAR/OpenAPI/Postman |
| `BOUNTYPROOF_MAX_IMPORT_BYTES` | `20000000` | Batas ukuran file surface |

## Test

```bash
python -m unittest discover -s tests -v
```

Unit test tidak mengakses target eksternal.

## Lisensi

MIT. Terinspirasi oleh ide orkestrasi MCP pada HexStrike AI, tetapi implementasinya baru dan secara sengaja hanya memakai pipeline kecil dengan guardrail ketat.
