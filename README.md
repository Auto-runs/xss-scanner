# XScanner v3 — vOVERPOWER

**Next-Generation XSS Detection & Exploitation Framework**

```
██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
╚██╗██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ╚███╔╝ ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔██╗ ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██╔╝ ██╗███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/Version-3.0.0-FF4757?style=for-the-badge)](https://github.com/Auto-runs/xss-scanner)
[![Tests](https://img.shields.io/badge/Tests-136%2F136_Passed-22C55E?style=for-the-badge)](https://github.com/Auto-runs/xss-scanner)
[![License](https://img.shields.io/badge/License-MIT-6B7280?style=for-the-badge)](LICENSE)

> ⚠️ **Authorized Security Testing Only** — Gunakan tool ini hanya pada sistem yang kamu miliki atau sudah mendapat izin tertulis. Penggunaan tanpa izin adalah tindak pidana.

---

## Apa itu XScanner?

XScanner adalah framework Python untuk mendeteksi XSS (Cross-Site Scripting) yang dirancang untuk **security researcher** dan **bug bounty hunter**. Dibandingkan scanner biasa yang hanya pakai beberapa ratus payload statis, XScanner menghasilkan **4.50 miliar kombinasi payload unik** dari 11 engine spesialis — mencakup semua jenis XSS yang relevan di tahun 2025-2026.

### Keunggulan Utama

- **4.50 miliar kombinasi payload** dari 11 engine termasuk Combinatorial v2, mXSS, Blind XSS, CSP Bypass, Prototype Pollution
- **31 teknik WAF bypass** dengan 36.456 chain per payload, termasuk 6 teknik baru 2025 (parser differential, new event handler, Cloudflare bypass)
- **Event handler HTML5 baru 2025** — `onbeforetoggle`, `oncontentvisibilityautostatechange`, `onscrollend` yang belum ada di blacklist WAF lama
- **InteractionSimulator** — Playwright automation yang tahu cara trigger setiap event handler (scroll, click, clipboard, mouse move)
- **File upload XSS** — test filename injection via multipart/form-data
- **10-layer detection engine** dengan CSP analysis, template injection, prototype pollution, mXSS, Shadow DOM
- **HPP ASP.NET comma concat exploit** — bypass teknik 2025 yang bypass 14/17 enterprise WAF (Ethiack Research)
- **Blind XSS server** dengan CORS headers — callback benar-benar sampai ke server
- **5 format laporan** — JSON, HTML dashboard, CSV, Markdown (bug bounty ready), SARIF (CI/CD)
- **136/136 unit tests passing**

---

## Persyaratan Sistem

- **Python 3.11+** (wajib — pakai sintaks 3.11+)
- **OS**: Linux, macOS, Windows (WSL disarankan)
- **RAM**: minimal 512MB, disarankan 2GB+ untuk engine v3 deep scan
- **Internet**: diperlukan untuk scan target, opsional untuk update playwright

---

## Instalasi

### 1. Clone repository

```bash
git clone https://github.com/Auto-runs/xss-scanner.git
cd xss-scanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Verifikasi instalasi

```bash
python xscanner.py --version
# Output: xscanner, version 3.0.0

python xscanner.py --help
```

### 4. (Opsional) Install Playwright untuk fitur headless

Diperlukan untuk `--dom-xss-scan`, `--spa-crawl`, `--verify-headless`, dan `--test-new-events` dengan verifikasi:

```bash
pip install playwright
playwright install chromium
```

### 5. (Opsional) Install sebagai command global

```bash
pip install -e .
xscanner --version  # bisa dijalankan dari mana saja
```

---

## Quick Start

```bash
# Scan dasar — cepat, tidak butuh Playwright
python xscanner.py -u "https://target.com/search?q=test"

# Scan dengan no-crawl (hanya parameter yang ada di URL)
python xscanner.py -u "https://target.com/page?id=1&name=test" --no-crawl

# Scan dengan semua teknik 2025 (butuh Playwright)
python xscanner.py -u "https://target.com" --engine-v3 --deep \
  --test-new-events --test-parser-diff --verify-headless

# Scan dengan batas waktu dan jumlah temuan
python xscanner.py -u "https://target.com" --scan-timeout 300 --max-findings 20

# Pakai custom payload file
python xscanner.py -u "https://target.com" --payload-file my_payloads.txt
```

---

## Full vOVERPOWER Mode (Bug Bounty)

```bash
python xscanner.py \
  -u "https://target.com" \
  --engine-v3 \
  --deep \
  --test-new-events \
  --test-parser-diff \
  --test-csp-bypass \
  --test-prototype \
  --test-template \
  --test-websocket \
  --unicode-bypass \
  --browser-quirks \
  --dom-clobbering \
  --dom-xss-scan \
  --spa-crawl \
  --test-hpp \
  --test-hpp-2025 \
  --test-headers \
  --waf-chain-depth 4 \
  --blind-callback "https://your.xsshunter.com/cb" \
  --verify-headless \
  --scope "target.com" "*.target.com" \
  --exclude-path "/logout" "/delete" "/unsubscribe" \
  --checkpoint \
  --scan-timeout 3600 \
  --max-findings 100 \
  --report-html report.html \
  --report-md submission.md \
  --report-sarif report.sarif
```

---

## Referensi CLI Lengkap

### Targeting

| Flag | Default | Deskripsi |
|------|---------|-----------|
| `-u, --url` | — | Target URL (bisa diulang: `-u url1 -u url2`) |
| `-l, --list` | — | File berisi URL target (satu per baris) |
| `--threads` | 10 | Jumlah request concurrent |
| `--timeout` | 10 | Timeout per request (detik) |
| `--depth` | 2 | Kedalaman crawl |
| `--profile` | normal | `fast` / `normal` / `deep` / `stealth` |
| `--deep` | off | Shorthand untuk `--profile deep` |
| `--no-crawl` | off | Hanya test parameter dari URL yang diberikan |
| `--scan-timeout` | 0 | Batas waktu total scan dalam detik (0 = tidak ada batas) |
| `--max-findings` | 0 | Berhenti setelah N finding (0 = tidak ada batas) |

### Request

| Flag | Deskripsi |
|------|-----------|
| `-H, --header` | Custom header: `'Name: Value'` (bisa diulang) |
| `-c, --cookie` | Cookie: `'name=value'` (bisa diulang) |
| `--proxy` | Proxy URL: `http://127.0.0.1:8080` |
| `--rate-limit N` | Jeda antar request dalam detik |
| `--no-waf-bypass` | Nonaktifkan WAF evasion |

### Authentication

| Flag | Deskripsi |
|------|-----------|
| `--login-url` | URL halaman login |
| `--username` | Username login |
| `--password` | Password login |

### Scope

| Flag | Deskripsi |
|------|-----------|
| `--scope` | Domain in-scope: `target.com *.target.com` |
| `--exclude-scope` | Domain yang dilewati |
| `--exclude-path` | Path yang dilewati: `/logout /delete` |

### Modules Standar

| Flag | Deskripsi |
|------|-----------|
| `--test-headers` | XSS via HTTP headers (User-Agent, Referer, X-Forwarded-For, dll) |
| `--test-hpp` | HTTP Parameter Pollution klasik |
| `--test-hpp-2025` | HPP ASP.NET comma concat exploit (Ethiack 2025) |
| `--test-json` | Injeksi JSON API endpoint |
| `--second-order` | Track dan verifikasi stored/second-order XSS |
| `--js-crawl` | Ekstrak param dari JavaScript (tanpa Playwright) |

### Engine vOVERPOWER

| Flag | Deskripsi |
|------|-----------|
| `--engine-v3` | Aktifkan ScanEngineV3 — 4.50B combos, semua 11 engine |
| `--engine-version` | `v1` / `v2` — kedalaman engine payload dalam v3 |
| `--test-csp-bypass` | CSP bypass: JSONP CDN, nonce leak, strict-dynamic (1.62M) |
| `--test-prototype` | Prototype pollution XSS: `__proto__`, DOMPurify bypass (2.7M) |
| `--test-template` | Template injection: Angular/Vue/React/Jinja2 |
| `--test-websocket` | WebSocket/SSE injection |
| `--test-smuggling` | HTTP request smuggling XSS |
| `--unicode-bypass` | Unicode homoglyph WAF evasion (2.88M) |
| `--browser-quirks` | Payload browser-spesifik: Chrome/Firefox/Safari/Edge |
| `--dom-clobbering` | DOM clobbering: document.head, config.url |
| `--ai-assist` | Saran payload dari AI (butuh `ANTHROPIC_API_KEY`) |
| `--waf-chain-depth N` | Kedalaman chain: 2=pairs 3=triples 4=quads (default: 3) |

### Teknik Terbaru 2025

| Flag | Deskripsi |
|------|-----------|
| `--test-new-events` | Event handler HTML5 baru yang belum di-blacklist WAF (onbeforetoggle, onscrollend, oncontentvisibilityautostatechange, dll) |
| `--test-parser-diff` | Parser differential bypass — eksploitasi perbedaan cara WAF vs browser tokenize HTML (Ethiack 2025) |
| `--test-hpp-2025` | ASP.NET comma concat + Azure WAF bypass format (Ethiack hackbot 2025) |

### DOM XSS + SPA (Butuh Playwright)

| Flag | Deskripsi |
|------|-----------|
| `--dom-xss-scan` | DOM XSS via JS instrumentation — patch innerHTML/eval sebelum page JS jalan |
| `--spa-crawl` | Temukan parameter di SPA (React/Vue/Angular/Next.js/Nuxt) |
| `--verify-headless` | Konfirmasi eksekusi XSS di Chromium (termasuk interaksi user gesture otomatis) |

### Blind XSS

| Flag | Deskripsi |
|------|-----------|
| `--blind-callback URL` | URL callback untuk blind XSS (XSS Hunter, dll) |
| `--start-blind-server` | Jalankan listener lokal di port 8765 (CORS enabled) |

### Custom Payload

| Flag | Deskripsi |
|------|-----------|
| `--payload-file PATH` | File berisi custom XSS payloads (satu per baris, `#` untuk komentar) |

### Output

| Flag | Deskripsi |
|------|-----------|
| `-o, --output` | Laporan JSON (default: `xscanner_report.json`) |
| `--report-html` | Dashboard HTML dark-theme |
| `--report-csv` | Spreadsheet CSV |
| `--report-md` | Markdown (siap bug bounty submission) |
| `--report-sarif` | SARIF 2.1.0 (GitHub Code Scanning, CI/CD) |
| `--no-progress` | Nonaktifkan progress output |

### Misc

| Flag | Deskripsi |
|------|-----------|
| `--checkpoint` | Simpan progress; lanjut jika terhenti |
| `-v, --verbose` | Output verbose |
| `-V, --version` | Tampilkan versi |
| `-h, --help` | Tampilkan bantuan |

---

## Scan Profiles

| Profile | Kecepatan | Payload | Cocok untuk |
|---------|-----------|---------|-------------|
| `fast` | ⚡ Sangat cepat | ~500 | Recon awal |
| `normal` | ⚖️ Seimbang | ~1.300 | Scan standar |
| `deep` | 🐢 Lambat | ~5.000 | Full assessment |
| `stealth` | 🤫 Sangat lambat | ~800 | Minimalisir noise di log |

---

## Format Laporan

| Format | Ekstensi | Kegunaan |
|--------|----------|----------|
| **JSON** | `.json` | Machine-readable, pipe ke tools lain |
| **HTML** | `.html` | Dashboard visual, semua field di-escape (aman dibuka di browser) |
| **Markdown** | `.md` | Submit langsung ke platform bug bounty |
| **CSV** | `.csv` | Import ke spreadsheet, tracking |
| **SARIF 2.1.0** | `.sarif` | GitHub Code Scanning, CI/CD pipeline |

---

## Arsitektur Teknik WAF Bypass

### Teknik Klasik (v1, 10 teknik)
`case_shuffle`, `comment_inject`, `double_encode`, `null_byte`, `tab_substitute`, `unicode_norm`, `html_entity`, `tag_break`, `event_obfus`, `slash_insert`

### Teknik Lanjut (v2, +15 teknik)
`homoglyph`, `zero_width_space`, `zero_width_joiner`, `rtl_override`, `html5_named_refs`, `svg_use_ref`, `css_unicode_esc`, `json_unicode_esc`, `soft_hyphen`, `vertical_tab`, `octal_encode`, `html_decimal_ent`, `js_template_split`, `prototype_chain`, `overlong_utf8`

### Teknik Baru 2025 (+6 teknik)
| Teknik | Sumber | Cara Kerja |
|--------|--------|------------|
| `parser_differential` | Ethiack Research Sept 2025 | Sisipkan soft-hyphen setelah `<` — WAF baca sebagai string biasa, browser tetap bentuk tag valid |
| `new_event_handler` | Sysdig 2025, PortSwigger Jan 2026 | Ganti `onerror`/`onload` dengan event handler Chrome 114-126+ yang belum di-blacklist WAF |
| `comma_operator_hpp` | Ethiack Research Sept 2025 | Format `';alert(1);//` untuk Azure WAF bypass + ASP.NET comma concat exploit |
| `attribute_breakout` | 2025 | Backtick sebagai quote delimiter + newline sebelum event handler |
| `cloudflare_2025` | Ethiack hackbot 2025 | `globalThis.alert` bypass window detection, `queueMicrotask(Function(...))` |
| `encoding_smuggling` | 2025 | Campur URL encode + HTML entity untuk karakter yang sama |

**Total: 31 teknik, 36.456 chain per payload**

---

## Event Handler Baru 2025

Event handler ini valid di browser modern tapi tidak ada di blacklist WAF yang tidak diupdate:

| Event Handler | Browser | Cara Trigger | Status WAF |
|--------------|---------|--------------|------------|
| `onbeforetoggle` | Chrome 114+ | Klik tombol yang buka popover | ✅ Bypass AWS WAF (Sysdig 2025) |
| `oncontentvisibilityautostatechange` | Chrome 124+ | Scroll ke elemen dengan `content-visibility:auto` | ✅ Bypass banyak WAF |
| `onscrollend` | Chrome 114+ | Scroll elemen lalu berhenti | ⚠️ Butuh interaksi |
| `onanimationcancel` | Chrome 120+ | Batalkan CSS animation yang sedang jalan | ⚠️ Butuh JS trigger |
| `ontransitioncancel` | Chrome 87+ | Batalkan CSS transition | ⚠️ Butuh JS trigger |
| `onpointerrawupdate` | Chrome 77+ | Gerakkan mouse di atas elemen | ⚠️ Butuh mouse |
| `onpointerleave` | Chrome 57+ | Mouse masuk lalu keluar elemen | ⚠️ Butuh mouse |
| `oncopy` / `oncut` | Semua | Ctrl+C / Ctrl+X di elemen | ⚠️ Butuh keyboard |

Saat `--verify-headless` aktif, **InteractionSimulator** otomatis men-trigger setiap event handler dengan cara yang sesuai (scroll, click, keyboard simulation, mouse movement).

---

## Testing di Lab Lokal

```bash
# DVWA (Docker)
docker run -d -p 8080:80 vulnerables/web-dvwa
# Login: admin / password → Security Level: Low
python xscanner.py \
  -u "http://localhost:8080" \
  --engine-v3 --deep \
  --dom-xss-scan --spa-crawl \
  --verify-headless \
  --report-html dvwa_results.html

# OWASP Juice Shop (Docker)
docker run -d -p 3000:3000 bkimminich/juice-shop
python xscanner.py \
  -u "http://localhost:3000" \
  --engine-v3 --deep \
  --test-json --test-prototype \
  --js-crawl \
  --report-html juiceshop_results.html

# bWAPP (Docker)
docker run -d -p 80:80 raesene/bwapp
python xscanner.py \
  -u "http://localhost/bwapp/xss_get.php?firstname=test&lastname=test" \
  --no-crawl --engine-v3 \
  --test-headers --unicode-bypass \
  --report-html bwapp_results.html
```

---

## Bug Bounty Workflow

```bash
# Phase 1: Quick recon
python xscanner.py \
  -u "https://target.com" \
  --profile fast \
  --scope "target.com" "*.target.com" \
  -o phase1.json

# Phase 2: Full vOVERPOWER sweep
python xscanner.py \
  -u "https://target.com" \
  --engine-v3 --deep \
  --scope "target.com" "*.target.com" \
  --exclude-path "/logout" "/unsubscribe" \
  --login-url "https://target.com/login" \
  --username user --password pass \
  --test-headers --test-hpp --test-hpp-2025 --test-json \
  --test-csp-bypass --test-prototype --test-template \
  --test-new-events --test-parser-diff \
  --unicode-bypass --browser-quirks \
  --dom-xss-scan --spa-crawl \
  --second-order --js-crawl \
  --blind-callback "https://your.xsshunter.com/cb" \
  --verify-headless \
  --waf-chain-depth 4 \
  --scan-timeout 7200 \
  --checkpoint \
  -o report.json \
  --report-html report.html \
  --report-md submission.md

# Phase 3: Verifikasi manual sebelum submit
```

---

## Arsitektur File

```
xss-scanner/
├── xscanner.py                       # Entry point
├── cli/
│   └── interface.py                  # CLI (Click) — 57+ flag
├── scanner/
│   ├── engine_v2.py                  # ScanEngineV2 — DEFAULT (152M combos)
│   ├── engine_v3.py                  # ScanEngineV3 — vOVERPOWER (4.50B)
│   ├── dom_xss_scanner.py            # DOM XSS via Playwright JS instrumentation
│   ├── interaction_simulator.py      # ★ BARU: Playwright user gesture simulator
│   ├── upload_injector.py            # ★ BARU: File upload XSS (filename injection)
│   ├── filter_probe.py               # CharacterMatrix — probe 23 karakter
│   ├── header_injector.py            # 14 header injection test
│   ├── real_world.py                 # Scope/Auth/Checkpoint/SecondOrder/HPP
│   ├── verifier.py                   # Headless Chromium verification
│   ├── blind_server.py               # Blind XSS listener (CORS enabled)
│   └── ai_advisor.py                 # AI payload advisor
├── payloads/
│   ├── combinatorial_engine_v2.py    # 4.26B combos
│   ├── mxss_engine_v2.py             # mXSS 115.4M
│   ├── blind_xss_v2.py               # Blind 1.09M
│   ├── advanced_engines_v2.py        # JSON+PP+Unicode+Browser+Smuggling
│   │                                 # ★ BARU: NewEventHandlerEngine2025
│   │                                 # ★ BARU: ParserDifferentialEngine2025
│   ├── csp_bypass_engine.py          # CSP+Template+DOMClob
│   └── generator.py                  # Static payloads (supplement)
├── waf_bypass/
│   ├── evasion_v2.py                 # 31 teknik, 36.456 chain/payload
│   │                                 # ★ BARU: 6 teknik 2025
│   └── detector.py                   # WAFDetector 20 vendor
├── detection/
│   ├── analyzer_v2.py                # 10-layer DetectionEngine
│   └── fuzzy.py                      # FuzzyDetector + ResponseDiffer
├── crawler/
│   ├── spider.py                     # BFS async crawler
│   └── spa_crawler.py                # SPA crawl via Playwright
├── utils/
│   ├── config.py                     # ScanConfig (54 fields) + Context
│   ├── http_client.py                # Async HTTP (rate-limited, thread-safe)
│   └── logger.py                     # Rich logging
├── reports/
│   └── reporter.py                   # JSON+HTML+CSV+MD+SARIF (semua field di-escape)
├── tests/
│   ├── test_core.py                  # Unit tests
│   ├── test_integration.py           # Integration tests
│   └── test_revolutionary.py         # Matrix/Fuzzy/Sequencer tests
└── requirements.txt

★ = File baru atau diupdate signifikan
```

---

## Menjalankan Test Suite

```bash
pip install pytest pytest-asyncio
python -m pytest tests/ -v
# Hasil: 136 passed, 0 failed
```

---

## Changelog Terbaru

### vOVERPOWER FIXED + 2025 Update

**Bug Fixes (8 bug diperbaiki):**
- FIX-1: `HttpClient._rate_limit()` race condition — tambah `asyncio.Lock`
- FIX-2: Global dedup key tidak include URL — multi-target scan skip target lain
- FIX-3: XSS di HTML report — semua field di-escape dengan `html.escape()`
- FIX-4: `test_websocket` ghost flag — handler diperbaiki dan di-wire
- FIX-5: `test_hpp_2025` tidak dicek HPPTester — flag sekarang dihormati
- FIX-6: Blind XSS server tanpa CORS — callback tidak pernah sampai
- FIX-7: `_max_findings_reached()` dipanggil tapi tidak didefinisikan
- FIX-8: `_esc()` scope error di `save_md()` dan `save_sarif()`

**Fitur Baru 2025:**
- `scanner/interaction_simulator.py` — Playwright user gesture simulation untuk event handler baru
- `scanner/upload_injector.py` — File upload XSS via filename injection
- `NewEventHandlerEngine2025` — 13 event handler Chrome 114-126+ yang bypass WAF
- `ParserDifferentialEngine2025` — 10 varian parser differential (Ethiack Research 2025)
- 6 teknik evasion baru di `EvasionEngineV2` (31 total, 36.456 chain)
- `--scan-timeout`, `--max-findings`, `--payload-file`, `--no-progress` flags
- `--test-new-events`, `--test-parser-diff`, `--test-hpp-2025` flags
- Blind XSS server dengan CORS + OPTIONS preflight handler
- HPPTester dengan framework detection + ASP.NET comma concat exploit

---

## Legal Notice

Tool ini disediakan **hanya untuk authorized security testing**.

- Dapatkan izin tertulis sebelum scan sistem apapun
- Patuhi scope program bug bounty yang diikuti
- Penulis tidak bertanggung jawab atas penyalahgunaan
- Penggunaan tanpa izin merupakan tindak pidana di Indonesia (UU ITE) dan negara lain

---

*XScanner v3.0.0 vOVERPOWER · Python 3.11+*  
*4.495.343.099 kombinasi payload · 11 engine · 10-layer detection · 31 WAF bypass teknik*  
*136/136 unit tests passing · 20 vendor WAF · CORS-enabled blind XSS server*
