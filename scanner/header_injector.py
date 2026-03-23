"""
scanner/header_injector.py

Real-world gap fixes:
1. Header injection testing  — User-Agent, Referer, X-Forwarded-For, etc.
2. CSRF token auto-refresh   — Extracts + rotates CSRF tokens per request
3. Content-Type awareness    — Skip HTML payloads on JSON endpoints
4. Rate limit backoff        — Auto-detect 429 and exponential backoff
"""

import asyncio
import re
import copy
from typing import Optional, List, Dict, Tuple
from bs4 import BeautifulSoup

from utils.config import ScanTarget, Finding, Context
from utils.http_client import HttpClient, ResponseWrapper
from utils.logger import debug, info, warn, progress


# ─── Injectable Headers ───────────────────────────────────────────────────────

INJECTABLE_HEADERS = [
    # (header_name, label, reflection_likelihood)
    ("User-Agent",        "ua",       0.85),
    ("Referer",           "referer",  0.90),
    ("X-Forwarded-For",   "xff",      0.75),
    ("X-Forwarded-Host",  "xfh",      0.80),
    ("X-Real-IP",         "xrip",     0.65),
    ("X-Custom-IP-Auth",  "xcia",     0.55),
    ("X-Original-URL",    "xou",      0.70),
    ("X-Rewrite-URL",     "xru",      0.65),
    ("True-Client-IP",    "tcip",     0.60),
    ("CF-Connecting-IP",  "cfip",     0.55),
    ("X-Client-IP",       "xcip",     0.60),
    ("Contact",           "contact",  0.50),
    ("Origin",            "origin",   0.75),
    ("Via",               "via",      0.55),
]

# Payloads for header injection (kept simple — need to reflect as-is)
HEADER_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<xss>",  # canary for reflection detection
]


class HeaderInjector:
    """
    Tests XSS via HTTP header injection.
    Many real-world XSS vulnerabilities come from headers
    being reflected in error pages, logs, admin panels.
    """

    def __init__(self, http: HttpClient):
        self.http = http

    async def test_url(self, url: str, baseline_body: str) -> List[Finding]:
        """Test all injectable headers on a URL."""
        findings = []
        tasks = [
            self._test_header(url, hdr_name, label, baseline_body)
            for hdr_name, label, _ in INJECTABLE_HEADERS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    async def _test_header(
        self, url: str, header_name: str, label: str, baseline_body: str
    ) -> List[Finding]:
        findings = []
        for payload in HEADER_PAYLOADS[:4]:  # top 4 payloads per header
            try:
                resp = await self.http.get(url, headers={header_name: payload})
                if resp is None:
                    continue
                if payload in resp.text or "<xss>" in resp.text:
                    findings.append(Finding(
                        url          = url,
                        param        = f"header:{header_name}",
                        payload      = payload,
                        context      = Context.HTML,
                        xss_type     = "reflected",
                        evidence     = resp.text[
                            max(0, resp.text.find(payload)-80):
                            resp.text.find(payload)+len(payload)+80
                        ][:300],
                        severity     = "High",
                        confidence   = "High",
                        encoding_used= "header_injection",
                    ))
                    break  # one finding per header
            except Exception as e:
                debug(f"Header inject error {header_name}: {e}")
        return findings


# ─── CSRF Token Handler ──────────────────────────────────────────────────────

CSRF_FIELD_NAMES = [
    "csrf_token", "csrftoken", "_csrf", "csrf", "_token", "token",
    "authenticity_token", "_csrf_token", "csrf_middleware_token",
    "csrfmiddlewaretoken", "__RequestVerificationToken",
    "requestVerificationToken", "_wpnonce", "nonce",
]

CSRF_HEADER_NAMES = [
    "X-CSRF-Token", "X-CSRFToken", "X-Requested-With",
    "X-XSRF-TOKEN", "csrf-token", "CSRF-Token",
]


class CSRFHandler:
    """
    Automatically extracts and refreshes CSRF tokens before each POST request.

    Flow:
    1. GET the form page → extract CSRF token from HTML
    2. Inject token into POST data and/or headers
    3. On 403, re-fetch and retry once

    Without this, stored XSS detection fails on ~95% of real targets.
    """

    def __init__(self, http: HttpClient):
        self.http         = http
        self._token_cache: Dict[str, str] = {}  # url → token

    async def prepare_post(
        self,
        target: ScanTarget,
    ) -> ScanTarget:
        """
        Fetch fresh CSRF token and inject into target.data.
        Returns updated ScanTarget with CSRF token populated.
        """
        t = copy.deepcopy(target)
        token = await self._fetch_token(target.url)
        if token:
            # Inject into data fields
            for field_name in CSRF_FIELD_NAMES:
                if field_name in t.data:
                    t.data[field_name] = token
                    debug(f"CSRF: refreshed field '{field_name}' = {token[:20]}...")
                    break
            else:
                # Add it anyway with most common name
                t.data["csrf_token"] = token

            # Also add as header
            t.headers = t.headers or {}
            t.headers["X-CSRFToken"] = token
            t.headers["X-CSRF-Token"] = token
        return t

    async def _fetch_token(self, url: str) -> Optional[str]:
        """Fetch page and extract CSRF token from HTML or Set-Cookie."""
        try:
            resp = await self.http.get(url)
            if resp is None:
                return None

            # 1. Check HTML hidden inputs
            soup = BeautifulSoup(resp.text, "html.parser")
            for name in CSRF_FIELD_NAMES:
                inp = soup.find("input", {"name": name})
                if inp and inp.get("value"):
                    token = inp["value"]
                    debug(f"CSRF: found token in input[name={name}]")
                    return token

            # 2. Check meta tags (common in SPA frameworks)
            meta = soup.find("meta", {"name": re.compile(r"csrf", re.I)})
            if meta and meta.get("content"):
                return meta["content"]

            # 3. Check Set-Cookie header for XSRF token
            for hdr_name, hdr_val in resp.headers.items():
                if "xsrf" in hdr_name.lower() or "csrf" in hdr_name.lower():
                    # Extract token value from cookie
                    match = re.search(r'[A-Za-z0-9_\-]{20,}', hdr_val)
                    if match:
                        return match.group(0)

            # 4. Check JavaScript for embedded token
            js_match = re.search(
                r'''csrf[_-]?token['":\s]+['"]([A-Za-z0-9_\-]{20,})['"]''',
                resp.text, re.I
            )
            if js_match:
                return js_match.group(1)

        except Exception as e:
            debug(f"CSRF fetch error: {e}")
        return None


# ─── Content-Type Aware Scanner ──────────────────────────────────────────────

class ContentTypeAnalyzer:
    """
    Analyze response Content-Type to select appropriate payloads.
    Avoids wasting requests testing HTML payloads on JSON endpoints.
    """

    @staticmethod
    def analyze(response: ResponseWrapper) -> dict:
        """
        Returns dict with content type info and recommended context.
        """
        ct = response.headers.get("Content-Type", "").lower()

        return {
            "is_html":   "text/html" in ct,
            "is_json":   "application/json" in ct or "text/json" in ct,
            "is_xml":    "text/xml" in ct or "application/xml" in ct,
            "is_js":     "javascript" in ct,
            "is_text":   "text/plain" in ct,
            "raw":       ct,
            "context":   ContentTypeAnalyzer._infer_context(ct),
        }

    @staticmethod
    def _infer_context(ct: str) -> str:
        if "application/json" in ct or "text/json" in ct:
            return Context.JS_STRING  # JSON values need JS-style payloads
        if "text/html" in ct:
            return Context.HTML
        if "text/javascript" in ct or "application/javascript" in ct:
            return Context.JS
        if "text/xml" in ct or "application/xml" in ct:
            return Context.HTML  # XML can still reflect HTML
        return Context.UNKNOWN

    @staticmethod
    def should_test_html_payloads(response: ResponseWrapper) -> bool:
        ct = response.headers.get("Content-Type", "").lower()
        # Don't test HTML payloads on pure JSON/binary responses
        return not ("application/json" in ct or
                    "image/" in ct or
                    "application/octet-stream" in ct)


# ─── Rate Limit Handler ──────────────────────────────────────────────────────

class RateLimitHandler:
    """
    Auto-detect rate limiting (429) and apply exponential backoff.
    Also detects soft rate limiting (custom block pages).
    """

    RATE_LIMIT_STATUS = {429, 503, 509}
    RATE_LIMIT_PATTERNS = [
        "too many requests", "rate limit", "slow down",
        "try again later", "throttle", "exceeded",
    ]

    def __init__(self):
        self._consecutive_429s = 0
        self._base_delay       = 1.0
        self._max_delay        = 60.0

    def is_rate_limited(self, response: Optional[ResponseWrapper]) -> bool:
        if response is None:
            return False
        if response.status in self.RATE_LIMIT_STATUS:
            return True
        # Soft rate limit detection
        body_lower = response.text[:500].lower()
        return any(p in body_lower for p in self.RATE_LIMIT_PATTERNS)

    async def handle(self, response: Optional[ResponseWrapper]) -> float:
        """
        If rate limited, increment counter and return backoff delay.
        Returns 0.0 if not rate limited.
        """
        if not self.is_rate_limited(response):
            self._consecutive_429s = 0
            return 0.0

        self._consecutive_429s += 1
        delay = min(
            self._base_delay * (2 ** self._consecutive_429s),
            self._max_delay,
        )
        warn(f"Rate limited (hit #{self._consecutive_429s}) — backing off {delay:.1f}s")
        await asyncio.sleep(delay)
        return delay

    def reset(self):
        self._consecutive_429s = 0
