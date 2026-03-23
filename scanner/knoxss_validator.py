"""
scanner/knoxss_validator.py

KNOXSS-inspired XSS Validator — konfirmasi XSS dengan Playwright
menggunakan pendekatan multi-engine browser validation.

KNOXSS kuat karena:
1. Validasi dengan browser engine nyata (Blink/WebKit/Gecko)
2. 50+ case coverage berdasarkan konteks spesifik
3. AFB (Advanced Filter Bypass) — probe karakter satu per satu
4. Flash Mode — polyglot yang jalan di semua konteks
5. CheckPoC — generate PoC proof yang proper untuk laporan

Implementasi ini:
- Validates XSS dengan Playwright headless Chromium
- AFB: probe setiap karakter kritis dan craft bypass presisi
- Context-aware payload selection berdasarkan AFB result
- PoC generator — HTML report yang bisa langsung di-submit
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Tuple

from utils.config import ScanTarget, Finding, Context
from utils.logger import debug, info, success, warn
from payloads.knoxss_cases import KnoxssCaseEngine


# Karakter kritis yang di-probe oleh AFB
# Masing-masing bisa "survive" (lolos filter) atau "blocked" (difilter)
AFB_CHARS = {
    "angle_open":    "<",
    "angle_close":   ">",
    "double_quote":  '"',
    "single_quote":  "'",
    "backtick":      "`",
    "semicolon":     ";",
    "parenthesis_o": "(",
    "parenthesis_c": ")",
    "slash":         "/",
    "backslash":     "\\",
    "space":         " ",
    "equals":        "=",
    "ampersand":     "&",
    "hash":          "#",
    "dollar":        "$",
    "curly_o":       "{",
    "curly_c":       "}",
    "newline":       "\n",
    "tab":           "\t",
    "null":          "\x00",
}


class AFBResult:
    """Hasil Advanced Filter Bypass probe."""

    def __init__(self):
        self.survived: Dict[str, str] = {}   # char_name → char
        self.blocked:  Dict[str, str] = {}   # char_name → char
        self.encoded:  Dict[str, str] = {}   # char_name → encoded form

    @property
    def can_break_html(self) -> bool:
        return "angle_open" in self.survived

    @property
    def can_break_dq_attr(self) -> bool:
        return "double_quote" in self.survived

    @property
    def can_break_sq_attr(self) -> bool:
        return "single_quote" in self.survived

    @property
    def can_execute_js(self) -> bool:
        return (
            "parenthesis_o" in self.survived and
            "parenthesis_c" in self.survived
        )

    @property
    def can_use_template_literal(self) -> bool:
        return "backtick" in self.survived

    @property
    def can_break_js_string_dq(self) -> bool:
        return "double_quote" in self.survived or "backslash" in self.survived

    @property
    def can_break_js_string_sq(self) -> bool:
        return "single_quote" in self.survived or "backslash" in self.survived

    def best_context(self) -> str:
        """Pilih konteks terbaik berdasarkan karakter yang survived."""
        if self.can_break_html and self.can_execute_js:
            return "html"
        if self.can_break_dq_attr and self.can_execute_js:
            return "attr_dq"
        if self.can_break_sq_attr and self.can_execute_js:
            return "attr_sq"
        if self.can_break_js_string_dq:
            return "js_dq"
        if self.can_break_js_string_sq:
            return "js_sq"
        if self.can_use_template_literal:
            return "js_template"
        if self.can_execute_js:
            return "attr_quoteless"
        return "unknown"

    def to_dict(self) -> dict:
        return {
            "survived": list(self.survived.keys()),
            "blocked":  list(self.blocked.keys()),
            "best_ctx": self.best_context(),
            "can_break_html":       self.can_break_html,
            "can_execute_js":       self.can_execute_js,
            "can_break_dq":         self.can_break_dq_attr,
            "can_break_sq":         self.can_break_sq_attr,
        }


class KnoxssValidator:
    """
    Validates dan meng-exploit XSS menggunakan pendekatan KNOXSS.
    """

    def __init__(self, http, timeout_ms: int = 8000):
        self.http       = http
        self.timeout_ms = timeout_ms
        self.case_eng   = KnoxssCaseEngine()
        self._browser   = None
        self._pw        = None

    async def start(self):
        """Start Playwright browser."""
        try:
            from playwright.async_api import async_playwright
            self._pw_ctx = async_playwright()
            self._pw     = await self._pw_ctx.__aenter__()
            self._browser = await self._pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            debug("KnoxssValidator: browser started")
        except ImportError:
            warn("Playwright tidak terinstall. Jalankan: pip install playwright && playwright install chromium")
            self._browser = None

    async def stop(self):
        if self._browser:
            await self._browser.close()
        if self._pw:
            try:
                await self._pw_ctx.__aexit__(None, None, None)
            except Exception:
                pass

    # ─── AFB: Advanced Filter Bypass ─────────────────────────────────────────

    async def run_afb(
        self,
        target: ScanTarget,
        context_hint: str = "unknown",
    ) -> AFBResult:
        """
        Probe setiap karakter kritis ke target.
        Return AFBResult yang menggambarkan karakter mana yang survive.
        """
        result = AFBResult()

        # Probe setiap karakter
        for char_name, char in AFB_CHARS.items():
            probe = f"XSSAFB{char}PROBE"
            try:
                injected = self._inject_payload(target, probe)
                resp     = await self.http.get(injected.url, params=injected.params)
                if not resp:
                    continue

                body = resp.text
                if probe in body:
                    result.survived[char_name] = char
                elif f"XSSAFB" in body and "PROBE" in body:
                    # Karakter di-encode
                    result.encoded[char_name] = char
                else:
                    result.blocked[char_name] = char

            except Exception as e:
                debug(f"AFB probe {char_name} error: {e}")

        debug(f"AFB result: survived={list(result.survived.keys())[:8]}")
        return result

    # ─── Context-aware payload generation ────────────────────────────────────

    def get_payloads_for_afb(
        self,
        afb: AFBResult,
        top_n: int = 30,
    ) -> List[Tuple[str, float, str]]:
        """
        Pilih payload terbaik berdasarkan AFB result.
        Payload yang butuh karakter yang di-block akan di-skip.
        """
        best_ctx = afb.best_context()
        if best_ctx == "unknown":
            # Tidak ada karakter yang survive — coba JS hoisting dan encoding tricks
            return self.case_eng.generate("all", top_n=10)

        candidates = self.case_eng.generate(best_ctx, top_n=top_n * 2)

        # Filter payload yang butuh karakter blocked
        filtered = []
        for payload, score, label in candidates:
            viable = True
            for char_name, char in afb.blocked.items():
                if char in payload:
                    viable = False
                    break
            if viable:
                filtered.append((payload, score, label))

        return filtered[:top_n]

    # ─── Browser-based validation ─────────────────────────────────────────────

    async def validate_in_browser(
        self,
        url:     str,
        finding: Finding,
    ) -> bool:
        """
        Buka URL di browser, cek apakah alert() benar-benar jalan.
        """
        if not self._browser:
            return False

        fired = False
        try:
            ctx  = await self._browser.new_context(
                viewport={"width": 1280, "height": 720}
            )
            page = await ctx.new_page()
            page.set_default_timeout(self.timeout_ms)

            async def on_dialog(dialog):
                nonlocal fired
                fired = True
                await dialog.dismiss()

            page.on("dialog", on_dialog)
            await page.goto(url, wait_until="domcontentloaded",
                            timeout=self.timeout_ms)
            await page.wait_for_timeout(500)

            if not fired:
                # Cek window.__xss_triggered
                try:
                    fired = await page.evaluate("() => !!window.__xss_triggered")
                except Exception:
                    pass

            await ctx.close()
        except Exception as e:
            debug(f"Browser validate error: {e}")

        return fired

    # ─── PoC Generator ────────────────────────────────────────────────────────

    def generate_poc_html(
        self,
        finding: Finding,
        afb:     Optional[AFBResult] = None,
    ) -> str:
        """
        Generate HTML PoC yang siap di-submit ke bug bounty.
        Terinspirasi dari knoxss CheckPoC output.
        """
        import html as _html

        esc_url     = _html.escape(finding.url)
        esc_payload = _html.escape(finding.payload)
        esc_param   = _html.escape(finding.param)
        esc_evidence= _html.escape(finding.evidence[:500])
        afb_section = ""
        if afb:
            afb_dict = afb.to_dict()
            afb_section = f"""
        <div class="section">
          <h2>Advanced Filter Bypass (AFB) Analysis</h2>
          <p><strong>Best context:</strong> <code>{afb_dict['best_ctx']}</code></p>
          <p><strong>Survived characters:</strong>
            {', '.join(f'<code>{c}</code>' for c in afb_dict['survived']) or 'none'}
          </p>
          <p><strong>Blocked characters:</strong>
            {', '.join(f'<code>{c}</code>' for c in afb_dict['blocked']) or 'none'}
          </p>
        </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>XSS PoC — {esc_param} @ {esc_url[:60]}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif;
           background: #0d1117; color: #e6edf3; padding: 24px; margin: 0; }}
    h1 {{ color: #f85149; margin-bottom: 4px; }}
    .subtitle {{ color: #8b949e; margin-bottom: 24px; }}
    .section {{ background: #161b22; border: 1px solid #30363d;
                border-radius: 8px; padding: 20px; margin-bottom: 16px; }}
    h2 {{ color: #58a6ff; font-size: 1em; margin: 0 0 12px; }}
    code {{ background: #21262d; padding: 2px 6px; border-radius: 4px;
            font-family: 'Courier New', monospace; font-size: 0.9em; }}
    .payload-box {{ background: #1c2128; border: 1px solid #f85149;
                    border-radius: 6px; padding: 12px; word-break: break-all;
                    font-family: monospace; font-size: 0.85em; color: #ff7b72; }}
    .severity-high {{ color: #f85149; font-weight: bold; }}
    .steps {{ counter-reset: step; }}
    .steps li {{ counter-increment: step; margin-bottom: 8px; }}
    .steps li::before {{ content: counter(step) ". "; color: #58a6ff; font-weight: bold; }}
    a {{ color: #58a6ff; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;
              font-size: 0.75em; font-weight: bold; }}
    .badge-high {{ background: #f85149; color: white; }}
    .badge-type {{ background: #1f6feb; color: white; }}
    .footer {{ color: #8b949e; font-size: 0.8em; text-align: center;
               margin-top: 32px; border-top: 1px solid #21262d; padding-top: 16px; }}
  </style>
</head>
<body>
  <h1>🎯 XSS Proof of Concept</h1>
  <p class="subtitle">Generated by XScanner vOVERPOWER · KnoxssValidator</p>

  <div class="section">
    <h2>Vulnerability Summary</h2>
    <table style="border-collapse:collapse;width:100%">
      <tr><td style="padding:4px 8px;color:#8b949e;width:140px">URL</td>
          <td><a href="{esc_url}">{esc_url}</a></td></tr>
      <tr><td style="padding:4px 8px;color:#8b949e">Parameter</td>
          <td><code>{esc_param}</code></td></tr>
      <tr><td style="padding:4px 8px;color:#8b949e">Type</td>
          <td>
            <span class="badge badge-type">{finding.xss_type.upper()}</span>
            <span class="badge badge-high">{finding.severity}</span>
          </td></tr>
      <tr><td style="padding:4px 8px;color:#8b949e">Context</td>
          <td><code>{finding.context}</code></td></tr>
      <tr><td style="padding:4px 8px;color:#8b949e">Verified</td>
          <td>{'✅ Confirmed in browser' if finding.verified else '⚠ Detected (verify manually)'}</td></tr>
    </table>
  </div>

  <div class="section">
    <h2>Payload</h2>
    <div class="payload-box">{esc_payload}</div>
  </div>

  <div class="section">
    <h2>Evidence</h2>
    <div class="payload-box">{esc_evidence}</div>
  </div>

  {afb_section}

  <div class="section">
    <h2>Reproduction Steps</h2>
    <ol class="steps">
      <li>Buka browser (Chrome/Firefox disarankan)</li>
      <li>Navigate ke: <a href="{esc_url}">{esc_url}</a></li>
      <li>Inject payload berikut ke parameter <code>{esc_param}</code>:
        <br><br><div class="payload-box">{esc_payload}</div></li>
      <li>Observe: JavaScript <code>alert()</code> dialog muncul atau payload ter-eksekusi</li>
    </ol>
  </div>

  <div class="section">
    <h2>Impact</h2>
    <ul>
      <li>Session hijacking via cookie theft</li>
      <li>Credential phishing via DOM manipulation</li>
      <li>Malicious redirects</li>
      <li>Keylogging dan form data theft</li>
      <li>Internal network scanning via browser</li>
    </ul>
  </div>

  <div class="section">
    <h2>Remediation</h2>
    <ul>
      <li>Escape semua user input sebelum di-render di HTML
          (gunakan <code>htmlspecialchars()</code> di PHP,
          <code>html.escape()</code> di Python, dll)</li>
      <li>Implementasi Content Security Policy (CSP) yang strict</li>
      <li>Validasi input di server-side, bukan hanya client-side</li>
      <li>Gunakan framework modern yang auto-escape secara default
          (React, Angular, dll)</li>
    </ul>
  </div>

  <div class="footer">
    XScanner vOVERPOWER · Generated {__import__('time').strftime('%Y-%m-%d %H:%M UTC', __import__('time').gmtime())}
  </div>
</body>
</html>"""

    # ─── Helper ───────────────────────────────────────────────────────────────

    def _inject_payload(self, target: ScanTarget, payload: str) -> ScanTarget:
        """Inject payload ke target."""
        import copy
        t = copy.deepcopy(target)
        if t.method == "GET":
            t.params[t.param_key] = payload
        else:
            t.data[t.param_key] = payload
        return t
