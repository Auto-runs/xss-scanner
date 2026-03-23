"""
scanner/verifier.py
Headless browser-based XSS verification using Playwright.
Confirms actual JavaScript execution, not just string reflection.

Requires: playwright install chromium
"""

import asyncio
from typing import Optional, List, Tuple
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from utils.config import ScanTarget, Finding
from utils.logger import debug, success, warn
from scanner.interaction_simulator import InteractionSimulator, INTERACTION_TIMEOUT


class HeadlessVerifier:
    """
    Uses a headless Chromium browser to verify XSS findings.

    For each Finding:
    1. Navigate to the URL with payload injected
    2. Listen for dialog events (alert/confirm/prompt)
    3. Mark finding as verified=True if dialog fires
    """

    def __init__(self, timeout_ms: int = 8000):
        self.timeout_ms = timeout_ms
        self._playwright = None
        self._browser    = None
        self._sim        = InteractionSimulator()

    async def start(self):
        try:
            from playwright.async_api import async_playwright
            self._pw_ctx  = async_playwright()
            self._playwright = await self._pw_ctx.__aenter__()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            debug("Headless browser started")
        except ImportError:
            warn("Playwright not installed. Run: pip install playwright && playwright install chromium")
            self._browser = None

    async def verify(self, finding: Finding) -> bool:
        """
        Verifikasi XSS di headless browser.
        Kalau finding punya interaction_type di encoding_used,
        InteractionSimulator otomatis trigger interaksi yang dibutuhkan.
        """
        if self._browser is None:
            return False

        url       = self._build_url(finding)
        triggered = False

        # Deteksi interaction_type dari encoding_used
        # Format label: new_event_2025:event_name:setup_type:chromeX+
        interaction_type = "none"
        enc = finding.encoding_used or ""
        if "new_event_2025" in enc:
            from payloads.advanced_engines_v2 import NewEventHandlerEngine2025
            interaction_type = NewEventHandlerEngine2025.get_interaction_type(enc)
        elif "parser_diff" in enc:
            interaction_type = "none"  # auto-fire

        timeout_ms = INTERACTION_TIMEOUT.get(interaction_type, self.timeout_ms)
        debug(f"[verify] interaction={interaction_type} url={url[:60]}")

        try:
            ctx  = await self._browser.new_context(viewport={"width": 1280, "height": 720})
            page = await ctx.new_page()
            page.set_default_timeout(timeout_ms)

            # Tangkap dialog
            async def on_dialog(dialog):
                nonlocal triggered
                triggered = True
                debug(f"[verify] Dialog! type={dialog.type} msg={dialog.message[:50]}")
                await dialog.dismiss()

            page.on("dialog", on_dialog)

            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            await page.wait_for_timeout(200)

            # Kalau belum fire, jalankan simulasi interaksi
            if not triggered:
                triggered = await self._sim.trigger(page, interaction_type, timeout_ms)

            # Fallback: coba semua strategi kalau masih belum fire
            if not triggered and interaction_type == "none":
                triggered = await self._sim.trigger_all_strategies(page, timeout_ms)

            # Cek window.__xss_triggered (untuk DOM XSS scanner)
            if not triggered:
                try:
                    triggered = await page.evaluate("() => window.__xss_triggered === true")
                except Exception:
                    pass

            await ctx.close()

        except Exception as e:
            debug(f"[verify] error: {e}")

        return triggered

    async def verify_all(self, findings: List[Finding]) -> List[Finding]:
        """Verify a batch of findings. Updates finding.verified in-place."""
        if self._browser is None:
            return findings

        sem = asyncio.Semaphore(3)

        async def _verify_one(f: Finding):
            async with sem:
                result = await self.verify(f)
                if result:
                    f.verified = True
                    success(f"✓ Verified: {f.url} param={f.param}")

        await asyncio.gather(*[_verify_one(f) for f in findings])
        return findings

    async def stop(self):
        if self._browser:
            await self._browser.close()
        if self._playwright:
            try:
                await self._pw_ctx.__aexit__(None, None, None)
            except Exception:
                pass

    def _build_url(self, finding: Finding) -> str:
        """
        Inject the payload back into the URL for browser navigation.

        BUG FIX #8: DOM XSS findings have param like "dom:hash", "dom:search",
        "dom_static:location.hash→innerHTML" — these are NOT real query params.
        Trying to inject them as ?dom:hash=<payload> causes invalid URLs and
        the verifier silently fails or crashes.

        Fix: route DOM findings to their actual injection point.
        """
        param = finding.param
        payload = finding.payload

        # DOM XSS: route based on source type
        if param.startswith("dom:") or param.startswith("dom_"):
            source = param.split(":")[-1].split("→")[0].strip()
            parsed = urlparse(finding.url)

            if "hash" in source:
                # Inject via fragment
                return urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, parsed.query, payload
                ))
            elif "search" in source or "query" in source:
                # Inject as ?xss=<payload>
                new_query = urlencode({"xss": payload})
                return urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, ""
                ))
            else:
                # Fallback: return base URL unchanged (verifier will still
                # open the page and check window.__dom_xss_triggered)
                return finding.url

        # Standard reflected XSS: inject as query param
        parsed = urlparse(finding.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]

        flat_params = {k: v[0] for k, v in params.items()}
        new_query   = urlencode(flat_params)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, ""
        ))
