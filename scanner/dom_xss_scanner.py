"""
scanner/dom_xss_scanner.py

╔══════════════════════════════════════════════════════════════╗
║   DOM XSS SCANNER — Fix #2                                   ║
║   Deteksi DOM XSS pure client-side yang sebelumnya miss       ║
║                                                              ║
║   Cara kerja:                                                ║
║   1. Buka halaman dengan Playwright                          ║
║   2. Inject monitor script SEBELUM page JS berjalan          ║
║      → track semua assignment ke innerHTML, outerHTML, eval, ║
║        document.write, location.href, setTimeout(string)     ║
║   3. Test DOM XSS via semua sumber user-controlled:          ║
║      → location.hash (#<payload>)                            ║
║      → location.search (?param=<payload>)                    ║
║      → document.referrer                                     ║
║      → window.name                                           ║
║      → postMessage                                           ║
║   4. Intercept dialog + check window.__dom_xss global        ║
║   5. Report findings dengan full sink+source trace           ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse

from utils.config import ScanTarget, Finding, Context
from utils.logger import debug, info, warn, success


# ─── JS Monitor Script ────────────────────────────────────────────────────────
# Diinjeksi ke setiap halaman sebelum page scripts jalan
# Tracks semua DOM sink assignments dan laporkan ke window.__dom_xss_log

_MONITOR_SCRIPT = """
(function() {
  window.__dom_xss_log    = [];
  window.__dom_xss_triggered = false;

  function log(sink, value, stack) {
    var entry = {sink: sink, value: String(value).substring(0, 200), stack: stack || ''};
    window.__dom_xss_log.push(entry);
    // Heuristic: apakah value mengandung XSS marker?
    var markers = ['__XSS__', 'alert(', 'confirm(', 'prompt(', 'javascript:',
                   '<script', 'onerror=', 'onload=', 'onfocus=', '<svg', '<img'];
    for (var i = 0; i < markers.length; i++) {
      if (String(value).toLowerCase().indexOf(markers[i].toLowerCase()) !== -1) {
        window.__dom_xss_triggered = true;
        entry.triggered = true;
        break;
      }
    }
  }

  // ── Patch innerHTML / outerHTML ──────────────────────────────────────────
  var origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (origInnerHTML && origInnerHTML.set) {
    Object.defineProperty(Element.prototype, 'innerHTML', {
      set: function(val) {
        log('innerHTML', val, new Error().stack);
        return origInnerHTML.set.call(this, val);
      },
      get: origInnerHTML.get,
      configurable: true,
    });
  }

  var origOuterHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
  if (origOuterHTML && origOuterHTML.set) {
    Object.defineProperty(Element.prototype, 'outerHTML', {
      set: function(val) {
        log('outerHTML', val, new Error().stack);
        return origOuterHTML.set.call(this, val);
      },
      get: origOuterHTML.get,
      configurable: true,
    });
  }

  // ── Patch document.write ─────────────────────────────────────────────────
  var origWrite = document.write.bind(document);
  document.write = function(val) {
    log('document.write', val);
    return origWrite(val);
  };
  var origWriteln = document.writeln.bind(document);
  document.writeln = function(val) {
    log('document.writeln', val);
    return origWriteln(val);
  };

  // ── Patch insertAdjacentHTML ─────────────────────────────────────────────
  var origInsertAdj = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function(pos, val) {
    log('insertAdjacentHTML', val);
    return origInsertAdj.call(this, pos, val);
  };

  // ── Patch eval ───────────────────────────────────────────────────────────
  var origEval = window.eval;
  window.eval = function(code) {
    log('eval', code);
    return origEval(code);
  };

  // ── Patch setTimeout/setInterval with string ─────────────────────────────
  var origST = window.setTimeout;
  window.setTimeout = function(fn) {
    if (typeof fn === 'string') log('setTimeout(string)', fn);
    return origST.apply(this, arguments);
  };
  var origSI = window.setInterval;
  window.setInterval = function(fn) {
    if (typeof fn === 'string') log('setInterval(string)', fn);
    return origSI.apply(this, arguments);
  };

  // ── Patch location.href setter ────────────────────────────────────────────
  try {
    var origLocation = Object.getOwnPropertyDescriptor(window, 'location');
    if (!origLocation || origLocation.configurable) {
      // Can't always override location directly, patch href
    }
    var hrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    if (hrefDesc && hrefDesc.set) {
      Object.defineProperty(Location.prototype, 'href', {
        set: function(val) {
          if (String(val).indexOf('javascript:') !== -1) {
            log('location.href', val);
            window.__dom_xss_triggered = true;
          }
          return hrefDesc.set.call(this, val);
        },
        get: hrefDesc.get,
        configurable: true,
      });
    }
  } catch(e) {}

  // ── Patch DOMParser ──────────────────────────────────────────────────────
  var origDP = DOMParser.prototype.parseFromString;
  DOMParser.prototype.parseFromString = function(str, type) {
    log('DOMParser.parseFromString', str);
    return origDP.call(this, str, type);
  };

  // ── Patch Range.createContextualFragment ─────────────────────────────────
  var origRCF = Range.prototype.createContextualFragment;
  Range.prototype.createContextualFragment = function(str) {
    log('createContextualFragment', str);
    return origRCF.call(this, str);
  };

})();
"""


# ─── DOM XSS Payloads ─────────────────────────────────────────────────────────

DOM_XSS_PAYLOADS = [
    # Via location.hash
    ("<img src=x onerror=window.__dom_xss_triggered=true>",     "hash"),
    ("<svg onload=window.__dom_xss_triggered=true>",            "hash"),
    ("<script>window.__dom_xss_triggered=true</script>",        "hash"),
    ("javascript:window.__dom_xss_triggered=true",              "hash"),
    # Via query string
    ("<img src=x onerror=window.__dom_xss_triggered=true>",     "search"),
    ("<svg onload=window.__dom_xss_triggered=true>",            "search"),
    ("<details open ontoggle=window.__dom_xss_triggered=true>", "search"),
    # Via window.name (for iframe test)
    ("<img src=x onerror=window.__dom_xss_triggered=true>",     "window_name"),
    # Via postMessage
    ("{\"type\":\"xss\",\"data\":\"<img onerror=window.__dom_xss_triggered=true src=x>\"}",
     "postmessage"),
]

# Common DOM XSS source-sink patterns to look for in JS
DOM_SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.URL", "document.referrer", "window.name",
    "document.cookie", "localStorage", "sessionStorage",
    "URLSearchParams", "postMessage", "location.pathname",
]

DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "insertAdjacentHTML",
    "eval(", "setTimeout(", "setInterval(", "location.href",
    "location.assign", "location.replace", "src=", "action=",
    "DOMParser", "createContextualFragment", "jQuery.html(",
    "$.html(", "dangerouslySetInnerHTML",
]


class DOMXSSScanner:
    """
    DOM XSS scanner menggunakan Playwright dengan JS instrumentation.

    Deteksi DOM XSS yang sebelumnya miss karena payload tidak ke server:
    - location.hash → innerHTML
    - URLSearchParams → document.write
    - window.name → eval
    - postMessage → insertAdjacentHTML
    dsb.
    """

    def __init__(self, timeout_ms: int = 8000):
        self.timeout_ms   = timeout_ms
        self._browser     = None
        self._playwright  = None
        self._pw_ctx      = None

    async def start(self):
        try:
            from playwright.async_api import async_playwright
            self._pw_ctx     = async_playwright()
            self._playwright = await self._pw_ctx.__aenter__()
            self._browser    = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-web-security",   # untuk postMessage cross-origin
                    "--allow-running-insecure-content",
                ],
            )
            info("DOMXSSScanner: Playwright ready")
        except ImportError:
            warn("Playwright not installed — run: pip install playwright && playwright install chromium")
            self._browser = None

    async def stop(self):
        if self._browser:
            await self._browser.close()
        if self._pw_ctx and self._playwright:
            try:
                await self._pw_ctx.__aexit__(None, None, None)
            except Exception:
                pass

    async def scan_url(self, url: str) -> List[Finding]:
        """
        Scan satu URL untuk DOM XSS.
        Returns list of DOM XSS findings.
        """
        if not self._browser:
            return []

        findings = []

        # Step 1: Collect DOM sinks di page source (static analysis)
        sink_info = await self._analyze_page_sinks(url)
        if not sink_info["has_sinks"]:
            debug(f"DOMXSSScanner: no DOM sinks found in {url}")
            # Still run dynamic test — sinks might be in loaded JS
            pass

        # Step 2: Dynamic test via all injection sources
        for payload, source in DOM_XSS_PAYLOADS:
            result = await self._test_via_source(url, payload, source)
            if result:
                f = Finding(
                    url=url,
                    param=f"dom:{source}",
                    payload=payload,
                    context=Context.HTML,
                    xss_type="dom",
                    evidence=result["evidence"],
                    severity="High",
                    confidence="High",
                    verified=True,
                )
                findings.append(f)
                success(f"DOM XSS via {source}: {url}")
                break  # satu finding per URL cukup, lanjut ke parameter lain

        # Step 3: Cek sink log dari monitor script
        sink_findings = await self._check_sink_flow(url, sink_info)
        findings.extend(sink_findings)

        return findings

    async def _analyze_page_sinks(self, url: str) -> Dict:
        """
        Buka halaman dan collect info tentang DOM sinks yang ada.
        """
        if not self._browser:
            return {"has_sinks": False, "sinks": [], "sources": []}

        try:
            page = await self._browser.new_page()

            # Inject monitor sebelum page load
            await page.add_init_script(_MONITOR_SCRIPT)

            await page.goto(url, wait_until="domcontentloaded",
                            timeout=self.timeout_ms)
            await asyncio.sleep(0.5)

            # Ambil semua script content dari page
            scripts = await page.evaluate("""
                () => Array.from(document.scripts)
                    .map(s => s.textContent || s.src || '')
                    .join('\\n')
            """)

            found_sinks   = [s for s in DOM_SINKS   if s in scripts]
            found_sources = [s for s in DOM_SOURCES  if s in scripts]

            # Ambil sink log dari monitor
            sink_log = await page.evaluate(
                "() => window.__dom_xss_log || []"
            )

            await page.close()

            return {
                "has_sinks":    bool(found_sinks),
                "sinks":        found_sinks,
                "sources":      found_sources,
                "sink_log":     sink_log,
                "risky":        bool(found_sinks and found_sources),
            }

        except Exception as e:
            debug(f"DOMXSSScanner._analyze_page_sinks error: {e}")
            return {"has_sinks": False, "sinks": [], "sources": []}

    async def _test_via_source(
        self, url: str, payload: str, source: str
    ) -> Optional[Dict]:
        """
        Test DOM XSS via specific source (hash, search, window.name, postMessage).
        """
        if not self._browser:
            return None

        try:
            context = await self._browser.new_context()
            page    = await context.new_page()

            # Inject monitor script SEBELUM page JS berjalan
            await page.add_init_script(_MONITOR_SCRIPT)

            triggered = False

            # Dialog = alert/confirm/prompt dipanggil
            async def on_dialog(dialog):
                nonlocal triggered
                triggered = True
                await dialog.dismiss()

            page.on("dialog", on_dialog)

            # Build injection URL sesuai source
            if source == "hash":
                test_url = f"{url}#{payload}"
            elif source == "search":
                # Inject ke semua GET params yang ada
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                if not params:
                    params = {"q": [payload]}
                else:
                    params = {k: [payload] for k in params}
                new_query = urlencode({k: v[0] for k, v in params.items()})
                test_url  = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, ""
                ))
            elif source == "window_name":
                # Set window.name sebelum navigate
                await page.evaluate(f"window.name = {json.dumps(payload)}")
                test_url = url
            elif source == "postmessage":
                test_url = url
            else:
                test_url = url

            await page.goto(test_url, wait_until="networkidle",
                            timeout=self.timeout_ms)
            await asyncio.sleep(0.3)

            # Test postMessage setelah page load
            if source == "postmessage" and not triggered:
                try:
                    await page.evaluate(
                        f"window.postMessage({json.dumps(payload)}, '*')"
                    )
                    await asyncio.sleep(0.3)
                except Exception:
                    pass

            # Check window.__dom_xss_triggered
            if not triggered:
                triggered = await page.evaluate(
                    "() => window.__dom_xss_triggered === true"
                )

            # Ambil sink log untuk evidence
            sink_log = []
            if triggered:
                try:
                    sink_log = await page.evaluate(
                        "() => (window.__dom_xss_log || []).filter(e => e.triggered)"
                    )
                except Exception:
                    pass

            await page.close()
            await context.close()

            if triggered:
                evidence = f"DOM XSS via {source}"
                if sink_log:
                    entry = sink_log[0]
                    evidence = (
                        f"DOM XSS via {source} → sink: {entry.get('sink','?')}"
                        f" | value: {entry.get('value','?')[:80]}"
                    )
                return {"triggered": True, "source": source,
                        "evidence": evidence, "sink_log": sink_log}

        except Exception as e:
            debug(f"DOMXSSScanner._test_via_source ({source}) error: {e}")

        return None

    async def _check_sink_flow(
        self, url: str, sink_info: Dict
    ) -> List[Finding]:
        """
        BUG FIX #7: Sebelumnya semua source→sink pair di-report sebagai Medium severity
        tanpa execution proof, menyebabkan false positive yang masuk ke final report.
        
        Fix: hanya report sebagai Low/Info, dan TIDAK masuk hitungan findings utama
        kecuali ada dynamic execution evidence dari sink_log monitor script.
        """
        findings = []
        if not sink_info.get("risky"):
            return findings

        sinks    = sink_info.get("sinks", [])
        sources  = sink_info.get("sources", [])
        sink_log = sink_info.get("sink_log", [])

        # Prioritas: cek apakah monitor script sudah mencatat triggered sinks
        triggered_sinks = [e for e in sink_log if e.get("triggered")]
        if triggered_sinks:
            # Ada bukti eksekusi dari monitor → ini valid Medium finding
            entry = triggered_sinks[0]
            f = Finding(
                url=url,
                param=f"dom_monitor:{entry.get('sink','unknown')}",
                payload=entry.get("value", "")[:200],
                context=Context.HTML,
                xss_type="dom",
                evidence=(
                    f"Monitor script: sink={entry.get('sink')} "
                    f"triggered with value: {entry.get('value','')[:100]}"
                ),
                severity="Medium",
                confidence="Medium",
                verified=False,  # belum browser-confirmed, tapi ada trace
            )
            findings.append(f)
            debug(f"DOM sink triggered by monitor: {entry.get('sink')} at {url}")
            return findings

        # Tidak ada execution evidence — hanya laporkan sebagai Low/Info
        # dengan label yang jelas bahwa ini perlu manual verification
        for source in sources[:1]:  # batasi 1 pair untuk avoid spam
            for sink in sinks[:1]:
                f = Finding(
                    url=url,
                    param=f"dom_static:{source}→{sink}",
                    payload=f"# Static analysis: {source} → {sink}",
                    context=Context.HTML,
                    xss_type="dom_potential",
                    evidence=(
                        f"[LOW CONFIDENCE - MANUAL VERIFY REQUIRED] "
                        f"Static analysis found {source} (source) and {sink} (sink) "
                        f"in page scripts. No execution confirmed."
                    ),
                    severity="Low",   # BUG FIX: turun dari Medium ke Low
                    confidence="Low",
                    verified=False,
                )
                findings.append(f)
                debug(f"DOM static potential: {source} → {sink} at {url}")

        return findings

    async def scan_targets(self, targets: List[ScanTarget]) -> List[Finding]:
        """Scan multiple targets."""
        if not self._browser:
            return []

        seen_urls = set()
        findings  = []
        sem       = asyncio.Semaphore(3)

        async def _scan_one(t):
            async with sem:
                if t.url in seen_urls:
                    return
                seen_urls.add(t.url)
                fs = await self.scan_url(t.url)
                findings.extend(fs)

        await asyncio.gather(*[_scan_one(t) for t in targets],
                             return_exceptions=True)
        return findings
