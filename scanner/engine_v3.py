"""
scanner/engine_v3.py — XScanner vOVERPOWER Unified Engine

╔══════════════════════════════════════════════════════════════╗
║   All 11 payload engines wired + Detection v2               ║
║   4,495,343,519 total combinations (4.50 BILLION)           ║
║                                                              ║
║   Engines active:                                            ║
║   ✅ CombinatorialEngineV2    4,260,695,040                  ║
║   ✅ MXSSEngineV2               115,404,800                  ║
║   ✅ BlindXSSEngineV2             1,088,640                  ║
║   ✅ JSONAPIEngineV2            110,909,568                  ║
║   ✅ CSPBypassEngine              1,620,000                  ║
║   ✅ PrototypePollutionEngine     2,700,000                  ║
║   ✅ UnicodeHomoglyphEngine       2,880,000                  ║
║   ✅ BrowserQuirksEngine               420                  ║
║   ✅ HTTPSmugglingXSSEngine          45,000                  ║
║   ✅ TemplateInjectionEngine             31                  ║
║   ✅ DOMClobberingEngine               20                   ║
║   ✅ EvasionEngineV2          15,275/payload                 ║
║   ✅ DetectionEngineV2        10-layer detection             ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import copy
import time
from typing import List, Optional, Dict, Set, Tuple
from urllib.parse import urlparse

from utils.config import (
    ScanConfig, ScanTarget, Finding, Context,  # Context includes NOT_REFLECTED
    COMBO_TOP_N, MXSS_TOP_N, BLIND_TOP_N, JSON_TOP_N,
    SCAN_PROFILES,
)
from utils.http_client import HttpClient
from utils.logger import debug, info, warn, success, finding as log_finding

# ── Crawler & Context ────────────────────────────────────────────────────────
from crawler.spider import Spider, ContextDetector
from crawler.spa_crawler import SPACrawler          # Fix #3: SPA param discovery
from scanner.dom_xss_scanner import DOMXSSScanner   # Fix #2: DOM XSS detection

# ── Payload Engines v2 ───────────────────────────────────────────────────────
from payloads.combinatorial_engine_v2 import CombinatorialEngineV2
from payloads.mxss_engine_v2 import MXSSEngineV2
from payloads.blind_xss_v2 import BlindXSSEngineV2
from payloads.advanced_engines_v2 import (
    JSONAPIEngineV2,
    PrototypePollutionEngine,
    UnicodeHomoglyphEngine,
    BrowserQuirksEngine,
    HTTPSmugglingXSSEngine,
    NewEventHandlerEngine2025,
    ParserDifferentialEngine2025,
)
from payloads.csp_bypass_engine import (
    CSPBypassEngine,
    TemplateInjectionEngine,
    DOMClobberingEngine,
)

# ── v1 engines (fallback + supplement) ───────────────────────────────────────
from payloads.generator import PayloadGenerator
from payloads.smart_generator import SmartGenerator, AdaptiveSequencer
from payloads.mxss_and_api import WAFChainEngine, JSONAPITester, BlindXSSEngine as BlindXSSEngineV1

# ── WAF ──────────────────────────────────────────────────────────────────────
from waf_bypass.detector import WAFDetector
from waf_bypass.evasion_v2 import EvasionEngineV2

# ── Detection ────────────────────────────────────────────────────────────────
from detection.analyzer_v2 import DetectionEngineV2
from detection.fuzzy import FuzzyDetector, ResponseDiffer

# ── Scanner modules ───────────────────────────────────────────────────────────
from scanner.filter_probe import FilterProbe, SmartPayloadFilter
from scanner.header_injector import (
    HeaderInjector, CSRFHandler,
    ContentTypeAnalyzer, RateLimitHandler,
)
from scanner.real_world import (
    HPPTester, SecondOrderTracker, ScopeManager,
    AuthHandler, JSParamExtractor, CheckpointManager,
)
from scanner.ai_advisor import AIPayloadAdvisor
from scanner.verifier import HeadlessVerifier
from scanner.upload_injector import UploadInjector
from scanner.interaction_simulator import InteractionSimulator, INTERACTION_TIMEOUT


class ScanEngineV3:
    """
    vOVERPOWER unified scan engine.
    All v2 payload engines + 10-layer detection + full feature parity.
    """

    def __init__(self, config: ScanConfig):
        self.config   = config
        self.http     = HttpClient(config)
        # config.deep adalah shorthand untuk profile='deep'
        effective_profile = 'deep' if config.deep else config.profile
        self._profile = SCAN_PROFILES.get(effective_profile, SCAN_PROFILES["normal"])
        self.findings: List[Finding] = []
        self._lock    = asyncio.Lock()
        self._ver     = config.engine_version  # "v1" | "v2"

        # Stats
        self._stats = {
            "requests_sent":   0,
            "requests_saved":  0,
            "payloads_tested": 0,
            "urls_scanned":    0,
        }

        # ── Payload engines ──────────────────────────────────
        prof = config.profile
        ver  = self._ver

        self.combo_engine  = CombinatorialEngineV2()
        self.mxss_engine   = MXSSEngineV2()
        self.blind_engine  = BlindXSSEngineV2()
        self.json_engine   = JSONAPIEngineV2()
        self.csp_engine    = CSPBypassEngine()
        self.tpl_engine    = TemplateInjectionEngine()
        self.dom_clob      = DOMClobberingEngine()
        self.pp_engine     = PrototypePollutionEngine()
        self.unicode_eng   = UnicodeHomoglyphEngine()
        self.browser_eng   = BrowserQuirksEngine()
        self.smuggle_eng   = HTTPSmugglingXSSEngine()
        # 2025/2026 engines
        self.new_event_eng    = NewEventHandlerEngine2025()
        self.upload_injector = UploadInjector(self.http)
        self.verifier        = HeadlessVerifier(timeout_ms=8000)
        self.parser_diff_eng = ParserDifferentialEngine2025()

        # v1 supplement
        self.payload_gen   = PayloadGenerator(
            max_per_ctx=self._profile["payloads_per_ctx"],
            waf_bypass=config.waf_bypass,
        )
        self.smart_gen     = SmartGenerator(max_payloads=self._profile["payloads_per_ctx"])
        self.waf_chain     = WAFChainEngine()         # v1 chain (kept for compat)
        self.json_tester_v1 = JSONAPITester(self.http)

        # ── Detection ────────────────────────────────────────
        self.detector    = DetectionEngineV2()
        self.fuzzy       = FuzzyDetector()
        self.differ      = ResponseDiffer()

        # ── WAF ──────────────────────────────────────────────
        self.waf_detector = WAFDetector()
        self.evasion      = EvasionEngineV2()

        # ── Context + Crawl ───────────────────────────────────
        self.ctx_detector  = ContextDetector()
        self.filter_probe  = FilterProbe(self.http)
        self.smart_filter  = SmartPayloadFilter()
        self.sequencer     = AdaptiveSequencer()

        # ── Scanner modules ───────────────────────────────────
        self.header_injector  = HeaderInjector(self.http)
        self.csrf_handler     = CSRFHandler(self.http)
        self.content_analyzer = ContentTypeAnalyzer()
        self.rate_limiter     = RateLimitHandler()
        self.hpp_tester       = HPPTester(self.http, config)
        self.second_order     = SecondOrderTracker(self.http)

        # ── Scope, auth, extras ───────────────────────────────
        self.scope_manager = ScopeManager(
            in_scope=config.scope,
            out_scope=config.exclude_scope,
            exclude_paths=config.exclude_path,
        )
        self.auth_handler  = AuthHandler(self.http)
        self.js_extractor  = JSParamExtractor(self.http) if config.js_crawl else None

        # ── Fix #2: DOM XSS Scanner ──────────────────────
        self.dom_xss_scanner = DOMXSSScanner() if config.dom_xss_scan else None

        # ── Fix #3: SPA Crawler ──────────────────────────
        self.spa_crawler = SPACrawler(
            base_url=config.targets[0] if config.targets else "",
            interact_forms=getattr(config, "spa_interact", False),
        ) if config.spa_crawl else None

        _ckpt_key = "|".join(sorted(config.targets))
        self.checkpoint_mgr = CheckpointManager(_ckpt_key) if config.checkpoint else None

        # ── AI advisor ────────────────────────────────────────
        self.ai_advisor = AIPayloadAdvisor() if config.ai_assist else None

        # ── Caches ────────────────────────────────────────────
        self._waf_cache:    Dict[str, Optional[str]] = {}
        self._filter_cache: Dict[str, object]        = {}
        self._tested:       Set[str]                 = set()

        # Report totals
        # Wire verbose ke logger
        if config.verbose:
            from utils.logger import set_verbose
            set_verbose(True)

        total = (self.combo_engine.total + self.mxss_engine.total +
                 self.blind_engine.total + self.json_engine.total +
                 self.csp_engine.total + self.pp_engine.total +
                 self.unicode_eng.total)
        info(f"XScanner vOVERPOWER ready — {total:,} combinations ({total/1e9:.2f}B)")

    # ═══ Public API ═══════════════════════════════════════════

    async def run(self) -> List[Finding]:
        """Entry point dengan scan_timeout support."""
        timeout = self.config.scan_timeout
        if timeout and timeout > 0:
            try:
                return await asyncio.wait_for(self._run_inner(), timeout=timeout)
            except asyncio.TimeoutError:
                warn(f"Scan timeout setelah {timeout}s — {len(self.findings)} findings")
                return self.findings
        return await self._run_inner()

    async def _run_inner(self) -> List[Finding]:
        # Start headless verifier jika diperlukan
        if self.config.verify_headless:
            await self.verifier.start()

        # Auth
        if self.config.login_url and self.config.username:
            ok = await self.auth_handler.login(
                self.config.login_url,
                self.config.username,
                self.config.password,
            )
            info("Auth: " + ("OK" if ok else "FAILED — continuing unauthenticated"))

        # Resume checkpoint
        if self.checkpoint_mgr and self.checkpoint_mgr.load():
            self._tested = set(self.checkpoint_mgr._state.get("tested", []))
            info(f"Checkpoint: resuming ({len(self._tested)} already tested)")

        # BUG FIX: inisialisasi _all_targets di sini supaya _scan_url bisa mengisinya
        self._all_targets: List[ScanTarget] = []

        tasks = [self._scan_url(url) for url in self.config.targets]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Fix #2: DOM XSS scan
        if self.dom_xss_scanner:
            await self.dom_xss_scanner.start()
            all_urls = list(set(t.url for t in getattr(self, '_all_targets', [])))
            if not all_urls:
                all_urls = self.config.targets
            dom_findings = await self.dom_xss_scanner.scan_targets(
                [ScanTarget(url=u, method='GET', param_key='dom') for u in all_urls]
            )
            async with self._lock:
                self.findings.extend(dom_findings)
            await self.dom_xss_scanner.stop()

        # Second-order verification
        if self.config.second_order and self.second_order._records:
            so = await self.second_order.verify_all()
            async with self._lock:
                self.findings.extend(so)

        # Save checkpoint
        if self.checkpoint_mgr:
            self.checkpoint_mgr.save(list(self._tested), self.findings)

        self._print_stats()
        if self.config.verify_headless:
            await self.verifier.stop()
        return self.findings

    # ═══ Per-URL ════════════════════════════════════════════

    async def _scan_url(self, url: str):
        info(f"Scanning: {url}")
        self._stats["urls_scanned"] += 1

        if not self.scope_manager.is_in_scope(url):
            warn(f"Out of scope: {url}")
            return

        # Crawl
        targets = (await Spider(self.config, self.http).crawl(url)
                   if self.config.crawl else self._url_to_targets(url))

        # BUG FIX: simpan semua discovered targets agar DOM XSS scanner bisa scan semuanya
        async with self._lock:
            self._all_targets.extend(targets)

        # Fix #3: SPA crawl (Playwright-based param discovery)
        if self.spa_crawler:
            await self.spa_crawler.start()
            spa_targets = await self.spa_crawler.crawl(url)
            if spa_targets:
                info(f'SPA crawl: +{len(spa_targets)} params')
                targets.extend(spa_targets)
            await self.spa_crawler.stop()

        # JS param extraction
        if self.js_extractor:
            js_t = await self.js_extractor.extract_from_page(url)
            if js_t:
                info(f"JS params: +{len(js_t)}")
                targets.extend(js_t)

        targets = self.scope_manager.filter_targets(targets)
        if not targets:
            warn(f"No injection points: {url}")
            return

        info(f"Found {len(targets)} injection points")

        # WAF (per host, cached)
        host = urlparse(url).netloc
        if host not in self._waf_cache:
            resp = await self.http.get(url)
            self._waf_cache[host] = self.waf_detector.detect(resp)
            if self._waf_cache[host]:
                warn(f"WAF: {self._waf_cache[host]} on {host}")
        waf = self._waf_cache.get(host)

        # Header injection
        if self.config.test_headers:
            resp = await self.http.get(url)
            baseline = resp.text if resp else ""
            hf = await self.header_injector.test_url(url, baseline)
            async with self._lock:
                self.findings.extend(hf)

        # HTTP smuggling
        if self.config.test_smuggling:
            await self._test_smuggling(url)

        # Per-param scan
        sem   = asyncio.Semaphore(self.config.threads)
        tasks = [self._scan_one_sem(t, sem, waf) for t in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _scan_one_sem(self, target, sem, waf):
        async with sem:
            await self._scan_one(target, waf)

    # Static asset extensions that never reflect to HTML → skip XSS testing
    _STATIC_EXTENSIONS = {
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3",
        ".pdf", ".zip", ".map", ".ts",
    }

    # Params that are pure cache-busting → never injectable
    _CACHE_PARAMS = {"ver", "v", "_ver", "version", "cache", "cb", "bust", "ts", "t", "_t"}

    @staticmethod
    def _is_static_asset(url: str) -> bool:
        from urllib.parse import urlparse
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in ScanEngineV3._STATIC_EXTENSIONS)

    async def _scan_one(self, target: ScanTarget, waf: Optional[str]):

        # max_findings early exit
        if self._max_findings_reached():
            return
        # Error isolation: satu param yang crash tidak stop scan lain
        try:
            await self.__scan_one_body(target, waf)
        except Exception as _exc:
            debug(f'[_scan_one] unhandled: {target.url} {target.param_key}: {_exc}')

    async def __scan_one_body(self, target: ScanTarget, waf: Optional[str]):
        """Inner body — dipanggil dari _scan_one wrapper."""

        # FIX: skip static assets entirely — .js/.css/.png files never render HTML payloads
        if self._is_static_asset(target.url):
            debug(f"Skip static asset: {target.url}")
            return

        # FIX: skip known cache-busting params on any URL — they are not reflected to HTML
        if target.param_key.lower() in self._CACHE_PARAMS:
            debug(f"Skip cache-busting param: {target.param_key} on {target.url}")
            return

        # Context detection
        context = await self.ctx_detector.detect(target, self.http)
        target.context = context

        # FIX: if canary was not reflected at all, this param is NOT injectable → skip
        if context == Context.NOT_REFLECTED:
            debug(f"Param not reflected: {target.param_key} on {target.url}")
            return

        # FIX #16 DEEP: context=URL detected, but we must verify the reflection
        # is inside an EXECUTABLE tag (<a href>, <form action>, <iframe src>)
        # NOT a non-executable tag (<link href>, <script src>, <img src>, etc.)
        # Strategy: re-inject canary, search full response for exec vs non-exec tag pattern
        if context == Context.URL:
            import re as _r16
            _canary = ContextDetector.CANARY
            _ct = copy.deepcopy(target)
            if _ct.method == "GET":
                _ct.params[_ct.param_key] = _canary
            else:
                _ct.data[_ct.param_key] = _canary
            _cr = await self._send(_ct)
            if _cr:
                _cb = _cr.text
                _exec_pat    = (r'<(?:a|area|form|button|iframe|frame)\b[^>]*'
                               r'(?:href|action|formaction|src)\s*=\s*["\'][^"\']*' + _canary)
                _nonexec_pat = (r'<(?:link|script|img|video|audio|source|track|input|embed|meta|base)\b[^>]*'
                               r'(?:href|src|data|poster|manifest)\s*=\s*["\'][^"\']*' + _canary)
                _css_pat     = (r'<link[^>]*href=["\'][^"\']*' + _canary + r'[^"\']*\.css')
                _in_exec    = bool(_r16.search(_exec_pat, _cb, _r16.IGNORECASE | _r16.DOTALL))
                _in_nonexec = bool(_r16.search(_nonexec_pat, _cb, _r16.IGNORECASE | _r16.DOTALL))
                _in_css     = bool(_r16.search(_css_pat, _cb, _r16.IGNORECASE))
                if _in_nonexec and not _in_exec:
                    debug(f"FP filtered: URL context in non-exec tag only ({target.param_key} @ {target.url})")
                    return
                if _in_css and not _in_exec:
                    debug(f"FP filtered: CSS link tag ({target.param_key} @ {target.url})")
                    return

        # Baseline
        baseline_resp = await self._send(target)
        if baseline_resp is None:
            return
        baseline_body    = baseline_resp.text
        baseline_headers = dict(baseline_resp.headers) if hasattr(baseline_resp, "headers") else {}

        # Content-type routing
        ct_info = self.content_analyzer.analyze(baseline_resp)
        if not self.content_analyzer.should_test_html_payloads(baseline_resp):
            if self.config.test_json:
                jf = await self.json_tester_v1.test_json_endpoint(
                    target.url, target.params,
                    method=target.method,
                    top_n=JSON_TOP_N.get(self.config.profile, {}).get(self._ver, 150),
                )
                async with self._lock:
                    self.findings.extend(jf)
            return

        # FilterProbe (cached per URL)
        cache_key = f"{target.url}|{target.method}"
        if cache_key in self._filter_cache:
            matrix = self._filter_cache[cache_key]
        else:
            matrix = await self.filter_probe.analyze(target)
            self._filter_cache[cache_key] = matrix

        # CSRF prep for POST
        if target.method == "POST":
            target = await self.csrf_handler.prepare_post(target)

        # HPP
        if self.config.test_hpp and target.method == "GET":
            hpf = await self.hpp_tester.test(target, baseline_body)
            async with self._lock:
                self.findings.extend(hpf)

        # File upload XSS test (POST endpoints)
        if target.method == 'POST' and 'multipart' not in str(target.headers.get('Content-Type','')):
            upf = await self.upload_injector.test(target, baseline_body)
            if upf:
                async with self._lock:
                    self.findings.extend(upf)

        # 2025: New event handler bypass test
        if self.config.test_new_events:
            nef = await self._test_new_event_handlers(target, baseline_body)
            if nef:
                async with self._lock:
                    self.findings.extend(nef)

        # 2025: Parser differential bypass test
        if self.config.test_parser_diff:
            pdf = await self._test_parser_differential(target, baseline_body)
            if pdf:
                async with self._lock:
                    self.findings.extend(pdf)

        # WebSocket injection test
        if self.config.test_websocket:
            wsf = await self._test_websocket(target, baseline_body)
            if wsf:
                async with self._lock:
                    self.findings.extend(wsf)

        # ── Build full payload list ───────────────────────────
        ver  = self._ver
        prof = self.config.profile

        # FIX: when context is UNKNOWN (canary reflected but position unclear),
        # generate payloads for ALL likely contexts instead of defaulting to
        # broken generic payloads like <script onerror=...> which never execute.
        effective_context = context
        if context == Context.UNKNOWN:
            # Generate payloads for the 3 most common contexts and merge
            combo_raw_html = self.combo_engine.generate(
                context=Context.HTML, matrix=None,
                top_n=max(80, COMBO_TOP_N.get(prof, {}).get(ver, 500) // 3)
            )
            combo_raw_attr = self.combo_engine.generate(
                context=Context.ATTRIBUTE, matrix=None,
                top_n=max(50, COMBO_TOP_N.get(prof, {}).get(ver, 500) // 4)
            )
            combo_raw_js = self.combo_engine.generate(
                context=Context.JS_STRING, matrix=None,
                top_n=max(50, COMBO_TOP_N.get(prof, {}).get(ver, 500) // 4)
            )
            combo_list = (
                [(p, lbl) for p, _, lbl in combo_raw_html] +
                [(p, lbl) for p, _, lbl in combo_raw_attr] +
                [(p, lbl) for p, _, lbl in combo_raw_js]
            )
            # Deduplicate
            seen_p = set()
            combo_list = [(p, l) for p, l in combo_list if not (p in seen_p or seen_p.add(p))]
            debug(f"Context UNKNOWN → using multi-context payload set ({len(combo_list)} payloads)")
        else:
            # 1. Combinatorial v2 — context-aware
            combo_n = COMBO_TOP_N.get(prof, {}).get(ver, 500)
            combo_raw = self.combo_engine.generate(
                context=context,
                matrix=matrix if matrix.exploitable else None,
                top_n=combo_n
            )
            combo_list = [(p, lbl) for p, _, lbl in combo_raw]

        # 2. mXSS v2
        mxss_n = MXSS_TOP_N.get(prof, {}).get(ver, 150)
        mxss_list = [(p, lbl) for p, _, lbl in self.mxss_engine.generate(top_n=mxss_n)]

        # 3. Standard v1 supplement
        std_raw   = self.payload_gen.for_context(effective_context)
        if matrix.exploitable:
            scored  = self.smart_filter.filter_payloads(std_raw, matrix)
            std_list = [(p, e) for p, e, _ in scored]
            self._stats["requests_saved"] += max(0, len(std_raw) - len(std_list))
        else:
            std_list = std_raw

        # 4. WAF evasion chains v2
        evasion_list = []
        if waf and self.config.waf_bypass:
            top_combo = [p for p, _ in combo_list[:25]]
            for payload in top_combo:
                chains = self.evasion.apply_chained(
                    payload, waf=waf,
                    max_chain=self.config.waf_chain_depth,
                    top_n=20,
                )
                evasion_list += [(ep, f"evasion:{t}") for ep, t in chains]

        # 5. Blind XSS v2
        blind_list = []
        if self.config.blind_callback:
            blind_n = BLIND_TOP_N.get(prof, {}).get(ver, 100)
            blind_list = [(p, lbl) for p, _, lbl in
                          self.blind_engine.generate(self.config.blind_callback, top_n=blind_n)]

        # 6. JSON v2
        json_list = []
        if self.config.test_json:
            json_n = JSON_TOP_N.get(prof, {}).get(ver, 150)
            json_list = [(str(p), lbl) for p, _, _, lbl in self.json_engine.generate(top_n=json_n)]

        # 7. CSP bypass
        csp_list = []
        if self.config.test_csp_bypass:
            csp_list = [(p, lbl) for p, _, lbl in self.csp_engine.generate(top_n=80)]

        # 8. Template injection
        tpl_list = []
        if self.config.test_template:
            tpl_list = [(p, lbl) for p, _, lbl in self.tpl_engine.generate(top_n=30)]

        # 9. Prototype pollution
        pp_list = []
        if self.config.test_prototype or self.config.proto_pollution:
            pp_list = [(p, lbl) for p, _, lbl in self.pp_engine.generate(top_n=80)]

        # 10. Unicode/homoglyph
        unicode_list = []
        if self.config.unicode_bypass:
            unicode_list = [(p, lbl) for p, _, lbl in self.unicode_eng.generate(top_n=60)]

        # 11. Browser quirks
        browser_list = []
        if self.config.browser_quirks:
            browser_list = [(p, lbl) for p, _, lbl in self.browser_eng.generate(top_n=50)]

        # 12. DOM clobbering
        dom_list = []
        if self.config.dom_clobbering:
            dom_list = [(p, lbl) for p, _, lbl in self.dom_clob.generate(top_n=20)]

        # 13. AI advisor (optional)
        ai_list = []
        if self.ai_advisor:
            suggestions = await self.ai_advisor.suggest(context, waf, baseline_body[:300])
            ai_list = [(p, "ai_suggest") for p, _ in suggestions]

        # ── Merge + dedup + rerank ────────────────────────────
        all_payloads = (
            combo_list + mxss_list + std_list + evasion_list +
            blind_list + json_list + csp_list + tpl_list +
            pp_list + unicode_list + browser_list + dom_list + ai_list
        )
        # Custom payload file
        all_payloads = list(all_payloads) + self._load_custom_payloads()

        from urllib.parse import urlparse as _up2
        dedup_key  = lambda p: f"{_up2(target.url).netloc}:{target.param_key}:{p}"
        all_payloads = [(p, e) for p, e in all_payloads
                        if dedup_key(p) not in self._tested]

        ranked = self.sequencer.rerank([(p, e, 1.0) for p, e in all_payloads])
        all_payloads = [(p, e) for p, e, _ in ranked]

        # Progress output
        if self.config.show_progress:
            info(f"[{self._stats['urls_scanned']}] {target.url[:60]} "
                 f"param={target.param_key} ctx={context} "
                 f"payloads={len(all_payloads):,}")
        info(f"Testing {len(all_payloads):,} payloads on '{target.param_key}' [{context}]")

        # ── Inject & analyze ──────────────────────────────────
        found_high = False  # BUG FIX #6: only skip after HIGH confidence finding
        for payload, encoding in all_payloads:
            async with self._lock:
                self._tested.add(dedup_key(payload))

            # BUG FIX #6: old code stopped after any fuzzy match (even low confidence)
            # causing missed findings. Now only early-stop after High confidence hit.
            if found_high and "blind" not in encoding and "evasion" not in encoding and "mxss" not in encoding:
                continue

            result = await self._test_payload(
                target, payload, encoding, context, waf,
                baseline_body, baseline_headers,
            )
            self._stats["payloads_tested"] += 1
            self._stats["requests_sent"]   += 1

            if result is None:
                await self.rate_limiter.handle(None)

            self.sequencer.feedback(payload, encoding, result)

            if result and result.get("reflected"):
                if result.get("confidence", 0) >= 0.7:
                    found_high = True  # only suppress further tests if HIGH confidence
                if target.method == "POST" and self.config.second_order:
                    canary = self.second_order.make_canary(target.param_key)
                    self.second_order.record(
                        target.url, target.param_key, payload, canary,
                        verify_urls=[target.url],
                    )

    # ═══ Core test ═══════════════════════════════════════════

    async def _test_payload(
        self, target, payload, encoding, context, waf,
        baseline_body, baseline_headers,
    ) -> Optional[dict]:

        injected = self._inject(target, payload)
        resp     = await self._send(injected)
        if resp is None:
            return None

        resp_headers = dict(resp.headers) if hasattr(resp, "headers") else {}

        # WAF block check
        if self.waf_detector.is_blocked(len(baseline_body), len(resp.text), resp.status):
            debug(f"Blocked [{resp.status}]: {payload[:40]}")
            return None

        # Detection v2 — 10 layers
        det = self.detector.analyze(
            payload, resp.text, context,
            waf_bypassed=(waf is not None),
            headers=resp_headers,
        )

        # Fuzzy fallback
        fuzzy  = self.fuzzy.analyze(payload, baseline_body, resp.text)
        diff   = self.differ.diff(baseline_body, resp.text)

        reflected = (det is not None or
                     fuzzy["reflected"] or
                     diff["suspicious"])

        if not reflected:
            return None

        # Determine best confidence
        if det:
            severity   = det["severity"]
            confidence = det["confidence"]
            evidence   = det["evidence"] or resp.text[100:300]
            xss_type   = det.get("xss_type", "reflected")
            raw_score  = det.get("raw_score", 0.5)
        else:
            severity   = "Medium" if fuzzy["confidence"] > 0.6 else "Low"
            confidence = severity
            evidence   = (f"fuzzy_tags={fuzzy.get('new_tags', [])}"
                          if fuzzy.get("new_tags") else resp.text[100:250])
            xss_type   = "reflected"
            raw_score  = fuzzy["confidence"]

        if raw_score < 0.20:
            return None

        f = Finding(
            url=target.url, param=target.param_key, payload=payload,
            context=context, xss_type=xss_type, evidence=evidence[:300],
            waf_bypassed=(waf is not None), severity=severity,
            confidence=confidence, encoding_used=encoding,
        )

        async with self._lock:
            # FIX: dedup by URL+param only (not context) when context is UNKNOWN
            # This prevents reporting 3x the same param with context=unknown from
            # multi-context payload sweep
            if context == Context.UNKNOWN:
                dupe = any(e.url == f.url and e.param == f.param for e in self.findings)
            else:
                dupe = any(
                    e.url == f.url and e.param == f.param and e.context == f.context
                    for e in self.findings
                )
            if not dupe:
                self.findings.append(f)
                log_finding(f.url, f.param, f.payload, f.xss_type, f.context)

        return {"reflected": True, "confidence": raw_score}

    # ═══ New event handler test 2025 ═══════════════════════════

    async def _test_new_event_handlers(self, target, baseline_body: str):
        """
        Test XSS dengan event handler HTML5 baru 2025.
        Sumber: Sysdig 2025 (onbeforetoggle), PortSwigger Jan 2026.

        Flow:
        1. Kirim payload ke server, cek apakah di-reflect (layer HTTP)
        2. Jika di-reflect + --verify-headless aktif, buka di Playwright
           dengan InteractionSimulator yang tahu cara trigger tiap event
        """
        if not self.config.test_new_events:
            return
        findings = []
        payloads = self.new_event_eng.generate(top_n=25)

        for payload, score, label in payloads:
            t    = self._inject(target, payload)
            resp = await self.http.request(t)
            if not resp:
                continue
            self._stats["requests_sent"] += 1

            result = self.detector.analyze(payload, resp.text, resp.status,
                                           dict(resp.headers))
            if not result:
                continue

            idx = resp.text.find(payload[:20]) if len(payload) > 20 else resp.text.find(payload)
            evidence = ""
            if idx >= 0:
                evidence = resp.text[max(0, idx-60):idx+len(payload)+60]

            f = Finding(
                url=t.url, param=t.param_key, payload=payload,
                context=Context.HTML, xss_type="reflected",
                evidence=evidence[:300],
                severity="High", confidence="Medium",
                encoding_used=label,   # berisi interaction_type untuk verifier
            )

            # Verifikasi headless dengan simulasi interaksi
            # InteractionSimulator di verifier.py baca interaction_type dari label
            if self.config.verify_headless:
                try:
                    verified = await self.verifier.verify(f)
                    f.verified = verified
                    if verified:
                        f.confidence = "High"
                        debug(f"[new_event] VERIFIED: {label}")
                except Exception as e:
                    debug(f"[new_event] verifier error: {e}")

            async with self._lock:
                self.findings.append(f)
            findings.append(f)

        return findings

    # ═══ Parser differential test 2025 ══════════════════════════

    async def _test_parser_differential(self, target, baseline_body: str):
        """
        Test bypass WAF menggunakan perbedaan cara tokenize HTML.
        Ethiack Research Sept 2025: bypass 14/17 enterprise WAF.
        """
        if not self.config.test_parser_diff:
            return
        findings = []
        payloads = self.parser_diff_eng.generate(top_n=20)
        for payload, score, label in payloads:
            t = self._inject(target, payload)
            resp = await self.http.request(t)
            if not resp:
                continue
            self._stats["requests_sent"] += 1
            result = self.detector.analyze(payload, resp.text, resp.status,
                                           dict(resp.headers))
            if result.get("reflected"):
                idx = resp.text.find(payload[:20]) if len(payload) > 20 else resp.text.find(payload)
                evidence = ""
                if idx >= 0:
                    evidence = resp.text[max(0, idx-60):idx+len(payload)+60]
                f = Finding(
                    url=t.url, param=t.param_key, payload=payload,
                    context=Context.HTML, xss_type="reflected",
                    evidence=evidence[:300],
                    severity="High", confidence="Medium",
                    encoding_used=label,
                )
                async with self._lock:
                    self.findings.append(f)
                findings.append(f)
                break
        return findings

    # ═══ WebSocket/SSE injection test 2025 ════════════════════

    async def _test_websocket(self, target, baseline_body: str):
        """
        Test XSS via WebSocket dan SSE message injection.
        Endpoint WS sering tidak punya WAF protection.
        Pakai payload dari JSONAPIEngineV2 dengan injection_point ws_message/sse_data.
        """
        if not self.config.test_websocket:
            return []
        findings = []
        # Ambil payload WS/SSE dari engine JSON/API
        ws_payloads = [
            (f'{{"type":"message","content":"{p}"}}', f"ws_inject:{l}")
            for p, _, l in self.json_engine.generate(top_n=15)
            if "ws_" in l or "sse_" in l
        ]
        if not ws_payloads:
            # Fallback payload minimal
            ws_payloads = [
                ('{"type":"msg","data":"<img src=x onerror=alert(1)>"}', "ws_fallback"),
                ('data: <script>alert(1)</script>\n\n',                "sse_fallback"),
            ]
        for payload, label in ws_payloads[:10]:
            t    = self._inject(target, payload)
            resp = await self.http.request(t)
            if not resp:
                continue
            self._stats["requests_sent"] += 1
            result = self.detector.analyze(payload, resp.text, resp.status, dict(resp.headers))
            if result:
                idx = resp.text.find(payload[:20]) if payload else -1
                evidence = resp.text[max(0,idx-60):idx+80] if idx >= 0 else ""
                f = Finding(
                    url=t.url, param=t.param_key, payload=payload,
                    context=Context.WEBSOCKET, xss_type="reflected",
                    evidence=evidence[:300], severity="High",
                    confidence="Medium", encoding_used=label,
                )
                async with self._lock:
                    self.findings.append(f)
                findings.append(f)
        return findings

    # ═══ HTTP smuggling test ══════════════════════════════════

    async def _test_smuggling(self, url: str):
        """Test HTTP request smuggling XSS at URL level."""
        if not self.config.test_smuggling:
            return
        payloads = self.smuggle_eng.generate(top_n=5)
        for payload, score, label in payloads:
            debug(f"Smuggle test [{label}]: {str(payload)[:60]}")
            # Smuggling payloads are at HTTP layer — log as potential
            # Real exploitation requires network-level testing
            # Flag as informational for manual review
            f = Finding(
                url=url, param="http_smuggling", payload=str(payload)[:500],
                context=Context.UNKNOWN, xss_type="smuggling",
                evidence=f"HTTP smuggling candidate: {label}",
                severity="Low", confidence="Low", encoding_used=label,
            )
            async with self._lock:
                self.findings.append(f)
            break  # one per URL to avoid spam

    # ═══ Max findings guard ══════════════════════════════════

    def _max_findings_reached(self) -> bool:
        """Return True jika sudah mencapai batas max_findings."""
        limit = self.config.max_findings
        return bool(limit and limit > 0 and len(self.findings) >= limit)

    # ═══ Custom payload file support ════════════════════════

    def _load_custom_payloads(self) -> list:
        """
        Load custom XSS payloads dari file yang ditentukan --payload-file.
        Format: satu payload per baris, baris kosong dan # diabaikan.
        Return list of (payload_str, "custom_file") tuples.
        """
        path = self.config.payload_file
        if not path:
            return []
        try:
            payloads = []
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append((line, "custom_file"))
            info(f"Loaded {len(payloads)} custom payloads from {path}")
            return payloads
        except Exception as e:
            warn(f"Could not load payload file {path}: {e}")
            return []

    # ═══ Helpers ═════════════════════════════════════════════

    def _inject(self, target, payload):
        t = copy.deepcopy(target)
        if t.method == "GET":
            t.params[t.param_key] = payload
        else:
            t.data[t.param_key] = payload
        return t

    async def _send(self, target):
        if target.method == "GET":
            return await self.http.get(target.url, params=target.params)
        return await self.http.post(target.url, data=target.data)

    def _url_to_targets(self, url):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            # BUG FIX #9: sebelumnya return [] tanpa info — user bingung kenapa 0 requests
            # Sekarang: kasih hint yang actionable
            warn(
                f"No query parameters found in URL: {url}\n"
                f"  → Tip: gunakan URL yang mengandung parameter, contoh: {url}?q=test\n"
                f"  → Atau jalankan tanpa --no-crawl agar spider cari params otomatis"
            )
            return []
        base = {k: v[0] for k, v in params.items()}
        return [ScanTarget(url=url, method="GET", params=base.copy(),
                           param_key=k) for k in params]

    def _print_stats(self):
        sent  = self._stats["requests_sent"]
        saved = self._stats["requests_saved"]
        total = sent + saved
        pct   = (saved / total * 100) if total > 0 else 0
        info(f"Scan complete: {sent:,} requests | "
             f"{saved:,} eliminated ({pct:.0f}%) | "
             f"{self._stats['payloads_tested']:,} payloads | "
             f"{len(self.findings)} findings")

    async def close(self):
        await self.http.close()
