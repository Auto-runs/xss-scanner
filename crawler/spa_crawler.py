"""
crawler/spa_crawler.py

╔══════════════════════════════════════════════════════════════╗
║   SPA CRAWLER — Fix #3                                       ║
║   Menemukan parameter yang hanya muncul setelah JS render    ║
║                                                              ║
║   Coverage yang sebelumnya miss:                             ║
║   - Input fields yang dirender React/Vue/Angular             ║
║   - Route params dari React Router / Vue Router              ║
║   - AJAX/fetch endpoint yang diintercept saat page load      ║
║   - history.pushState URL patterns                           ║
║   - Semua visible input setelah JS settle                    ║
║                                                              ║
║   Cara kerja:                                                ║
║   1. Buka halaman dengan Playwright, tunggu networkidle       ║
║   2. Intercept semua XHR/fetch → collect API endpoints       ║
║   3. Extract semua input/form setelah JS render              ║
║   4. Intercept history.pushState → collect SPA routes        ║
║   5. Detect framework (React/Vue/Angular) → route extraction  ║
║   6. Return ScanTarget list lengkap                          ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import re
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, urlencode

from utils.config import ScanTarget, Context
from utils.logger import debug, info, warn


class SPACrawler:
    """
    Headless browser crawler untuk SPA (React, Vue, Angular).
    Menemukan parameter injection points yang tidak muncul di HTML statis.
    """

    def __init__(
        self,
        base_url: str,
        timeout_ms: int = 12000,
        max_routes: int = 30,
        interact_forms: bool = True,
    ):
        self.base_url       = base_url
        self.base_host      = urlparse(base_url).netloc
        self.timeout_ms     = timeout_ms
        self.max_routes     = max_routes
        self.interact_forms = interact_forms
        self._browser       = None
        self._playwright    = None
        self._pw_ctx        = None

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
                    "--disable-web-security",
                ],
            )
            info("SPACrawler: Playwright ready")
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

    async def crawl(self, url: str = None) -> List[ScanTarget]:
        """
        Main entry point.
        Returns daftar ScanTarget yang ditemukan dari SPA rendering.
        """
        if not self._browser:
            return []

        url = url or self.base_url
        targets: List[ScanTarget] = []
        seen_keys: Set[str] = set()

        def add_target(t: ScanTarget):
            key = f"{t.url}|{t.param_key}|{t.method}"
            if key not in seen_keys:
                seen_keys.add(key)
                targets.append(t)

        # ── Phase 1: Render halaman utama ─────────────────────────────────
        page_data = await self._render_and_collect(url)
        if not page_data:
            return targets

        # ── Phase 2: Masukkan semua input params dari rendered DOM ─────────
        for t in page_data["form_targets"]:
            add_target(t)

        # ── Phase 3: API endpoints dari XHR/fetch intercept ───────────────
        for endpoint_target in page_data["api_targets"]:
            add_target(endpoint_target)

        # ── Phase 4: SPA routes ───────────────────────────────────────────
        routes_visited = {url}
        for route in page_data["spa_routes"][:self.max_routes]:
            if route not in routes_visited:
                routes_visited.add(route)
                sub_data = await self._render_and_collect(route)
                if sub_data:
                    for t in sub_data["form_targets"]:
                        add_target(t)
                    for t in sub_data["api_targets"]:
                        add_target(t)

        info(f"SPACrawler: {len(targets)} injection points found (SPA)")
        return targets

    async def _render_and_collect(self, url: str) -> Optional[Dict]:
        """
        Render halaman dan collect semua data yang berguna.
        context dan page selalu di-close di finally — cegah memory leak.
        """
        if not self._browser:
            return None

        context = None
        try:
            context = await self._browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                )
            )
            page = await context.new_page()

            # Intercept XHR/fetch untuk discover API endpoints
            api_requests: List[Dict] = []

            async def on_request(request):
                req_url = request.url
                parsed  = urlparse(req_url)
                # Hanya same-host requests yang relevan
                if parsed.netloc == self.base_host:
                    api_requests.append({
                        "url":    req_url,
                        "method": request.method,
                        "params": parse_qs(parsed.query),
                    })

            page.on("request", on_request)

            # Intercept history.pushState untuk collect SPA routes
            await page.add_init_script("""
                window.__spa_routes = [];
                var origPush    = history.pushState.bind(history);
                var origReplace = history.replaceState.bind(history);
                history.pushState = function(state, title, url) {
                    if (url) window.__spa_routes.push(String(url));
                    return origPush(state, title, url);
                };
                history.replaceState = function(state, title, url) {
                    if (url) window.__spa_routes.push(String(url));
                    return origReplace(state, title, url);
                };
            """)

            # Navigate dan tunggu JS settle
            try:
                await page.goto(url, wait_until="networkidle",
                                timeout=self.timeout_ms)
            except Exception:
                try:
                    await page.goto(url, wait_until="domcontentloaded",
                                    timeout=self.timeout_ms)
                    await asyncio.sleep(1.5)  # manual wait for JS
                except Exception as e:
                    debug(f"SPACrawler navigate error: {e}")
                    await page.close(); await context.close()
                    return None

            await asyncio.sleep(0.5)  # extra time for late renders

            # ── Detect framework ──────────────────────────────────────────
            framework = await self._detect_framework(page)
            debug(f"SPACrawler: framework={framework} at {url}")

            # ── Extract inputs setelah render ─────────────────────────────
            form_targets = await self._extract_inputs(page, url)

            # ── Collect SPA routes dari history intercept ─────────────────
            spa_routes_raw = await page.evaluate(
                "() => window.__spa_routes || []"
            )
            # Juga klik link untuk trigger routing
            link_routes = await self._click_spa_links(page, url)
            all_spa_routes = list(set(
                [self._resolve_url(r, url) for r in spa_routes_raw
                 if self._is_same_host(r, url)]
                + link_routes
            ))

            # ── Framework-specific route extraction ───────────────────────
            fw_routes = await self._extract_framework_routes(page, framework, url)
            all_spa_routes.extend(fw_routes)
            all_spa_routes = list(set(all_spa_routes))

            # ── Build API targets from XHR intercepts ─────────────────────
            api_targets = self._build_api_targets(api_requests, url)

            await page.close()
            await context.close()

            return {
                "url":          url,
                "framework":    framework,
                "form_targets": form_targets,
                "api_targets":  api_targets,
                "spa_routes":   all_spa_routes[:self.max_routes],
            }

        except Exception as e:
            debug(f"SPACrawler._render_and_collect error: {e}")
            try:
                await page.close()
                await context.close()
            except Exception:
                pass
            return None

    async def _extract_inputs(self, page, base_url: str) -> List[ScanTarget]:
        """
        Extract semua input/form setelah JS render selesai.
        Ini yang paling berbeda dari static crawler.
        """
        targets = []
        try:
            inputs_data = await page.evaluate("""
                () => {
                    var results = [];
                    // Semua input, textarea, select yang visible
                    var inputs = document.querySelectorAll(
                        'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=file]),'
                        + 'textarea, select'
                    );
                    inputs.forEach(function(el) {
                        var form = el.closest('form');
                        var formAction = form ? (form.action || window.location.href) : window.location.href;
                        var formMethod = form ? (form.method || 'get').toUpperCase() : 'GET';
                        results.push({
                            name:   el.name || el.id || el.getAttribute('data-name') || '',
                            type:   el.type || el.tagName.toLowerCase(),
                            action: formAction,
                            method: formMethod,
                            visible: el.offsetParent !== null,
                        });
                    });
                    return results;
                }
            """)

            # Grup per form action
            forms: Dict[str, Dict] = {}
            for inp in inputs_data:
                if not inp["name"]:
                    continue
                key = f"{inp['action']}|{inp['method']}"
                if key not in forms:
                    forms[key] = {
                        "action": inp["action"],
                        "method": inp["method"],
                        "params": {},
                    }
                forms[key]["params"][inp["name"]] = ""

            for form_data in forms.values():
                action = form_data["action"]
                method = form_data["method"]
                params = form_data["params"]

                if not params:
                    continue

                for param_name in params:
                    all_params = dict(params)
                    all_params[param_name] = "test"
                    t = ScanTarget(
                        url=action,
                        method=method,
                        params=dict(all_params) if method == "GET" else {},
                        data=dict(all_params) if method == "POST" else {},
                        context=Context.HTML,
                        param_key=param_name,
                    )
                    targets.append(t)

        except Exception as e:
            debug(f"SPACrawler._extract_inputs error: {e}")

        return targets

    async def _click_spa_links(self, page, base_url: str) -> List[str]:
        """
        Klik link yang kemungkinan adalah SPA navigation (tidak reload halaman).
        Collect URL yang muncul.
        """
        routes = []
        try:
            # Cari link yang likely SPA (tidak full reload)
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(href => href && !href.startsWith('javascript:')
                                        && !href.includes('#')
                                        && !href.includes('mailto:'))
                    .slice(0, 15)
            """)

            base_host = urlparse(base_url).netloc
            for link in links:
                if urlparse(link).netloc == base_host:
                    routes.append(link)

        except Exception as e:
            debug(f"SPACrawler._click_spa_links error: {e}")

        return routes

    async def _detect_framework(self, page) -> str:
        """Detect JS framework dari page globals."""
        try:
            fw = await page.evaluate("""
                () => {
                    if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__
                        || document.querySelector('[data-reactroot]')
                        || document.querySelector('[data-reactid]'))
                        return 'react';
                    if (window.Vue || window.__VUE__ || window.__VUE_DEVTOOLS_GLOBAL_HOOK__)
                        return 'vue';
                    if (window.angular || window.getAllAngularRootElements)
                        return 'angular';
                    if (window.Svelte || document.querySelector('[class^=svelte-]'))
                        return 'svelte';
                    if (window.next || window.__NEXT_DATA__)
                        return 'nextjs';
                    if (window.nuxt || window.__NUXT__)
                        return 'nuxt';
                    return 'unknown';
                }
            """)
            return fw or "unknown"
        except Exception:
            return "unknown"

    async def _extract_framework_routes(
        self, page, framework: str, base_url: str
    ) -> List[str]:
        """
        Framework-specific route extraction.
        """
        routes = []
        base_origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"

        try:
            if framework == "react":
                # React Router: window.__reactRouterRoutes atau dari bundle
                raw = await page.evaluate("""
                    () => {
                        // Try React Router v6
                        var router = window.__reactRouter || window.__REACT_ROUTER__;
                        if (router && router.routes) {
                            return router.routes.map(function(r) { return r.path || ''; });
                        }
                        // Fallback: look for Link hrefs
                        return Array.from(document.querySelectorAll('a'))
                            .map(function(a) { return a.pathname; })
                            .filter(function(p) { return p && p !== '/'; });
                    }
                """)
                if isinstance(raw, list):
                    routes = [f"{base_origin}{r}" for r in raw if r]

            elif framework in ("vue", "nuxt"):
                raw = await page.evaluate("""
                    () => {
                        var vueApp = document.querySelector('#app')?.__vue_app__;
                        if (!vueApp) vueApp = document.querySelector('[data-app]')?.__vue_app__;
                        if (vueApp && vueApp.config && vueApp.config.globalProperties
                            && vueApp.config.globalProperties.$router) {
                            var r = vueApp.config.globalProperties.$router;
                            return r.getRoutes ? r.getRoutes().map(function(route) {
                                return route.path;
                            }) : [];
                        }
                        return [];
                    }
                """)
                if isinstance(raw, list):
                    routes = [f"{base_origin}{r}" for r in raw if r and r != '/']

            elif framework == "angular":
                raw = await page.evaluate("""
                    () => {
                        try {
                            var rootElements = getAllAngularRootElements();
                            if (rootElements.length > 0) {
                                var injector = rootElements[0].__ngContext__
                                    || ng.getInjector(rootElements[0]);
                                if (injector) {
                                    var router = injector.get(ng.coreTokens.Router);
                                    if (router && router.config) {
                                        return router.config.map(function(r) {
                                            return '/' + (r.path || '');
                                        });
                                    }
                                }
                            }
                        } catch(e) {}
                        return [];
                    }
                """)
                if isinstance(raw, list):
                    routes = [f"{base_origin}{r}" for r in raw if r]

        except Exception as e:
            debug(f"SPACrawler._extract_framework_routes error: {e}")

        return routes

    def _build_api_targets(
        self, api_requests: List[Dict], base_url: str
    ) -> List[ScanTarget]:
        """Convert intercepted API requests ke ScanTarget list."""
        targets = []
        seen = set()

        for req in api_requests:
            req_url = req["url"]
            method  = req["method"].upper()
            params  = req["params"]  # dict dari parse_qs

            if not params:
                continue

            for param_name, values in params.items():
                key = f"{req_url}|{param_name}|{method}"
                if key in seen:
                    continue
                seen.add(key)

                all_params = {k: v[0] for k, v in params.items()}
                t = ScanTarget(
                    url=req_url,
                    method=method,
                    params=dict(all_params) if method == "GET" else {},
                    data=dict(all_params) if method == "POST" else {},
                    context=Context.HTML,
                    param_key=param_name,
                )
                targets.append(t)

        return targets

    def _resolve_url(self, url: str, base: str) -> str:
        if url.startswith("http"):
            return url
        if url.startswith("/"):
            parsed = urlparse(base)
            return f"{parsed.scheme}://{parsed.netloc}{url}"
        return urljoin(base, url)

    def _is_same_host(self, url: str, base: str) -> bool:
        if not url:
            return False
        if url.startswith("/"):
            return True
        try:
            return urlparse(url).netloc == self.base_host
        except Exception:
            return False
