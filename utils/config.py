"""
utils/config.py
Global configuration, constants, and shared data structures.
"""

from dataclasses import dataclass, field
from typing import Optional


# ─── Scan Profiles ────────────────────────────────────────────────────────────

SCAN_PROFILES = {
    "fast":    {"depth": 1, "threads": 20, "timeout": 5,  "payloads_per_ctx": 10},
    "normal":  {"depth": 2, "threads": 10, "timeout": 10, "payloads_per_ctx": 30},
    "deep":    {"depth": 4, "threads":  5, "timeout": 20, "payloads_per_ctx": 80},
    "stealth": {"depth": 2, "threads":  2, "timeout": 15, "payloads_per_ctx": 25},
}


# ─── Injection Context Tags ────────────────────────────────────────────────────

class Context:
    HTML         = "html"
    ATTRIBUTE    = "attribute"
    JS           = "javascript"
    JS_STRING    = "js_string"
    JS_TEMPLATE  = "js_template"
    URL          = "url"
    CSS          = "css"
    COMMENT      = "comment"
    SCRIPT_SRC   = "script_src"
    UNKNOWN      = "unknown"
    NOT_REFLECTED = "not_reflected"  # FIX: canary tidak muncul = param tidak di-reflect
    # vOVERPOWER new contexts
    WEBSOCKET   = "websocket"
    GRAPHQL     = "graphql"
    GRPC        = "grpc"
    SSE         = "sse"
    SHADOW_DOM  = "shadow_dom"
    TEMPLATE    = "template"     # Framework template injection
    PROTO_CHAIN = "proto_chain"  # Prototype pollution


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class ScanTarget:
    url:       str
    method:    str  = "GET"
    params:    dict = field(default_factory=dict)
    headers:   dict = field(default_factory=dict)
    cookies:   dict = field(default_factory=dict)
    data:      dict = field(default_factory=dict)
    context:   str  = Context.UNKNOWN
    param_key: str  = ""


@dataclass
class Finding:
    url:            str
    param:          str
    payload:        str
    context:        str
    xss_type:       str          # reflected | stored | dom
    evidence:       str
    waf_bypassed:   bool = False
    severity:       str  = "High"
    confidence:     str  = "High"
    encoding_used:  str  = "none"
    verified:       bool = False


@dataclass
class ScanConfig:
    # ── Core ────────────────────────────────────────────────────────────────
    targets:        list       = field(default_factory=list)
    threads:        int        = 10
    timeout:        int        = 10
    depth:          int        = 2
    profile:        str        = "normal"
    headers:        dict       = field(default_factory=dict)
    cookies:        dict       = field(default_factory=dict)
    proxy:          Optional[str] = None
    output:         str        = "report.json"
    crawl:          bool       = True
    deep:           bool       = False
    blind_callback: Optional[str] = None
    verify_headless:bool       = False
    waf_bypass:     bool       = True
    verbose:        bool       = False
    rate_limit:     float      = 0.0   # seconds between requests (0 = no limit)

    # ── Auth ─────────────────────────────────────────────────────────────────
    login_url:      Optional[str] = None
    username:       Optional[str] = None
    password:       Optional[str] = None

    # ── Scope ────────────────────────────────────────────────────────────────
    scope:          list       = field(default_factory=list)
    exclude_scope:  list       = field(default_factory=list)
    exclude_path:   list       = field(default_factory=list)

    # ── Extended test flags ──────────────────────────────────────────────────
    test_headers:   bool       = False   # inject XSS into HTTP headers
    test_hpp:       bool       = False   # HTTP parameter pollution
    # ── Baru ────────────────────────────────────────────────────────────────
    # ── Rich Blind XSS (XSS Hunter style) ──────────────────────────────────
    start_rich_blind_server: bool    = False
    blind_server_port:       int     = 8765
    blind_output_dir:        str     = "./blind_xss_hits"
    blind_screenshot:        bool    = True   # html2canvas screenshot
    # ── KNOXSS-style validation ───────────────────────────────────────────────
    run_afb:                 bool    = False  # Advanced Filter Bypass probe
    generate_poc:            bool    = False  # Generate HTML PoC per finding
    poc_output_dir:          str     = "./xss_pocs"
    knoxss_validate:         bool    = False  # Validate dengan KnoxssValidator
    scan_timeout:     int      = 0        # detik, 0 = tidak ada batas
    max_findings:     int      = 0        # 0 = tidak ada batas
    show_progress:    bool     = True     # tampilkan progress bar
    payload_file:     Optional[str] = None  # file custom payloads
    test_new_events:  bool     = False   # [2025] event handler HTML5 baru
    test_parser_diff: bool     = False   # [2025] parser differential bypass
    test_hpp_2025:    bool     = False   # [2025] ASP.NET comma concat exploit
    test_json:      bool       = False   # JSON API endpoints
    second_order:   bool       = False   # track + verify stored/second-order XSS
    js_crawl:       bool       = False   # extract params from JavaScript files

    # ── Report formats ───────────────────────────────────────────────────────
    report_html:    Optional[str] = None
    report_csv:     Optional[str] = None
    report_md:      Optional[str] = None
    report_sarif:   Optional[str] = None

    # ── Checkpoint (save/resume) ─────────────────────────────────────────────
    checkpoint:     bool       = False

    # ── vOVERPOWER: New engine flags ─────────────────────────────────────────
    engine_version:   str        = "v2"      # "v1" | "v2" — selects payload engine
    test_csp_bypass:  bool       = False     # CSP bypass technique testing
    test_prototype:   bool       = False     # Prototype pollution XSS
    test_websocket:   bool       = False     # WebSocket/SSE injection
    test_template:    bool       = False     # Template injection (Angular/Vue/React)
    test_smuggling:   bool       = False     # HTTP request smuggling XSS
    browser_quirks:   bool       = False     # Browser-specific payload variants
    unicode_bypass:   bool       = False     # Unicode/homoglyph WAF evasion
    proto_pollution:  bool       = False     # Alias for test_prototype
    dom_clobbering:   bool       = False     # DOM clobbering payloads
    ai_assist:        bool       = False     # AI-powered payload suggestions
    waf_chain_depth:  int        = 3         # WAFChain max: 2=pairs, 3=triples, 4=quads
    # ── Fix #2 & #3 flags ────────────────────────────────────────────────────
    dom_xss_scan:     bool       = False     # DOM XSS via JS instrumentation (--dom-xss-scan)
    spa_crawl:        bool       = False     # SPA crawling via Playwright (--spa-crawl)
    spa_interact:     bool       = False     # Interact with forms during SPA crawl


# ─── Common Headers ───────────────────────────────────────────────────────────

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
}


# ─── DOM Sink Patterns ────────────────────────────────────────────────────────

DOM_SINKS = [
    # Classic sinks
    "document.write", "document.writeln", "innerHTML", "outerHTML",
    "insertAdjacentHTML", "eval(", "setTimeout(", "setInterval(",
    "location.href", "location.replace", "location.assign",
    "window.location", "document.location", "document.URL",
    "document.referrer", "document.cookie", "window.name",
    "element.src", "element.action", "element.formAction",
    "execScript", "msSetImmediate",
    # Modern / vOVERPOWER sinks
    "dangerouslySetInnerHTML",  # React
    "v-html",                   # Vue
    "[innerHTML]",              # Angular property binding
    "bypassSecurityTrustHtml",  # Angular DomSanitizer bypass
    "trustAsHtml",              # AngularJS
    "Sanitizer",                # Native Sanitizer API
    "createPolicy",             # Trusted Types
    "createHTML",               # Trusted Types createHTML
    "srcdoc",                   # iframe srcdoc
    "shadowRoot.innerHTML",     # Shadow DOM
    "importNode",               # importNode from foreign doc
    "adoptNode",                # adoptNode
    "createContextualFragment", # Range.createContextualFragment
    "parseFromString",          # DOMParser sink
    "postMessage",              # postMessage sink
    "prototype.innerHTML",      # Prototype pollution sink
    "__proto__",                # Prototype chain pollution
    "constructor.prototype",
]

DOM_SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.URL", "document.referrer", "window.name",
    "document.cookie", "localStorage", "sessionStorage",
    "postMessage", "URLSearchParams",
    # vOVERPOWER: additional sources
    "location.pathname", "location.port", "location.protocol",
    "history.state", "history.pushState",
    "indexedDB", "webkitIndexedDB",
    "opener.location", "parent.location", "top.location",
    "frames[", "window.frames",
    "document.domain", "document.baseURI",
    "crypto.getRandomValues",  # not XSS source but WebCrypto exfil vector
    "navigator.userAgent", "navigator.language",
    "performance.timing",    # timing attack source
    "Worker", "SharedWorker", "ServiceWorker",
    "WebSocket", "EventSource", "fetch(",
]


# ─── WAF Fingerprints ─────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare":    ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "ModSecurity":   ["mod_security", "modsecurity", "NOYB", "mod_sec"],
    "Akamai":        ["akamai", "ak_bmsc", "AkamaiGHost", "akamai-x-"],
    "Imperva":       ["imperva", "incap_ses", "_incap_", "visid_incap"],
    "F5 BIG-IP":     ["BigIP", "F5", "TS0", "BigIP", "X-WA-Info"],
    "Sucuri":        ["sucuri", "x-sucuri-id", "sucuri-waf"],
    "AWS WAF":       ["awswaf", "x-amzn-requestid", "x-amzn-trace-id"],
    "Barracuda":     ["barracuda_", "barra_counter_session"],
    "Wordfence":     ["wordfence"],
    "Nginx":         ["nginx"],
    # vOVERPOWER: additional WAF signatures
    "Fortinet":      ["fortigate", "x-cachekey", "FORTIWAFSID"],
    "Palo Alto":     ["pan-", "x-pan-"],
    "Radware":       ["x-rdwr-", "rdwr"],
    "Citrix":        ["citrix_ns_id", "x-citrix-", "NSC_"],
    "Wallarm":       ["wallarm", "x-wallarm-"],
    "Reblaze":       ["x-reblaze-", "rbzid"],
    "Azure":         ["x-azure-ref", "x-ms-request-id"],
    "Fastly":        ["fastly-", "x-fastly-", "x-served-by"],
    "Kong":          ["x-kong-", "kong-request-id"],
    "Traefik":       ["x-forwarded-server", "x-real-ip"],
}

# ── Scan Profile per engine version ──────────────────────────────────────────

COMBO_TOP_N = {
    "fast":    {"v1": 200,  "v2": 300},
    "normal":  {"v1": 500,  "v2": 800},
    "deep":    {"v1": 2000, "v2": 3000},
    "stealth": {"v1": 300,  "v2": 500},
}

MXSS_TOP_N = {
    "fast":    {"v1": 50,  "v2": 100},
    "normal":  {"v1": 150, "v2": 300},
    "deep":    {"v1": 500, "v2": 1000},
    "stealth": {"v1": 80,  "v2": 150},
}

BLIND_TOP_N = {
    "fast":    {"v1": 30,  "v2": 60},
    "normal":  {"v1": 100, "v2": 200},
    "deep":    {"v1": 400, "v2": 800},
    "stealth": {"v1": 50,  "v2": 100},
}

JSON_TOP_N = {
    "fast":    {"v1": 50,  "v2": 100},
    "normal":  {"v1": 150, "v2": 300},
    "deep":    {"v1": 500, "v2": 1000},
    "stealth": {"v1": 80,  "v2": 150},
}
