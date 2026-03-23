"""
detection/analyzer_v2.py

╔══════════════════════════════════════════════════════════════╗
║   DETECTION ENGINE v2 — Multi-layer, context-aware          ║
║                                                              ║
║   Layers (v1 had 5, v2 has 10):                             ║
║   1.  Reflection check (exact + fuzzy + URL-decoded)         ║
║   2.  HTML position analysis (BeautifulSoup)                 ║
║   3.  DOM sink heuristics                                    ║
║   4.  Signature matching                                     ║
║   5.  Confidence scoring (context-aware)                     ║
║   +6. CSP header analysis                                    ║
║   +7. Template injection detection (Angular/Vue/React/Jinja) ║
║   +8. Prototype pollution detection                          ║
║   +9. mXSS mutation detection                               ║
║   +10. Shadow DOM / Trusted Types detection                  ║
╚══════════════════════════════════════════════════════════════╝
"""

import re
import json
import math
from typing import Optional, Tuple, List, Dict, Any
from bs4 import BeautifulSoup, Comment
from urllib.parse import unquote
from collections import Counter

from utils.config import Context, DOM_SINKS, DOM_SOURCES
from utils.logger import debug


# ═══════════════════════════════════════════════════════════════
# LAYER 1: Reflection Analyzer (enhanced)
# ═══════════════════════════════════════════════════════════════

class ReflectionAnalyzerV2:
    """
    Multi-mode reflection check:
    - Exact string match
    - URL-decoded match
    - HTML-entity decoded match
    - Partial match (first 30 chars)
    - Unicode normalized match
    """

    _CRITICAL_CHARS = ["<", ">", "\"", "'", "(", ")", "/", "\\", "`", "{", "}"]
    _HTML_ENTITIES  = {"&lt;": "<", "&gt;": ">", "&quot;": "\"",
                        "&#39;": "'", "&amp;": "&", "&#x27;": "'",
                        "&#60;": "<", "&#62;": ">", "&#34;": "\""}

    def check(self, payload: str, body: str) -> Tuple[bool, str, str]:
        """
        Returns (reflected: bool, evidence: str, match_type: str)
        match_type: 'exact' | 'url_decoded' | 'html_decoded' | 'partial' | 'unicode_norm'
        """
        # Exact match
        if payload in body:
            idx = body.find(payload)
            # Guard: in JS context, check if payload preceded by escaped quote (\')
            # which means the JS string was NOT broken
            if len(payload) > 0 and payload[0] in ("'", '"'):
                prefix = body[max(0, idx-3):idx]
                if prefix.endswith("\\") or prefix.endswith("\\'") or prefix.endswith('\\"'):
                    # Backslash before quote → escaped → string not broken → safe
                    # BUT: double-backslash \\ means literal backslash, quote IS closing
                    if not prefix.endswith("\\\\"):
                        return False, "", "js_escaped_quote"
            return True, body[max(0,idx-100):idx+len(payload)+100], "exact"

        # URL-decoded
        decoded = unquote(payload)
        if decoded != payload and decoded in body:
            idx = body.find(decoded)
            return True, body[max(0,idx-100):idx+len(decoded)+100], "url_decoded"

        # Double URL-decoded
        double_decoded = unquote(decoded)
        if double_decoded != decoded and double_decoded in body:
            idx = body.find(double_decoded)
            return True, body[max(0,idx-100):idx+len(double_decoded)+100], "double_url_decoded"

        # HTML entity decoded
        html_decoded = self._decode_html_entities(payload)
        if html_decoded != payload and html_decoded in body:
            idx = body.find(html_decoded)
            return True, body[max(0,idx-100):idx+len(html_decoded)+100], "html_decoded"

        # Unicode normalized (homoglyph attack response)
        try:
            import unicodedata
            normalized = unicodedata.normalize("NFKD", payload)
            if normalized != payload and normalized in body:
                idx = body.find(normalized)
                return True, body[max(0,idx-100):idx+len(normalized)+100], "unicode_norm"
        except Exception:
            pass

        # Partial match (first 20 chars — lowered to catch more truncations)
        partial = payload[:20].strip()
        if len(partial) >= 8 and partial in body:
            idx = body.find(partial)
            return True, body[max(0,idx-80):idx+100], "partial"

        # Segment scan — overlapping windows 6–20 chars (catches heavily truncated)
        if len(payload) >= 6:
            for size in (16, 12, 8, 6):
                for start in range(0, len(payload) - size + 1, max(1, size // 2)):
                    seg = payload[start:start + size].strip()
                    if seg and len(seg) >= 6 and seg in body:
                        idx = body.find(seg)
                        return True, body[max(0,idx-60):idx+len(seg)+60], "segment"

        return False, "", "none"

    def _decode_html_entities(self, text: str) -> str:
        for ent, char in self._HTML_ENTITIES.items():
            text = text.replace(ent, char)
        return text

    def critical_chars_survive(self, payload: str, body: str) -> Dict[str, bool]:
        """Returns per-char survival status."""
        result = {}
        for char in self._CRITICAL_CHARS:
            if char in payload:
                result[char] = char in body
        return result

    def survival_score(self, payload: str, body: str) -> float:
        """0.0-1.0 score of critical char survival."""
        survival = self.critical_chars_survive(payload, body)
        if not survival:
            return 1.0
        survived = sum(1 for v in survival.values() if v)
        return survived / len(survival)


# ═══════════════════════════════════════════════════════════════
# LAYER 2: HTML Position Analyzer (enhanced)
# ═══════════════════════════════════════════════════════════════

class HTMLPositionAnalyzerV2:

    _EXEC_CONTEXTS = [
        (r"<script[^>]*>.*?</script>", "script_block", 1.0),
        (r"on\w+\s*=\s*[\"']?[^\"'>\s]*", "event_handler", 0.9),
        (r"javascript\s*:", "js_protocol", 0.85),
        (r"href\s*=\s*[\"']?\s*javascript", "href_js", 0.8),
        (r"src\s*=\s*[\"']?\s*javascript", "src_js", 0.8),
        (r"action\s*=\s*[\"']?\s*javascript", "action_js", 0.75),
        (r"srcdoc\s*=", "srcdoc", 0.85),
        (r"data\s*=\s*[\"']?\s*javascript", "data_js", 0.75),
        (r"<(?:img|video|audio|svg|iframe|object|embed)[^>]*onerror", "media_onerror", 0.9),
        (r"<template[^>]*shadowrootmode", "shadow_root", 0.88),
    ]

    # Tags whose href/src cannot execute javascript: URLs
    _NON_EXEC_TAGS = {
        "link", "script", "img", "video", "audio", "source",
        "track", "input", "embed", "object", "meta", "base",
    }

    def analyze(self, payload: str, body: str) -> Tuple[bool, str, float]:
        """
        Returns (executable: bool, reason: str, confidence_boost: float)
        """
        # Fix6: strip leading/trailing whitespace when doing partial check
        payload_stripped = payload.strip()
        if payload not in body and payload_stripped not in body:
            partial = payload_stripped[:20]
            if len(partial) < 5 or partial not in body:
                return False, "", 0.0

        # BUG FIX #16 (detection side): if payload is only inside non-executable
        # tag URL attributes (<link href>, <script src>, <img src>, etc.),
        # mark as not executable to prevent false positives.
        import re as _re16
        _non_exec = (
            r'<(?:link|script|img|video|audio|source|track|input|embed|meta|base)'
            r'[^>]*(?:href|src|data|poster|manifest|codebase)\s*=\s*["\'][^"\']*'
        )
        _exec_pat = (
            r'<(?:a|area|form|button|iframe|frame)\b[^>]*'
            r'(?:href|action|formaction|src)\s*=\s*["\'][^"\']*'
        )
        _probe16 = _re16.escape(payload_stripped[:15])
        if _re16.search(_non_exec + _probe16, body, _re16.IGNORECASE | _re16.DOTALL):
            if not _re16.search(_exec_pat + _probe16, body, _re16.IGNORECASE | _re16.DOTALL):
                return False, "non_executable_tag_url", 0.0

        # Fix2: check HTML comment FIRST — before any other check
        comment_pat = r"<!--.*?-->"
        comments = re.findall(comment_pat, body, re.DOTALL)
        if comments:
            body_no_comments = re.sub(comment_pat, "", body, flags=re.DOTALL)
            p_check = payload_stripped[:15]
            if p_check in body and p_check not in body_no_comments:
                return False, "inside_html_comment", 0.0

        try:
            soup = BeautifulSoup(body, "html.parser")
        except Exception:
            return False, "parser_error", 0.0

        # Check script blocks
        for script in soup.find_all("script"):
            text = script.string or ""
            if payload_stripped[:15] in text or (len(payload_stripped) > 5 and payload_stripped[:20] in body):
                return True, "inside_script_block", 0.9

        # Check event handlers on all tags
        for tag in soup.find_all(True):
            for attr, val in (tag.attrs or {}).items():
                val_str = " ".join(val) if isinstance(val, list) else str(val)
                if attr.lower().startswith("on") and payload_stripped[:15] in val_str:
                    return True, f"event_handler_{attr}", 0.85

        # Regex-based checks on raw body
        body_lower = body.lower()
        for pattern, reason, boost in self._EXEC_CONTEXTS:
            matches = list(re.finditer(pattern, body_lower, re.DOTALL | re.IGNORECASE))
            for m in matches:
                window = body[max(0, m.start()-50):m.end()+50]
                if payload_stripped[:15] in window or payload_stripped[:15].lower() in window.lower():
                    return True, reason, boost

        # Check if payload created new tags
        if re.search(r"<(?:script|img|svg|iframe|object|embed|video|audio|details|input|dialog)[^>]*>", body, re.IGNORECASE):
            if any(tag in body for tag in ["onerror", "onload", "onfocus", "ontoggle"]):
                return True, "injected_executable_tag", 0.7

        # Shadow DOM
        if "shadowrootmode" in body.lower() or "shadowroot" in body.lower():
            return True, "shadow_dom_sink", 0.75

        return False, "reflected_not_executable", 0.0


# ═══════════════════════════════════════════════════════════════
# LAYER 6: CSP Analysis
# ═══════════════════════════════════════════════════════════════

class CSPAnalyzer:
    """
    Analyzes CSP headers to determine exploitability and bypass potential.
    """

    def analyze_headers(self, headers: dict) -> Dict[str, Any]:
        """
        Returns CSP analysis result dict.
        """
        csp_header = ""
        for k, v in headers.items():
            if k.lower() in ("content-security-policy", "x-content-security-policy"):
                csp_header = v
                break

        if not csp_header:
            return {"has_csp": False, "strict": False, "bypassable": True,
                    "bypass_vectors": ["no_csp"], "score": 0.0}

        directives = self._parse_csp(csp_header)
        strict = self._is_strict(directives)
        bypassable, vectors = self._find_bypass_vectors(directives)

        # strict-dynamic + nonce without real CDN/unsafe bypasses → not bypassable
        if strict and bypassable:
            real = [v for v in vectors if v not in
                    ("missing_base_uri","missing_form_action","permissive_object_src")]
            if not real:
                bypassable = False
                vectors    = []

        return {
            "has_csp": True,
            "strict": strict,
            "bypassable": bypassable,
            "bypass_vectors": vectors,
            "directives": directives,
            "score": 0.3 if not bypassable else 0.8,
        }

    def _parse_csp(self, header: str) -> Dict[str, List[str]]:
        directives = {}
        for part in header.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directives[tokens[0].lower()] = tokens[1:]
        return directives

    def _is_strict(self, directives: dict) -> bool:
        script_src = directives.get("script-src", directives.get("default-src", []))
        if not script_src:
            return False
        has_nonce = any("nonce-" in s for s in script_src)
        has_hash  = any(s.startswith("sha") for s in script_src)
        has_strict_dyn = "'strict-dynamic'" in script_src
        no_unsafe  = "'unsafe-inline'" not in script_src and "'unsafe-eval'" not in script_src
        no_wildcard = "*" not in script_src
        return (has_nonce or has_hash) and has_strict_dyn and no_unsafe and no_wildcard

    def _find_bypass_vectors(self, directives: dict) -> Tuple[bool, List[str]]:
        vectors = []
        script_src = directives.get("script-src", directives.get("default-src", []))

        if not script_src or "*" in script_src:
            vectors.append("wildcard_script_src")

        if "'unsafe-inline'" in script_src:
            vectors.append("unsafe_inline")

        if "'unsafe-eval'" in script_src:
            vectors.append("unsafe_eval")

        # Check for JSONP-capable CDNs
        jsonp_cdns = ["googleapis.com", "cloudflare.com", "jsdelivr.net",
                      "jquery.com", "bootstrapcdn.com", "unpkg.com", "cdnjs"]
        for src in script_src:
            for cdn in jsonp_cdns:
                if cdn in src:
                    vectors.append(f"jsonp_via_{cdn.split('.')[0]}")

        # base-uri not restricted
        if "base-uri" not in directives:
            vectors.append("missing_base_uri")

        # form-action not restricted
        if "form-action" not in directives:
            vectors.append("missing_form_action")

        # object-src not restricted
        obj_src = directives.get("object-src", [])
        if not obj_src or "*" in obj_src:
            vectors.append("permissive_object_src")

        # Angular allowed = CSTI possible
        if any("angular" in s.lower() for s in script_src):
            vectors.append("angular_csti_via_csp_allowlist")

        return (len(vectors) > 0, vectors)


# ═══════════════════════════════════════════════════════════════
# LAYER 7: Template Injection Detector
# ═══════════════════════════════════════════════════════════════

class TemplateInjectionDetector:
    """Detect SSTI/CSTI indicators in responses."""

    # If these patterns appear in response after injection, it's likely SSTI/CSTI
    _SSTI_INDICATORS = [
        (r"\b49\b",           "7*7=49 — arithmetic executed",           0.9),
        (r"\b7777777\b",      "7*7777777 — arithmetic executed",        0.85),
        (r"TemplateError",    "Template engine error revealed",         0.7),
        (r"JinjaError",       "Jinja2 template error",                  0.8),
        (r"TemplateSyntaxError", "Template syntax error",               0.75),
        (r"UndefinedError",   "Jinja2 UndefinedError",                  0.7),
        (r"\bconfig\b.*SECRET", "config object exposed",                0.9),
        (r"os\.system",       "OS command in template",                 0.95),
        (r"subprocess",       "subprocess module visible",              0.95),
        (r"\{\{.*\}\}",       "Template delimiters in response",        0.6),
        (r"ng-app",           "Angular app in response",                0.7),
        (r"data-ng-",         "Angular directive in response",          0.65),
        (r"v-html",           "Vue v-html directive",                   0.75),
        (r"React\.createElement", "React in response",                 0.6),
    ]

    _CSTI_PAYLOADS_INDICATORS = {
        "{{7*7}}":   ["49"],
        "{{7*'7'}}": ["7777777", "49"],
        "${7*7}":    ["49"],
        "<%=7*7%>":  ["49"],
    }

    def detect(self, payload: str, body: str) -> Optional[Dict]:
        """Returns detection result or None."""
        findings = []

        # Check if arithmetic payload got evaluated
        # REQUIRE execution proof: result must appear in response, NOT the literal payload
        for tpl_payload, expected_results in self._CSTI_PAYLOADS_INDICATORS.items():
            is_probe = (payload.strip() == tpl_payload.strip() or
                        payload.strip().endswith(tpl_payload.strip()) or
                        tpl_payload == payload)
            if is_probe or tpl_payload in payload:
                for expected in expected_results:
                    if expected in body:
                        # Confirm: the EVALUATED result is there
                        # AND the template was NOT just reflected back literally
                        if tpl_payload in body and expected in tpl_payload:
                            # e.g. if '{{7*7}}' appears literally AND '7' is there — no exec proof
                            continue
                        return {
                            "type": "template_injection",
                            "evidence": f"Payload {tpl_payload!r} evaluated → {expected!r} in response",
                            "confidence": 0.95,
                            "framework": self._guess_framework(body),
                        }

        # Detect Angular/Vue CSTI even without server-side evaluation
        _ng_pat  = ["ng-app","ng-bind","ng-controller","data-ng-app","angular.module"]
        _vue_pat = ["v-html","v-bind","v-model","Vue.component","createApp","__vue__"]
        _has_ng  = any(p in body for p in _ng_pat)
        _has_vue = any(p in body for p in _vue_pat)
        _is_tmpl = bool(__import__('re').search(r'\{\{.+?\}\}', payload))
        if _is_tmpl and payload in body and (_has_ng or _has_vue):
            return {
                "type": "template_injection",
                "evidence": f"Template expr reflected in {'Angular' if _has_ng else 'Vue'} — client-side eval",
                "confidence": 0.82,
                "framework": "Angular" if _has_ng else "Vue",
            }

        # Check for SSTI indicators — but ONLY if payload was evaluated (not just reflected)
        # Key: if the EXACT template probe appears literally in response, it was NOT executed
        for probe in self._CSTI_PAYLOADS_INDICATORS:
            if probe in payload and probe in body:
                # Template syntax reflected literally → NOT executed → not SSTI
                return None

        for pattern, reason, score in self._SSTI_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                # Extra guard: 'ng-app' or framework indicators alone aren't enough
                # Need co-occurrence with something dangerous
                if reason in ("Angular app in response", "React in response",
                              "Vue v-html directive", "Angular directive in response"):
                    # These are just framework indicators — skip without other signals
                    continue
                findings.append({"reason": reason, "score": score})

        if findings:
            best = max(findings, key=lambda x: x["score"])
            if best["score"] >= 0.7:
                return {
                    "type": "template_injection",
                    "evidence": best["reason"],
                    "confidence": best["score"],
                    "framework": self._guess_framework(body),
                }
        return None

    def _guess_framework(self, body: str) -> str:
        body_l = body.lower()
        if "jinja" in body_l or "flask" in body_l or "django" in body_l:
            return "Jinja2/Python"
        if "angular" in body_l or "ng-app" in body_l:
            return "Angular"
        if "vue" in body_l or "__vue" in body_l:
            return "Vue"
        if "react" in body_l or "__reactfiber" in body_l:
            return "React"
        if "handlebars" in body_l:
            return "Handlebars"
        if "twig" in body_l:
            return "Twig/PHP"
        if "smarty" in body_l:
            return "Smarty/PHP"
        return "Unknown"


# ═══════════════════════════════════════════════════════════════
# LAYER 8: Prototype Pollution Detector
# ═══════════════════════════════════════════════════════════════

class PrototypePollutionDetector:
    """Detect prototype pollution XSS exploitation indicators."""

    _INDICATORS = [
        (r"__proto__\s*=",         "proto assignment in response",  0.85),
        (r"Object\.prototype",     "Object.prototype in response",  0.80),
        (r"innerHTML.*__proto__",  "innerHTML via proto pollution",  0.90),
        (r"DOMPurify.*bypass",     "DOMPurify bypass indicator",    0.75),
        (r"TypeError.*prototype",  "Prototype TypeError exposed",   0.70),
        (r"\[object Object\]",     "Object serialization artifact", 0.55),
        (r"ALLOWED_TAGS.*\[",      "DOMPurify config exposed",      0.85),
    ]

    def detect(self, payload: str, body: str) -> Optional[Dict]:
        if "__proto__" not in payload and "prototype" not in payload.lower():
            return None

        for pattern, reason, score in self._INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                return {
                    "type": "prototype_pollution",
                    "evidence": reason,
                    "confidence": score,
                }
        # __proto__ reflected in body = signal even without pattern match
        if "__proto__" in body and "__proto__" in payload:
            return {
                "type": "prototype_pollution",
                "evidence": "__proto__ key reflected/error in response",
                "confidence": 0.65,
            }
        return None


# ═══════════════════════════════════════════════════════════════
# LAYER 9: mXSS Mutation Detector
# ═══════════════════════════════════════════════════════════════

class MXSSMutationDetector:
    """
    Detect mXSS — payload entered as 'safe' but mutated to executable.
    Key insight: we need to compare what we SENT vs what APPEARED in DOM.
    """

    _MUTATION_INDICATORS = [
        # Parser breaks out of raw-text elements
        (r"</(?:noscript|xmp|textarea|listing|plaintext)>",
         "Raw-text element closing — possible parser confusion", 0.85),
        # Namespace switching
        (r"<svg>.*<foreignObject",
         "SVG/HTML namespace switch", 0.88),
        (r"<math>.*<mtext>.*</mtext>",
         "MathML mtext boundary", 0.82),
        # Shadow DOM boundary
        (r"shadowrootmode",
         "Shadow DOM root detected", 0.80),
        # DOM mutation via innerHTML
        (r"innerHTML\s*=",
         "innerHTML assignment in page JS", 0.75),
        # Template instantiation
        (r"<template[^>]*>.*<img[^>]*onerror",
         "Template instantiation with XSS", 0.90),
    ]

    def detect(self, original_payload: str, response_body: str) -> Optional[Dict]:
        """Check if mXSS technique might be effective."""
        # Only check mXSS payloads
        mxss_containers = ["noscript", "xmp", "textarea", "listing", "plaintext",
                           "template", "noframes", "style", "svg", "math", "table"]
        is_mxss = any(f"<{c}" in original_payload.lower() for c in mxss_containers)
        if not is_mxss:
            return None

        for pattern, reason, score in self._MUTATION_INDICATORS:
            if re.search(pattern, response_body, re.IGNORECASE | re.DOTALL):
                return {
                    "type": "mxss_mutation",
                    "evidence": reason,
                    "confidence": score,
                }
        return None


# ═══════════════════════════════════════════════════════════════
# LAYER 10: Shadow DOM / Trusted Types Detector
# ═══════════════════════════════════════════════════════════════

class ModernWebAPIDetector:
    """Detect Shadow DOM, Trusted Types, and other modern API XSS vectors."""

    _SHADOW_INDICATORS = [
        (r"attachShadow\s*\(",       "attachShadow API call", 0.80),
        (r"shadowRoot\.innerHTML",   "shadowRoot innerHTML sink", 0.90),
        (r"shadowRoot\.open",        "Open shadow root", 0.75),
        (r"customElements\.define",  "Custom element defined", 0.70),
        (r"<slot\s",                 "Slot element in DOM", 0.65),
    ]

    _TRUSTED_TYPES_INDICATORS = [
        (r"trustedTypes\.createPolicy", "Trusted Types policy creation", 0.85),
        (r"createHTML\s*\(",           "TT createHTML call", 0.82),
        (r"createScript\s*\(",         "TT createScript call", 0.82),
        (r"TrustedHTML",               "TrustedHTML type", 0.75),
        (r"require-trusted-types-for", "TT enforcement header", 0.70),
    ]

    def detect(self, payload: str, body: str, headers: dict = None) -> Optional[Dict]:
        """Detect shadow DOM and Trusted Types XSS vectors."""
        results = []

        for pattern, reason, score in self._SHADOW_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                results.append({"type": "shadow_dom", "evidence": reason, "confidence": score})

        if headers:
            csp_report = headers.get("content-security-policy-report-only", "")
            if "require-trusted-types-for" in csp_report.lower():
                results.append({"type": "trusted_types_enforced",
                               "evidence": "CSP report-only Trusted Types", "confidence": 0.7})

        for pattern, reason, score in self._TRUSTED_TYPES_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                results.append({"type": "trusted_types_bypass", "evidence": reason, "confidence": score})

        if results:
            best = max(results, key=lambda x: x["confidence"])
            return best
        return None


# ═══════════════════════════════════════════════════════════════
# CONFIDENCE SCORER v2 (context + attack-type aware)
# ═══════════════════════════════════════════════════════════════

class ConfidenceScorerV2:

    CONTEXT_WEIGHTS = {
        Context.JS:          1.0,
        Context.JS_STRING:   0.95,
        Context.JS_TEMPLATE: 0.92,
        Context.ATTRIBUTE:   0.88,
        Context.HTML:        0.80,
        Context.URL:         0.85,
        Context.SHADOW_DOM:  0.90,
        Context.TEMPLATE:    0.92,
        Context.WEBSOCKET:   0.85,
        Context.GRAPHQL:     0.82,
        Context.PROTO_CHAIN: 0.88,
        Context.CSS:         0.50,
        Context.COMMENT:     0.30,
        Context.UNKNOWN:     0.60,
    }

    def score(
        self,
        reflected:      bool,
        match_type:     str,
        survival_score: float,
        executable:     bool,
        exec_reason:    str,
        exec_boost:     float,
        dom_vuln:       bool,
        waf_bypassed:   bool,
        context:        str,
        extra_detections: List[Optional[Dict]] = None,
    ) -> Tuple[str, str, float]:
        """
        Returns (severity, confidence_label, raw_score_0_to_1)
        """
        score = 0.0

        # Base signals
        if reflected:
            base = {"exact": 0.35, "url_decoded": 0.30, "double_url_decoded": 0.28,
                    "html_decoded": 0.25, "partial": 0.15, "unicode_norm": 0.20, "none": 0.0}
            score += base.get(match_type, 0.20)

        score += survival_score * 0.15

        if executable:
            score += exec_boost * 0.30
        elif dom_vuln:
            score += 0.15

        if waf_bypassed:
            score += 0.05

        # Context weight
        ctx_weight = self.CONTEXT_WEIGHTS.get(context, 0.60)
        score *= ctx_weight

        # Extra detections bonus
        for det in (extra_detections or []):
            if det:
                score = max(score, det.get("confidence", 0.0) * 0.95)

        # Exec reason bonuses
        if "script_block" in exec_reason:     score = max(score, 0.85)
        if "event_handler" in exec_reason:    score = max(score, 0.80)
        if "shadow_dom" in exec_reason:       score = max(score, 0.75)
        if "srcdoc" in exec_reason:           score = max(score, 0.75)

        score = min(1.0, score)

        if score >= 0.80:
            return "High", "High", score
        elif score >= 0.55:
            return "Medium", "Medium", score
        elif score >= 0.30:
            return "Low", "Low", score
        else:
            return "Informational", "Info", score


# ═══════════════════════════════════════════════════════════════
# MASTER DETECTION ENGINE v2
# ═══════════════════════════════════════════════════════════════

class DetectionEngineV2:
    """
    10-layer detection engine. Drop-in upgrade for DetectionEngine.
    Backward compatible: same .analyze() signature.
    """

    def __init__(self):
        self.reflection    = ReflectionAnalyzerV2()
        self.html_pos      = HTMLPositionAnalyzerV2()
        self.csp           = CSPAnalyzer()
        self.template      = TemplateInjectionDetector()
        self.prototype     = PrototypePollutionDetector()
        self.mxss          = MXSSMutationDetector()
        self.modern_api    = ModernWebAPIDetector()
        self.scorer        = ConfidenceScorerV2()

    def analyze(
        self,
        payload:       str,
        response_body: str,
        context:       str = Context.UNKNOWN,
        waf_bypassed:  bool = False,
        headers:       dict = None,
    ) -> Optional[dict]:
        """
        Full 10-layer analysis.
        Returns detection dict or None if not vulnerable.
        """
        headers = headers or {}

        # ── Pre-check: HTML comment guard ───────────────────────
        # If payload is ONLY inside HTML comments → not executable → skip early
        import re as _re_comment
        _comment_blocks = _re_comment.findall(r'<!--.*?-->', response_body, _re_comment.DOTALL)
        _in_comment_only = (
            payload in response_body and
            bool(_comment_blocks) and
            all(payload not in response_body.replace(c, '') for c in _comment_blocks)
        )
        if _in_comment_only:
            return None  # payload only in HTML comment → not exploitable

        # ── Layer 1: Reflection ───────────────────────────────
        reflected, evidence, match_type = self.reflection.check(payload, response_body)
        survival = self.reflection.survival_score(payload, response_body)

        # ── Layer 2: HTML Position ────────────────────────────
        executable, exec_reason, exec_boost = self.html_pos.analyze(payload, response_body)

        # ── Layer 3: DOM sinks ────────────────────────────────
        dom_vuln = self._check_dom_sinks(response_body)

        # ── Layer 6: CSP ──────────────────────────────────────
        csp_result = self.csp.analyze_headers(headers)

        # ── Layer 7: Template injection ───────────────────────
        tpl_result = self.template.detect(payload, response_body)

        # ── Layer 8: Prototype pollution ──────────────────────
        pp_result = self.prototype.detect(payload, response_body)

        # ── Layer 9: mXSS mutation ────────────────────────────
        mxss_result = self.mxss.detect(payload, response_body)

        # ── Layer 10: Shadow DOM / Trusted Types ──────────────
        modern_result = self.modern_api.detect(payload, response_body, headers)

        # ── Combine ───────────────────────────────────────────
        extra = [tpl_result, pp_result, mxss_result, modern_result]
        any_extra = any(e is not None for e in extra)

        # Short-circuit: if no reflection AND no extra detections, skip
        if not reflected and not any_extra and not dom_vuln:
            return None

        # Score
        severity, confidence, raw_score = self.scorer.score(
            reflected=reflected,
            match_type=match_type,
            survival_score=survival,
            executable=executable,
            exec_reason=exec_reason,
            exec_boost=exec_boost,
            dom_vuln=dom_vuln,
            waf_bypassed=waf_bypassed,
            context=context,
            extra_detections=extra,
        )

        # Filter out very low confidence unless special detection
        if raw_score < 0.35 and not any_extra:  # raised from 0.25 to reduce FP
            return None

        # Determine XSS type
        xss_type = "reflected"
        if tpl_result:
            xss_type = "template_injection"
        elif pp_result:
            xss_type = "prototype_pollution"
        elif mxss_result:
            xss_type = "mxss"
        elif modern_result and "shadow" in modern_result.get("type", ""):
            xss_type = "shadow_dom_xss"

        # Build result
        result = {
            "reflected":   reflected,
            "match_type":  match_type,
            "executable":  executable,
            "exec_reason": exec_reason,
            "dom_vuln":    dom_vuln,
            "chars_ok":    survival >= 0.5,
            "confidence":  confidence,
            "severity":    severity,
            "raw_score":   round(raw_score, 3),
            "evidence":    evidence[:300] if evidence else "",
            "xss_type":    xss_type,
            "csp_bypassable": csp_result.get("bypassable", True),
            "csp_vectors": csp_result.get("bypass_vectors", []),
        }

        # Attach specific detection details
        if tpl_result:
            result["template_injection"] = tpl_result
        if pp_result:
            result["prototype_pollution"] = pp_result
        if mxss_result:
            result["mxss"] = mxss_result
        if modern_result:
            result["modern_api"] = modern_result

        return result

    # Sinks that are SAFE — they don't interpret HTML
    _SAFE_SINKS = {
        "textcontent", "innertext", "textcontent=", "innertext=",
        "setattribute", "setattribute('class'",
        "classname", "classlist", "title=", ".value =", ".value=",
        "createtextnode",
    }

    def _check_dom_sinks(self, body: str) -> bool:
        """Check for dangerous DOM sinks near user-controllable sources."""
        body_lower = body.lower()
        for sink in DOM_SINKS:
            if sink.lower() in body_lower:
                # Skip safe sinks
                if any(safe in body_lower for safe in self._SAFE_SINKS):
                    # Only skip if the dangerous sink is absent
                    has_dangerous = any(
                        ds.lower() in body_lower
                        for ds in ["innerhtml", "outerhtml", "document.write",
                                   "insertadjacenthtml", "eval("]
                    )
                    if not has_dangerous:
                        continue
                idx = body_lower.find(sink.lower())
                window = body_lower[max(0,idx-400):idx+400]
                for src in DOM_SOURCES:
                    if src.lower() in window:
                        return True
        return False

    def quick_reflect(self, payload: str, body: str) -> bool:
        """Fast check for bulk filtering."""
        return (payload in body or
                unquote(payload) in body or
                payload[:25] in body)

    # ── Backward compatibility with v1 ───────────────────────
    def analyze_v1_compat(
        self,
        payload: str,
        response_body: str,
        context: str = Context.UNKNOWN,
        waf_bypassed: bool = False,
    ) -> Optional[dict]:
        """Same as analyze() but returns v1-compatible dict format."""
        result = self.analyze(payload, response_body, context, waf_bypassed)
        if result is None:
            return None
        return {
            "reflected":   result["reflected"],
            "executable":  result["executable"],
            "exec_reason": result["exec_reason"],
            "dom_vuln":    result.get("dom_vuln", False),
            "dom_sinks":   [],
            "chars_ok":    result["chars_ok"],
            "confidence":  result["confidence"],
            "severity":    result["severity"],
            "evidence":    result["evidence"],
        }


# ── Keep v1 name for backward compat ─────────────────────────────────────────
DetectionEngine = DetectionEngineV2
