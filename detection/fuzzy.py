"""
detection/fuzzy.py

FuzzyDetector — Multi-signal similarity detection engine.

Problems with exact-match detection (XSStrike has this partially, XScanner v1 too):
  - Server encodes & then re-decodes → payload appears transformed
  - WAF strips individual chars → payload partially reflected
  - Template engines render payload differently

Solution: Multi-signal fuzzy analysis:
  1. Levenshtein similarity ratio     — how similar is reflection to payload?
  2. Token overlap score              — how many payload tokens appear in response?
  3. Entropy delta                    — does injection change response randomness?
  4. Response length delta            — significant change = something happened
  5. Structure mutation score         — did HTML structure change post-injection?
  6. Semantic tag injection check     — did new executable tags appear?
"""

import re
import math
from typing import Optional, Tuple, List
from collections import Counter

try:
    from rapidfuzz import fuzz as rfuzz
    _HAS_RAPIDFUZZ = True
except ImportError:
    _HAS_RAPIDFUZZ = False

from utils.logger import debug


# ─── Entropy calculator ──────────────────────────────────────────────────────

def _entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    total  = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ─── Token extractor ─────────────────────────────────────────────────────────

def _tokenize(text: str) -> set:
    """Extract meaningful tokens from payload/response."""
    return set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,}', text.lower()))


# ─── HTML tag extractor ──────────────────────────────────────────────────────

_EXECUTABLE_TAGS = {
    "script", "svg", "img", "iframe", "object", "embed",
    "video", "audio", "body", "details", "input", "form",
    "marquee", "math", "link", "meta", "base", "style",
}

def _extract_executable_tags(html: str) -> set:
    """Extract all executable HTML tags from a response."""
    tags = set(re.findall(r'<(\w+)', html.lower()))
    return tags & _EXECUTABLE_TAGS


# ─── Main FuzzyDetector ──────────────────────────────────────────────────────

class FuzzyDetector:
    """
    Multi-signal fuzzy XSS detection.

    Thresholds tuned to minimize false positives while catching
    partial/encoded reflections that exact-match would miss.
    """

    # Minimum similarity ratio (0-100) to consider "reflected"
    SIMILARITY_THRESHOLD   = 55   # lowered: 65→55 to catch more partials
    # Minimum token overlap to consider "reflected"
    TOKEN_OVERLAP_THRESHOLD = 0.30 # lowered: 0.4→0.30
    # Entropy delta that indicates injection had structural effect
    ENTROPY_DELTA_THRESHOLD = 0.3

    def analyze(
        self,
        payload:      str,
        baseline:     str,
        response:     str,
        fast_mode:    bool = False,
    ) -> dict:
        """
        Full fuzzy analysis.

        Args:
            payload:   The injected payload string
            baseline:  Response WITHOUT payload injection (for diff)
            response:  Response WITH payload injection
            fast_mode: Skip expensive checks if True

        Returns dict with:
            reflected:        bool
            confidence:       float (0.0–1.0)
            similarity:       float (0–100, Levenshtein ratio)
            token_overlap:    float (0.0–1.0)
            entropy_delta:    float
            new_tags:         List[str]  — new executable tags that appeared
            structural_change: bool
            method:           str — which signal triggered detection
        """
        result = {
            "reflected":         False,
            "confidence":        0.0,
            "similarity":        0.0,
            "token_overlap":     0.0,
            "entropy_delta":     0.0,
            "new_tags":          [],
            "structural_change": False,
            "method":            "none",
        }

        # ── Signal -1: Non-XSS payload guard (MUST be first) ─────────────────
        # If payload has ZERO XSS indicators → benign probe → skip detection
        # Prevents "test", "1", "foo" matching plain body text
        _XSS_MARKERS = ['<', '>', '"', "'", '(', 'javascript:',
                        'onerror', 'onload', 'onfocus', 'onclick', 'alert',
                        'confirm', 'eval', 'script', 'svg', '__proto__', '{{', '\\u00']
        _has_xss = any(m.lower() in payload.lower() for m in _XSS_MARKERS)
        if not _has_xss and len(payload) < 40:
            result['method'] = 'non_xss_payload'
            return result  # not an XSS payload — skip all detection

        # ── Signal 1: Exact match (fastest) ──────────────────────────────────
        if payload in response:
            # Anti-FP: check if reflection is inside HTML comment <!-- ... -->
            idx         = response.find(payload)
            win_left    = response[max(0, idx - 300):idx]
            win_right   = response[idx + len(payload):idx + len(payload) + 50]
            comment_open  = win_left.rfind('<!--')
            comment_close = win_left.rfind('-->')
            in_comment    = (comment_open > comment_close) and \
                            ('-->' in win_right or '-->' in response[idx:idx+200])
            if in_comment:
                # Inside HTML comment — not directly executable; skip exact-match signal
                pass
            else:
                _bt = _extract_executable_tags(baseline)
                _rt = _extract_executable_tags(response)
                result.update({
                    "reflected":  True,
                    "confidence": 1.0,
                    "similarity": 100.0,
                    "method":     "exact",
                    "new_tags":   list(_rt - _bt),
                })
                return result

        # ── Signal 0: Critical char survival guard (anti-FP) ─────────────────
        # If payload has critical XSS chars and they appear ONLY as HTML entities
        # in the response context where the payload is reflected → server encoded
        if '<' in payload and '>' in payload:
            import re as _re
            # Extract content of payload first tag (e.g. 'script' from <script>)
            tag_match = _re.search(r'<([a-zA-Z][a-zA-Z0-9]*)', payload)
            if tag_match:
                tag_name = tag_match.group(1).lower()
                # Check if encoded form of tag appears in response body text
                encoded_forms = [
                    f'&lt;{tag_name}', f'&lt;/{tag_name}',
                    f'&#60;{tag_name}', f'&#x3c;{tag_name}',
                    f'%3c{tag_name}', f'%3C{tag_name}',
                ]
                # Check if the tag appears UNencoded (raw) in response
                raw_tag_pattern = f'<{tag_name}[\\s>/]'
                has_raw_tag = bool(_re.search(raw_tag_pattern, response, _re.IGNORECASE))
                has_encoded = any(ef in response.lower() for ef in encoded_forms)
                if has_encoded and not has_raw_tag:
                    # Tag is encoded → server sanitized it → NOT reflected
                    result['method'] = 'encoded_safe'
                    return result

        # ── Signal 0b: WAF block guard (anti-FP) ───────────────────────────
        WAF_KEYWORDS = ['blocked', 'forbidden', 'security policy', 'malicious content',
                        'access denied', 'not allowed', 'detected', 'threat detected',
                        'attack detected', 'blocked by', 'security rule']
        resp_lower = response.lower()
        waf_kw_found = [k for k in WAF_KEYWORDS if k in resp_lower]
        # Short WAF page: small body + WAF keyword + payload NOT in body = block
        # BUT: if the payload's XSS tag appears raw in the body, it's partial reflection
        if waf_kw_found and len(response) < 800 and payload not in response:
            import re as _re_waf
            payload_has_tag = bool(_re_waf.search(r'<([a-zA-Z][a-zA-Z0-9]*)', payload))
            if payload_has_tag:
                tag_m = _re_waf.search(r'<([a-zA-Z][a-zA-Z0-9]*)', payload)
                raw_tag = f'<{tag_m.group(1)}'
                if raw_tag.lower() in response.lower():
                    # Payload's raw tag IS in response → partial reflection, NOT waf block
                    pass  # let detection continue
                else:
                    result['method'] = 'waf_block'
                    return result
            else:
                result['method'] = 'waf_block'
                return result
        # Payload in body but WAF encoded the critical tag
        if waf_kw_found and '<' in payload:
            import re as _re2
            tag_m = _re2.search(r'<([a-zA-Z][a-zA-Z0-9]*)', payload)
            if tag_m:
                enc = f'&lt;{tag_m.group(1).lower()}'
                if enc in response.lower():
                    result['method'] = 'waf_encoded_block'
                    return result

        # ── Signal 0c: HTML comment guard (anti-FP) ─────────────────────────
        # If payload found inside HTML comment → not an executable reflection
        if payload in response:
            import re as _re3
            # Find all HTML comment blocks
            comments = _re3.findall(r'<!--.*?-->', response, _re3.DOTALL)
            in_comment = any(payload in c for c in comments)
            if in_comment:
                result['method'] = 'in_html_comment'
                return result  # inside comment = not exploitable

        # ── Signal 0d: pre/code block guard ─────────────────────────────────
        # Payload inside <pre><code> = display context, not executable
        if payload in response or (len(payload) > 8 and payload[:15] in response):
            import re as _re4
            code_blocks = _re4.findall(r'<(?:pre|code|kbd|samp)[^>]*>.*?</(?:pre|code|kbd|samp)>', response, _re4.DOTALL | _re4.IGNORECASE)
            if any(payload in b or (len(payload)>8 and payload[:15] in b) for b in code_blocks):
                result['method'] = 'in_code_block'
                return result  # inside code block = display only

        # ── Signal 1b: Segment/Partial match (NEW — fixes truncated reflection) ─
        # Split payload into overlapping 8-char windows, check each in response
        if not result['reflected'] and len(payload) >= 8:
            segments = self._get_segments(payload, min_len=8)
            matched = [s for s in segments if s in response]
            if matched:
                # Score based on: how many segments matched AND how long
                total_len  = sum(len(s) for s in segments)
                match_len  = sum(len(s) for s in matched)
                coverage   = match_len / max(total_len, 1)
                # Need at least 40% of payload segments to match
                if coverage >= 0.40:
                    conf = round(coverage * 0.75, 3)
                    result.update({
                        'reflected':  True,
                        'confidence': conf,
                        'method':     f'segment_match({coverage:.0%}_{len(matched)}/{len(segments)})',
                    })

        # ── Signal 2: Levenshtein similarity ─────────────────────────────────
        # Compare payload against all substrings of response of similar length
        similarity = self._best_similarity(payload, response)
        result["similarity"] = similarity

        if similarity >= self.SIMILARITY_THRESHOLD:
            # Anti-FP: if payload has event handlers, check they survived in response
            has_event_in_payload = bool(re.search(r'on(?:error|load|click|focus|mouse\w+)\s*=', payload, re.IGNORECASE))
            has_event_in_response = bool(re.search(r'on(?:error|load|click|focus|mouse\w+)\s*=', response, re.IGNORECASE))
            if has_event_in_payload and not has_event_in_response:
                # Event handler in payload was stripped — likely sanitized
                pass  # skip this signal
            else:
                conf = (similarity - self.SIMILARITY_THRESHOLD) / (100 - self.SIMILARITY_THRESHOLD)
                result.update({
                    "reflected":  True,
                    "confidence": round(conf * 0.85, 3),
                    "method":     f"levenshtein({similarity:.0f}%)",
                })

        # ── Signal 3: Token overlap ───────────────────────────────────────────
        payload_tokens  = _tokenize(payload)
        response_tokens = _tokenize(response)
        if payload_tokens:
            overlap = len(payload_tokens & response_tokens) / len(payload_tokens)
            result["token_overlap"] = round(overlap, 3)
            if overlap >= self.TOKEN_OVERLAP_THRESHOLD and not result["reflected"]:
                # Guard: token overlap alone is not enough — we need HTML evidence.
                # Avoid FP on pages that just mention keywords in plain text.
                # ALSO require payload has structural XSS chars, not just keywords
                # Prevents "script","alert" as plain words in educational text
                _structural = set('<>"\'()/=')
                payload_has_struct = bool(_structural & set(payload))
                has_html_ctx = bool(
                    re.search(r'<[a-zA-Z][^>]*(?:on\w+|javascript:|src\s*=|href\s*=)', response, re.IGNORECASE)
                    or '<script' in response.lower()
                )
                if has_html_ctx and payload_has_struct:
                    result.update({
                        "reflected":  True,
                        "confidence": round(overlap * 0.6, 3),
                        "method":     f"token_overlap({overlap:.0%})",
                    })

        if fast_mode:
            return result

        # ── Signal 4: New executable tags ─────────────────────────────────────
        baseline_tags = _extract_executable_tags(baseline)
        response_tags = _extract_executable_tags(response)
        new_tags      = list(response_tags - baseline_tags)
        result["new_tags"] = new_tags

        if new_tags:
            # New executable tag appeared → high confidence
            boost = min(0.3, len(new_tags) * 0.1)
            result["confidence"] = min(1.0, result["confidence"] + boost)
            if not result["reflected"]:
                result.update({
                    "reflected":  True,
                    "confidence": 0.7,
                    "method":     f"new_exec_tags({new_tags})",
                })

        # ── Signal 5: Entropy delta ───────────────────────────────────────────
        ent_baseline = _entropy(baseline[:5000])
        ent_response = _entropy(response[:5000])
        ent_delta    = abs(ent_response - ent_baseline)
        result["entropy_delta"] = round(ent_delta, 4)

        if ent_delta > self.ENTROPY_DELTA_THRESHOLD and not result["reflected"]:
            # Anti-FP: entropy delta alone too noisy
            # Require: payload has XSS chars + response not drastically shorter
            _ent_structural = set("<>\"'()/=")
            _ent_has_struct = bool(_ent_structural & set(payload))
            _resp_not_empty = len(response) > len(baseline) * 0.25
            _tok_overlap    = result.get("token_overlap", 0.0)
            if _ent_has_struct and _resp_not_empty and _tok_overlap > 0.40:
                result.update({
                    "reflected":  True,
                    "confidence": 0.35,
                    "method":     f"entropy_delta({ent_delta:.3f})",
                })

        # ── Signal 6: Response length structural change ───────────────────────
        len_base = len(baseline)
        len_resp = len(response)
        if len_base > 0:
            delta_ratio = abs(len_resp - len_base) / len_base
            if delta_ratio > 0.15:
                result["structural_change"] = True
                if result["reflected"]:
                    result["confidence"] = min(1.0, result["confidence"] + 0.1)

        return result

    def _get_segments(self, payload: str, min_len: int = 8) -> list:
        """
        Break payload into meaningful overlapping segments.
        Strategy: XSS keywords + fixed windows + token boundaries.
        """
        segments = set()
        # Fixed windows: every N chars
        for size in (8, 12, 16, 20):
            for start in range(0, len(payload) - size + 1, size // 2):
                seg = payload[start:start + size]
                if seg.strip():
                    segments.add(seg)
        # XSS keyword segments (high value)
        import re
        for kw in re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,}', payload):
            if len(kw) >= min_len:
                segments.add(kw)
        # Include payload first half and second half
        mid = len(payload) // 2
        if mid >= min_len:
            segments.add(payload[:mid])
            segments.add(payload[mid:])
        return list(segments)

    def _best_similarity(self, payload: str, response: str) -> float:
        """
        Find the best Levenshtein similarity between payload and
        any substring of response. Uses full payload — no truncation.
        """
        if not _HAS_RAPIDFUZZ:
            return self._fallback_similarity(payload, response)

        plen = len(payload)
        if plen == 0:
            return 0.0

        # Use full payload for partial_ratio — critical for long polyglots/mXSS
        best = rfuzz.partial_ratio(payload, response)

        # Also check most distinctive segment (middle 60%) for very long payloads
        if plen > 150:
            start = plen // 5
            end   = plen - plen // 5
            mid_score = rfuzz.partial_ratio(payload[start:end], response)
            best = max(best, mid_score)

        return float(best)

    def _fallback_similarity(self, s1: str, s2: str) -> float:
        """
        Pure-Python Levenshtein ratio fallback (no external deps).
        Only checks if s1 appears roughly in s2.
        """
        s1 = s1[:80].lower()
        s2 = s2.lower()
        plen = len(s1)
        if plen == 0:
            return 0.0

        best = 0.0
        step = max(1, plen // 4)
        for i in range(0, len(s2) - plen + 1, step):
            window  = s2[i:i + plen]
            matches = sum(a == b for a, b in zip(s1, window))
            ratio   = (matches / plen) * 100
            if ratio > best:
                best = ratio
            if best >= 95:
                break
        return best


# ─── Response Differ ─────────────────────────────────────────────────────────

class ResponseDiffer:
    """
    Structural diff between baseline and injected response.
    Detects DOM mutations introduced by payload injection.
    Goes beyond simple string comparison — looks at tag structure.
    """

    def diff(self, baseline: str, response: str) -> dict:
        """
        Returns:
            added_tags:    new HTML tags in response
            removed_tags:  tags that disappeared
            new_scripts:   new <script> blocks
            new_handlers:  new event handlers (onXxx attributes)
            delta_ratio:   length change ratio
        """
        base_tags    = self._extract_tags(baseline)
        resp_tags    = self._extract_tags(response)
        base_scripts = self._extract_scripts(baseline)
        resp_scripts = self._extract_scripts(response)
        base_handlers = self._extract_handlers(baseline)
        resp_handlers = self._extract_handlers(response)

        added_tags   = [t for t in resp_tags   if t not in base_tags]
        new_scripts  = [s for s in resp_scripts if s not in base_scripts]
        new_handlers = [h for h in resp_handlers if h not in base_handlers]

        delta_ratio = (
            abs(len(response) - len(baseline)) / max(1, len(baseline))
        )

        return {
            "added_tags":   added_tags[:10],
            "new_scripts":  new_scripts[:5],
            "new_handlers": new_handlers[:10],
            "delta_ratio":  round(delta_ratio, 3),
            "suspicious":   bool(new_scripts or new_handlers or added_tags),
        }

    @staticmethod
    def _extract_tags(html: str) -> List[str]:
        return re.findall(r'<(\w+)[^>]*>', html.lower())

    @staticmethod
    def _extract_scripts(html: str) -> List[str]:
        return re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)

    @staticmethod
    def _extract_handlers(html: str) -> List[str]:
        return re.findall(r'\bon\w+\s*=\s*["\'][^"\']*["\']', html, re.IGNORECASE)
