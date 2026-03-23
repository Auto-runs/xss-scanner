"""
scanner/filter_probe.py

FilterProbe — Character-level filter intelligence engine.

THIS is what makes the difference vs XSStrike's approach but better:
XSStrike tests chars one-by-one sequentially.
FilterProbe does it concurrently AND builds a character survival matrix
that feeds directly into the payload generator to guarantee only
"survivor payloads" are generated — zero wasted requests.

Flow:
  1. Send canary to get baseline reflection
  2. Concurrently probe all critical characters & sequences
  3. Build CharacterMatrix: which chars survive, which get encoded/stripped
  4. Score payload templates against the matrix
  5. Return ONLY payloads that can realistically execute
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import quote

from utils.config import ScanTarget, Context
from utils.http_client import HttpClient
from utils.logger import debug, info, progress


# ─── Critical character/sequence probes ─────────────────────────────────────

PROBE_CHARS = {
    # (probe_string, label, required_by_contexts)
    "<":          ("tag_open",       {Context.HTML, Context.ATTRIBUTE}),
    ">":          ("tag_close",      {Context.HTML, Context.ATTRIBUTE}),
    "\"":         ("double_quote",   {Context.ATTRIBUTE, Context.JS}),
    "'":          ("single_quote",   {Context.ATTRIBUTE, Context.JS}),
    "`":          ("backtick",       {Context.JS, Context.JS_TEMPLATE}),
    "(":          ("paren_open",     {Context.JS, Context.HTML}),
    ")":          ("paren_close",    {Context.JS, Context.HTML}),
    "/":          ("slash",          {Context.HTML, Context.JS}),
    "\\":          ("backslash",      {Context.JS}),
    ";":          ("semicolon",      {Context.JS}),
    "=":          ("equals",         {Context.HTML, Context.ATTRIBUTE}),
    "&":          ("ampersand",      {Context.HTML}),
    "#":          ("hash",           {Context.URL}),
    "javascript:": ("js_proto",      {Context.ATTRIBUTE, Context.URL}),
    "onerror":    ("event_handler",  {Context.HTML, Context.ATTRIBUTE}),
    "onload":     ("onload",         {Context.HTML}),
    "alert":      ("alert_keyword",  {Context.JS, Context.HTML}),
    "script":     ("script_keyword", {Context.HTML}),
    "svg":        ("svg_keyword",    {Context.HTML}),
    "iframe":     ("iframe_keyword", {Context.HTML}),
    "<script":    ("script_tag",     {Context.HTML}),
    "<img":       ("img_tag",        {Context.HTML}),
    "<svg":       ("svg_tag",        {Context.HTML}),
}

# Characters required for each context to be exploitable
CONTEXT_REQUIREMENTS: Dict[str, List[str]] = {
    Context.HTML:        ["tag_open", "tag_close"],
    Context.ATTRIBUTE:   ["double_quote", "tag_close"],
    Context.JS:          ["paren_open", "paren_close"],
    Context.JS_STRING:   ["single_quote", "paren_open"],
    Context.JS_TEMPLATE: ["backtick", "paren_open"],
    Context.URL:         ["js_proto"],
    Context.CSS:         ["paren_open"],
    Context.UNKNOWN:     [],
}


@dataclass
class CharacterMatrix:
    """
    Result of filter probing.
    Maps character label → survival status and transformation.
    """
    survivors:   Set[str] = field(default_factory=set)   # labels that pass through raw
    encoded:     Dict[str, str] = field(default_factory=dict)  # label → how it was encoded
    stripped:    Set[str] = field(default_factory=set)   # labels that were removed
    context:     str = Context.UNKNOWN
    exploitable: bool = False
    score:       float = 0.0  # 0.0–1.0 exploitability score

    def can_use(self, label: str) -> bool:
        return label in self.survivors

    def viable_contexts(self) -> List[str]:
        """Return contexts that are exploitable given surviving chars."""
        viable = []
        for ctx, required in CONTEXT_REQUIREMENTS.items():
            if not required or all(self.can_use(r) for r in required):
                viable.append(ctx)
        return viable

    def summary(self) -> str:
        return (
            f"survivors={len(self.survivors)} "
            f"encoded={len(self.encoded)} "
            f"stripped={len(self.stripped)} "
            f"score={self.score:.2f}"
        )


# ─── FilterProbe engine ──────────────────────────────────────────────────────

class FilterProbe:
    """
    Concurrently probe a target parameter to build a CharacterMatrix.

    Usage:
        probe  = FilterProbe(http_client)
        matrix = await probe.analyze(target)
        payloads = gen.for_matrix(matrix)
    """

    CANARY_PREFIX = "xfp"

    def __init__(self, http: HttpClient, concurrency: int = 15):
        self.http       = http
        self._sem       = asyncio.Semaphore(concurrency)

    async def analyze(self, target: ScanTarget) -> CharacterMatrix:
        """
        Full filter analysis. Returns CharacterMatrix.
        """
        matrix = CharacterMatrix(context=target.context)

        # Step 1: Baseline — confirm parameter reflects at all
        baseline = await self._baseline(target)
        if baseline is None:
            debug(f"FilterProbe: no baseline reflection for {target.url} param={target.param_key}")
            return matrix

        progress(f"FilterProbe: analyzing filter on param '{target.param_key}'...")

        # Step 2: Concurrent char probing
        tasks = [
            self._probe_char(target, probe_str, label)
            for probe_str, (label, _) in PROBE_CHARS.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Step 3: Build matrix
        for result in results:
            if isinstance(result, Exception):
                continue
            if result is None:
                continue
            label, status, encoded_as = result
            if status == "survived":
                matrix.survivors.add(label)
            elif status == "encoded":
                matrix.encoded[label] = encoded_as
            elif status == "stripped":
                matrix.stripped.add(label)

        # Step 4: Score and assess exploitability
        matrix.score       = self._score(matrix)
        matrix.exploitable = matrix.score > 0.3

        info(
            f"FilterProbe result: {matrix.summary()} "
            f"| viable contexts: {matrix.viable_contexts()}"
        )
        return matrix

    async def _baseline(self, target: ScanTarget) -> Optional[str]:
        """Confirm reflection and return baseline response."""
        import copy
        t = copy.deepcopy(target)
        canary = f"{self.CANARY_PREFIX}baseline"
        if t.method == "GET":
            t.params[t.param_key] = canary
            resp = await self.http.get(t.url, params=t.params)
        else:
            t.data[t.param_key] = canary
            resp = await self.http.post(t.url, data=t.data)

        if resp and canary in resp.text:
            return resp.text
        return None

    async def _probe_char(
        self,
        target: ScanTarget,
        probe_str: str,
        label: str,
    ) -> Optional[Tuple[str, str, str]]:
        """
        Probe a single character/sequence.
        Returns (label, status, encoded_as) where status ∈ {survived, encoded, stripped}.
        """
        import copy
        async with self._sem:
            canary = f"{self.CANARY_PREFIX}{label[:4]}{probe_str}{self.CANARY_PREFIX}"
            t = copy.deepcopy(target)

            if t.method == "GET":
                t.params[t.param_key] = canary
                resp = await self.http.get(t.url, params=t.params)
            else:
                t.data[t.param_key] = canary
                resp = await self.http.post(t.url, data=t.data)

            if resp is None:
                return None

            body = resp.text

            # Check exact survival
            if canary in body:
                return (label, "survived", "")

            # Check if canary prefix/suffix survived (char itself was transformed)
            prefix = f"{self.CANARY_PREFIX}{label[:4]}"
            suffix = f"{self.CANARY_PREFIX}"
            if prefix in body and suffix in body:
                # Extract what the char became
                try:
                    start = body.index(prefix) + len(prefix)
                    end   = body.index(suffix, start)
                    transformed = body[start:end]
                    if transformed != probe_str:
                        return (label, "encoded", transformed)
                except ValueError:
                    pass
                return (label, "stripped", "")

            # Canary prefix not found — entire value was stripped/blocked
            return (label, "stripped", "")

    def _score(self, matrix: CharacterMatrix) -> float:
        """
        Compute exploitability score 0.0–1.0.
        Weights key characters by their impact on exploitability.
        """
        weights = {
            "tag_open":       0.20,
            "tag_close":      0.10,
            "event_handler":  0.15,
            "js_proto":       0.12,
            "paren_open":     0.10,
            "paren_close":    0.10,
            "script_tag":     0.08,
            "svg_tag":        0.07,
            "alert_keyword":  0.05,
            "double_quote":   0.03,
        }
        score = sum(
            w for label, w in weights.items()
            if matrix.can_use(label)
        )
        return min(1.0, score)


# ─── Smart payload filter ────────────────────────────────────────────────────

class SmartPayloadFilter:
    """
    Given a CharacterMatrix, score and rank payload templates.
    Returns only payloads that have realistic chance of execution.
    Eliminates ~60-80% of useless payloads before sending any requests.
    """

    def filter_payloads(
        self,
        payloads: List[Tuple[str, str]],
        matrix: CharacterMatrix,
    ) -> List[Tuple[str, str, float]]:
        """
        Returns list of (payload, encoding, score) sorted by score desc.
        Only returns payloads with score > 0.
        """
        scored = []
        for payload, enc in payloads:
            score = self._score_payload(payload, matrix)
            if score > 0:
                scored.append((payload, enc, score))
        scored.sort(key=lambda x: x[2], reverse=True)
        return scored

    def _score_payload(self, payload: str, matrix: CharacterMatrix) -> float:
        """Score a single payload against the matrix."""
        payload_lower = payload.lower()
        score = 1.0
        penalties = 0

        checks = [
            ("<",          "tag_open",       0.8),
            (">",          "tag_close",      0.5),
            ("\"",         "double_quote",   0.3),
            ("'",          "single_quote",   0.3),
            ("(",          "paren_open",     0.6),
            (")",          "paren_close",    0.6),
            ("javascript:","js_proto",       0.7),
            ("onerror",    "event_handler",  0.4),
            ("onload",     "onload",         0.4),
            ("script",     "script_keyword", 0.3),
            ("alert",      "alert_keyword",  0.2),
        ]

        for char, label, penalty_weight in checks:
            if char in payload_lower:
                if label in matrix.stripped:
                    penalties += penalty_weight
                elif label in matrix.encoded:
                    penalties += penalty_weight * 0.5  # Partial penalty if encoded

        score = max(0.0, 1.0 - penalties)
        return score
