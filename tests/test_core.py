"""
tests/test_core.py
Unit tests for XScanner core modules.
Run: python -m pytest tests/ -v
"""

import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest


# ─── PayloadGenerator Tests ──────────────────────────────────────────────────

class TestPayloadGenerator:
    from payloads.generator import PayloadGenerator, MutationEngine, Encoder
    from utils.config import Context

    def test_html_context_returns_payloads(self):
        from payloads.generator import PayloadGenerator
        from utils.config import Context
        gen = PayloadGenerator(max_per_ctx=20)
        payloads = gen.for_context(Context.HTML)
        assert len(payloads) > 0
        assert all(isinstance(p, tuple) and len(p) == 2 for p in payloads)

    def test_js_context_different_from_html(self):
        from payloads.generator import PayloadGenerator
        from utils.config import Context
        gen = PayloadGenerator(max_per_ctx=15)
        html_p = set(p for p, _ in gen.for_context(Context.HTML))
        js_p   = set(p for p, _ in gen.for_context(Context.JS))
        # JS payloads should have some unique entries
        assert len(js_p - html_p) > 0

    def test_respects_max_per_ctx(self):
        from payloads.generator import PayloadGenerator
        from utils.config import Context
        gen = PayloadGenerator(max_per_ctx=5)
        payloads = gen.for_context(Context.HTML)
        assert len(payloads) <= 5

    def test_blind_xss_contains_callback(self):
        from payloads.generator import PayloadGenerator
        gen = PayloadGenerator()
        blind = gen.for_blind_xss("http://callback.test/x")
        assert any("callback.test" in p for p, _ in blind)

    def test_mutation_produces_variants(self):
        from payloads.generator import MutationEngine
        m = MutationEngine()
        base = "<script>alert(1)</script>"
        variants = m.mutate(base, count=3)
        assert len(variants) >= 1
        assert all(v != base for v in variants)

    def test_encoder_html_entity(self):
        from payloads.generator import Encoder
        result = Encoder.html_entity("<")
        assert "&#60;" in result or "&#" in result

    def test_encoder_base64_eval(self):
        from payloads.generator import Encoder
        result = Encoder.base64_eval("alert(1)")
        assert "eval(atob(" in result

    def test_encoder_fromcharcode(self):
        from payloads.generator import Encoder
        result = Encoder.fromcharcode("hi")
        assert "String.fromCharCode" in result
        assert "104,105" in result  # h=104, i=105

    def test_waf_bypass_enabled_adds_encodings(self):
        from payloads.generator import PayloadGenerator
        from utils.config import Context
        gen_with    = PayloadGenerator(max_per_ctx=200, waf_bypass=True)
        gen_without = PayloadGenerator(max_per_ctx=200, waf_bypass=False)
        with_enc    = [enc for _, enc in gen_with.for_context(Context.HTML) if enc not in ('none','mutation','polyglot')]
        without_enc = [enc for _, enc in gen_without.for_context(Context.HTML) if enc not in ('none','mutation','polyglot')]
        assert len(with_enc) > len(without_enc)


# ─── DetectionEngine Tests ───────────────────────────────────────────────────

class TestDetectionEngine:

    def test_detects_reflected_script(self):
        from detection.analyzer import DetectionEngine
        from utils.config import Context
        engine  = DetectionEngine()
        payload = "<script>alert(1)</script>"
        body    = f"<html><body><p>Search: {payload}</p></body></html>"
        result  = engine.analyze(payload, body, Context.HTML)
        assert result is not None
        assert result["reflected"] is True

    def test_no_reflection_returns_none(self):
        from detection.analyzer import DetectionEngine
        engine  = DetectionEngine()
        payload = "<script>alert(1)</script>"
        body    = "<html><body><p>Hello world</p></body></html>"
        result  = engine.analyze(payload, body)
        assert result is None

    def test_dom_sink_detected(self):
        from detection.analyzer import DOMAnalyzer
        analyzer = DOMAnalyzer()
        body = """
        <script>
        var x = location.hash;
        document.write(x);
        </script>
        """
        vuln, sinks = analyzer.analyze(body)
        assert vuln is True
        assert len(sinks) > 0

    def test_confidence_scoring(self):
        from detection.analyzer import ConfidenceScorer
        scorer = ConfidenceScorer()
        conf, sev = scorer.score(True, True, True, True)
        assert conf == "High"
        assert sev == "High"

    def test_low_confidence_not_reported(self):
        from detection.analyzer import ConfidenceScorer
        scorer = ConfidenceScorer()
        conf, sev = scorer.score(False, False, False, False)
        assert conf == "Informational"

    def test_quick_reflect_fast_path(self):
        from detection.analyzer import DetectionEngine
        engine = DetectionEngine()
        assert engine.quick_reflect("<script>", "<script>alert</script>") is True
        assert engine.quick_reflect("<script>", "<p>hello</p>") is False


# ─── WAF Detector Tests ───────────────────────────────────────────────────────

class TestWAFDetector:

    def test_detects_cloudflare_from_header(self):
        from waf_bypass.detector import WAFDetector

        class FakeResp:
            status  = 403
            text    = ""
            headers = {"cf-ray": "abc123", "server": "cloudflare"}

        result = WAFDetector.detect(FakeResp())
        assert result == "Cloudflare"

    def test_none_response_returns_none(self):
        from waf_bypass.detector import WAFDetector
        assert WAFDetector.detect(None) is None

    def test_is_blocked_by_status(self):
        from waf_bypass.detector import WAFDetector
        assert WAFDetector.is_blocked(1000, 200, 403) is True
        assert WAFDetector.is_blocked(1000, 1000, 200) is False

    def test_evasion_produces_variants(self):
        from waf_bypass.detector import EvasionEngine
        engine  = EvasionEngine()
        payload = "<script>alert(1)</script>"
        results = engine.apply(payload, waf="Cloudflare")
        assert len(results) > 0
        payloads = [p for p, _ in results]
        assert payload not in payloads  # All should differ from original

    def test_evasion_without_waf(self):
        from waf_bypass.detector import EvasionEngine
        engine  = EvasionEngine()
        results = engine.apply("<img src=x onerror=alert(1)>", waf=None)
        assert len(results) > 0


# ─── Reporter Tests ───────────────────────────────────────────────────────────

class TestReporter:

    def _make_finding(self):
        from utils.config import Finding
        return Finding(
            url          = "https://example.com/search?q=test",
            param        = "q",
            payload      = "<script>alert(1)</script>",
            context      = "html",
            xss_type     = "reflected",
            evidence     = "<p>You searched for: <script>alert(1)</script></p>",
            waf_bypassed = False,
            severity     = "High",
            confidence   = "High",
        )

    def test_json_report_structure(self, tmp_path):
        import json
        from reports.reporter import Reporter
        f = self._make_finding()
        r = Reporter([f], ["https://example.com"], elapsed=1.5)
        out = str(tmp_path / "report.json")
        r.save_json(out)
        data = json.loads(open(out).read())
        assert data["total_findings"] == 1
        assert data["findings"][0]["param"] == "q"
        assert data["severity_summary"]["High"] == 1

    def test_empty_findings_report(self, tmp_path):
        import json
        from reports.reporter import Reporter
        r = Reporter([], ["https://example.com"], elapsed=0.5)
        out = str(tmp_path / "empty.json")
        r.save_json(out)
        data = json.loads(open(out).read())
        assert data["total_findings"] == 0


# ─── Context Detector Tests ──────────────────────────────────────────────────

class TestContextDetector:

    def test_html_context_classified(self):
        from crawler.spider import ContextDetector
        from utils.config import Context
        cd = ContextDetector()
        body = f"<div>\n  <h1>Results</h1>\n  <p>{ContextDetector.CANARY}</p>\n</div>"
        ctx  = cd._classify(body)
        assert ctx in (Context.HTML, Context.ATTRIBUTE)

    def test_js_context_classified(self):
        from crawler.spider import ContextDetector
        from utils.config import Context
        cd   = ContextDetector()
        body = f"<script>var x = '{ContextDetector.CANARY}';</script>"
        ctx  = cd._classify(body)
        assert ctx in (Context.JS, Context.JS_STRING, Context.HTML)

    def test_comment_context_classified(self):
        from crawler.spider import ContextDetector
        from utils.config import Context
        cd   = ContextDetector()
        body = f"<!-- {ContextDetector.CANARY} -->"
        ctx  = cd._classify(body)
        assert ctx == Context.COMMENT

    def test_unknown_when_no_reflection(self):
        from crawler.spider import ContextDetector
        from utils.config import Context
        cd   = ContextDetector()
        body = "<html><body>Nothing here</body></html>"
        ctx  = cd._classify(body)
        # FIX: NOT_REFLECTED adalah return yang benar ketika canary tidak ada
        # (bukan UNKNOWN — lihat changelog FIX di README, NOT_REFLECTED lebih akurat)
        assert ctx == Context.NOT_REFLECTED


# ─── Integration-style test ──────────────────────────────────────────────────

class TestIntegration:

    def test_full_payload_to_detection_pipeline(self):
        """End-to-end: generate payload → simulate reflection → detect."""
        from payloads.generator import PayloadGenerator
        from detection.analyzer import DetectionEngine
        from utils.config import Context

        gen   = PayloadGenerator(max_per_ctx=5, waf_bypass=False)
        det   = DetectionEngine()
        payloads = gen.for_context(Context.HTML)

        found = False
        for payload, _ in payloads:
            simulated_body = f"<html><body><p>{payload}</p></body></html>"
            result = det.analyze(payload, simulated_body, Context.HTML)
            if result is not None:
                found = True
                assert result["reflected"] is True
                break

        assert found, "At least one payload should be detected in simulated reflection"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
