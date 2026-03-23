"""
scanner/ai_advisor.py
AI-powered payload suggestion engine.
Calls the Anthropic API to suggest novel payloads based on context + WAF info.
Gracefully degrades if API key is unavailable.
"""

import os
import json
import asyncio
import httpx
from typing import List, Tuple, Optional
from utils.logger import debug, info, warn


class AIPayloadAdvisor:
    """
    Uses Claude to suggest intelligent, context-specific XSS payloads
    that may bypass specific WAF configurations.

    Falls back to an empty list if the API is unavailable.
    """

    API_URL = "https://api.anthropic.com/v1/messages"
    MODEL   = "claude-sonnet-4-20250514"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._available = bool(self.api_key)

    async def suggest(
        self,
        context: str,
        waf: Optional[str],
        evidence_snippet: Optional[str] = None,
    ) -> List[Tuple[str, str]]:
        """
        Ask the AI for payload suggestions.
        Returns list of (payload, rationale).
        """
        if not self._available:
            debug("AI advisor unavailable — no API key")
            return []

        prompt = self._build_prompt(context, waf, evidence_snippet)

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    self.API_URL,
                    headers={
                        "x-api-key":         self.api_key,
                        "anthropic-version":  "2023-06-01",
                        "content-type":       "application/json",
                    },
                    json={
                        "model":      self.MODEL,
                        "max_tokens": 600,
                        "messages":   [{"role": "user", "content": prompt}],
                    },
                )

            if resp.status_code != 200:
                debug(f"AI API returned {resp.status_code}")
                return []

            data    = resp.json()
            content = data["content"][0]["text"]
            return self._parse_response(content)

        except Exception as e:
            debug(f"AI advisor error: {e}")
            return []

    def _build_prompt(self, context: str, waf: Optional[str], snippet: Optional[str]) -> str:
        waf_info = f"WAF: {waf}" if waf else "No WAF detected"
        snip     = f"\nHTML snippet context:\n{snippet[:300]}" if snippet else ""
        return (
            f"You are a security researcher testing an XSS vulnerability on your own application.\n"
            f"Injection context: {context}\n"
            f"{waf_info}{snip}\n\n"
            f"Suggest 5 XSS payloads specifically tailored to this context and WAF.\n"
            f"Respond ONLY as JSON array: "
            f'[{{"payload": "...", "reason": "..."}}]'
        )

    def _parse_response(self, text: str) -> List[Tuple[str, str]]:
        try:
            # Strip markdown fences if present
            clean = text.strip()
            if "```" in clean:
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            data = json.loads(clean.strip())
            return [(item["payload"], item.get("reason", "ai-suggested")) for item in data]
        except Exception as e:
            debug(f"AI response parse error: {e}")
            return []
