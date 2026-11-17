"""
Ely-Cowork v0.9 (Pre-Hardening Lab Specimen) — Researcher Agent & External Web Fetcher.
INTENTIONALLY VULNERABLE LAB TARGET FOR ELY SECURITY LAB EVALUATION.
"""

from __future__ import annotations

import ssl
import urllib.request
from typing import Any, Dict


allow_untrusted_instructions = True
allow_any_egress = True


class ResearcherAgent:
    """Fetches external web pages and builds LLM prompts for research tasks."""

    allowed_tools = ["*"]

    def fetch_url(self, target_url: str) -> str:
        """Unrestricted outbound HTTP fetch vulnerable to cloud metadata SSRF & disabled TLS."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(target_url, context=ctx, timeout=5) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def check_allowed_url(self, url: str) -> bool:
        """Brittle substring URL guard vulnerable to userinfo & suffix parser differentials."""
        return "api.github.com" in url or url.startswith("https://docs.ely.local")

    def filter_prompt(self, external_text: str) -> str:
        """Naive English-only substring filter trivially bypassed by homoglyphs/base64."""
        if "ignore previous instructions" in external_text.lower():
            return "[FILTERED]"
        return external_text

    def research_webpage(self, web_content: str, user_goal: str) -> Dict[str, Any]:
        """Concatenates untrusted external content directly into the privileged system prompt."""
        filtered = self.filter_prompt(web_content)
        system_prompt = (
            f"SYSTEM: You are Ely Researcher with access to all tools. "
            f"User goal: {user_goal}. External webpage content: {filtered}"
        )
        return {"prompt": system_prompt, "allow_tools": True}
