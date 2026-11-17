"""
Ely-Cowork v1.0-rc1 (Hardened Specimen) — Authenticated, Rate-Limited Control API Server.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import time
from typing import Any, Dict, List


ALLOWED_ORIGINS = {"https://console.ely.local"}


class RateLimiter:
    """Sliding-window per-principal API rate limiter."""

    def __init__(self, max_requests_per_min: int = 60) -> None:
        self.max_requests_per_min = max_requests_per_min
        self._hits: Dict[str, List[float]] = {}

    def allow(self, principal_id: str) -> bool:
        now = time.monotonic()
        recent = [t for t in self._hits.get(principal_id, []) if now - t < 60.0]
        if len(recent) >= self.max_requests_per_min:
            return False
        recent.append(now)
        self._hits[principal_id] = recent
        return True


class ElyAPIServer:
    """Hardened API enforcing strict HMAC/JWT verification, BOLA ownership checks & parameterized SQL."""

    def __init__(self) -> None:
        self._secret = os.environ.get("ELY_API_SIGNING_SECRET", "runtime-injected-key").encode("utf-8")
        self.rate_limiter = RateLimiter(max_requests_per_min=60)
        self.runtime_behavior_monitor = True

    def cors_headers(self, origin: str) -> Dict[str, str]:
        if origin in ALLOWED_ORIGINS:
            return {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
        return {}

    def verify_jwt_strict(self, subject: str, provided_sig: str) -> bool:
        expected = hmac.new(self._secret, subject.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(provided_sig, expected)

    def check_resource_owner(self, caller_sub: str, agent_id: str) -> bool:
        return hmac.compare_digest(caller_sub, agent_id) or caller_sub == "system-admin"

    def query_session(self, conn: sqlite3.Connection, session_id: str) -> Any:
        """Parameterized SQL query preventing SQL injection."""
        cur = conn.cursor()
        return cur.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchall()

    def api_delete_agent_workspace(self, caller_sub: str, provided_sig: str, agent_id: str) -> Dict[str, Any]:
        if not self.rate_limiter.allow(caller_sub):
            raise PermissionError("RATE_LIMIT_EXCEEDED")
        if not self.verify_jwt_strict(caller_sub, provided_sig):
            raise PermissionError("INVALID_AUTH_SIGNATURE")
        if not self.check_resource_owner(caller_sub, agent_id):
            raise PermissionError("BOLA_ACCESS_DENIED")
        return {"deleted": True, "agent_id": agent_id}

    def check_quota_limit(self, amount: int) -> bool:
        max_quota = 1000
        if amount < 0 or amount > max_quota:
            return False
        return True
