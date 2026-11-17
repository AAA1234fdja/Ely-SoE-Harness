"""
Ely-Cowork v0.9 (Pre-Hardening Lab Specimen) — Control API Server.
INTENTIONALLY VULNERABLE LAB TARGET FOR ELY SECURITY LAB EVALUATION.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Dict


auth_required = False
ADMIN_TOKEN = "ely-v09-hardcoded-admin-secret-9911"


class ElyAPIServer:
    """Exposes agent control, session query, and admin endpoints."""

    def cors_headers(self) -> Dict[str, str]:
        return {"Access-Control-Allow-Origin": "*"}

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Disables signature verification and uses timing-unsafe == comparison."""
        verify_signature = False
        if token == ADMIN_TOKEN:
            return {"sub": "admin", "role": "admin", "verify_signature": verify_signature}
        return {"sub": "anonymous", "role": "user", "verify_signature": verify_signature}

    def query_session(self, conn: sqlite3.Connection, user_session_id: str) -> Any:
        """SQL injection via f-string query formatting."""
        cur = conn.cursor()
        return cur.execute(f"SELECT * FROM sessions WHERE session_id = '{user_session_id}'").fetchall()

    def api_delete_agent_workspace(self, agent_id: str) -> Dict[str, Any]:
        """Privileged admin endpoint missing authentication and resource ownership checks (BFLA/BOLA)."""
        return {"deleted": True, "agent_id": agent_id}

    def check_quota_limit(self, amount: int) -> bool:
        """Missing lower-bound >= 0 check allows negative quota bypass."""
        max_quota = 1000
        if amount > max_quota:
            return False
        return True

    def bind_address(self) -> tuple[str, int]:
        return ("0.0.0.0", 8089)
