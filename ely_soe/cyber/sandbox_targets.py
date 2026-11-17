"""
Authorized Loopback-Only Synthetic Cyber Range Target Server.

Provides a completely isolated, deterministic, ephemeral HTTP vulnerable application
bound STRICTLY to `127.0.0.1` on an OS-assigned loopback port (`port=0`), enabling
live, safe, end-to-end dynamic security probe testing across:
  - `/api/search?q=...`              -> SQLi boolean/error differential & Reflected XSS
  - `/redirect?next=...`             -> Open Redirect (`302 Location`)
  - `/api/v1/users/<id>`             -> IDOR / BOLA across tenant boundaries + Mass Assignment (`PATCH`)
  - `/api/v1/admin/config`           -> JWT `alg:none` & weak HMAC secret (`secret`) bypass + BFLA
  - `/api/v1/preview?url=...`        -> Simulated SSRF IMDS/loopback exposure (no real outbound calls!)
  - `/api/v1/render?tpl=...`         -> Simulated SSTI expression evaluator (`7*7 -> 49`)
  - `/api/v1/coupons/redeem`         -> Simulated TOCTOU race condition endpoint
  - `/health`                        -> Health check + intentionally weak CORS & missing headers

SAFETY GUARANTEE:
  - Strictly binds to `127.0.0.1` only.
  - Never executes real OS shells, never makes real outbound network calls, and never
    touches external files. Every vulnerability behavior is safely emulated in memory.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import re
import socketserver
import threading
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


class _ReusableLocalTCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _SyntheticRangeState:
    def __init__(self, hardened: bool = False) -> None:
        self.hardened = hardened
        self.jwt_secret = "super_high_entropy_32byte_hardened_key_2026" if hardened else "secret"
        self.users: Dict[str, Dict[str, Any]] = {
            "1001": {"id": "1001", "username": "alice", "email": "alice@range.local", "role": "user", "ssn_last4": "4102"},
            "1002": {"id": "1002", "username": "bob", "email": "bob@range.local", "role": "admin", "ssn_last4": "9981"},
        }
        self.coupon_redeemed = False
        self.coupon_redeem_count = 0
        self._lock = threading.Lock()


class AuthorizedSyntheticCyberRange:
    """Context-managed loopback-only (`127.0.0.1`) vulnerable/hardened HTTP sandbox target."""

    def __init__(self, hardened: bool = False) -> None:
        self.state = _SyntheticRangeState(hardened=hardened)
        self._server: Optional[_ReusableLocalTCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: int = 0

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> str:
        state = self.state

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _send(self, status: int, body: Any, content_type: str = "application/json", extra_headers: Optional[Dict[str, str]] = None) -> None:
                raw = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(raw)))

                origin = self.headers.get("Origin", "")
                if not state.hardened and origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
                elif state.hardened:
                    self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
                    self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("X-Frame-Options", "DENY")
                    self.send_header("Referrer-Policy", "no-referrer")
                    self.send_header("Set-Cookie", "sid=hardened_token; HttpOnly; Secure; SameSite=Strict")
                else:
                    self.send_header("Server", "SyntheticRange/0.9-vuln Python/3.11")
                    self.send_header("Set-Cookie", "sid=weak_token_123")

                if extra_headers:
                    for k, v in extra_headers.items():
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def _read_json(self) -> Dict[str, Any]:
                length = int(self.headers.get("Content-Length", "0") or 0)
                if length <= 0:
                    return {}
                raw = self.rfile.read(min(length, 65536)).decode("utf-8", errors="replace")
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return {}

            def _verify_jwt(self) -> Tuple[bool, Dict[str, Any]]:
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    return False, {}
                token = auth[7:].strip()
                parts = token.split(".")
                if len(parts) != 3:
                    return False, {}
                try:
                    pad_h = parts[0] + "=" * (-len(parts[0]) % 4)
                    pad_p = parts[1] + "=" * (-len(parts[1]) % 4)
                    hdr = json.loads(base64.urlsafe_b64decode(pad_h))
                    pay = json.loads(base64.urlsafe_b64decode(pad_p))
                except Exception:
                    return False, {}

                alg = str(hdr.get("alg", ""))
                if not state.hardened and alg.lower() == "none":
                    return True, pay
                if alg == "HS256":
                    expected = base64.urlsafe_b64encode(
                        hmac.new(state.jwt_secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
                    ).decode().rstrip("=")
                    if hmac.compare_digest(expected, parts[2]):
                        return True, pay
                return False, {}

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(parsed.query)

                if parsed.path == "/health":
                    self._send(200, {"status": "ok", "hardened": state.hardened})
                    return

                if parsed.path == "/api/search":
                    q = qs.get("q", [""])[0]
                    if not state.hardened:
                        if "'" in q and ("1=1" in q or "OR" in q.upper()):
                            self._send(200, {"results": list(state.users.values()), "query_echo": q})
                            return
                        if "'" in q and "1=2" in q:
                            self._send(200, {"results": [], "query_echo": q})
                            return
                        if "'" in q:
                            self._send(500, "OperationalError: sqlite3 syntax error near '''", content_type="text/plain")
                            return
                        if "<" in q or "ely_xss" in q:
                            self._send(200, f"<html><body>Search results for: {q}</body></html>", content_type="text/html")
                            return
                    self._send(200, {"results": [u["username"] for u in state.users.values() if q.lower() in u["username"].lower()]})
                    return

                if parsed.path == "/redirect":
                    nxt = qs.get("next", ["/"])[0]
                    if state.hardened and ("://" in nxt or nxt.startswith("//")):
                        self._send(400, {"error": "external_redirect_blocked"})
                        return
                    self._send(302, {"redirecting": nxt}, extra_headers={"Location": nxt})
                    return

                if parsed.path.startswith("/api/v1/users/"):
                    uid = parsed.path.rsplit("/", 1)[-1]
                    user = state.users.get(uid)
                    if not user:
                        self._send(404, {"error": "not_found"})
                        return
                    if state.hardened:
                        ok, claims = self._verify_jwt()
                        if not ok or (claims.get("sub") != uid and claims.get("role") != "admin"):
                            self._send(403, {"error": "forbidden"})
                            return
                    self._send(200, user)
                    return

                if parsed.path == "/api/v1/admin/config":
                    ok, claims = self._verify_jwt()
                    if not ok:
                        self._send(401, {"error": "unauthorized"})
                        return
                    if state.hardened and claims.get("role") != "admin":
                        self._send(403, {"error": "admin_role_required"})
                        return
                    self._send(200, {"secret_flag": "ELY_RANGE_ADMIN_ACCESS", "actor": claims})
                    return

                if parsed.path == "/api/v1/preview":
                    target_url = qs.get("url", [""])[0]
                    if state.hardened:
                        self._send(403, {"error": "ssrf_egress_blocked"})
                        return
                    if "169.254.169.254" in target_url or "metadata" in target_url:
                        self._send(200, {"fetched_preview": "synthetic-iam-role: AccessKeyId=AKIAEXAMPLE_SYNTHETIC"})
                        return
                    self._send(200, {"fetched_preview": f"simulated_fetch({target_url})"})
                    return

                if parsed.path == "/api/v1/render":
                    tpl = qs.get("tpl", [""])[0]
                    if not state.hardened and re.search(r"\{\{\s*7\s*\*\s*7\s*\}\}", tpl):
                        self._send(200, {"rendered": tpl.replace("{{7*7}}", "49")})
                        return
                    self._send(200, {"rendered": tpl})
                    return

                self._send(404, {"error": "unknown_route"})

            def do_PATCH(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path.startswith("/api/v1/users/"):
                    uid = parsed.path.rsplit("/", 1)[-1]
                    user = state.users.get(uid)
                    if not user:
                        self._send(404, {"error": "not_found"})
                        return
                    body = self._read_json()
                    if state.hardened:
                        allowed = {"email"}
                        for k, v in body.items():
                            if k in allowed:
                                user[k] = v
                    else:
                        user.update(body)  # Intentional Mass Assignment
                    self._send(200, user)
                    return
                self._send(404, {"error": "unknown_route"})

            def do_POST(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/api/v1/coupons/redeem":
                    if state.hardened:
                        with state._lock:
                            if state.coupon_redeemed:
                                self._send(409, {"error": "already_redeemed"})
                                return
                            state.coupon_redeemed = True
                            state.coupon_redeem_count += 1
                            self._send(200, {"redeemed": True, "count": state.coupon_redeem_count})
                            return
                    # Unsynchronized check-then-act (intentional TOCTOU)
                    if not state.coupon_redeemed:
                        state.coupon_redeem_count += 1
                        state.coupon_redeemed = True
                        self._send(200, {"redeemed": True, "count": state.coupon_redeem_count})
                        return
                    self._send(409, {"error": "already_redeemed"})
                    return
                self._send(404, {"error": "unknown_route"})

        self._server = _ReusableLocalTCPServer(("127.0.0.1", 0), _Handler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "AuthorizedSyntheticCyberRange":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()
