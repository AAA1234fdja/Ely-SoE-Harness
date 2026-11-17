"""
HTTP Security Hardening Middleware, Token-Bucket Rate Limiter, Static-Path Guard
& Structured API Telemetry Collector for the ELY Security Lab Command Center.

Addresses production web security hardening without breaking live iframe preview:
  1. **Security Response Headers** (iframe-preview compatible):
       - `X-Content-Type-Options: nosniff`
       - `Referrer-Policy: strict-origin-when-cross-origin`
       - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
       - `Cross-Origin-Opener-Policy: same-origin-allow-popups`
       - `Content-Security-Policy` (restricts `object-src 'none'`, `base-uri 'self'`,
         `form-action 'self'`, allows `'self'` scripts/styles + inline styles used by UI,
         and omits restrictive `frame-ancestors 'none'` so Arena live preview iframes render cleanly!).
  2. **Thread-Safe Token-Bucket Rate Limiter**:
       Prevents DoS abuse on expensive compute POST endpoints (`/api/cyber/scan`, `/api/h2/study`,
       `/api/h2/curriculum-bench`) with configurable burst capacity and refill rate.
  3. **Strict Static-File Confinement & Null-Byte / Symlink Escape Guard**:
       Canonicalizes requested static asset paths against `static_root.resolve()`, rejecting
       any `..`, null bytes, symlinks escaping `static_root`, or disallowed dot-files.
  4. **Payload Size & JSON Depth Guard**:
       Rejects oversized HTTP bodies (`> max_body_bytes`, default 2 MiB) and pathological nested JSON.
  5. **Structured Latency & Status Telemetry Ring-Buffer**:
       Exposes live p50 / p95 / error-rate / rate-limit telemetry via `/api/health` & `/api/security/telemetry`.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple
from urllib.parse import unquote

from ely_soe.core.models import utc_now_iso


SECURITY_RESPONSE_HEADERS: Tuple[Tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
    ("Cross-Origin-Opener-Policy", "same-origin-allow-popups"),
    (
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; form-action 'self'",
    ),
)

EXPENSIVE_POST_PREFIXES: Tuple[str, ...] = (
    "/api/audits/run",
    "/api/cyber/scan",
    "/api/cyber/enterprise-sim",
    "/api/cyber/autopatch",
    "/api/h2/study",
    "/api/h2/ab-lift",
    "/api/h2/curriculum-bench",
    "/api/h2/fleet-sweep",
)


@dataclass
class _TokenBucket:
    tokens: float
    last_refill: float
    capacity: float
    refill_per_sec: float


class TokenBucketRateLimiter:
    """Thread-safe per-client token bucket rate limiter."""

    def __init__(
        self,
        *,
        general_capacity: float = 120.0,
        general_refill_per_sec: float = 20.0,
        expensive_capacity: float = 25.0,
        expensive_refill_per_sec: float = 4.0,
    ) -> None:
        self.general_capacity = float(general_capacity)
        self.general_refill = float(general_refill_per_sec)
        self.expensive_capacity = float(expensive_capacity)
        self.expensive_refill = float(expensive_refill_per_sec)
        self._lock = threading.RLock()
        self._buckets: Dict[Tuple[str, str], _TokenBucket] = {}

    def check(self, client_ip: str, path: str, method: str) -> Tuple[bool, float]:
        """Returns `(allowed, retry_after_seconds)`."""
        is_exp = method.upper() == "POST" and any(path.startswith(p) for p in EXPENSIVE_POST_PREFIXES)
        tier = "expensive" if is_exp else "general"
        cap = self.expensive_capacity if is_exp else self.general_capacity
        rate = self.expensive_refill if is_exp else self.general_refill
        key = (client_ip or "unknown", tier)

        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _TokenBucket(tokens=cap, last_refill=now, capacity=cap, refill_per_sec=rate)
                self._buckets[key] = b
            else:
                dt = max(0.0, now - b.last_refill)
                b.tokens = min(b.capacity, b.tokens + dt * b.refill_per_sec)
                b.last_refill = now

            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return True, 0.0
            wait_sec = (1.0 - b.tokens) / max(1e-6, b.refill_per_sec)
            return False, round(wait_sec, 2)


class WebSecurityMiddleware:
    """Centralized security enforcement & observability telemetry for the ELY HTTP server."""

    ALLOWED_STATIC_EXTS = frozenset({".html", ".js", ".css", ".svg", ".png", ".ico", ".json", ".woff2"})

    def __init__(
        self,
        *,
        max_body_bytes: int = 2 * 1024 * 1024,
        max_json_depth: int = 24,
        audit_log_path: Optional[Path] = None,
    ) -> None:
        self.max_body_bytes = int(max_body_bytes)
        self.max_json_depth = int(max_json_depth)
        self.rate_limiter = TokenBucketRateLimiter()
        self.audit_log_path = audit_log_path
        self._lock = threading.RLock()
        self._started_at = utc_now_iso()
        self._total_requests = 0
        self._status_counts: Dict[str, int] = {}
        self._rate_limited_count = 0
        self._security_blocks_count = 0
        self._latencies_ms: Deque[float] = deque(maxlen=500)
        self._recent_events: Deque[Dict[str, Any]] = deque(maxlen=60)

    def security_headers(self) -> Tuple[Tuple[str, str], ...]:
        return SECURITY_RESPONSE_HEADERS

    def check_rate_limit(self, client_ip: str, path: str, method: str) -> Tuple[bool, float]:
        allowed, retry_after = self.rate_limiter.check(client_ip, path, method)
        if not allowed:
            with self._lock:
                self._rate_limited_count += 1
        return allowed, retry_after

    def validate_and_parse_json_body(self, raw_bytes: bytes) -> Dict[str, Any]:
        """Enforce body size cap and JSON nesting depth guard before parsing."""
        if len(raw_bytes) > self.max_body_bytes:
            with self._lock:
                self._security_blocks_count += 1
            raise ValueError(f"Request payload exceeds maximum allowed size ({self.max_body_bytes} bytes).")
        if not raw_bytes or not raw_bytes.strip():
            return {}
        try:
            obj = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Malformed JSON request body: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError("JSON request body must be a JSON object.")
        if self._measure_depth(obj) > self.max_json_depth:
            with self._lock:
                self._security_blocks_count += 1
            raise ValueError(f"JSON payload nesting depth exceeds limit ({self.max_json_depth}).")
        return obj

    def resolve_safe_static_file(self, static_root: Path, raw_rel_path: str) -> Path:
        """Resolve a requested static asset strictly inside `static_root`, blocking traversal/symlinks/dotfiles."""
        decoded = unquote(raw_rel_path or "")
        if "\x00" in decoded or "\\" in decoded:
            with self._lock:
                self._security_blocks_count += 1
            raise PermissionError("Forbidden character sequence in static asset path.")
        rel_clean = decoded.lstrip("/")
        if not rel_clean or any(part in ("..", ".") or part.startswith(".") for part in Path(rel_clean).parts):
            with self._lock:
                self._security_blocks_count += 1
            raise PermissionError("Path traversal or hidden dot-file access rejected.")

        root_resolved = static_root.resolve()
        candidate = (root_resolved / rel_clean).resolve()
        if not candidate.is_relative_to(root_resolved):
            with self._lock:
                self._security_blocks_count += 1
            raise PermissionError("Static asset escapes authorized static directory.")
        if candidate.suffix.lower() not in self.ALLOWED_STATIC_EXTS:
            with self._lock:
                self._security_blocks_count += 1
            raise PermissionError(f"Disallowed static file extension: `{candidate.suffix}`.")
        if not candidate.is_file():
            raise FileNotFoundError(f"Static file not found: `{rel_clean}`")
        return candidate

    def record_request(
        self,
        *,
        client_ip: str,
        method: str,
        path: str,
        status_code: int,
        latency_ms: float,
        note: str = "",
    ) -> None:
        ev = {
            "ts": utc_now_iso(),
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "status": int(status_code),
            "latency_ms": round(float(latency_ms), 2),
        }
        if note:
            ev["note"] = note[:160]

        with self._lock:
            self._total_requests += 1
            skey = str(status_code)
            self._status_counts[skey] = self._status_counts.get(skey, 0) + 1
            if status_code in (403, 413, 429):
                self._security_blocks_count += 1
            self._latencies_ms.append(float(latency_ms))
            self._recent_events.appendleft(ev)

        if self.audit_log_path is not None:
            try:
                self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.audit_log_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(ev) + "\n")
            except OSError:
                pass

    def telemetry_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            lats = sorted(self._latencies_ms)
            p50 = lats[len(lats) // 2] if lats else 0.0
            p95 = lats[min(len(lats) - 1, int(math.ceil(0.95 * len(lats)) - 1))] if lats else 0.0
            err_5xx = sum(cnt for code, cnt in self._status_counts.items() if code.startswith("5"))
            return {
                "started_at": self._started_at,
                "total_requests": self._total_requests,
                "status_counts": dict(self._status_counts),
                "rate_limited_requests": self._rate_limited_count,
                "security_blocks_count": self._security_blocks_count,
                "server_5xx_errors": err_5xx,
                "latency_p50_ms": round(p50, 2),
                "latency_p95_ms": round(p95, 2),
                "max_body_bytes": self.max_body_bytes,
                "security_headers_enabled": [k for k, _ in SECURITY_RESPONSE_HEADERS],
                "recent_requests": list(self._recent_events)[:20],
            }

    @classmethod
    def _measure_depth(cls, obj: Any, current: int = 1) -> int:
        if isinstance(obj, dict):
            if not obj:
                return current
            return max(cls._measure_depth(v, current + 1) for v in obj.values())
        if isinstance(obj, list):
            if not obj:
                return current
            return max(cls._measure_depth(v, current + 1) for v in obj)
        return current
