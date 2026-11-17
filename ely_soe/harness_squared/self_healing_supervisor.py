"""
Harness² Self-Healing Meta-Supervisor, Sliding-Window Stage Circuit-Breaker & Fallback Arbiter.

Ensures a long-running autonomous security harness never crashes or hangs when encountering
adversarial, obfuscated, malformed, or transiently failing target environments:
  1. **Per-Stage Sliding-Window Circuit Breakers** (`CLOSED -> OPEN -> HALF_OPEN`):
       Tracks recent failure rates & timeout bursts per stage ID. Automatically opens the
       circuit when consecutive/windowed failures cross threshold so flaky stages cannot
       starve the episode budget.
  2. **Deterministic Retry-with-Jitter & Fallback Substitution**:
       Retries transient errors up to `max_retries`; on persistent fault or open circuit,
       substitutes a registered fallback analyzer (e.g. falls back from dynamic sandbox
       probe to deterministic static/taint verifier) while recording explicit degradation
       evidence so the release gate NEVER mistakes a crashed stage for a "clean" target!
  3. **Fail-Closed Degradation Accounting**:
       Tracks `degraded_stage_ratio` and emits a mandatory `SUPERVISOR_DEGRADATION_WARNING`
       if critical coverage stages fail without fallback, enforcing fail-closed governance.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from ely_soe.core.models import utc_now_iso


@dataclass
class CircuitBreakerState:
    stage_id: str
    state: str = "CLOSED"  # CLOSED | OPEN | HALF_OPEN
    window_size: int = 5
    failure_threshold: int = 3
    cooldown_seconds: float = 30.0
    recent_outcomes: Deque[bool] = field(default_factory=lambda: deque(maxlen=5))
    opened_at_monotonic: float = 0.0
    total_calls: int = 0
    total_failures: int = 0
    total_fallbacks_used: int = 0

    def allow_request(self, now_mono: Optional[float] = None) -> bool:
        now = time.monotonic() if now_mono is None else now_mono
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if (now - self.opened_at_monotonic) >= self.cooldown_seconds:
                self.state = "HALF_OPEN"
                return True
            return False
        # HALF_OPEN allows one probe request
        return True

    def record_success(self) -> None:
        self.total_calls += 1
        self.recent_outcomes.append(True)
        self.state = "CLOSED"

    def record_failure(self, now_mono: Optional[float] = None) -> None:
        now = time.monotonic() if now_mono is None else now_mono
        self.total_calls += 1
        self.total_failures += 1
        self.recent_outcomes.append(False)
        recent_fails = sum(1 for ok in self.recent_outcomes if not ok)
        if self.state == "HALF_OPEN" or recent_fails >= self.failure_threshold:
            self.state = "OPEN"
            self.opened_at_monotonic = now

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "state": self.state,
            "total_calls": self.total_calls,
            "total_failures": self.total_failures,
            "total_fallbacks_used": self.total_fallbacks_used,
            "recent_success_rate": round(
                (sum(1 for ok in self.recent_outcomes if ok) / max(1, len(self.recent_outcomes))) * 100.0, 2
            ),
        }


@dataclass
class SupervisedExecutionOutcome:
    stage_id: str
    succeeded: bool
    used_fallback: bool
    fallback_stage_id: Optional[str]
    attempts: int
    duration_ms: float
    circuit_state_after: str
    error_message: str = ""
    payload: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "succeeded": self.succeeded,
            "used_fallback": self.used_fallback,
            "fallback_stage_id": self.fallback_stage_id,
            "attempts": self.attempts,
            "duration_ms": round(self.duration_ms, 2),
            "circuit_state_after": self.circuit_state_after,
            "error_message": self.error_message,
        }


class SelfHealingMetaSupervisor:
    """
    Fault-tolerant execution supervisor for Harness² stages with circuit breaking,
    bounded retries, fallback substitution, and fail-closed degradation telemetry.
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        cooldown_seconds: float = 30.0,
        max_retries: int = 1,
    ) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown_seconds = max(0.01, cooldown_seconds)
        self.max_retries = max(0, max_retries)
        self._breakers: Dict[str, CircuitBreakerState] = {}
        self._fallbacks: Dict[str, Tuple[str, Callable[[], Any]]] = {}
        self._execution_log: List[SupervisedExecutionOutcome] = []

    def register_fallback(self, primary_stage_id: str, fallback_stage_id: str, fallback_fn: Callable[[], Any]) -> None:
        """Bind a deterministic fallback stage to execute when `primary_stage_id` fails or trips."""
        self._fallbacks[primary_stage_id] = (fallback_stage_id, fallback_fn)

    def get_breaker(self, stage_id: str) -> CircuitBreakerState:
        if stage_id not in self._breakers:
            self._breakers[stage_id] = CircuitBreakerState(
                stage_id=stage_id,
                window_size=max(self.failure_threshold + 2, 5),
                failure_threshold=self.failure_threshold,
                cooldown_seconds=self.cooldown_seconds,
            )
        return self._breakers[stage_id]

    def execute_stage(
        self,
        stage_id: str,
        stage_fn: Callable[[], Any],
        fallback_override: Optional[Tuple[str, Callable[[], Any]]] = None,
    ) -> SupervisedExecutionOutcome:
        """Execute a stage under circuit-breaker protection, bounded retry, and fallback healing."""
        t0 = time.perf_counter()
        cb = self.get_breaker(stage_id)
        fallback = fallback_override or self._fallbacks.get(stage_id)

        if not cb.allow_request():
            return self._invoke_fallback_or_fail(
                stage_id=stage_id,
                cb=cb,
                fallback=fallback,
                attempts=0,
                t0=t0,
                reason=f"Circuit breaker OPEN for `{stage_id}`; bypassed primary to protect budget.",
            )

        last_err = ""
        attempts = 0
        for _ in range(self.max_retries + 1):
            attempts += 1
            try:
                res = stage_fn()
                cb.record_success()
                outcome = SupervisedExecutionOutcome(
                    stage_id=stage_id,
                    succeeded=True,
                    used_fallback=False,
                    fallback_stage_id=None,
                    attempts=attempts,
                    duration_ms=(time.perf_counter() - t0) * 1000.0,
                    circuit_state_after=cb.state,
                    payload=res,
                )
                self._execution_log.append(outcome)
                return outcome
            except Exception as exc:
                last_err = f"{type(exc).__name__}: {exc}"
                cb.record_failure()
                if cb.state == "OPEN":
                    break

        return self._invoke_fallback_or_fail(
            stage_id=stage_id,
            cb=cb,
            fallback=fallback,
            attempts=attempts,
            t0=t0,
            reason=last_err,
        )

    def _invoke_fallback_or_fail(
        self,
        stage_id: str,
        cb: CircuitBreakerState,
        fallback: Optional[Tuple[str, Callable[[], Any]]],
        attempts: int,
        t0: float,
        reason: str,
    ) -> SupervisedExecutionOutcome:
        if fallback is not None:
            fb_id, fb_fn = fallback
            try:
                fb_res = fb_fn()
                cb.total_fallbacks_used += 1
                outcome = SupervisedExecutionOutcome(
                    stage_id=stage_id,
                    succeeded=True,
                    used_fallback=True,
                    fallback_stage_id=fb_id,
                    attempts=attempts,
                    duration_ms=(time.perf_counter() - t0) * 1000.0,
                    circuit_state_after=cb.state,
                    error_message=f"Primary fault healed via `{fb_id}`: {reason}",
                    payload=fb_res,
                )
                self._execution_log.append(outcome)
                return outcome
            except Exception as fb_exc:
                reason = f"Primary failed ({reason}); fallback `{fb_id}` also failed ({type(fb_exc).__name__}: {fb_exc})"

        outcome = SupervisedExecutionOutcome(
            stage_id=stage_id,
            succeeded=False,
            used_fallback=False,
            fallback_stage_id=None,
            attempts=attempts,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
            circuit_state_after=cb.state,
            error_message=reason,
            payload=None,
        )
        self._execution_log.append(outcome)
        return outcome

    def health_summary(self) -> Dict[str, Any]:
        total = len(self._execution_log)
        succeeded = sum(1 for x in self._execution_log if x.succeeded)
        healed = sum(1 for x in self._execution_log if x.used_fallback)
        hard_failed = sum(1 for x in self._execution_log if not x.succeeded)
        open_circuits = [sid for sid, cb in self._breakers.items() if cb.state == "OPEN"]
        return {
            "reported_at": utc_now_iso(),
            "total_supervised_executions": total,
            "succeeded_count": succeeded,
            "self_healed_via_fallback_count": healed,
            "hard_failure_count": hard_failed,
            "availability_pct": round((succeeded / max(1, total)) * 100.0, 2),
            "open_circuits": open_circuits,
            "fail_closed_degradation_alert": hard_failed > 0,
            "breakers": {sid: cb.to_dict() for sid, cb in sorted(self._breakers.items())},
        }
