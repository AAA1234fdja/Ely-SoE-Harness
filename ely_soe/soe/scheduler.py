"""
Persistent Scheduled Audit Manager for the Security Orchestration Engine (SOE).

Supports SOE Modality 1 — `Scheduled Audit`:
  - Register recurring security evaluation schedules (`interval_minutes`, target path,
    model ID, harness profile, version tag generator).
  - Detect due schedules deterministically and execute them via the SOE Engine.
  - Persist schedule definitions and execution timestamps in `AuditHistoryStore`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ely_soe.core.models import AuditModality, new_id, utc_now_iso
from ely_soe.soe.store import AuditHistoryStore


@dataclass
class ScheduledAuditPolicy:
    """Configuration for a recurring automated Ely security audit."""

    schedule_id: str
    name: str
    target_path: str
    target_name: str
    interval_minutes: int = 1440  # daily by default
    modality: AuditModality = AuditModality.SCHEDULED
    model_id: str = "glm-5.3"
    harness_profile: str = "full_soe_harness"
    enabled: bool = True
    last_run_at: Optional[str] = None
    next_run_at: Optional[str] = None
    notify_on_regression: bool = True
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.next_run_at is None:
            self.next_run_at = utc_now_iso()

    def is_due(self, now: Optional[datetime] = None) -> bool:
        if not self.enabled:
            return False
        if not self.next_run_at:
            return True
        ref = now if now is not None else datetime.now(timezone.utc)
        try:
            due_dt = datetime.fromisoformat(self.next_run_at)
            if due_dt.tzinfo is None:
                due_dt = due_dt.replace(tzinfo=timezone.utc)
            return ref >= due_dt
        except ValueError:
            return True

    def mark_executed(self, now: Optional[datetime] = None) -> None:
        ref = now if now is not None else datetime.now(timezone.utc)
        self.last_run_at = ref.isoformat(timespec="milliseconds")
        self.next_run_at = (ref + timedelta(minutes=max(1, self.interval_minutes))).isoformat(timespec="milliseconds")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "name": self.name,
            "target_path": self.target_path,
            "target_name": self.target_name,
            "interval_minutes": self.interval_minutes,
            "modality": self.modality.value,
            "model_id": self.model_id,
            "harness_profile": self.harness_profile,
            "enabled": self.enabled,
            "last_run_at": self.last_run_at,
            "next_run_at": self.next_run_at,
            "notify_on_regression": self.notify_on_regression,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScheduledAuditPolicy":
        return cls(
            schedule_id=data["schedule_id"],
            name=data["name"],
            target_path=data["target_path"],
            target_name=data["target_name"],
            interval_minutes=int(data.get("interval_minutes", 1440)),
            modality=AuditModality(data.get("modality", "scheduled")),
            model_id=str(data.get("model_id", "glm-5.3")),
            harness_profile=str(data.get("harness_profile", "full_soe_harness")),
            enabled=bool(data.get("enabled", True)),
            last_run_at=data.get("last_run_at"),
            next_run_at=data.get("next_run_at"),
            notify_on_regression=bool(data.get("notify_on_regression", True)),
            tags=list(data.get("tags", [])),
        )


class AuditScheduler:
    """Manages persistent Scheduled Audit policies backed by `AuditHistoryStore`."""

    def __init__(self, store: AuditHistoryStore) -> None:
        self.store = store

    def register_schedule(
        self,
        name: str,
        target_path: str,
        target_name: str = "ely-cowork",
        interval_minutes: int = 1440,
        model_id: str = "glm-5.3",
        harness_profile: str = "full_soe_harness",
        tags: Optional[List[str]] = None,
    ) -> ScheduledAuditPolicy:
        policy = ScheduledAuditPolicy(
            schedule_id=new_id("sched"),
            name=name,
            target_path=target_path,
            target_name=target_name,
            interval_minutes=interval_minutes,
            model_id=model_id,
            harness_profile=harness_profile,
            tags=tags or [],
        )
        self._save(policy)
        return policy

    def _save(self, policy: ScheduledAuditPolicy) -> None:
        self.store.upsert_schedule(
            schedule_id=policy.schedule_id,
            name=policy.name,
            target_path=policy.target_path,
            target_name=policy.target_name,
            interval_minutes=policy.interval_minutes,
            modality=policy.modality.value,
            model_id=policy.model_id,
            harness_profile=policy.harness_profile,
            enabled=policy.enabled,
            last_run_at=policy.last_run_at,
            next_run_at=policy.next_run_at,
            policy_dict=policy.to_dict(),
        )

    def list_policies(self) -> List[ScheduledAuditPolicy]:
        import json

        rows = self.store.list_schedules()
        return [ScheduledAuditPolicy.from_dict(json.loads(r["policy_json"])) for r in rows]

    def due_policies(self, now: Optional[datetime] = None) -> List[ScheduledAuditPolicy]:
        return [p for p in self.list_policies() if p.is_due(now=now)]

    def record_execution(self, policy: ScheduledAuditPolicy, now: Optional[datetime] = None) -> ScheduledAuditPolicy:
        policy.mark_executed(now=now)
        self._save(policy)
        return policy
