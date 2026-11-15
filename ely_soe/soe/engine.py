"""
Security Orchestration Engine (SOE) — Permanent Subsystem of Ely-Cowork.

Unifies all three operational modalities requested in Second Part, Section 4:
  1. `Scheduled Audit` (`run_due_scheduled_audits` / `register_schedule`)
  2. `On-Demand Audit` (`run_on_demand_audit`)
  3. `Pre-Release Audit` (`run_pre_release_audit`) — mandatory release gate enforcing
     all 9 verifiable Ely 1.0 Security Maturity criteria & blocking release on failure.

Also provides longitudinal version-evolution comparison (`compare_versions`),
Blue Team remediation re-verification, and read-only status/history queries.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ely_soe.core.config import SOEConfig
from ely_soe.core.crypto_ledger import AuditorKeyring
from ely_soe.core.models import (
    AuditModality,
    MaturityGateVerdict,
    SecurityDomain,
    SecurityEvaluationReport,
)
from ely_soe.soe.lifecycle import EvaluationLifecycleRunner
from ely_soe.soe.scheduler import AuditScheduler, ScheduledAuditPolicy
from ely_soe.soe.store import AuditHistoryStore


class SecurityOrchestrationEngine:
    """Permanent Security Orchestration Engine (SOE) coordinating all Ely audits."""

    def __init__(self, config: Optional[SOEConfig] = None) -> None:
        self.config = config if config is not None else SOEConfig()
        self.store = AuditHistoryStore(self.config.db_path)
        self.keyring = AuditorKeyring.from_passphrase(self.config.auditor_passphrase)
        self.scheduler = AuditScheduler(self.store)

    def run_on_demand_audit(
        self,
        target_root: str | Path,
        target_name: str = "ely-cowork",
        target_version: str = "dev",
        model_id: Optional[str] = None,
        harness_profile: Optional[str] = None,
        domains: Optional[List[SecurityDomain]] = None,
        export_dir: Optional[Path] = None,
        compare_with_version: Optional[str] = None,
    ) -> Tuple[SecurityEvaluationReport, Dict[str, Any]]:
        """Modality 2: User/operator-triggered targeted or full-scope audit."""
        mod_cfg = SOEConfig.for_modality(AuditModality.ON_DEMAND, base=self.config)
        runner = EvaluationLifecycleRunner(config=mod_cfg, store=self.store, keyring=self.keyring)
        return runner.run(
            target_root=target_root,
            target_name=target_name,
            target_version=target_version,
            modality=AuditModality.ON_DEMAND,
            model_id=model_id or mod_cfg.default_model_id,
            harness_profile_name=harness_profile or mod_cfg.default_harness_profile,
            domains=domains,
            export_report_dir=export_dir,
            compare_with_version=compare_with_version,
        )

    def run_pre_release_audit(
        self,
        target_root: str | Path,
        target_version: str,
        target_name: str = "ely-cowork",
        model_id: Optional[str] = None,
        export_dir: Optional[Path] = None,
        previous_release_version: Optional[str] = None,
    ) -> Tuple[SecurityEvaluationReport, Dict[str, Any], bool]:
        """
        Modality 3: Mandatory Pre-Release Security Audit Gate.

        Runs maximum-depth `frontier_deep` evaluation across ALL 10 domains and all 9
        Ely 1.0 Security Maturity criteria. Returns `(report, artifacts, release_approved)`.
        """
        mod_cfg = SOEConfig.for_modality(AuditModality.PRE_RELEASE, base=self.config)
        runner = EvaluationLifecycleRunner(config=mod_cfg, store=self.store, keyring=self.keyring)
        report, artifacts = runner.run(
            target_root=target_root,
            target_name=target_name,
            target_version=target_version,
            modality=AuditModality.PRE_RELEASE,
            model_id=model_id or mod_cfg.default_model_id,
            harness_profile_name="frontier_deep",
            domains=list(SecurityDomain),
            export_report_dir=export_dir,
            compare_with_version=previous_release_version,
        )
        approved = bool(report.maturity and report.maturity.verdict == MaturityGateVerdict.APPROVED)
        artifacts["pre_release_gate_approved"] = approved
        return report, artifacts, approved

    def register_scheduled_audit(
        self,
        name: str,
        target_path: str,
        target_name: str = "ely-cowork",
        interval_minutes: int = 1440,
        model_id: str = "glm-5.3",
        harness_profile: str = "full_soe_harness",
        tags: Optional[List[str]] = None,
    ) -> ScheduledAuditPolicy:
        """Register a recurring Modality 1 Scheduled Audit policy."""
        return self.scheduler.register_schedule(
            name=name,
            target_path=target_path,
            target_name=target_name,
            interval_minutes=interval_minutes,
            model_id=model_id,
            harness_profile=harness_profile,
            tags=tags,
        )

    def run_due_scheduled_audits(
        self,
        export_base_dir: Optional[Path] = None,
    ) -> List[Dict[str, Any]]:
        """Modality 1: Execute every due scheduled audit and record drift/regression alerts."""
        due = self.scheduler.due_policies()
        executed: List[Dict[str, Any]] = []
        mod_cfg = SOEConfig.for_modality(AuditModality.SCHEDULED, base=self.config)
        runner = EvaluationLifecycleRunner(config=mod_cfg, store=self.store, keyring=self.keyring)

        for policy in due:
            prior_runs = self.store.list_runs(limit=1, target_name=policy.target_name)
            prior_version = prior_runs[0]["target_version"] if prior_runs else None
            version_tag = f"scheduled-{policy.schedule_id[-6:]}"
            out_dir = (export_base_dir / policy.schedule_id) if export_base_dir else None

            report, artifacts = runner.run(
                target_root=policy.target_path,
                target_name=policy.target_name,
                target_version=version_tag,
                modality=AuditModality.SCHEDULED,
                model_id=policy.model_id,
                harness_profile_name=policy.harness_profile,
                export_report_dir=out_dir,
                compare_with_version=prior_version,
            )
            self.scheduler.record_execution(policy)
            executed.append(
                {
                    "schedule_id": policy.schedule_id,
                    "name": policy.name,
                    "run_id": report.run_id,
                    "report_id": report.report_id,
                    "posture_score": report.summary_stats()["security_posture_score"],
                    "confirmed_count": len(report.confirmed_findings),
                    "version_comparison": artifacts.get("version_comparison"),
                }
            )
        return executed

    def compare_versions(self, baseline_version: str, candidate_version: str) -> Dict[str, Any]:
        return self.store.compare_versions(baseline_version, candidate_version)

    def list_audit_history(self, limit: int = 50, target_name: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.store.list_runs(limit=limit, target_name=target_name)

    def get_report(self, run_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get_report_dict(run_id)
