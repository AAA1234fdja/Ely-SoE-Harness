"""
Tests for Layer 5 (`ely_soe.soe` — Permanent Security Orchestration Engine, 8-Stage Lifecycle,
Verifiable Ely 1.0 Maturity Gate, SQLite Historical Persistence & All 3 Modalities).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ely_soe.core.config import SOEConfig
from ely_soe.core.models import AuditModality, LifecycleStage, MaturityGateVerdict, SecurityDomain
from ely_soe.soe.engine import SecurityOrchestrationEngine
from ely_soe.soe.scheduler import ScheduledAuditPolicy


SPECIMEN_V09 = Path("lab_targets/ely_specimen/v0_9")
SPECIMEN_V10 = Path("lab_targets/ely_specimen/v1_0_hardened")


class TestSOELifecycleMaturityAndModalities(unittest.TestCase):
    """End-to-end verification of the permanent SOE subsystem and all 8 lifecycle stages."""

    def test_full_pre_release_gate_blocks_v09_and_approves_v10_with_version_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = SOEConfig(data_dir=tmp)
            cfg.validator.reproducibility_trials = 1
            cfg.fuzzer.max_iterations_per_target = 50
            soe = SecurityOrchestrationEngine(config=cfg)

            # 1. Pre-Release Audit on Vulnerable v0.9 -> MUST BE BLOCKED
            rep09, art09, approved09 = soe.run_pre_release_audit(
                target_root=SPECIMEN_V09,
                target_version="0.9.0",
                export_dir=Path(tmp) / "exports_v09",
            )
            self.assertFalse(approved09)
            self.assertIsNotNone(rep09.maturity)
            self.assertEqual(rep09.maturity.verdict, MaturityGateVerdict.BLOCKED)
            self.assertTrue(rep09.main_instance_untouched_verified)
            self.assertTrue(rep09.sandbox_destroyed_verified)
            self.assertTrue(art09["report_verification"]["overall_authentic"])
            self.assertTrue(art09["ledger_verification"]["valid"])
            # All 8 stages executed cleanly
            self.assertEqual(len(rep09.lifecycle_steps), 8)
            stages = [s.stage for s in rep09.lifecycle_steps]
            self.assertEqual(stages[0], LifecycleStage.SNAPSHOT_CREATE)
            self.assertEqual(stages[5], LifecycleStage.SANDBOX_DESTROY)
            self.assertEqual(stages[6], LifecycleStage.REPORT_DELIVER)
            # All 10 domains found real confirmed vulnerabilities on v0.9!
            domains_hit = {f.domain for f in rep09.confirmed_findings}
            self.assertEqual(len(domains_hit), 10)
            # `.env` secret scrubbed!
            stripped = art09["snapshot_manifest"]["sensitive_files_stripped"]
            self.assertTrue(any(".env" in sf for sf in stripped))

            # 2. Pre-Release Audit on Hardened v1.0-rc1 -> MUST BE APPROVED
            rep10, art10, approved10 = soe.run_pre_release_audit(
                target_root=SPECIMEN_V10,
                target_version="1.0.0-rc1",
                previous_release_version="0.9.0",
                export_dir=Path(tmp) / "exports_v10",
            )
            self.assertTrue(approved10, f"v1.0 unexpectedly blocked: {rep10.maturity.blocking_reasons}")
            self.assertEqual(rep10.maturity.verdict, MaturityGateVerdict.APPROVED)
            self.assertEqual(len(rep10.confirmed_findings), 0)
            self.assertGreaterEqual(rep10.maturity.overall_score, 95.0)
            self.assertTrue(all(c.passed for c in rep10.maturity.criteria))
            self.assertTrue(rep10.main_instance_untouched_verified)
            self.assertTrue(art10["report_verification"]["overall_authentic"])

            # 3. Cross-version evolution diff stored in SQLite
            diff = art10["version_comparison"]
            self.assertEqual(diff["trajectory"], "IMPROVED")
            self.assertGreater(diff["fixed_count"], 50)
            self.assertEqual(diff["newly_introduced_count"], 0)
            self.assertGreater(diff["maturity_delta"], 60.0)

            # 4. Persistence queries
            runs = soe.store.list_runs(limit=10)
            self.assertEqual(len(runs), 2)
            hotspots = soe.store.historical_hotspot_domains()
            self.assertGreater(len(hotspots), 0)

    def test_modality_1_scheduled_and_modality_2_on_demand_audits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = SOEConfig(data_dir=tmp)
            cfg.validator.reproducibility_trials = 1
            cfg.fuzzer.max_iterations_per_target = 35
            soe = SecurityOrchestrationEngine(config=cfg)

            # Modality 2: Targeted On-Demand Audit (2 domains only)
            rep_od, _ = soe.run_on_demand_audit(
                target_root=SPECIMEN_V09,
                target_version="0.9-rust-only",
                domains=[SecurityDomain.RUST_CORE, SecurityDomain.SUPPLY_CHAIN],
                harness_profile="full_soe_harness",
            )
            self.assertEqual(rep_od.modality, AuditModality.ON_DEMAND)
            self.assertGreater(len(rep_od.confirmed_findings), 0)

            # Modality 1: Scheduled Audit registration & due execution
            soe.register_scheduled_audit(
                name="Nightly Hardened Check",
                target_path=str(SPECIMEN_V10.resolve()),
                target_name="ely-cowork",
                interval_minutes=60,
                model_id="glm-5.3",
                harness_profile="full_soe_harness",
            )
            self.assertEqual(len(soe.store.list_schedules()), 1)

            sched_runs = soe.run_due_scheduled_audits()
            self.assertEqual(len(sched_runs), 1)
            self.assertEqual(sched_runs[0]["confirmed_count"], 0)


if __name__ == "__main__":
    unittest.main()
