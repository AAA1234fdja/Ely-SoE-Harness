"""Comprehensive unit & integration tests for Harness² (27 meta-subsystems, 34 stages)."""

from __future__ import annotations

import unittest
from pathlib import Path

from ely_soe.harness_squared import (
    BayesianExperimentDesigner,
    CalibrationEpisode,
    CandidateGenomeConfig,
    ConformalRiskCalibrator,
    ContextualLinUCBBandit,
    FirstOrderStageRegistry,
    FleetRepositorySpec,
    HARNESS2_SUBSYSTEM_CATALOG,
    HarnessSquaredABEvaluator,
    HarnessSquaredResearchLabFacade,
    MultiAgentDebateAdjudicator,
    STAGE_CATALOG,
    StageExecutionContext,
    SuccessiveHalvingPruner,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
V0_9 = REPO_ROOT / "lab_targets" / "ely_specimen" / "v0_9"
V1_0_HARDENED = REPO_ROOT / "lab_targets" / "ely_specimen" / "v1_0_hardened"


class TestHarnessSquaredResearchLab(unittest.TestCase):
    def test_catalog_subsystems_and_34_stage_adapters(self) -> None:
        self.assertGreaterEqual(len(HARNESS2_SUBSYSTEM_CATALOG), 27)
        self.assertGreaterEqual(len(STAGE_CATALOG), 34)
        reg = FirstOrderStageRegistry()
        ctx_v = StageExecutionContext(target_path=V0_9, hardened_simulation=False)
        ctx_h = StageExecutionContext(target_path=V1_0_HARDENED, hardened_simulation=True)
        for st in ("zeroday_vex_triage", "k8s_admission_opa", "oauth21_pkce_audit", "hardware_boot_attest"):
            rv = reg.execute_stage(st, ctx_v)
            rh = reg.execute_stage(st, ctx_h)
            self.assertIsNone(rv.error)
            self.assertIsNone(rh.error)
            self.assertGreater(len(rv.vulnerabilities), len(rh.vulnerabilities))

    def test_complete_meta_study_m1_m8_proofs_and_root_cause(self) -> None:
        lab = HarnessSquaredResearchLabFacade()
        study = lab.run_complete_meta_study(V0_9, preferred_profile="fast_ci")
        self.assertEqual(study["harness2_run"]["gate_verdict"], "BLOCKED")
        fv = study["formal_meta_verification"]
        self.assertEqual(fv["overall_verdict"], "PROVEN_SAFE")
        self.assertEqual(fv["theorems_passed"], 8)
        self.assertTrue(fv["signature_verified"])
        self.assertGreaterEqual(study["architectural_root_causes"]["systemic_root_causes_identified"], 3)
        self.assertEqual(study["sarif_v2_1"]["version"], "2.1.0")
        self.assertGreater(len(study["sarif_v2_1"]["runs"][0]["results"]), 20)

    def test_ab_controlled_adaptive_lift(self) -> None:
        ab = HarnessSquaredABEvaluator()
        res = ab.run_ab_benchmark(V0_9, seed_profile="fast_ci")
        lift = res["adaptive_lift"]
        self.assertGreater(lift["vulnerability_discovery_lift_pct"], 0.0)
        self.assertGreater(lift["risk_yield_lift_pct"], 0.0)
        self.assertTrue(lift["safety_invariants_preserved"])

    def test_adversarial_evasion_stress_and_fleet_sweep(self) -> None:
        lab = HarnessSquaredResearchLabFacade()
        stress = lab.run_adversarial_evasion_stress()
        # Wave V Anti-Evasion AST Deobfuscator & Multi-Layer Normalizer closed all 6 prior blind spots
        self.assertEqual(stress["baseline_detection_rate_pct"], 100.0)
        self.assertEqual(stress["evasion_resilience_rate_pct"], 100.0)
        self.assertEqual(stress["blind_spot_count"], 0)

        fleet = lab.run_fleet_sweep(
            [
                FleetRepositorySpec("v0_9", str(V0_9), "platform-sec", tier="tier0_crown_jewel"),
                FleetRepositorySpec("v1_0", str(V1_0_HARDENED), "platform-sec", tier="tier1_prod"),
            ],
            force_profile="fast_ci",
        )
        self.assertEqual(fleet["fleet_repos_assessed"], 2)

    def test_conformal_calibrator_and_bayesian_eig_designer(self) -> None:
        cal = ConformalRiskCalibrator(alpha=0.10)
        eps = [
            CalibrationEpisode(f"e{i}", 40.0 + i, 40.0 + i + ((-1) ** i) * (i % 3), 0.85 if i % 2 == 0 else 0.15, 1 if i % 2 == 0 else 0, (1.0, 0.2 * (i % 3), 0.5))
            for i in range(18)
        ]
        fit = cal.fit(eps)
        self.assertGreaterEqual(fit["conformal_q_hat_residual"], 0.0)
        in_d = cal.predict_conformal_interval(50.0, (1.0, 0.2, 0.5))
        ood = cal.predict_conformal_interval(50.0, (9.0, 9.0, 9.0))
        self.assertFalse(in_d["ood_abstention_triggered"])
        self.assertTrue(ood["ood_abstention_triggered"])

        eig = BayesianExperimentDesigner()
        plan = eig.plan_greedy_optimal_sequence(budget_ms=700.0)
        self.assertGreater(plan["entropy_reduction_pct"], 35.0)
        self.assertGreaterEqual(len(plan["stages_selected"]), 3)

    def test_debate_adjudicator_linucb_and_successive_halving(self) -> None:
        adj = MultiAgentDebateAdjudicator()
        res = adj.adjudicate_batch([
            {"vuln_id": "V1", "rule_id": "SQLI", "severity": "critical", "confidence": 0.96, "sandbox_reproduced": True, "cwe_ids": ["CWE-89"], "file_path": "app/api.py"},
            {"vuln_id": "V2", "rule_id": "NOISE", "severity": "low", "confidence": 0.40, "sandbox_reproduced": False, "cwe_ids": ["CWE-200"], "file_path": "tests/mock_fixture.py"},
        ])
        self.assertEqual(res["verdict_counts"]["CONFIRMED_EXPLOITABLE"], 1)
        self.assertEqual(res["verdict_counts"]["REJECTED_FALSE_POSITIVE"], 1)
        self.assertTrue(res["separation_of_duties_enforced"])

        bandit = ContextualLinUCBBandit(["fast_ci", "deep_exploit"], feature_dim=4, alpha=0.4)
        for i in range(20):
            ctx = [1.0, 0.9, 0.1, 0.1] if i % 2 == 0 else [0.1, 0.1, 0.9, 1.0]
            arm = bandit.select_arm(ctx)["selected_arm"]
            rew = 0.95 if (i % 2 == 0 and arm == "deep_exploit") or (i % 2 == 1 and arm == "fast_ci") else 0.2
            bandit.update(arm, ctx, rew)
        self.assertEqual(bandit.select_arm([1.0, 0.9, 0.1, 0.1])["selected_arm"], "deep_exploit")
        self.assertEqual(bandit.select_arm([0.1, 0.1, 0.9, 1.0])["selected_arm"], "fast_ci")

        pruner = SuccessiveHalvingPruner(eta=2, min_budget_ms=200.0, max_budget_ms=1600.0)
        cands = [CandidateGenomeConfig(f"G{i}", {"score": i}) for i in range(8)]
        sh = pruner.run_bracket(cands, lambda cfg, b: cfg.params["score"] * 10.0 + b / 100.0)
        self.assertEqual(sh["winner_config_id"], "G7")
        self.assertGreater(sh["compute_savings_pct"], 40.0)


if __name__ == "__main__":
    unittest.main()
