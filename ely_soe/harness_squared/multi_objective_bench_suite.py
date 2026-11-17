"""
Harness² Multi-Tier Automated Self-Evolution, Curriculum Convergence & Pareto Hypervolume Benchmark Suite.

Provides a unified scientific evaluation harness comparing:
  1. `static_control` (First-Order fixed workflow, `enable_adaptation=False`)
  2. `harness2_adaptive` (Second-Order MAPE-K + LinUCB + Thompson + Hypothesis Engine)
  3. `harness2_ensemble` (Multi-Genome Portfolio Consensus Coordinator)

Across all 5 Curriculum Tiers (`Tier 0 Hardened Control` -> `Tier 4 Full Multi-Hop Kill Chain`),
verifying:
  - CWE Ground-Truth Recall % per tier & overall macro-recall
  - Fail-Closed Release Gate Accuracy (100% `APPROVED` on Tier 0, 100% `BLOCKED` on Tiers 1–4)
  - Formal Meta-Verifier `M1–M8` Proof Rate (must be `100.0% PROVEN_SAFE`)
  - Exact 2D Pareto Hypervolume Indicator (normalized `(RiskYield, SpeedEfficiency)` area)
  - Adaptive Lift Summary across all tiers.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import utc_now_iso
from ely_soe.harness_squared.causal_attribution import CausalAttributionEngine
from ely_soe.harness_squared.curriculum_generator import AdversarialCurriculumGenerator
from ely_soe.harness_squared.meta_orchestrator import HarnessSquaredEngine
from ely_soe.harness_squared.meta_verifier import HarnessSquaredMetaVerifier


class HarnessSquaredMultiTierBenchmark:
    """Automated scientific benchmark suite across Curriculum Tiers 0..4."""

    def __init__(
        self,
        engine: Optional[HarnessSquaredEngine] = None,
        curriculum: Optional[AdversarialCurriculumGenerator] = None,
        verifier: Optional[HarnessSquaredMetaVerifier] = None,
    ) -> None:
        self.engine = engine or HarnessSquaredEngine()
        self.curriculum = curriculum or AdversarialCurriculumGenerator()
        self.verifier = verifier or HarnessSquaredMetaVerifier()
        self.attribution = CausalAttributionEngine()

    def run_curriculum_benchmark(
        self,
        tiers: Sequence[int] = (0, 1, 2, 3, 4),
        profile: str = "fast_ci",
    ) -> Dict[str, Any]:
        """Execute paired Static Control vs Adaptive Harness² trials across requested curriculum tiers."""
        tier_results: List[Dict[str, Any]] = []
        static_recalls: List[float] = []
        adaptive_recalls: List[float] = []
        static_yields: List[float] = []
        adaptive_yields: List[float] = []
        meta_proofs_passed = 0
        gate_correct_adaptive = 0

        with tempfile.TemporaryDirectory(prefix="ely_h2_curriculum_") as tmpdir:
            root = Path(tmpdir)
            for tier in tiers:
                scen = self.curriculum.generate_scenario(tier=tier, output_root=root)

                static_rep = self.engine.run_adaptive_assessment(
                    target_path=scen.target_dir,
                    target_name=f"{scen.scenario_id}_static",
                    preferred_profile=profile,
                    enable_adaptation=False,
                )
                adaptive_rep = self.engine.run_adaptive_assessment(
                    target_path=scen.target_dir,
                    target_name=f"{scen.scenario_id}_adaptive",
                    preferred_profile=profile,
                    enable_adaptation=True,
                )

                eval_static = self.curriculum.evaluate_detections(scen, static_rep["vulnerabilities"], static_rep["gate_verdict"])
                eval_adaptive = self.curriculum.evaluate_detections(scen, adaptive_rep["vulnerabilities"], adaptive_rep["gate_verdict"])
                cert = self.verifier.verify_run(adaptive_rep)
                if cert.overall_verdict == "PROVEN_SAFE":
                    meta_proofs_passed += 1
                if eval_adaptive.gate_decision_correct:
                    gate_correct_adaptive += 1

                s_yield = float(static_rep["telemetry"]["total_risk_weighted_yield"])
                a_yield = float(adaptive_rep["telemetry"]["total_risk_weighted_yield"])
                static_recalls.append(eval_static.cwe_recall_pct)
                adaptive_recalls.append(eval_adaptive.cwe_recall_pct)
                static_yields.append(s_yield)
                adaptive_yields.append(a_yield)

                tier_results.append({
                    "tier": tier,
                    "scenario_id": scen.scenario_id,
                    "scenario_name": scen.name,
                    "expected_gate": scen.expected_release_decision,
                    "static_control": {
                        "vulns": static_rep["total_vulnerabilities"],
                        "risk_yield": round(s_yield, 2),
                        "duration_ms": round(static_rep["duration_ms"], 2),
                        "cwe_recall_pct": round(eval_static.cwe_recall_pct, 2),
                        "gate_verdict": static_rep["gate_verdict"],
                        "gate_correct": eval_static.gate_decision_correct,
                    },
                    "harness2_adaptive": {
                        "vulns": adaptive_rep["total_vulnerabilities"],
                        "risk_yield": round(a_yield, 2),
                        "duration_ms": round(adaptive_rep["duration_ms"], 2),
                        "adaptations_applied": adaptive_rep["mapek_adaptation"]["total_adaptations_applied"],
                        "cwe_recall_pct": round(eval_adaptive.cwe_recall_pct, 2),
                        "gate_verdict": adaptive_rep["gate_verdict"],
                        "gate_correct": eval_adaptive.gate_decision_correct,
                        "meta_verification": f"{cert.overall_verdict} ({cert.theorems_passed}/{cert.theorems_total})",
                    },
                    "yield_lift_delta": round(a_yield - s_yield, 2),
                })

        n = max(1, len(tier_results))
        tot_s_yield = sum(static_yields)
        tot_a_yield = sum(adaptive_yields)
        overall_yield_lift_pct = ((tot_a_yield - tot_s_yield) / max(1.0, tot_s_yield)) * 100.0

        # Compute exact 2D Pareto Hypervolume over normalized (recall_ratio, speed_score)
        hv_points = [
            (r["harness2_adaptive"]["cwe_recall_pct"] / 100.0, 1.0 / (1.0 + r["harness2_adaptive"]["duration_ms"] / 1000.0))
            for r in tier_results
        ]
        hv = self.compute_2d_hypervolume(hv_points)

        return {
            "benchmarked_at": utc_now_iso(),
            "seed_profile": profile,
            "tiers_evaluated": list(tiers),
            "macro_static_cwe_recall_pct": round(sum(static_recalls) / n, 2),
            "macro_adaptive_cwe_recall_pct": round(sum(adaptive_recalls) / n, 2),
            "cumulative_static_yield": round(tot_s_yield, 2),
            "cumulative_adaptive_yield": round(tot_a_yield, 2),
            "overall_adaptive_yield_lift_pct": round(overall_yield_lift_pct, 2),
            "adaptive_gate_accuracy_pct": round((gate_correct_adaptive / n) * 100.0, 2),
            "meta_safety_proof_rate_pct": round((meta_proofs_passed / n) * 100.0, 2),
            "pareto_2d_hypervolume": round(hv, 4),
            "tier_results": tier_results,
        }

    @staticmethod
    def compute_2d_hypervolume(points: Sequence[Tuple[float, float]], ref: Tuple[float, float] = (0.0, 0.0)) -> float:
        """Exact 2D hypervolume indicator dominated by `points` above reference point `ref`."""
        valid = [(max(ref[0], x), max(ref[1], y)) for x, y in points if x > ref[0] and y > ref[1]]
        if not valid:
            return 0.0
        # Sort by x descending, filter non-dominated staircase
        valid.sort(key=lambda p: (p[0], p[1]), reverse=True)
        front: List[Tuple[float, float]] = []
        max_y = ref[1]
        for x, y in valid:
            if y > max_y:
                front.append((x, y))
                max_y = y
        front.sort(key=lambda p: p[0])
        hv = 0.0
        prev_x = ref[0]
        for x, y in front:
            hv += (x - prev_x) * (y - ref[1])
            prev_x = x
        return hv
