"""
Harness² Controlled A/B Meta-Benchmark & Adaptive Lift Evaluator.

Runs an apples-to-apples controlled experiment on the exact same authorized target:
  - **Control Arm (Static First-Order Harness)**: fixed `fast_ci` profile with
    `enable_adaptation=False` (no live drilldowns, no hypothesis probing, no branch pruning).
  - **Treatment Arm (Adaptive Harness² Meta-Harness)**: same initial seed profile with
    `enable_adaptation=True` (MAPE-K live drilldowns, Bayesian hypothesis probes, dynamic
    branch pruning, and invariant-checked DAG rewriting).

Quantifies exact empirical **Adaptive Lift**:
  - Total Vulnerabilities Discovered Lift (`+Δ%`)
  - Critical & Sandbox-Reproduced Confirmation Lift (`+Δ`)
  - Multi-Domain Exploit Chains Discovered Lift (`+Δ`)
  - Risk-Weighted Yield / Second Efficiency Ratio
  - Compliance Controls Evaluated & Safety Invariant Compliance (must be 100%).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from ely_soe.core.models import utc_now_iso
from ely_soe.harness_squared.meta_orchestrator import HarnessSquaredEngine


class HarnessSquaredABEvaluator:
    """Controlled side-by-side Static Baseline vs. Adaptive Harness² meta-benchmark evaluator."""

    def __init__(self, engine: Optional[HarnessSquaredEngine] = None) -> None:
        self.engine = engine or HarnessSquaredEngine()

    def run_ab_benchmark(
        self,
        target_path: Optional[Path] = None,
        *,
        seed_profile: str = "fast_ci",
        hardened_simulation: bool = False,
    ) -> Dict[str, Any]:
        """Compare static non-adaptive control run against live-adapting Harness² treatment run."""
        control = self.engine.run_adaptive_assessment(
            target_path=target_path,
            preferred_profile=seed_profile,
            enable_adaptation=False,
            hardened_simulation=hardened_simulation,
            evolve_pareto=False,
        )
        treatment = self.engine.run_adaptive_assessment(
            target_path=target_path,
            preferred_profile=seed_profile,
            enable_adaptation=True,
            hardened_simulation=hardened_simulation,
            evolve_pareto=True,
        )

        c_vulns = control["total_vulnerabilities"]
        t_vulns = treatment["total_vulnerabilities"]
        c_crit = control["severity_counts"].get("critical", 0)
        t_crit = treatment["severity_counts"].get("critical", 0)
        c_repro = control["portfolio_risk"].get("sandbox_reproduced_count", 0)
        t_repro = treatment["portfolio_risk"].get("sandbox_reproduced_count", 0)
        c_chains = control["exploit_chains"].get("kill_chains_found", 0)
        t_chains = treatment["exploit_chains"].get("kill_chains_found", 0)
        c_yield = float(control["telemetry"].get("total_risk_weighted_yield", 0.0))
        t_yield = float(treatment["telemetry"].get("total_risk_weighted_yield", 0.0))

        vuln_lift_pct = round(((t_vulns - c_vulns) / max(1, c_vulns)) * 100.0, 2)
        yield_lift_pct = round(((t_yield - c_yield) / max(1.0, c_yield)) * 100.0, 2)

        t_inv = treatment["safety_invariants"]["guard_ledger_summary"]
        invariants_intact = bool(t_inv.get("ledger_chain_valid", False))

        return {
            "evaluated_at": utc_now_iso(),
            "target": treatment["target_fingerprint"]["target_name"],
            "seed_profile": seed_profile,
            "control_static": {
                "run_id": control["run_id"],
                "duration_ms": control["duration_ms"],
                "total_vulnerabilities": c_vulns,
                "critical_vulnerabilities": c_crit,
                "sandbox_reproduced": c_repro,
                "kill_chains_found": c_chains,
                "risk_weighted_yield": c_yield,
                "adaptations_applied": control["mapek_adaptation"]["total_adaptations_applied"],
                "gate_verdict": control["gate_verdict"],
            },
            "treatment_harness_squared": {
                "run_id": treatment["run_id"],
                "duration_ms": treatment["duration_ms"],
                "total_vulnerabilities": t_vulns,
                "critical_vulnerabilities": t_crit,
                "sandbox_reproduced": t_repro,
                "kill_chains_found": t_chains,
                "risk_weighted_yield": t_yield,
                "adaptations_applied": treatment["mapek_adaptation"]["total_adaptations_applied"],
                "injected_stages": treatment["workflow_dag"]["injected_stage_count"],
                "pruned_stages": treatment["workflow_dag"]["pruned_stage_count"],
                "hypotheses_confirmed": treatment["hypotheses"]["confirmed"],
                "gate_verdict": treatment["gate_verdict"],
            },
            "adaptive_lift": {
                "additional_vulnerabilities_found": t_vulns - c_vulns,
                "vulnerability_discovery_lift_pct": vuln_lift_pct,
                "additional_criticals_found": t_crit - c_crit,
                "additional_sandbox_reproductions": t_repro - c_repro,
                "additional_kill_chains_uncovered": t_chains - c_chains,
                "risk_yield_lift_pct": yield_lift_pct,
                "safety_invariants_preserved": invariants_intact,
            },
            "pareto_frontier_summary": treatment.get("pareto_evolution"),
        }
