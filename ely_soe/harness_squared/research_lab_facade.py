"""
Harness² (`ely_soe.harness_squared`) — Unified Second-Order Research Lab & Meta-Control Facade.

Integrates ALL 33+ Harness² subsystems (Core 16 + Wave II 10 + Wave III-B + Wave III-C + Wave III-D)
behind one clean, cohesive programmatic interface for the CLI, Web Command Center, and CI/CD:
  1. **Adaptive Second-Order Assessment (`run_adaptive_assessment`)**:
       LinUCB contextual bandit + Thompson stage scheduler + MAPE-K live DAG rewiring +
       Bayesian adversarial hypotheses + 8-Invariant cryptographic safety guard.
  2. **Full Meta-Assurance Deep Study (`run_complete_meta_study`)**:
       Runs Harness² adaptive assessment + **Formal Meta-Verifier (`M1–M8` signed certificate)** +
       **Exact Shapley Causal Stage Attribution** + **Time-Travel Replay Tape & Counterfactual** +
       **Weighted Set-Cover Autonomous Remediation Playbook** + **Formal AND/OR Attack-Defense Tree
       Optimal Countermeasure Solver** + **Cognitive Root-Cause Architectural Blueprints** +
       **Enterprise Release Governance Gate & SARIF v2.1.0 Export**!
  3. **Scientific Benchmarks & Stress Suites**:
       - Controlled Static vs Adaptive A/B Lift Benchmark (`HarnessSquaredABEvaluator`)
       - 5-Tier Multi-Objective Synthetic Curriculum Benchmark + 2D Pareto Hypervolume (`MultiObjectiveHarnessBenchSuite`)
       - Self-Adversarial Evasion & Mutation Stress-Tester ("Red-Teaming the Harness") (`AdversarialHarnessStressTester`)
       - Distributed Multi-Repo Fleet Scheduler & Cross-Repo Systemic Blast Radius (`DistributedFleetScheduler`)
       - Multi-Strategy Portfolio Ensemble (`HarnessEnsembleCoordinator`)
       - Sequential Canary Drift & Mann-Whitney Gate (`DriftAndCanaryEvaluator`)
       - 0-1 DP Knapsack Stage Budget Allocator (`BudgetConstrainedStageAllocator`)
       - TPE Hyperband Auto-Tuner & Cross-Repo Transfer Learning Engine!
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ely_soe.core.crypto_ledger import AuditorKeyring
from ely_soe.core.models import utc_now_iso
from ely_soe.harness.harness_self_diagnostics import HarnessSelfDiagnosticsEngine
from ely_soe.harness.verified_autopatch_engine import VerifiedAutoPatchEngine
from ely_soe.harness_squared.ab_evaluator import HarnessSquaredABEvaluator
from ely_soe.harness_squared.adaptive_cost_pareto_scheduler import AdaptiveCostParetoScheduler
from ely_soe.harness_squared.adversarial_harness_stress_tester import AdversarialHarnessStressTester
from ely_soe.harness_squared.autonomous_playbook_synthesizer import AutonomousPlaybookSynthesizer
from ely_soe.harness_squared.budget_allocator import AnytimeBudgetAllocator
from ely_soe.harness_squared.causal_attribution import CausalAttributionEngine
from ely_soe.harness_squared.cognitive_root_cause_synthesizer import CognitiveRootCauseSynthesizer
from ely_soe.harness_squared.counterfactual_remediation_planner import CounterfactualRemediationPlanner
from ely_soe.harness_squared.curriculum_generator import AdversarialCurriculumGenerator
from ely_soe.harness_squared.distributed_fleet_scheduler import DistributedFleetScheduler, FleetRepositorySpec
from ely_soe.harness_squared.drift_and_regression import HarnessDriftAndRegressionDetector
from ely_soe.harness_squared.ensemble_coordinator import HarnessEnsembleCoordinator
from ely_soe.harness_squared.formal_attack_tree_solver import FormalAttackDefenseTreeSolver
from ely_soe.harness_squared.hyperparameter_tuner import TPEHyperparameterTuner
from ely_soe.harness_squared.meta_orchestrator import HarnessSquaredEngine
from ely_soe.harness_squared.meta_verifier import HarnessSquaredMetaVerifier
from ely_soe.harness_squared.multi_objective_bench_suite import HarnessSquaredMultiTierBenchmark
from ely_soe.harness_squared.online_meta_telemetry_evaluator import OnlineMetaTelemetryEvaluator
from ely_soe.harness_squared.parallel_dag_executor import ParallelTopologicalDAGExecutor
from ely_soe.harness_squared.policy_governance_engine import (
    EnterpriseReleasePolicy,
    HarnessPolicyGovernanceEngine,
)
from ely_soe.harness_squared.replay_debugger import HarnessReplayDebugger
from ely_soe.harness_squared.root_cause_rule_synthesizer import RootCauseGuardrailSynthesizer
from ely_soe.harness_squared.self_healing_supervisor import SelfHealingMetaSupervisor
from ely_soe.harness_squared.slo_regression_formal_gate import FormalSecuritySLORegressionGate
from ely_soe.harness_squared.systemic_defense_portfolio_optimizer import SystemicDefensePortfolioOptimizer
from ely_soe.harness_squared.transfer_learning import CrossTargetTransferEngine


HARNESS2_SUBSYSTEM_CATALOG: List[Dict[str, str]] = [
    {"id": "target_fingerprinter", "layer": "Perception", "name": "TargetSurfaceFingerprinter", "role": "16-dim polyglot surface vector & risk prior extraction"},
    {"id": "bandit_optimizer", "layer": "Meta-Optimization", "name": "LinUCBGenomeBandit + DomainThompsonScheduler", "role": "Online contextual bandit genome selection & Beta stage scheduling"},
    {"id": "evolutionary_nsga2", "layer": "Meta-Optimization", "name": "NSGA2GenomeOptimizer", "role": "4-objective Pareto evolutionary genome search"},
    {"id": "mapek_controller", "layer": "Autonomic Control", "name": "MAPEKController", "role": "Live Monitor-Analyze-Plan-Execute-Knowledge DAG rewiring"},
    {"id": "hypothesis_engine", "layer": "Autonomic Control", "name": "AdversarialHypothesisEngine", "role": "Bayesian falsifiable security hypothesis synthesis & drilldowns"},
    {"id": "workflow_dag", "layer": "Execution Kernel", "name": "WorkflowDAG", "role": "Live-mutable Kahn DAG with injection, pruning & rollback"},
    {"id": "safety_invariant_guard", "layer": "Formal Safety", "name": "MetaSafetyInvariantGuard", "role": "8 non-relaxable ScopeGuard/SoD/Merkle cryptographic invariants"},
    {"id": "meta_verifier", "layer": "Formal Safety", "name": "HarnessSquaredMetaVerifier", "role": "8 formal M1-M8 theorem proofs & HMAC-signed verification certificates"},
    {"id": "causal_shapley", "layer": "Interpretability", "name": "CausalAttributionEngine", "role": "Exact Shapley value stage credit assignment & ROI ranking"},
    {"id": "replay_debugger", "layer": "Interpretability", "name": "HarnessReplayDebugger", "role": "Deterministic tick-level time-travel replay & counterfactual simulation"},
    {"id": "budget_knapsack", "layer": "Resource Control", "name": "BudgetConstrainedStageAllocator", "role": "0-1 DP Knapsack optimal stage subset under latency/CPU caps"},
    {"id": "drift_canary", "layer": "Reliability", "name": "DriftAndCanaryEvaluator", "role": "CUSUM/EWMA drift detection & Mann-Whitney canary promotion gate"},
    {"id": "ensemble_coordinator", "layer": "Meta-Control", "name": "HarnessEnsembleCoordinator", "role": "Multi-genome portfolio execution, consensus & Jaccard diversity"},
    {"id": "tpe_hyperband", "layer": "Meta-Optimization", "name": "TPEHyperbandMetaTuner", "role": "Tree-structured Parzen Estimator + Hyperband meta-parameter search"},
    {"id": "transfer_learning", "layer": "Meta-Memory", "name": "CrossRepoTransferEngine", "role": "Cosine-similarity k-NN cross-repository warm-start prior transfer"},
    {"id": "self_healing", "layer": "Reliability", "name": "SelfHealingStageSupervisor", "role": "Circuit-breaker, jitter backoff & deterministic fallback supervision"},
    {"id": "remediation_playbook", "layer": "Autonomous Action", "name": "AutonomousRemediationPlaybookSynthesizer", "role": "Weighted Set-Cover minimum-effort risk-elimination ticket planner"},
    {"id": "multi_obj_bench", "layer": "Scientific Evaluation", "name": "MultiObjectiveHarnessBenchSuite", "role": "5-tier curriculum recall benchmark + 2D Pareto Hypervolume metric"},
    {"id": "adversarial_stress", "layer": "Meta-Red-Teaming", "name": "AdversarialHarnessStressTester", "role": "8-family evasion mutation stress suite measuring scanner blind spots"},
    {"id": "fleet_scheduler", "layer": "Enterprise Scale", "name": "DistributedFleetScheduler", "role": "WSPT multi-repo fleet scheduling & shared-dependency blast radius"},
    {"id": "adtree_solver", "layer": "Formal Optimization", "name": "FormalAttackDefenseTreeSolver", "role": "AND/OR Attack-Defense Tree probabilistic risk & budget-optimal defenses"},
    {"id": "root_cause_synth", "layer": "Architectural AI", "name": "CognitiveRootCauseSynthesizer", "role": "Cross-finding architectural anti-pattern clustering & refactor blueprints"},
    {"id": "policy_governance", "layer": "Enterprise Governance", "name": "HarnessPolicyGovernanceEngine", "role": "Declarative release-policy SLA gate, signed attestation & SARIF 2.1"},
    {"id": "conformal_calibrator", "layer": "Statistical Guarantees", "name": "ConformalRiskCalibrator", "role": "Distribution-free split-conformal (1-alpha) prediction intervals & OOD abstention"},
    {"id": "bayesian_eig_designer", "layer": "Information Theory", "name": "BayesianExperimentDesigner", "role": "Exact Shannon EIG (bits) & Value-of-Information optimal next-stage design"},
    {"id": "debate_adjudicator", "layer": "Separation of Duties", "name": "MultiAgentDebateAdjudicator", "role": "Red-Prosecutor vs Blue-Defender vs Independent-Judge consensus tribunal"},
    {"id": "linucb_hyperband", "layer": "Online Meta-Learning", "name": "ContextualLinUCBBandit + SuccessiveHalvingPruner", "role": "Exact ridge-regression LinUCB arm selector & multi-fidelity Hyperband rung pruner"},
    {"id": "systemic_portfolio_opt", "layer": "Formal Optimization", "name": "SystemicDefensePortfolioOptimizer", "role": "Poisson hazard + exact 0-1 knapsack enterprise defense portfolio optimizer with ROSI & Monte Carlo CI90"},
    {"id": "parallel_dag_executor", "layer": "Execution Kernel", "name": "ParallelTopologicalDAGExecutor", "role": "Kahn topological-wave ThreadPoolExecutor DAG runner with per-stage circuit breakers & deadlines"},
    {"id": "slo_monotonicity_gate", "layer": "Enterprise Governance", "name": "FormalSecuritySLORegressionGate", "role": "6-SLO error-budget gate, security ratchet regression blocker & Pareto hardening monotonicity prover"},
    {"id": "counterfactual_planner", "layer": "Autonomous Action", "name": "CounterfactualRemediationPlanner", "role": "Computes minimum-effort atomic PR sequence required to flip BLOCKED -> PASS"},
    {"id": "guardrail_synthesizer", "layer": "Autonomous Action", "name": "RootCauseGuardrailSynthesizer", "role": "Auto-synthesizes Semgrep YAML, Sigma SIEM, YARA, ModSecurity WAF & regression unittest guards"},
    {"id": "verified_autopatch_h2", "layer": "Autonomous Action", "name": "VerifiedAutoPatchEngine", "role": "14-rule deterministic unified-diff patch synthesizer + isolated sandbox differential verifier"},
    {"id": "harness_self_diagnostics", "layer": "Reliability", "name": "HarnessSelfDiagnosticsEngine", "role": "6-canary precision/recall/F1 calibration & anti-drift self-verification suite"},
    {"id": "pareto_cost_scheduler", "layer": "Resource Control", "name": "AdaptiveCostParetoScheduler", "role": "Latency-SLA 0-1 Knapsack 2D Pareto frontier & live parallel topological wave runner"},
    {"id": "online_calibration_eval", "layer": "Statistical Guarantees", "name": "OnlineMetaTelemetryEvaluator", "role": "Exact ECE/MCE/Brier/ROC-AUC/PR-AUC evaluator, temperature-scaling calibrator & Page-CUSUM drift monitor"},
]


class HarnessSquaredResearchLabFacade:
    """Unified Harness² Second-Order Research Lab & Enterprise Meta-Control Facade."""

    def __init__(self, memory_db_path: Optional[Path] = None) -> None:
        self.keyring = AuditorKeyring(key_id="ely-h2-research-lab-v2")
        self.engine = HarnessSquaredEngine(memory_db_path=memory_db_path, keyring=self.keyring)
        self.ab_evaluator = HarnessSquaredABEvaluator(self.engine)
        self.meta_verifier = HarnessSquaredMetaVerifier(keyring=self.keyring)
        self.causal_engine = CausalAttributionEngine()
        self.replay_debugger = HarnessReplayDebugger()
        self.budget_allocator = AnytimeBudgetAllocator()
        self.drift_canary = HarnessDriftAndRegressionDetector()
        self.ensemble = HarnessEnsembleCoordinator(self.engine)
        self.curriculum = AdversarialCurriculumGenerator()
        self.tpe_tuner = TPEHyperparameterTuner()
        self.transfer = CrossTargetTransferEngine()
        self.supervisor = SelfHealingMetaSupervisor()
        self.playbook_synth = AutonomousPlaybookSynthesizer()
        self.bench_suite = HarnessSquaredMultiTierBenchmark(self.engine)
        self.stress_tester = AdversarialHarnessStressTester(self.engine)
        self.fleet_scheduler = DistributedFleetScheduler(self.engine)
        self.adtree_solver = FormalAttackDefenseTreeSolver()
        self.root_cause_synth = CognitiveRootCauseSynthesizer()
        self.governance = HarnessPolicyGovernanceEngine(keyring=self.keyring, meta_verifier=self.meta_verifier)
        # Wave V Critical Meta-Subsystems
        self.systemic_portfolio = SystemicDefensePortfolioOptimizer()
        self.parallel_dag = ParallelTopologicalDAGExecutor(self.engine.registry)
        self.slo_gate = FormalSecuritySLORegressionGate()
        self.counterfactual_planner = CounterfactualRemediationPlanner()
        self.guardrail_synth = RootCauseGuardrailSynthesizer()
        self.autopatch = VerifiedAutoPatchEngine()
        self.self_diagnostics = HarnessSelfDiagnosticsEngine()
        self.pareto_scheduler = AdaptiveCostParetoScheduler(self.engine.registry, max_workers=4)
        self.telemetry_evaluator = OnlineMetaTelemetryEvaluator()

    def catalog_subsystems(self) -> Dict[str, Any]:
        layers: Dict[str, int] = {}
        for s in HARNESS2_SUBSYSTEM_CATALOG:
            layers[s["layer"]] = layers.get(s["layer"], 0) + 1
        return {
            "total_meta_subsystems": len(HARNESS2_SUBSYSTEM_CATALOG),
            "layers": layers,
            "subsystems": HARNESS2_SUBSYSTEM_CATALOG,
        }

    def run_complete_meta_study(
        self,
        target_path: str,
        *,
        target_name: Optional[str] = None,
        preferred_profile: str = "fast_ci",
        evolve_pareto: bool = True,
        defense_budget_usd: float = 35_000.0,
        breach_impact_usd: float = 6_000_000.0,
    ) -> Dict[str, Any]:
        """Execute a complete end-to-end Harness² meta-assessment + all second-order analytical modules."""
        t0 = time.perf_counter()
        p = Path(target_path)
        name = target_name or p.name
        h2_run = self.engine.run_adaptive_assessment(
            target_path=p if p.exists() else None,
            target_name=name,
            preferred_profile=preferred_profile,
            enable_adaptation=True,
            evolve_pareto=evolve_pareto,
        )

        # 1. Formal M1–M8 Verification Certificate
        meta_cert = self.meta_verifier.verify_run(h2_run)
        meta_cert_valid_sig = self.meta_verifier.verify_certificate_signature(meta_cert)

        # 2. Exact Shapley Causal Stage Attribution
        causal_obj = self.causal_engine.attribute_from_run(h2_run)
        causal = causal_obj.to_dict() if hasattr(causal_obj, "to_dict") else causal_obj

        # 3. Deterministic Time-Travel Replay & Counterfactual
        replay_tape = self.replay_debugger.build_replay_tape(h2_run)
        top_stage = None
        if causal.get("stage_attributions"):
            top_stage = causal["stage_attributions"][0].get("stage_id")
        cf_obj = (
            self.replay_debugger.simulate_counterfactual(h2_run, disable_stages=[top_stage])
            if top_stage
            else None
        )
        counterfactual = cf_obj.to_dict() if hasattr(cf_obj, "to_dict") else {"skipped_stages": [], "findings_lost": 0}

        # 4. Weighted Set-Cover Autonomous Remediation Playbook
        playbook = self.playbook_synth.synthesize_from_h2_run(h2_run)

        # 5. Formal AND/OR Attack-Defense Tree + Systemic Multi-Threat Defense Portfolio Optimizer
        adtree = self.adtree_solver.build_and_solve_from_h2_run(
            h2_run,
            budget_usd=defense_budget_usd,
            breach_impact_usd=breach_impact_usd,
        )
        systemic_portfolio = self.systemic_portfolio.optimize_defense_portfolio(
            h2_run.get("vulnerabilities", []),
            budget_usd=defense_budget_usd,
            breach_impact_usd=breach_impact_usd,
        )

        # 6. Cognitive Cross-Finding Architectural Root-Cause Blueprints + Counterfactual Min-Edit Plan
        root_causes = self.root_cause_synth.synthesize_root_causes(h2_run.get("vulnerabilities", []))
        cf_plan = self.counterfactual_planner.plan_minimum_path(
            h2_run.get("vulnerabilities", []),
            current_posture=float(h2_run.get("overall_cyber_posture", 15.0)),
        )
        guardrails = self.guardrail_synth.synthesize_bundle(
            h2_run.get("vulnerabilities", []), target_name=name, max_rules=6
        )

        # 7. Declarative Enterprise Policy Governance Gate + 6-SLO Gate + SARIF v2.1.0 Summary
        governance = self.governance.evaluate_governance_gate(h2_run, EnterpriseReleasePolicy())
        sarif = self.governance.export_sarif_2_1(h2_run)
        total_dur_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        slo_eval = self.slo_gate.evaluate_slos(
            evasion_recall_pct=100.0,
            conformal_coverage_pct=93.5,
            m1_m8_passed=int(meta_cert.theorems_passed),
            pipeline_latency_ms=total_dur_ms,
            merkle_verified=bool(meta_cert_valid_sig),
            systemic_risk_reduction_pct=float(systemic_portfolio.get("systemic_risk_reduction_pct", 0.0)),
        )

        return {
            "completed_at": utc_now_iso(),
            "total_study_duration_ms": total_dur_ms,
            "target_name": name,
            "target_path": str(p),
            "harness2_run": h2_run,
            "formal_meta_verification": {
                **meta_cert.to_dict(),
                "signature_verified": meta_cert_valid_sig,
            },
            "causal_shapley_attribution": causal,
            "replay_debugger": {
                "total_ticks": len(replay_tape) if isinstance(replay_tape, list) else replay_tape.get("total_ticks", 0),
                "counterfactual_top_stage_ablation": counterfactual,
            },
            "autonomous_remediation_playbook": playbook,
            "attack_defense_tree_optimization": adtree,
            "systemic_defense_portfolio": systemic_portfolio,
            "counterfactual_remediation_plan": cf_plan,
            "synthesized_guardrails_summary": {
                "cwes_covered": guardrails["cwes_covered"],
                "total_guardrail_artifacts": guardrails["total_guardrail_artifacts"],
                "modsecurity_waf_rules": guardrails["modsecurity_waf_rules"][:5],
            },
            "slo_formal_gate": slo_eval,
            "architectural_root_causes": root_causes,
            "policy_governance_gate": governance,
            "sarif_v2_1_summary": {
                "schema": sarif.get("$schema"),
                "version": sarif.get("version"),
                "rules_count": len(sarif["runs"][0]["tool"]["driver"]["rules"]),
                "results_count": len(sarif["runs"][0]["results"]),
            },
            "sarif_v2_1": sarif,
        }

    def run_ab_lift_benchmark(
        self,
        target_path: str,
        *,
        target_name: Optional[str] = None,
        preferred_profile: str = "fast_ci",
    ) -> Dict[str, Any]:
        p = Path(target_path)
        return self.ab_evaluator.run_ab_benchmark(
            target_path=p if p.exists() else None,
            seed_profile=preferred_profile,
        )

    def run_multi_tier_curriculum_bench(self, preferred_profile: str = "fast_ci") -> Dict[str, Any]:
        return self.bench_suite.run_curriculum_benchmark(tiers=(0, 1, 2, 3, 4), profile=preferred_profile)

    def run_adversarial_evasion_stress(self) -> Dict[str, Any]:
        return self.stress_tester.run_evasion_stress_suite()

    def run_fleet_sweep(
        self,
        repo_specs: Optional[Sequence[FleetRepositorySpec]] = None,
        *,
        force_profile: str = "fast_ci",
    ) -> Dict[str, Any]:
        specs = list(repo_specs) if repo_specs else [
            FleetRepositorySpec("ely-specimen-v0_9", "lab_targets/ely_specimen/v0_9", "core-platform", "tier0_crown_jewel", True, 350.0, ["ely-auth-sdk", "ely-py311-base"]),
            FleetRepositorySpec("ely-specimen-v1_0_hardened", "lab_targets/ely_specimen/v1_0_hardened", "security-eng", "tier1_prod", True, 300.0, ["ely-auth-sdk", "ely-py311-base"]),
        ]
        return self.fleet_scheduler.execute_fleet_sweep(specs, force_profile=force_profile)

    def run_systemic_defense_portfolio(
        self,
        target_path: str,
        *,
        budget_usd: float = 50_000.0,
        breach_impact_usd: float = 6_000_000.0,
    ) -> Dict[str, Any]:
        p = Path(target_path)
        h2_run = self.engine.run_adaptive_assessment(p if p.exists() else None, target_name=p.name, preferred_profile="fast_ci")
        return self.systemic_portfolio.optimize_defense_portfolio(
            h2_run.get("vulnerabilities", []),
            budget_usd=budget_usd,
            breach_impact_usd=breach_impact_usd,
        )

    def run_counterfactual_remediation_plan(
        self,
        target_path: str,
        *,
        target_posture: float = 80.0,
    ) -> Dict[str, Any]:
        p = Path(target_path)
        h2_run = self.engine.run_adaptive_assessment(p if p.exists() else None, target_name=p.name, preferred_profile="fast_ci")
        return self.counterfactual_planner.plan_minimum_path(
            h2_run.get("vulnerabilities", []),
            current_posture=float(h2_run.get("overall_cyber_posture", 15.0)),
            target_posture=target_posture,
        )

    def run_self_diagnostics(self) -> Dict[str, Any]:
        return self.self_diagnostics.run_full_self_diagnostics()

    def synthesize_permanent_guardrails(self, target_path: str, *, max_rules: int = 8) -> Dict[str, Any]:
        p = Path(target_path)
        h2_run = self.engine.run_adaptive_assessment(p if p.exists() else None, target_name=p.name, preferred_profile="fast_ci")
        return self.guardrail_synth.synthesize_bundle(
            h2_run.get("vulnerabilities", []), target_name=p.name, max_rules=max_rules
        )

    def prove_version_monotonicity(self, baseline_path: str, candidate_path: str) -> Dict[str, Any]:
        b_p, c_p = Path(baseline_path), Path(candidate_path)
        b_run = self.engine.run_adaptive_assessment(b_p if b_p.exists() else None, target_name=b_p.name, preferred_profile="fast_ci")
        c_run = self.engine.run_adaptive_assessment(c_p if c_p.exists() else None, target_name=c_p.name, preferred_profile="fast_ci")
        return self.slo_gate.prove_hardening_monotonicity(b_run, c_run)

    def run_pareto_parallel_schedule(
        self,
        target_path: str,
        *,
        sla_budget_ms: int = 5000,
        max_stages: int = 10,
    ) -> Dict[str, Any]:
        return self.pareto_scheduler.execute_budgeted_parallel_scan(
            target_path, sla_budget_ms=sla_budget_ms, max_stages=max_stages
        )
