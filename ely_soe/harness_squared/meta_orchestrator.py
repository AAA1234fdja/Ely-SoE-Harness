"""
Harness² (`HarnessSquaredEngine`) Unified Second-Order Meta-Harness Orchestrator.

Wraps the first-order security harness and all 22+ `ely_soe.cyber` testing engines in
a closed-loop, self-adapting, cryptographically-governed second-order meta-workflow:
  1. **Surface Fingerprinting (`TargetSurfaceFingerprinter`)**: extracts 16-dim feature vector,
     archetype, tech stack, sink density, and domain affinities.
  2. **Transfer Recall & Bandit Strategy Selection (`MetaMemoryStore` + `LinUCBGenomeBandit` +
     `DomainThompsonScheduler`)**: recalls nearest prior engagements and synthesizes a
     target-tailored `HarnessGenome`.
  3. **Formal Pre-Flight Safety Verification (`MetaSafetyInvariantGuard`)**: cryptographically
     verifies all 8 non-relaxable invariants (`INV-01`..`INV-08`) before execution.
  4. **Dynamic Workflow DAG Synthesis (`WorkflowDAG`)**: compiles initial dependency graph with
     empirical Thompson priorities and a terminal cross-domain synthesis gate.
  5. **Closed-Loop Live Execution + MAPE-K Adaptation + Bayesian Hypothesis Testing**:
     runs stages in priority-topological order, streaming telemetry to `TelemetryObserver`,
     proposing falsifiable hypotheses via `AdversarialHypothesisEngine`, and applying
     safety-gated live DAG rewrites via `MAPEKController`!
  6. **Cross-Domain Executive Synthesis**: CVSS v4.0/EPSS/KEV prioritization, Multi-Domain
     Exploit-Chain Planning, 7-Framework Compliance Mapping, and STRIDE Threat Modeling.
  7. **Online Meta-Learning & NSGA-II Pareto Evolution**: updates LinUCB ridge matrices,
     Thompson Beta posteriors, MAPE-K rule efficacy ledger, and optional Pareto frontier.
  8. **Cryptographically Sealed `MetaRunReport`**: includes Merkle root, invariant proof log,
     live-adapted Mermaid DAG, adaptation timeline, and all findings.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.crypto_ledger import AuditorKeyring, ForensicAuditLedger
from ely_soe.core.models import Severity, new_id, utc_now_iso
from ely_soe.core.scope_guard import ScopeGuard
from ely_soe.cyber.compliance_mapper import EnterpriseComplianceMapper
from ely_soe.cyber.cvss4_risk_engine import CyberRiskPrioritizationEngine
from ely_soe.cyber.cwe_knowledge_base import CWEKnowledgeBase
from ely_soe.cyber.exploit_chain_planner import GeneralizedExploitChainPlanner
from ely_soe.cyber.models import AssetCriticality, CyberVulnerability
from ely_soe.cyber.threat_model_stride import AutomatedStrideThreatModeler
from ely_soe.harness_squared.bandit_optimizer import (
    DomainThompsonScheduler,
    LinUCBGenomeBandit,
)
from ely_soe.harness_squared.evolutionary_optimizer import NSGA2GenomeOptimizer
from ely_soe.harness_squared.hypothesis_engine import AdversarialHypothesisEngine
from ely_soe.harness_squared.mapek_controller import MAPEKController
from ely_soe.harness_squared.meta_memory import MetaMemoryStore
from ely_soe.harness_squared.models import (
    HarnessGenome,
    StageCategory,
    StageStatus,
    TargetFingerprint,
    WorkflowStageNode,
)
from ely_soe.harness_squared.safety_invariant_guard import MetaSafetyInvariantGuard
from ely_soe.harness_squared.stage_registry import (
    STAGE_CATALOG,
    FirstOrderStageRegistry,
    StageExecutionContext,
)
from ely_soe.harness_squared.target_fingerprinter import TargetSurfaceFingerprinter
from ely_soe.harness_squared.telemetry_observer import TelemetryObserver
from ely_soe.harness_squared.workflow_dag import WorkflowDAG


class HarnessSquaredEngine:
    """Unified Harness² second-order adaptive meta-harness orchestrator."""

    def __init__(
        self,
        *,
        memory_db_path: Optional[Path] = None,
        scope_guard: Optional[ScopeGuard] = None,
        keyring: Optional[AuditorKeyring] = None,
    ) -> None:
        self.scope_guard = scope_guard
        self.keyring = keyring or AuditorKeyring(key_id="ely_harness_squared")
        self.ledger = ForensicAuditLedger(self.keyring)
        self.invariant_guard = MetaSafetyInvariantGuard(
            scope_guard=scope_guard,
            keyring=self.keyring,
            ledger=self.ledger,
        )
        self.memory = MetaMemoryStore(memory_db_path)
        self.fingerprinter = TargetSurfaceFingerprinter()
        self.bandit = LinUCBGenomeBandit()
        self.thompson = DomainThompsonScheduler()
        self.evolution = NSGA2GenomeOptimizer(self.invariant_guard)
        self.registry = FirstOrderStageRegistry()
        self.risk_engine = CyberRiskPrioritizationEngine()
        self.chain_planner = GeneralizedExploitChainPlanner()
        self.compliance = EnterpriseComplianceMapper()
        self.stride = AutomatedStrideThreatModeler()
        self.cwe_kb = CWEKnowledgeBase()

        # Reload persisted bandit & Thompson state if present
        saved_bandit = self.memory.load_kv("linucb_state")
        if isinstance(saved_bandit, dict):
            self.bandit.load_state(saved_bandit)
        saved_ts = self.memory.load_kv("thompson_state")
        if isinstance(saved_ts, dict):
            self.thompson.alphas.update(saved_ts.get("alphas", {}))
            self.thompson.betas.update(saved_ts.get("betas", {}))

    def run_adaptive_assessment(
        self,
        target_path: Optional[Path] = None,
        *,
        target_name: Optional[str] = None,
        preferred_profile: Optional[str] = None,
        enable_adaptation: bool = True,
        hardened_simulation: bool = False,
        live_local_url: Optional[str] = None,
        evolve_pareto: bool = False,
        asset_criticality: AssetCriticality = AssetCriticality.TIER_1_PRODUCTION,
    ) -> Dict[str, Any]:
        """Execute a full closed-loop Harness² adaptive cybersecurity workflow."""
        t0 = time.perf_counter()
        run_id = new_id("h2run")
        started_at = utc_now_iso()

        # 1. Deep Target Surface Fingerprinting
        fingerprint = self.fingerprinter.fingerprint(target_path=target_path, target_name=target_name)
        similar_runs = self.memory.find_similar_runs(fingerprint.feature_vector, top_k=3)

        # 2. Contextual Bandit (LinUCB) Genome Synthesis
        genome, bandit_decision = self.bandit.select_genome(fingerprint, preferred_profile=preferred_profile)

        # 3. Formal Pre-Flight Invariant Verification (INV-01 .. INV-07)
        preflight_checks = self.invariant_guard.verify_genome(
            genome,
            target_path=target_path,
            live_local_url=live_local_url,
            raise_on_violation=True,
        )

        # 4. Build Initial Adaptive Execution DAG
        dag = self._compile_initial_dag(genome, fingerprint)

        # 5. Closed-Loop Live Execution + Telemetry + Hypothesis + MAPE-K Adaptation
        observer = TelemetryObserver(total_budget_ms=genome.total_budget_ms)
        hyp_engine = AdversarialHypothesisEngine()
        mapek = MAPEKController(
            invariant_guard=self.invariant_guard,
            hypothesis_engine=hyp_engine,
            rule_efficacy_priors=self.memory.get_rule_efficacy(),
        )
        exec_ctx = StageExecutionContext(
            target_path=Path(target_path).resolve() if target_path else None,
            hardened_simulation=hardened_simulation,
            live_local_url=live_local_url,
            fuzz_iterations=genome.fuzz_iterations_per_grammar,
        )

        all_vulns: List[CyberVulnerability] = []
        stage_artifacts: Dict[str, Any] = {}
        stage_execution_order: List[str] = []

        while True:
            node = dag.next_ready_stage()
            if node is None:
                break

            node.status = StageStatus.RUNNING
            node.started_at = utc_now_iso()

            if node.category == StageCategory.SYNTHESIS_COMPLIANCE:
                node.elapsed_ms = 2.0
                node.status = StageStatus.COMPLETED
                node.completed_at = utc_now_iso()
                stage_execution_order.append(node.stage_id)
                continue

            res = self.registry.execute_stage(node.adapter_name, exec_ctx)
            node.elapsed_ms = res.elapsed_ms
            node.completed_at = utc_now_iso()
            stage_execution_order.append(node.stage_id)

            if res.error:
                node.status = StageStatus.FAILED
                node.error_message = res.error
                continue

            node.status = StageStatus.COMPLETED
            node.findings_count = len(res.vulnerabilities)
            node.critical_count = sum(1 for v in res.vulnerabilities if v.severity == Severity.CRITICAL)
            node.high_count = sum(1 for v in res.vulnerabilities if v.severity == Severity.HIGH)

            all_vulns.extend(res.vulnerabilities)
            exec_ctx.accumulated_vulns.extend(res.vulnerabilities)
            stage_artifacts.update(res.artifacts)

            # Update Thompson Sampling online posterior for this stage adapter
            rec, signals = observer.observe_stage(node, res.vulnerabilities, res.extra_metrics)
            self.thompson.observe_outcome(node.adapter_name, rec.risk_weighted_yield)

            # Update MAPE-K rule efficacy if this stage was injected by an adaptation rule
            if node.stage_id in mapek.injected_stage_to_rule:
                self.memory.update_rule_efficacy(mapek.injected_stage_to_rule[node.stage_id], rec.risk_weighted_yield)

            # Propose new Bayesian hypotheses & update existing hypotheses targeting this adapter
            hyp_engine.update_from_verification(
                node.adapter_name,
                res.vulnerabilities,
                extra_confirmed=bool(res.artifacts.get("fuzz_campaign", {}).get("unique_failures", 0)),
            )
            hyp_engine.propose_from_findings(node.stage_id, res.vulnerabilities)

            # Live MAPE-K Adaptation Step (if enabled)
            if enable_adaptation:
                mapek.adapt_step(
                    completed_node=node,
                    telemetry=rec,
                    signals=signals,
                    dag=dag,
                    genome=genome,
                )

        # 6. Cross-Domain Synthesis: Dedup + CVSS4/EPSS/KEV + Exploit Chains + Compliance + STRIDE
        deduped = self._deduplicate(all_vulns)
        risk_summary = self.risk_engine.enrich_and_prioritize(deduped, asset_criticality=asset_criticality)
        chain_report = self.chain_planner.plan_chains(deduped)
        compliance_report = self.compliance.evaluate(deduped)
        stride_report = self.stride.build_threat_model(exec_ctx.target_path, deduped)

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in deduped:
            sev_counts[v.severity.value] = sev_counts.get(v.severity.value, 0) + 1

        if sev_counts["critical"] > 0 or chain_report["max_chain_risk"] >= 70.0:
            gate_verdict = "BLOCKED"
        elif sev_counts["high"] > 2:
            gate_verdict = "CONDITIONAL"
        else:
            gate_verdict = "APPROVED"

        duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        tel_summary = observer.summary()

        # 7. Compute Meta-Reward in [0, 1] and Update LinUCB + Persist Meta-Memory
        reward = self._compute_meta_reward(
            total_yield=tel_summary["total_risk_weighted_yield"],
            duration_ms=duration_ms,
            budget_ms=genome.total_budget_ms,
            reproduced_count=risk_summary.get("sandbox_reproduced_count", 0),
            chains_found=chain_report["kill_chains_found"],
            pruned_count=sum(1 for n in dag.nodes.values() if n.status == StageStatus.PRUNED),
        )
        self.bandit.update(genome.profile_family, fingerprint.feature_vector, reward)
        self.memory.save_kv("linucb_state", self.bandit.export_state())
        self.memory.save_kv("thompson_state", {"alphas": self.thompson.alphas, "betas": self.thompson.betas})

        # Optional NSGA-II Pareto Evolution snapshot
        pareto_report = None
        if evolve_pareto:
            ev = self.evolution.evolve_pareto_frontier(
                fingerprint,
                population_size=14,
                generations=5,
                empirical_stage_means=self.thompson.posterior_means(),
            )
            pareto_report = {k: v for k, v in ev.items() if k != "recommended_genome"}

        # 8. Seal Run in Cryptographic Ledger
        self.ledger.append(
            event_type="H2_ADAPTIVE_RUN_COMPLETED",
            actor="ely_harness_squared",
            payload={
                "run_id": run_id,
                "target": fingerprint.target_name,
                "genome_arm": genome.profile_family,
                "adaptations_applied": mapek.applied_count,
                "total_vulns": len(deduped),
                "gate_verdict": gate_verdict,
                "reward": round(reward, 4),
            },
        )

        top_cwes = sorted({c for v in deduped for c in v.cwe_ids})[:10]
        remediation_recipes = self.cwe_kb.get_remediation_bundle(top_cwes)

        report: Dict[str, Any] = {
            "run_id": run_id,
            "started_at": started_at,
            "completed_at": utc_now_iso(),
            "duration_ms": duration_ms,
            "adaptation_enabled": enable_adaptation,
            "gate_verdict": gate_verdict,
            "overall_cyber_posture": float(risk_summary.get("overall_cyber_posture", 100.0)),
            "meta_reward": round(reward, 4),
            "severity_counts": sev_counts,
            "total_vulnerabilities": len(deduped),
            "target_fingerprint": fingerprint.to_dict(),
            "similar_historical_runs": similar_runs,
            "bandit_decision": bandit_decision,
            "thompson_stage_posteriors": self.thompson.posterior_means(),
            "selected_genome": genome.to_dict(),
            "workflow_dag": dag.to_dict(),
            "stage_execution_order": stage_execution_order,
            "telemetry": tel_summary,
            "mapek_adaptation": mapek.summary(),
            "hypotheses": hyp_engine.summary(),
            "safety_invariants": {
                "preflight_checks": [c.to_dict() for c in preflight_checks],
                "guard_ledger_summary": self.invariant_guard.ledger_summary(),
            },
            "portfolio_risk": risk_summary,
            "exploit_chains": {k: v for k, v in chain_report.items() if k != "raw_chains"},
            "compliance": compliance_report,
            "stride_threat_model": stride_report,
            "cwe_remediation_recipes": remediation_recipes,
            "stage_artifacts": stage_artifacts,
            "pareto_evolution": pareto_report,
            "vulnerabilities": [v.to_dict() for v in deduped],
        }

        self.memory.record_run(
            run_id=run_id,
            fingerprint=fingerprint,
            genome=genome,
            reward=reward,
            posture_score=report["overall_cyber_posture"],
            total_vulns=len(deduped),
            critical_vulns=sev_counts["critical"],
            adaptations_applied=mapek.applied_count,
            duration_ms=duration_ms,
            ttfc_ms=tel_summary["time_to_first_critical_ms"],
            report_summary=report,
        )
        return report

    def _compile_initial_dag(self, genome: HarnessGenome, fingerprint: TargetFingerprint) -> WorkflowDAG:
        dag = WorkflowDAG(total_budget_ms=genome.total_budget_ms)
        synthesis_node = WorkflowStageNode(
            stage_id="st_synthesis_gate",
            adapter_name="synthesis_gate",
            label="Cross-Domain Synthesis, Compliance & Gate",
            category=StageCategory.SYNTHESIS_COMPLIANCE,
            priority=0.05,
            budget_ms=500,
        )
        dag.add_node(synthesis_node)

        for adapter in genome.enabled_stages:
            if adapter not in STAGE_CATALOG:
                continue
            spec = STAGE_CATALOG[adapter]
            prior_p = float(genome.stage_priorities.get(adapter, 0.5))
            ts_p = self.thompson.sample_priority(adapter, prior_affinity=prior_p)
            node = WorkflowStageNode(
                stage_id=f"st_{adapter}",
                adapter_name=adapter,
                label=spec.label,
                category=spec.category,
                priority=ts_p,
                budget_ms=int(genome.stage_budgets_ms.get(adapter, spec.default_budget_ms)),
            )
            dag.add_node(node)
            dag.add_edge(node.stage_id, synthesis_node.stage_id, edge_kind="depends_on")

        # Wire natural ordering dependencies: static web before live DAST if both exist
        if "st_web_injection" in dag.nodes and "st_live_sandbox_dast" in dag.nodes:
            dag.add_edge("st_web_injection", "st_live_sandbox_dast", edge_kind="depends_on")
        if "st_mitre_sigma_purple" in dag.nodes and "st_bas_campaigns" in dag.nodes:
            dag.add_edge("st_mitre_sigma_purple", "st_bas_campaigns", edge_kind="depends_on")

        return dag

    @staticmethod
    def _compute_meta_reward(
        *,
        total_yield: float,
        duration_ms: float,
        budget_ms: int,
        reproduced_count: int,
        chains_found: int,
        pruned_count: int,
    ) -> float:
        yield_norm = min(1.0, total_yield / 220.0)
        speed_norm = max(0.0, min(1.0, 1.0 - (duration_ms / max(1000.0, float(budget_ms)))))
        repro_bonus = min(0.25, reproduced_count * 0.025)
        chain_bonus = min(0.15, chains_found * 0.025)
        prune_bonus = min(0.10, pruned_count * 0.04)
        return max(0.0, min(1.0, 0.45 * yield_norm + 0.25 * speed_norm + repro_bonus + chain_bonus + prune_bonus))

    @staticmethod
    def _deduplicate(vulns: Sequence[CyberVulnerability]) -> List[CyberVulnerability]:
        seen: Set[Tuple[str, str, int]] = set()
        out: List[CyberVulnerability] = []
        for v in vulns:
            key = (v.rule_id, v.file_path or v.endpoint_or_asset, v.line_start)
            if key in seen:
                continue
            seen.add(key)
            out.append(v)
        return out
