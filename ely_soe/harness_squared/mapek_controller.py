"""
Harness² Autonomic MAPE-K (Monitor – Analyze – Plan – Execute – Knowledge) Live Adaptation Controller.

Closes the second-order control loop *during* live security workflow execution:
  - **Monitor**: Reads `StageTelemetryRecord`, emitted `TelemetrySignal`s, and `WorkflowDAG` state
  - **Analyze**: Evaluates **10 Cross-Domain Adaptation Rules** + `AdversarialHypothesisEngine`
    proposals, skipping rules historically proven ineffective in `MetaMemoryStore`
  - **Plan**: Ranks candidate `AdaptationDirective` actions by Expected Value of Information (EVI)
    scaled by `genome.drilldown_aggressiveness`
  - **Execute**: Passes EVERY directive through `MetaSafetyInvariantGuard.verify_adaptation_directive`
    before applying atomic mutations to `WorkflowDAG` (drilldown injection, branch pruning,
    budget reallocation, priority elevation, or validation escalation)
  - **Knowledge**: Tracks which injected stages yielded additional risk so `MetaMemoryStore`
    updates each rule's empirical hit rate after execution!
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import new_id
from ely_soe.harness_squared.hypothesis_engine import AdversarialHypothesisEngine
from ely_soe.harness_squared.models import (
    AdaptationActionType,
    AdaptationDirective,
    HarnessGenome,
    StageCategory,
    StageStatus,
    StageTelemetryRecord,
    TelemetrySignal,
    WorkflowStageNode,
)
from ely_soe.harness_squared.safety_invariant_guard import MetaSafetyInvariantGuard
from ely_soe.harness_squared.stage_registry import STAGE_CATALOG
from ely_soe.harness_squared.workflow_dag import WorkflowDAG


@dataclass(frozen=True)
class MAPEKRule:
    rule_id: str
    trigger_signal: str
    action_type: AdaptationActionType
    inject_adapter: Optional[str]
    base_evi: float
    rationale: str


BUILTIN_MAPEK_RULES: Tuple[MAPEKRule, ...] = (
    MAPEKRule(
        "MAPEK-R01-SQLI-DAST",
        "pivot_injection_to_dast_and_fuzz",
        AdaptationActionType.EXPAND_DRILLDOWN,
        "live_sandbox_dast",
        0.92,
        "Static injection sink detected -> inject live loopback DAST sandbox verifier to prove exploitability.",
    ),
    MAPEKRule(
        "MAPEK-R02-SQLI-FUZZ",
        "pivot_injection_to_dast_and_fuzz",
        AdaptationActionType.EXPAND_DRILLDOWN,
        "grammar_fuzzer",
        0.80,
        "Injection CWE cluster detected -> inject grammar-aware multi-protocol fuzzer for boundary stress-testing.",
    ),
    MAPEKRule(
        "MAPEK-R03-SSRF-IAM",
        "pivot_ssrf_to_cloud_iam",
        AdaptationActionType.EXPAND_DRILLDOWN,
        "cloud_iam_graph",
        0.90,
        "SSRF/server-side exposure found -> inject Cloud IAM privilege-escalation graph solver for IMDS blast radius.",
    ),
    MAPEKRule(
        "MAPEK-R04-SECRET-SBOM",
        "pivot_secrets_to_supply_chain",
        AdaptationActionType.EXPAND_DRILLDOWN,
        "supply_chain_sbom",
        0.86,
        "Exposed credentials or supply-chain weakness -> inject SBOM/CVE/typosquatting integrity audit.",
    ),
    MAPEKRule(
        "MAPEK-R05-K8S-EBPF",
        "pivot_k8s_to_runtime_ebpf",
        AdaptationActionType.EXPAND_DRILLDOWN,
        "container_runtime_ebpf",
        0.91,
        "Container privilege risk detected -> inject Seccomp BPF / Capabilities / Falco eBPF escape drilldown.",
    ),
    MAPEKRule(
        "MAPEK-R06-AUTH-AD",
        "pivot_auth_to_identity_and_dast",
        AdaptationActionType.EXPAND_DRILLDOWN,
        "active_directory_graph",
        0.82,
        "Auth/JWT weakness detected -> expand identity graph analysis to check Tier-0 escalation chains.",
    ),
    MAPEKRule(
        "MAPEK-R07-AI-REDTEAM",
        "ai_surface_hit",
        AdaptationActionType.EXPAND_DRILLDOWN,
        "ai_llm_redteam",
        0.88,
        "AI/LLM surface signal -> inject OWASP LLM 2025 & MITRE ATLAS adversarial agent red-team suite.",
    ),
    MAPEKRule(
        "MAPEK-R08-CRIT-VALIDATE",
        "unverified_criticals",
        AdaptationActionType.ESCALATE_VALIDATION,
        "independent_validation_drilldown",
        0.95,
        "Multiple unverified critical findings -> escalate independent validator corroboration stage (SoD enforced).",
    ),
    MAPEKRule(
        "MAPEK-R09-SATURATION-PRUNE",
        "low_yield_saturation",
        AdaptationActionType.PRUNE_LOW_YIELD_BRANCH,
        None,
        0.74,
        "Consecutive zero-yield stages observed -> prune lowest-priority pending peripheral branch to preserve budget.",
    ),
    MAPEKRule(
        "MAPEK-R10-BUDGET-REALLOC",
        "budget_pressure",
        AdaptationActionType.REALLOCATE_BUDGET,
        None,
        0.78,
        "Workflow budget utilization exceeded 65% -> reallocate budget from lowest-priority stage to highest-priority frontier.",
    ),
)


class MAPEKController:
    """Closed-loop autonomic MAPE-K live adaptation controller governed by `MetaSafetyInvariantGuard`."""

    def __init__(
        self,
        invariant_guard: MetaSafetyInvariantGuard,
        hypothesis_engine: AdversarialHypothesisEngine,
        rules: Sequence[MAPEKRule] = BUILTIN_MAPEK_RULES,
        rule_efficacy_priors: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self.invariant_guard = invariant_guard
        self.hypothesis_engine = hypothesis_engine
        self.rules = list(rules)
        self.rule_efficacy_priors = rule_efficacy_priors or {}
        self.directives_history: List[AdaptationDirective] = []
        self.applied_count: int = 0
        self.injected_stage_to_rule: Dict[str, str] = {}
        self._fired_rule_adapter_keys: Set[Tuple[str, str]] = set()

    def adapt_step(
        self,
        *,
        completed_node: WorkflowStageNode,
        telemetry: StageTelemetryRecord,
        signals: Sequence[TelemetrySignal],
        dag: WorkflowDAG,
        genome: HarnessGenome,
    ) -> List[AdaptationDirective]:
        """Run one complete Monitor-Analyze-Plan-Execute cycle after a stage finishes."""
        candidates: List[AdaptationDirective] = []
        existing_adapters = {n.adapter_name for n in dag.nodes.values()}

        # ---- ANALYZE + PLAN (Rule-based signals) ----
        for sig in signals:
            for rule in self.rules:
                if rule.trigger_signal != sig.signal_type:
                    continue

                # Self-pruning: skip rules with strong historical zero-yield evidence (>= 5 pulls & hit_rate < 0.1)
                prior = self.rule_efficacy_priors.get(rule.rule_id)
                if prior and prior.get("times_triggered", 0) >= 5 and prior.get("hit_rate", 1.0) < 0.10:
                    continue

                evi = rule.base_evi * sig.strength * (0.65 + 0.35 * genome.drilldown_aggressiveness)

                if rule.action_type in (AdaptationActionType.EXPAND_DRILLDOWN, AdaptationActionType.ESCALATE_VALIDATION):
                    adapter = rule.inject_adapter
                    if not adapter or adapter not in STAGE_CATALOG:
                        continue
                    fire_key = (rule.rule_id, adapter)
                    if fire_key in self._fired_rule_adapter_keys:
                        continue
                    if adapter in existing_adapters:
                        # If already pending, boost its priority instead of duplicating
                        pending_match = [
                            n for n in dag.nodes.values()
                            if n.adapter_name == adapter and n.status == StageStatus.PENDING
                        ]
                        if pending_match:
                            self._fired_rule_adapter_keys.add(fire_key)
                            candidates.append(
                                AdaptationDirective(
                                    directive_id=new_id("dir"),
                                    rule_id=rule.rule_id,
                                    action_type=AdaptationActionType.REPRIORITIZE_QUEUE,
                                    target_stage_id=pending_match[0].stage_id,
                                    rationale=f"{rule.rationale} (Already scheduled -> elevating execution priority.)",
                                    expected_value_of_info=evi,
                                    payload={"new_priority": min(0.99, pending_match[0].priority + 0.25)},
                                )
                            )
                        continue

                    self._fired_rule_adapter_keys.add(fire_key)
                    spec = STAGE_CATALOG[adapter]
                    candidates.append(
                        AdaptationDirective(
                            directive_id=new_id("dir"),
                            rule_id=rule.rule_id,
                            action_type=rule.action_type,
                            target_stage_id=completed_node.stage_id,
                            rationale=rule.rationale,
                            expected_value_of_info=evi,
                            payload={
                                "adapter_name": adapter,
                                "label": spec.label,
                                "category": spec.category.value,
                                "budget_ms": min(spec.default_budget_ms, max(1200, dag.remaining_budget_ms() // 3)),
                                "priority": min(0.98, 0.78 + 0.18 * sig.strength),
                            },
                        )
                    )

                elif rule.action_type == AdaptationActionType.PRUNE_LOW_YIELD_BRANCH:
                    pending_low = [
                        n for n in dag.nodes.values()
                        if n.status == StageStatus.PENDING
                        and not n.injected_by_adaptation
                        and n.category != StageCategory.SYNTHESIS_COMPLIANCE
                        and n.priority <= 0.45
                    ]
                    if pending_low:
                        pending_low.sort(key=lambda n: n.priority)
                        victim = pending_low[0]
                        fire_key = (rule.rule_id, victim.stage_id)
                        if fire_key not in self._fired_rule_adapter_keys:
                            self._fired_rule_adapter_keys.add(fire_key)
                            candidates.append(
                                AdaptationDirective(
                                    directive_id=new_id("dir"),
                                    rule_id=rule.rule_id,
                                    action_type=AdaptationActionType.PRUNE_LOW_YIELD_BRANCH,
                                    target_stage_id=victim.stage_id,
                                    rationale=f"{rule.rationale} Victim: `{victim.stage_id}` (priority={victim.priority:.2f}).",
                                    expected_value_of_info=evi,
                                    payload={"victim_stage_id": victim.stage_id},
                                )
                            )

                elif rule.action_type == AdaptationActionType.REALLOCATE_BUDGET:
                    pending = [
                        n for n in dag.nodes.values()
                        if n.status == StageStatus.PENDING and n.category != StageCategory.SYNTHESIS_COMPLIANCE
                    ]
                    if len(pending) >= 2:
                        pending.sort(key=lambda n: n.priority)
                        donor, receiver = pending[0], pending[-1]
                        fire_key = (rule.rule_id, f"{donor.stage_id}->{receiver.stage_id}")
                        if fire_key not in self._fired_rule_adapter_keys and donor.budget_ms >= 900:
                            self._fired_rule_adapter_keys.add(fire_key)
                            delta = min(600, donor.budget_ms // 3)
                            candidates.append(
                                AdaptationDirective(
                                    directive_id=new_id("dir"),
                                    rule_id=rule.rule_id,
                                    action_type=AdaptationActionType.REALLOCATE_BUDGET,
                                    target_stage_id=receiver.stage_id,
                                    rationale=f"{rule.rationale} Shift {delta}ms from `{donor.stage_id}` to `{receiver.stage_id}`.",
                                    expected_value_of_info=evi,
                                    payload={"from_stage_id": donor.stage_id, "to_stage_id": receiver.stage_id, "delta_ms": delta},
                                )
                            )

        # ---- PLAN (Bayesian Hypothesis Verification Micro-Stage Injection) ----
        for hyp in self.hypothesis_engine.hypotheses.values():
            adapter = hyp.target_verification_adapter
            if hyp.status.value == "proposed" and adapter in STAGE_CATALOG and adapter not in existing_adapters:
                fire_key = ("HYPOTHESIS_INJECT", adapter)
                if fire_key not in self._fired_rule_adapter_keys and hyp.prior_probability >= (1.0 - genome.drilldown_aggressiveness * 0.5):
                    self._fired_rule_adapter_keys.add(fire_key)
                    spec = STAGE_CATALOG[adapter]
                    candidates.append(
                        AdaptationDirective(
                            directive_id=new_id("dir"),
                            rule_id=f"HYP-{hyp.hypothesis_id}",
                            action_type=AdaptationActionType.INJECT_HYPOTHESIS_PROBE,
                            target_stage_id=completed_node.stage_id,
                            rationale=f"Hypothesis `{hyp.title}` (prior={hyp.prior_probability:.2f}) -> inject `{adapter}` verification.",
                            expected_value_of_info=hyp.prior_probability * 0.90,
                            payload={
                                "adapter_name": adapter,
                                "label": f"[Hyp] {spec.label}",
                                "category": StageCategory.HYPOTHESIS_DRILLDOWN.value,
                                "budget_ms": min(spec.default_budget_ms, 2200),
                                "priority": min(0.97, 0.75 + 0.2 * hyp.prior_probability),
                                "hypothesis_id": hyp.hypothesis_id,
                            },
                        )
                    )

        # Sort directives by highest EVI first and cap per-step mutations to avoid thrashing
        candidates.sort(key=lambda d: -d.expected_value_of_info)
        executed: List[AdaptationDirective] = []

        # ---- EXECUTE (Safety-Invariant Gated) ----
        for directive in candidates[:3]:
            check = self.invariant_guard.verify_adaptation_directive(
                directive,
                current_adaptation_count=self.applied_count,
                max_adaptation_rounds=genome.max_adaptation_rounds,
                current_node_count=len(dag.nodes),
                remaining_budget_ms=dag.remaining_budget_ms(),
                would_create_cycle=False,
            )
            self.directives_history.append(directive)
            if not check.passed:
                continue

            applied = self._apply_directive(directive, dag)
            directive.applied = applied
            if applied:
                self.applied_count += 1
                executed.append(directive)

        return executed

    def _apply_directive(self, directive: AdaptationDirective, dag: WorkflowDAG) -> bool:
        act = directive.action_type
        p = directive.payload

        if act in (AdaptationActionType.EXPAND_DRILLDOWN, AdaptationActionType.ESCALATE_VALIDATION, AdaptationActionType.INJECT_HYPOTHESIS_PROBE):
            adapter = str(p["adapter_name"])
            if any(n.adapter_name == adapter for n in dag.nodes.values()):
                return False
            new_id_str = f"st_adapt_{adapter}"
            cat = StageCategory(str(p.get("category", StageCategory.HYPOTHESIS_DRILLDOWN.value)))
            node = WorkflowStageNode(
                stage_id=new_id_str,
                adapter_name=adapter,
                label=str(p.get("label", adapter)),
                category=cat,
                priority=float(p.get("priority", 0.85)),
                budget_ms=int(p.get("budget_ms", 2000)),
                injected_by_adaptation=True,
                injection_reason=directive.rationale,
            )
            cp = dag.checkpoint()
            try:
                dag.inject_drilldown_after(directive.target_stage_id, node, connect_before_synthesis=True)
                if dag.has_cycle():
                    dag.rollback(cp)
                    return False
                self.injected_stage_to_rule[node.stage_id] = directive.rule_id
                return True
            except Exception:
                dag.rollback(cp)
                return False

        if act == AdaptationActionType.PRUNE_LOW_YIELD_BRANCH:
            return dag.prune_stage(str(p["victim_stage_id"]), directive.rationale) > 0

        if act == AdaptationActionType.REALLOCATE_BUDGET:
            return dag.reallocate_budget(str(p["from_stage_id"]), str(p["to_stage_id"]), int(p["delta_ms"]))

        if act == AdaptationActionType.REPRIORITIZE_QUEUE:
            return dag.reprioritize_stage(directive.target_stage_id, float(p["new_priority"]))

        return False

    def summary(self) -> Dict[str, Any]:
        return {
            "total_directives_evaluated": len(self.directives_history),
            "total_adaptations_applied": self.applied_count,
            "rejected_by_invariant_guard": sum(1 for d in self.directives_history if not d.approved_by_invariant_guard),
            "directives": [d.to_dict() for d in self.directives_history],
        }
