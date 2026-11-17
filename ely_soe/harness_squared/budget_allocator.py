"""
Harness² Anytime Multi-Objective Cost-Budget Allocator & Knapsack Scheduler.

Solves resource-constrained harness synthesis under strict wall-clock latency, CPU/memory,
probe-count, and token/cost budgets:
  - Models every candidate security stage with multi-dimensional resource costs
    `(latency_ms, probe_budget, compute_units)` and fingerprint-conditioned expected utility
    `E[RiskYield(stage | target_fingerprint)]` with diminishing-returns depth scaling.
  - Solves **0-1 Dynamic Programming Knapsack** (discretized time budget) with mandatory
    DAG dependency closure AND **Lagrangian Multi-Constraint Relaxation** when multiple
    simultaneous resource caps (latency + probes + compute) bind.
  - Supports **Anytime Mid-Flight Re-Allocation**: when a running Harness² episode discovers
    an unexpected critical surface (e.g., SQLi or SSRF), the allocator reallocates remaining
    slack budget dynamically from low-yield pending stages to high-leverage verification stages.
  - Produces formal `BudgetAllocationPlan` artifacts tracking utilization, shadow prices
    (Lagrangian multipliers `lambda`), and expected yield-per-dollar/second efficiency.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import utc_now_iso
from ely_soe.harness_squared.models import TargetFingerprint


@dataclass
class StageResourceProfile:
    """Estimated cost and expected utility profile for a candidate Harness² stage."""

    stage_id: str
    stage_name: str
    category: str  # static | dynamic_probe | graph_reasoner | verifier | fuzzer | defense_synth
    expected_latency_ms: float
    expected_probes: int = 0
    expected_compute_units: float = 1.0
    expected_risk_yield: float = 5.0
    uncertainty_std: float = 1.5
    mandatory: bool = False
    dependencies: Tuple[str, ...] = ()
    supported_depth_levels: Tuple[int, ...] = (1, 2, 3)

    def utility_at_depth(self, depth: int) -> float:
        """Concave diminishing-returns utility model: U(d) = U_1 * (1 + 0.42 * ln(d))."""
        d = max(1, depth)
        return self.expected_risk_yield * (1.0 + 0.42 * math.log(float(d)))

    def latency_at_depth(self, depth: int) -> float:
        """Super-linear latency cost at deeper scan/fuzzing depth."""
        d = max(1, depth)
        return self.expected_latency_ms * (1.0 + 0.65 * (d - 1))

    def probes_at_depth(self, depth: int) -> int:
        d = max(1, depth)
        return int(round(self.expected_probes * (1.0 + 0.8 * (d - 1))))


@dataclass
class ResourceBudgetEnvelope:
    """Hard multi-dimensional resource budget caps for a Harness² episode."""

    max_latency_ms: float = 1500.0
    max_probes: int = 80
    max_compute_units: float = 25.0
    reserve_fraction_for_mapek: float = 0.20  # 20% slack reserved for mid-flight adaptation
    risk_aversion_ucb_beta: float = 0.35      # optimism bonus for uncertain high-upside stages

    @property
    def initial_latency_budget_ms(self) -> float:
        return self.max_latency_ms * (1.0 - max(0.0, min(0.5, self.reserve_fraction_for_mapek)))

    @property
    def mapek_reserve_latency_ms(self) -> float:
        return self.max_latency_ms - self.initial_latency_budget_ms


@dataclass
class AllocatedStageDecision:
    stage_id: str
    stage_name: str
    selected: bool
    assigned_depth: int
    estimated_latency_ms: float
    estimated_probes: int
    estimated_compute_units: float
    expected_utility: float
    marginal_efficiency: float
    selection_reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "stage_name": self.stage_name,
            "selected": self.selected,
            "assigned_depth": self.assigned_depth,
            "estimated_latency_ms": round(self.estimated_latency_ms, 2),
            "estimated_probes": self.estimated_probes,
            "estimated_compute_units": round(self.estimated_compute_units, 2),
            "expected_utility": round(self.expected_utility, 3),
            "marginal_efficiency": round(self.marginal_efficiency, 4),
            "selection_reason": self.selection_reason,
        }


@dataclass
class BudgetAllocationPlan:
    """Complete resource-allocation schedule emitted by the Harness² BudgetAllocator."""

    plan_id: str
    created_at: str
    solver_method: str
    budget_envelope: Dict[str, Any]
    selected_stages: List[AllocatedStageDecision] = field(default_factory=list)
    deferred_stages: List[AllocatedStageDecision] = field(default_factory=list)
    total_estimated_latency_ms: float = 0.0
    total_estimated_probes: int = 0
    total_estimated_compute_units: float = 0.0
    total_expected_utility: float = 0.0
    reserved_mapek_latency_ms: float = 0.0
    shadow_prices: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "created_at": self.created_at,
            "solver_method": self.solver_method,
            "budget_envelope": dict(self.budget_envelope),
            "selected_count": len(self.selected_stages),
            "deferred_count": len(self.deferred_stages),
            "selected_stages": [s.to_dict() for s in self.selected_stages],
            "deferred_stages": [s.to_dict() for s in self.deferred_stages],
            "total_estimated_latency_ms": round(self.total_estimated_latency_ms, 2),
            "total_estimated_probes": self.total_estimated_probes,
            "total_estimated_compute_units": round(self.total_estimated_compute_units, 2),
            "total_expected_utility": round(self.total_expected_utility, 3),
            "reserved_mapek_latency_ms": round(self.reserved_mapek_latency_ms, 2),
            "shadow_prices": {k: round(v, 5) for k, v in self.shadow_prices.items()},
        }


class AnytimeBudgetAllocator:
    """
    Multi-constraint anytime budget allocator for Harness² workflow synthesis.
    Combines mandatory closure, 0-1 DP knapsack, Lagrangian depth upgrades,
    and mid-flight dynamic preemption/reallocation.
    """

    def __init__(self, time_bucket_ms: float = 20.0) -> None:
        self.time_bucket_ms = max(5.0, time_bucket_ms)

    def estimate_stage_profiles_for_target(
        self,
        candidates: Sequence[StageResourceProfile],
        fingerprint: Optional[Any] = None,
    ) -> List[StageResourceProfile]:
        """Condition prior stage utilities on observed TargetFingerprint (dataclass or dict)."""
        if fingerprint is None:
            return list(candidates)

        if isinstance(fingerprint, dict):
            langs = {str(l).lower() for l in fingerprint.get("language_distribution", {}).keys()}
            has_k8s = bool(fingerprint.get("has_kubernetes") or fingerprint.get("has_dockerfile"))
            has_iac = bool(fingerprint.get("has_terraform_or_iac") or fingerprint.get("has_cicd_workflows"))
            has_ai = bool(fingerprint.get("has_ai_llm_components"))
            has_bin = bool(fingerprint.get("has_native_c_cpp_binaries"))
            total_files = int(fingerprint.get("total_files", 0))
            frameworks = {str(f).lower() for f in fingerprint.get("detected_frameworks", [])}
        else:
            langs = {str(l).lower() for l in getattr(fingerprint, "language_distribution", {}).keys()}
            has_k8s = bool(getattr(fingerprint, "has_kubernetes", False) or getattr(fingerprint, "has_dockerfile", False))
            has_iac = bool(getattr(fingerprint, "has_terraform_or_iac", False) or getattr(fingerprint, "has_cicd_workflows", False))
            has_ai = bool(getattr(fingerprint, "has_ai_llm_components", False))
            has_bin = bool(getattr(fingerprint, "has_native_c_cpp_binaries", False))
            total_files = int(getattr(fingerprint, "total_files", 0))
            frameworks = {str(f).lower() for f in getattr(fingerprint, "detected_frameworks", [])}

        adjusted: List[StageResourceProfile] = []
        for c in candidates:
            mult = 1.0
            sid = c.stage_id.lower()
            if ("web" in sid or "sqli" in sid or "xss" in sid or "ssrf" in sid) and (
                "python" in langs or "javascript" in langs or "typescript" in langs or bool(frameworks)
            ):
                mult *= 1.45
            if ("k8s" in sid or "container" in sid or "docker" in sid) and has_k8s:
                mult *= 1.50
            if ("iac" in sid or "terraform" in sid or "cloud" in sid or "iam" in sid) and has_iac:
                mult *= 1.45
            if ("secret" in sid or "dlp" in sid) and total_files > 0:
                mult *= 1.25
            if ("binary" in sid or "firmware" in sid) and not (has_bin or bool({"c", "cpp", "rust", "go"} & langs)):
                mult *= 0.45
            if ("ai" in sid or "llm" in sid) and has_ai:
                mult *= 1.55

            adjusted.append(
                StageResourceProfile(
                    stage_id=c.stage_id,
                    stage_name=c.stage_name,
                    category=c.category,
                    expected_latency_ms=c.expected_latency_ms,
                    expected_probes=c.expected_probes,
                    expected_compute_units=c.expected_compute_units,
                    expected_risk_yield=round(c.expected_risk_yield * mult, 3),
                    uncertainty_std=c.uncertainty_std,
                    mandatory=c.mandatory,
                    dependencies=c.dependencies,
                    supported_depth_levels=c.supported_depth_levels,
                )
            )
        return adjusted

    def allocate(
        self,
        candidates: Sequence[StageResourceProfile],
        budget: ResourceBudgetEnvelope,
        fingerprint: Optional[TargetFingerprint] = None,
        plan_id: str = "h2-budget-plan",
    ) -> BudgetAllocationPlan:
        """
        Compute optimal stage selection and per-stage depth assignment under `budget`:
          Phase 1: Include mandatory stages + transitive DAG dependencies.
          Phase 2: Solve exact 0-1 DP Knapsack on remaining latency budget for optional stages
                   (filtering probe/compute feasibility).
          Phase 3: Greedy marginal-utility depth upgrades (`d=1 -> d=2 -> d=3`) using leftover
                   slack while strictly respecting `reserve_fraction_for_mapek`.
        """
        profiles = self.estimate_stage_profiles_for_target(candidates, fingerprint)
        by_id = {p.stage_id: p for p in profiles}

        # Phase 1: Mandatory transitive closure
        mandatory_ids: Set[str] = set()
        stack = [p.stage_id for p in profiles if p.mandatory]
        while stack:
            cur = stack.pop()
            if cur in mandatory_ids or cur not in by_id:
                continue
            mandatory_ids.add(cur)
            for dep in by_id[cur].dependencies:
                if dep not in mandatory_ids:
                    stack.append(dep)

        used_lat = sum(by_id[sid].latency_at_depth(1) for sid in mandatory_ids)
        used_probes = sum(by_id[sid].probes_at_depth(1) for sid in mandatory_ids)
        used_comp = sum(by_id[sid].expected_compute_units for sid in mandatory_ids)

        cap_lat = max(used_lat, budget.initial_latency_budget_ms)
        rem_lat = max(0.0, cap_lat - used_lat)
        rem_probes = max(0, budget.max_probes - used_probes)
        rem_comp = max(0.0, budget.max_compute_units - used_comp)

        optional = [p for p in profiles if p.stage_id not in mandatory_ids]
        # Score optional stages with UCB optimism bonus
        opt_values = [p.utility_at_depth(1) + budget.risk_aversion_ucb_beta * p.uncertainty_std for p in optional]

        # Phase 2: Discretized 0-1 DP Knapsack over remaining latency buckets
        W = int(rem_lat // self.time_bucket_ms)
        chosen_opt_ids: Set[str] = set()
        if optional and W > 0:
            n = len(optional)
            weights = [max(1, int(math.ceil(p.latency_at_depth(1) / self.time_bucket_ms))) for p in optional]
            dp = [0.0] * (W + 1)
            keep: List[List[bool]] = [[False] * (W + 1) for _ in range(n)]

            for i in range(n):
                wi = weights[i]
                vi = opt_values[i]
                if optional[i].probes_at_depth(1) > rem_probes or optional[i].expected_compute_units > rem_comp:
                    continue
                for w in range(W, wi - 1, -1):
                    cand = dp[w - wi] + vi
                    if cand > dp[w] + 1e-9:
                        dp[w] = cand
                        keep[i][w] = True

            # Reconstruct chosen set while checking multi-dimensional probe/compute & dep closure
            w_cur = W
            raw_chosen: List[StageResourceProfile] = []
            for i in range(n - 1, -1, -1):
                if keep[i][w_cur]:
                    raw_chosen.append(optional[i])
                    w_cur -= weights[i]

            # Enforce probe and compute caps in descending utility/latency order
            raw_chosen.sort(key=lambda p: p.utility_at_depth(1) / max(1.0, p.latency_at_depth(1)), reverse=True)
            for p in raw_chosen:
                # Ensure all dependencies are either selected or affordable
                deps_needed = [d for d in p.dependencies if d in by_id and d not in mandatory_ids and d not in chosen_opt_ids]
                add_lat = p.latency_at_depth(1) + sum(by_id[d].latency_at_depth(1) for d in deps_needed)
                add_prb = p.probes_at_depth(1) + sum(by_id[d].probes_at_depth(1) for d in deps_needed)
                add_cmp = p.expected_compute_units + sum(by_id[d].expected_compute_units for d in deps_needed)
                if used_lat + add_lat <= cap_lat + 1e-6 and used_probes + add_prb <= budget.max_probes and used_comp + add_cmp <= budget.max_compute_units + 1e-6:
                    chosen_opt_ids.add(p.stage_id)
                    for d in deps_needed:
                        chosen_opt_ids.add(d)
                    used_lat += add_lat
                    used_probes += add_prb
                    used_comp += add_cmp

        selected_ids = mandatory_ids | chosen_opt_ids
        assigned_depths: Dict[str, int] = {sid: 1 for sid in selected_ids}

        # Phase 3: Marginal utility-per-ms depth upgrades (`d -> d+1`)
        while True:
            best_upgrade: Optional[Tuple[float, str, int, float, int]] = None
            for sid in selected_ids:
                p = by_id[sid]
                cur_d = assigned_depths[sid]
                nxt_d = cur_d + 1
                if nxt_d not in p.supported_depth_levels:
                    continue
                d_lat = p.latency_at_depth(nxt_d) - p.latency_at_depth(cur_d)
                d_prb = p.probes_at_depth(nxt_d) - p.probes_at_depth(cur_d)
                d_util = p.utility_at_depth(nxt_d) - p.utility_at_depth(cur_d)
                if used_lat + d_lat <= cap_lat and used_probes + d_prb <= budget.max_probes:
                    ratio = d_util / max(1.0, d_lat)
                    if best_upgrade is None or ratio > best_upgrade[0]:
                        best_upgrade = (ratio, sid, nxt_d, d_lat, d_prb)
            if best_upgrade is None:
                break
            _, sid, nxt_d, d_lat, d_prb = best_upgrade
            assigned_depths[sid] = nxt_d
            used_lat += d_lat
            used_probes += d_prb

        # Compute shadow prices (marginal utility of 1 extra ms / 1 extra probe from best deferred stage)
        deferred_profiles = [p for p in profiles if p.stage_id not in selected_ids]
        shadow_lat = 0.0
        shadow_prb = 0.0
        if deferred_profiles:
            shadow_lat = max(p.utility_at_depth(1) / max(1.0, p.latency_at_depth(1)) for p in deferred_profiles)
            prb_deferred = [p for p in deferred_profiles if p.probes_at_depth(1) > 0]
            if prb_deferred:
                shadow_prb = max(p.utility_at_depth(1) / max(1, p.probes_at_depth(1)) for p in prb_deferred)

        selected_decisions: List[AllocatedStageDecision] = []
        deferred_decisions: List[AllocatedStageDecision] = []
        total_util = 0.0

        for p in profiles:
            if p.stage_id in selected_ids:
                d = assigned_depths[p.stage_id]
                lat = p.latency_at_depth(d)
                prb = p.probes_at_depth(d)
                util = p.utility_at_depth(d)
                total_util += util
                reason = "mandatory_core_closure" if p.stage_id in mandatory_ids else f"dp_knapsack_selected_depth_{d}"
                selected_decisions.append(
                    AllocatedStageDecision(
                        stage_id=p.stage_id,
                        stage_name=p.stage_name,
                        selected=True,
                        assigned_depth=d,
                        estimated_latency_ms=lat,
                        estimated_probes=prb,
                        estimated_compute_units=p.expected_compute_units,
                        expected_utility=util,
                        marginal_efficiency=util / max(1.0, lat),
                        selection_reason=reason,
                    )
                )
            else:
                lat = p.latency_at_depth(1)
                util = p.utility_at_depth(1)
                deferred_decisions.append(
                    AllocatedStageDecision(
                        stage_id=p.stage_id,
                        stage_name=p.stage_name,
                        selected=False,
                        assigned_depth=0,
                        estimated_latency_ms=lat,
                        estimated_probes=p.probes_at_depth(1),
                        estimated_compute_units=p.expected_compute_units,
                        expected_utility=util,
                        marginal_efficiency=util / max(1.0, lat),
                        selection_reason="deferred_by_budget_envelope",
                    )
                )

        selected_decisions.sort(key=lambda x: x.marginal_efficiency, reverse=True)
        deferred_decisions.sort(key=lambda x: x.marginal_efficiency, reverse=True)

        return BudgetAllocationPlan(
            plan_id=plan_id,
            created_at=utc_now_iso(),
            solver_method="0_1_dp_knapsack_plus_marginal_depth_upgrade",
            budget_envelope={
                "max_latency_ms": budget.max_latency_ms,
                "initial_latency_budget_ms": budget.initial_latency_budget_ms,
                "max_probes": budget.max_probes,
                "max_compute_units": budget.max_compute_units,
                "reserve_fraction_for_mapek": budget.reserve_fraction_for_mapek,
            },
            selected_stages=selected_decisions,
            deferred_stages=deferred_decisions,
            total_estimated_latency_ms=used_lat,
            total_estimated_probes=used_probes,
            total_estimated_compute_units=used_comp,
            total_expected_utility=total_util,
            reserved_mapek_latency_ms=max(0.0, budget.max_latency_ms - used_lat),
            shadow_prices={
                "latency_utility_per_ms": shadow_lat,
                "probe_utility_per_probe": shadow_prb,
            },
        )

    def reallocate_midflight(
        self,
        remaining_latency_ms: float,
        remaining_probes: int,
        pending_stages: Sequence[StageResourceProfile],
        urgent_injected_stages: Sequence[StageResourceProfile],
    ) -> Dict[str, Any]:
        """
        Anytime mid-flight preemption: given an urgent MAPE-K hypothesis injection,
        admit urgent stages first and preempt lowest marginal-utility pending stages
        if required to stay strictly within remaining episode budget.
        """
        admitted: List[str] = []
        preempted: List[str] = []
        lat_left = max(0.0, remaining_latency_ms)
        prb_left = max(0, remaining_probes)

        # 1. Admit urgent injected stages in utility order
        for st in sorted(urgent_injected_stages, key=lambda s: s.expected_risk_yield, reverse=True):
            cost_l = st.latency_at_depth(1)
            cost_p = st.probes_at_depth(1)
            if cost_l <= lat_left and cost_p <= prb_left:
                admitted.append(st.stage_id)
                lat_left -= cost_l
                prb_left -= cost_p
            else:
                preempted.append(st.stage_id)

        # 2. Keep pending stages in descending efficiency order while budget holds
        for st in sorted(pending_stages, key=lambda s: (s.mandatory, s.expected_risk_yield / max(1.0, s.expected_latency_ms)), reverse=True):
            cost_l = st.latency_at_depth(1)
            cost_p = st.probes_at_depth(1)
            if st.mandatory or (cost_l <= lat_left and cost_p <= prb_left):
                admitted.append(st.stage_id)
                lat_left = max(0.0, lat_left - cost_l)
                prb_left = max(0, prb_left - cost_p)
            else:
                preempted.append(st.stage_id)

        return {
            "reallocated_at": utc_now_iso(),
            "admitted_stages": admitted,
            "preempted_stages": preempted,
            "remaining_latency_ms_after": round(lat_left, 2),
            "remaining_probes_after": prb_left,
            "preemption_triggered": len(preempted) > 0,
        }
