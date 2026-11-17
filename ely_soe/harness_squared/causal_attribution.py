"""
Harness² Causal Credit Assignment, Exact/Monte-Carlo Shapley Attribution & Stage ROI Analyzer.

Computes exact coalition Shapley values (for `n <= 10` stages) and antithetic Monte-Carlo
Shapley values (for `n > 10`) directly over completed `HarnessSquaredEngine` run reports
or raw stage-level findings, decomposing:
  - Exact marginal risk-yield credit per executed stage (`sum(phi_i) == v(N)`)
  - Unique discoveries vs overlap redundancy ratio (`REDUNDANT_CANDIDATE`, `PRUNE_CANDIDATE`)
  - Leave-one-out critical recall loss
  - Counterfactual MAPE-K adaptation lift per rule ID (`MAPEK-R01-SQLI-DAST`, etc.)
  - Gini yield concentration & Pareto efficiency metrics.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import CyberVulnerability, GeneralizedExploitChain


SEVERITY_YIELD_WEIGHTS: Dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.1,
}


@dataclass
class StageAttributionRecord:
    """Causal credit assignment metrics for a single executed Harness² stage."""

    stage_id: str
    adapter_name: str
    was_injected_by_mapek: bool
    elapsed_ms: float
    raw_finding_count: int
    unique_finding_count: int
    shapley_risk_yield: float
    shapley_share_pct: float
    leave_one_out_yield_loss: float
    leave_one_out_critical_loss: int
    overlap_redundancy_ratio: float
    yield_per_second: float
    classification: str  # INDISPENSABLE | HIGH_LEVERAGE | COMPLEMENTARY | REDUNDANT_CANDIDATE | PRUNE_CANDIDATE
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "adapter_name": self.adapter_name,
            "was_injected_by_mapek": self.was_injected_by_mapek,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "raw_finding_count": self.raw_finding_count,
            "unique_finding_count": self.unique_finding_count,
            "shapley_risk_yield": round(self.shapley_risk_yield, 4),
            "shapley_share_pct": round(self.shapley_share_pct, 2),
            "leave_one_out_yield_loss": round(self.leave_one_out_yield_loss, 4),
            "leave_one_out_critical_loss": self.leave_one_out_critical_loss,
            "overlap_redundancy_ratio": round(self.overlap_redundancy_ratio, 4),
            "yield_per_second": round(self.yield_per_second, 2),
            "classification": self.classification,
            "recommendation": self.recommendation,
        }


@dataclass
class AdaptationRuleAttribution:
    """Counterfactual lift attribution for a single triggered MAPE-K directive."""

    rule_id: str
    action_type: str
    target_stage_id: str
    unlocked_findings: int
    unlocked_criticals: int
    unlocked_risk_yield: float
    added_latency_ms: float
    marginal_roi_yield_per_sec: float
    verdict: str  # HIGH_VALUE_ADAPTATION | POSITIVE_LIFT | NEUTRAL | COSTLY_NO_LIFT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "action_type": self.action_type,
            "target_stage_id": self.target_stage_id,
            "unlocked_findings": self.unlocked_findings,
            "unlocked_criticals": self.unlocked_criticals,
            "unlocked_risk_yield": round(self.unlocked_risk_yield, 3),
            "added_latency_ms": round(self.added_latency_ms, 2),
            "marginal_roi_yield_per_sec": round(self.marginal_roi_yield_per_sec, 2),
            "verdict": self.verdict,
        }


@dataclass
class CausalAttributionReport:
    """Complete Shapley + Counterfactual causal credit assignment report for a Harness² run."""

    run_id: str
    computed_at: str
    computation_method: str  # exact_coalition_shapley | stratified_mc_shapley
    total_coalition_risk_yield: float
    baseline_static_yield: float
    adaptive_counterfactual_lift: float
    adaptive_lift_share_pct: float
    efficiency_check_error: float
    stage_attributions: List[StageAttributionRecord] = field(default_factory=list)
    adaptation_attributions: List[AdaptationRuleAttribution] = field(default_factory=list)
    prune_candidates: List[str] = field(default_factory=list)
    indispensable_stages: List[str] = field(default_factory=list)
    pareto_efficiency_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "computed_at": self.computed_at,
            "computation_method": self.computation_method,
            "total_coalition_risk_yield": round(self.total_coalition_risk_yield, 4),
            "baseline_static_yield": round(self.baseline_static_yield, 4),
            "adaptive_counterfactual_lift": round(self.adaptive_counterfactual_lift, 4),
            "adaptive_lift_share_pct": round(self.adaptive_lift_share_pct, 2),
            "efficiency_check_error": round(self.efficiency_check_error, 6),
            "stage_attributions": [s.to_dict() for s in self.stage_attributions],
            "adaptation_attributions": [a.to_dict() for a in self.adaptation_attributions],
            "prune_candidates": list(self.prune_candidates),
            "indispensable_stages": list(self.indispensable_stages),
            "pareto_efficiency_summary": dict(self.pareto_efficiency_summary),
        }


def _vuln_dict_fingerprint(v: Dict[str, Any]) -> str:
    return str(v.get("fingerprint") or f"{v.get('rule_id','')}|{v.get('file_path','')}:{v.get('line_start',0)}|{v.get('endpoint_or_asset','')}")


def _vuln_dict_yield(v: Dict[str, Any]) -> float:
    sev = str(v.get("severity", "medium")).lower()
    base = SEVERITY_YIELD_WEIGHTS.get(sev, 1.0)
    conf = float(v.get("confidence", 0.85))
    conf_mult = 0.5 + 0.5 * max(0.0, min(1.0, conf))
    repro_bonus = 1.25 if v.get("sandbox_reproduced") else 1.0
    return base * conf_mult * repro_bonus


class CausalAttributionEngine:
    """
    Computes exact and Monte-Carlo Shapley values and counterfactual MAPE-K rule
    credit assignment over Harness² execution telemetry.
    """

    def __init__(self, exact_stage_limit: int = 10, mc_permutations: int = 400, seed: int = 42) -> None:
        self.exact_stage_limit = exact_stage_limit
        self.mc_permutations = mc_permutations
        self.seed = seed

    def attribute_from_run(self, run_report: Dict[str, Any]) -> CausalAttributionReport:
        """
        Compute exact/MC Shapley causal credit assignment directly from a
        `HarnessSquaredEngine.run_adaptive_assessment(...)` dict.
        """
        run_id = str(run_report.get("run_id", "h2-run"))
        telemetry = run_report.get("telemetry", {})
        stage_records: List[Dict[str, Any]] = list(telemetry.get("stage_records", []))
        vulns: List[Dict[str, Any]] = list(run_report.get("vulnerabilities", []))
        directives: List[Dict[str, Any]] = list(run_report.get("mapek_adaptation", {}).get("directives", []))
        dag_nodes: List[Dict[str, Any]] = list(run_report.get("workflow_dag", {}).get("nodes", []))
        chains_raw: List[Dict[str, Any]] = list(run_report.get("exploit_chains", {}).get("top_chains", []))

        injected_ids: Set[str] = {
            str(n.get("stage_id")) for n in dag_nodes if n.get("injected_by_adaptation")
        }
        for d in directives:
            if d.get("applied") and str(d.get("action_type", "")) in ("inject_stage", "inject_drilldown", "add_stage"):
                if d.get("target_stage_id"):
                    injected_ids.add(str(d["target_stage_id"]))

        # Map each vulnerability to the stage(s) whose adapter/domains/CWEs match its provenance
        fp_weights: Dict[str, float] = {}
        fp_is_critical: Dict[str, bool] = {}
        stage_fp_sets: Dict[str, Set[str]] = {str(r["stage_id"]): set() for r in stage_records}
        stage_meta: Dict[str, Dict[str, Any]] = {str(r["stage_id"]): r for r in stage_records}

        for v in vulns:
            fp = _vuln_dict_fingerprint(v)
            w = _vuln_dict_yield(v)
            if fp not in fp_weights or w > fp_weights[fp]:
                fp_weights[fp] = w
            if str(v.get("severity", "")).lower() == "critical":
                fp_is_critical[fp] = True

            disc = str(v.get("discovered_by", "")).lower()
            v_dom = str(v.get("cyber_domain", "")).lower()
            v_cwes = set(v.get("cwe_ids", []))
            matched_any = False

            for r in stage_records:
                sid = str(r["stage_id"])
                adapter = str(r.get("adapter_name", "")).lower()
                r_doms = {str(d).lower() for d in r.get("distinct_domains", [])}
                r_cwes = set(r.get("distinct_cwes", []))
                adapter_tokens = [t for t in adapter.split("_") if len(t) > 2]

                if (
                    adapter in disc
                    or any(tok in disc for tok in adapter_tokens)
                    or (v_dom and v_dom in r_doms and (not v_cwes or bool(v_cwes & r_cwes)))
                ):
                    stage_fp_sets[sid].add(fp)
                    matched_any = True

            if not matched_any and stage_records:
                # Assign to highest-finding stage whose CWEs overlap or highest overall
                best_r = max(
                    stage_records,
                    key=lambda r: (len(v_cwes & set(r.get("distinct_cwes", []))), int(r.get("findings_total", 0))),
                )
                stage_fp_sets[str(best_r["stage_id"])].add(fp)

        # Ensure stages with recorded telemetry yield that didn't match deduped vulns still get synthetic unique evidence tokens
        for r in stage_records:
            sid = str(r["stage_id"])
            if not stage_fp_sets[sid] and float(r.get("risk_weighted_yield", 0.0)) > 0:
                syn_fp = f"STAGE_TELEM|{sid}"
                fp_weights[syn_fp] = float(r["risk_weighted_yield"])
                fp_is_critical[syn_fp] = int(r.get("critical_count", 0)) > 0
                stage_fp_sets[sid].add(syn_fp)

        # Chain bonuses
        chain_bonuses: List[Tuple[Set[str], float]] = []
        fp_to_rule = {fp: fp.split("|", 1)[0] for fp in fp_weights}
        for ch in chains_raw:
            steps = ch.get("steps", [])
            req = {str(s.get("rule_id") or s.get("vuln_rule_id") or "") for s in steps} - {""}
            if req:
                chain_bonuses.append((req, max(2.5, float(ch.get("composite_risk_score", 20.0)) * 0.1)))

        def coalition_value(stage_subset: Iterable[str]) -> float:
            covered: Set[str] = set()
            for sid in stage_subset:
                covered.update(stage_fp_sets.get(sid, ()))
            val = sum(fp_weights[fp] for fp in covered)
            if chain_bonuses and covered:
                rules = {fp_to_rule[fp] for fp in covered}
                for req, bonus in chain_bonuses:
                    if req.issubset(rules):
                        val += bonus
            return val

        stage_ids = [str(r["stage_id"]) for r in stage_records]
        n = len(stage_ids)
        total_value = coalition_value(stage_ids)

        if n == 0:
            return CausalAttributionReport(
                run_id=run_id,
                computed_at=utc_now_iso(),
                computation_method="exact_coalition_shapley",
                total_coalition_risk_yield=0.0,
                baseline_static_yield=0.0,
                adaptive_counterfactual_lift=0.0,
                adaptive_lift_share_pct=0.0,
                efficiency_check_error=0.0,
            )

        if n <= self.exact_stage_limit:
            shapley_map = self._compute_exact_shapley(stage_ids, coalition_value)
            method = "exact_coalition_shapley"
        else:
            shapley_map = self._compute_mc_shapley(stage_ids, coalition_value)
            method = "stratified_mc_shapley"

        eff_err = abs(sum(shapley_map.values()) - total_value)

        stage_attrs: List[StageAttributionRecord] = []
        prune_candidates: List[str] = []
        indispensable: List[str] = []

        for sid in stage_ids:
            rec = stage_meta[sid]
            own_fps = stage_fp_sets[sid]
            others_fps: Set[str] = set()
            for other in stage_ids:
                if other != sid:
                    others_fps.update(stage_fp_sets[other])

            unique_fps = own_fps - others_fps
            overlap_ratio = 0.0 if not own_fps else (len(own_fps) - len(unique_fps)) / len(own_fps)
            loo_loss = max(0.0, total_value - coalition_value([o for o in stage_ids if o != sid]))
            loo_crit_loss = sum(1 for fp in unique_fps if fp_is_critical.get(fp, False))

            phi = shapley_map.get(sid, 0.0)
            share_pct = (phi / total_value * 100.0) if total_value > 1e-9 else 0.0
            elapsed_ms = float(rec.get("elapsed_ms", 1.0))
            yps = phi / max(0.001, elapsed_ms / 1000.0)

            classification, recommendation = self._classify_stage(
                phi=phi,
                share_pct=share_pct,
                unique_count=len(unique_fps),
                loo_crit_loss=loo_crit_loss,
                overlap_ratio=overlap_ratio,
                elapsed_ms=elapsed_ms,
                raw_count=len(own_fps),
            )
            if classification == "INDISPENSABLE":
                indispensable.append(sid)
            elif classification in ("REDUNDANT_CANDIDATE", "PRUNE_CANDIDATE"):
                prune_candidates.append(sid)

            stage_attrs.append(
                StageAttributionRecord(
                    stage_id=sid,
                    adapter_name=str(rec.get("adapter_name", sid)),
                    was_injected_by_mapek=sid in injected_ids,
                    elapsed_ms=elapsed_ms,
                    raw_finding_count=len(own_fps),
                    unique_finding_count=len(unique_fps),
                    shapley_risk_yield=phi,
                    shapley_share_pct=share_pct,
                    leave_one_out_yield_loss=loo_loss,
                    leave_one_out_critical_loss=loo_crit_loss,
                    overlap_redundancy_ratio=overlap_ratio,
                    yield_per_second=yps,
                    classification=classification,
                    recommendation=recommendation,
                )
            )

        stage_attrs.sort(key=lambda x: x.shapley_risk_yield, reverse=True)

        static_stage_ids = [sid for sid in stage_ids if sid not in injected_ids]
        baseline_yield = coalition_value(static_stage_ids)
        adaptive_lift = max(0.0, total_value - baseline_yield)
        adaptive_share = (adaptive_lift / total_value * 100.0) if total_value > 1e-9 else 0.0

        static_fps: Set[str] = set()
        for sid in static_stage_ids:
            static_fps.update(stage_fp_sets.get(sid, ()))

        adaptation_attrs: List[AdaptationRuleAttribution] = []
        for d in directives:
            if not d.get("applied"):
                continue
            target_sid = str(d.get("target_stage_id", ""))
            unlocked_fps = stage_fp_sets.get(target_sid, set()) - static_fps if target_sid in injected_ids else set()
            added_ms = float(stage_meta[target_sid].get("elapsed_ms", 0.0)) if target_sid in stage_meta else 0.0
            unlocked_yield = sum(fp_weights[fp] for fp in unlocked_fps)
            unlocked_crits = sum(1 for fp in unlocked_fps if fp_is_critical.get(fp, False))
            roi = unlocked_yield / max(0.001, added_ms / 1000.0) if added_ms > 0 else 0.0

            if unlocked_crits > 0 or unlocked_yield >= 15.0:
                verdict = "HIGH_VALUE_ADAPTATION"
            elif unlocked_yield > 0.0 or str(d.get("action_type")) == "reprioritize_queue":
                verdict = "POSITIVE_LIFT"
            elif added_ms > 200.0:
                verdict = "COSTLY_NO_LIFT"
            else:
                verdict = "NEUTRAL"

            adaptation_attrs.append(
                AdaptationRuleAttribution(
                    rule_id=str(d.get("rule_id", "MAPEK-RULE")),
                    action_type=str(d.get("action_type", "unknown")),
                    target_stage_id=target_sid,
                    unlocked_findings=len(unlocked_fps),
                    unlocked_criticals=unlocked_crits,
                    unlocked_risk_yield=unlocked_yield,
                    added_latency_ms=added_ms,
                    marginal_roi_yield_per_sec=roi,
                    verdict=verdict,
                )
            )

        total_ms = sum(float(r.get("elapsed_ms", 0.0)) for r in stage_records)
        top3_share = sum(s.shapley_share_pct for s in stage_attrs[:3])
        return CausalAttributionReport(
            run_id=run_id,
            computed_at=utc_now_iso(),
            computation_method=method,
            total_coalition_risk_yield=total_value,
            baseline_static_yield=baseline_yield,
            adaptive_counterfactual_lift=adaptive_lift,
            adaptive_lift_share_pct=adaptive_share,
            efficiency_check_error=eff_err,
            stage_attributions=stage_attrs,
            adaptation_attributions=adaptation_attrs,
            prune_candidates=prune_candidates,
            indispensable_stages=indispensable,
            pareto_efficiency_summary={
                "total_stages": n,
                "total_duration_ms": round(total_ms, 2),
                "top3_stage_yield_concentration_pct": round(top3_share, 2),
                "gini_stage_concentration": round(self._gini([s.shapley_risk_yield for s in stage_attrs]), 4),
                "overall_yield_per_second": round(total_value / max(0.001, total_ms / 1000.0), 2),
            },
        )

    def _compute_exact_shapley(self, stage_ids: Sequence[str], v_fn: Any) -> Dict[str, float]:
        n = len(stage_ids)
        fact = [math.factorial(k) for k in range(n + 1)]
        denom = float(fact[n])
        val_cache: Dict[int, float] = {0: 0.0}
        for mask in range(1, 1 << n):
            subset = [stage_ids[i] for i in range(n) if mask & (1 << i)]
            val_cache[mask] = v_fn(subset)

        shapley: Dict[str, float] = {sid: 0.0 for sid in stage_ids}
        full_mask = (1 << n) - 1
        for i, sid in enumerate(stage_ids):
            bit = 1 << i
            other_mask = full_mask ^ bit
            total = 0.0
            sub = other_mask
            while True:
                k = sub.bit_count()
                weight = (fact[k] * fact[n - k - 1]) / denom
                total += weight * (val_cache[sub | bit] - val_cache[sub])
                if sub == 0:
                    break
                sub = (sub - 1) & other_mask
            shapley[sid] = total
        return shapley

    def _compute_mc_shapley(self, stage_ids: Sequence[str], v_fn: Any) -> Dict[str, float]:
        rng = random.Random(self.seed)
        ids = list(stage_ids)
        accum: Dict[str, float] = {sid: 0.0 for sid in ids}
        pairs = max(25, self.mc_permutations // 2)
        for _ in range(pairs):
            perm = list(ids)
            rng.shuffle(perm)
            for order in (perm, list(reversed(perm))):
                prefix: List[str] = []
                prev_val = 0.0
                for sid in order:
                    prefix.append(sid)
                    cur_val = v_fn(prefix)
                    accum[sid] += cur_val - prev_val
                    prev_val = cur_val
        total_samples = float(pairs * 2)
        return {sid: val / total_samples for sid, val in accum.items()}

    @staticmethod
    def _classify_stage(
        phi: float,
        share_pct: float,
        unique_count: int,
        loo_crit_loss: int,
        overlap_ratio: float,
        elapsed_ms: float,
        raw_count: int,
    ) -> Tuple[str, str]:
        if loo_crit_loss > 0 or share_pct >= 20.0:
            return ("INDISPENSABLE", "Keep permanently enabled; contributes unique critical findings or >=20% of total causal risk yield.")
        if unique_count > 0 and phi > 0.0 and (phi / max(0.001, elapsed_ms / 1000.0)) >= 25.0:
            return ("HIGH_LEVERAGE", "Strong yield/second; prioritize early in DAG to trigger MAPE-K hypotheses faster.")
        if unique_count > 0 or phi > 1.0:
            return ("COMPLEMENTARY", "Provides incremental coverage; retain in balanced/deep profiles.")
        if raw_count > 0 and overlap_ratio >= 0.95:
            return ("REDUNDANT_CANDIDATE", ">=95% overlap with other stages; candidate for conditional gating under tight budgets.")
        return ("PRUNE_CANDIDATE", "Zero marginal yield on this target class; disable by default unless activated by hypothesis.")

    @staticmethod
    def _gini(values: Sequence[float]) -> float:
        xs = sorted(max(0.0, v) for v in values)
        n = len(xs)
        if n == 0 or sum(xs) <= 1e-9:
            return 0.0
        cum = sum((2 * idx - n - 1) * x for idx, x in enumerate(xs, start=1))
        return cum / (n * sum(xs))
