"""
Bayesian Expected Information Gain (EIG) & Value-of-Information (VoI)
Optimal Next-Stage Experiment Designer for Harness².

Models security auditing as sequential Bayesian Optimal Experimental Design (Lindley 1956):
  - Maintains independent Beta-Bernoulli beliefs `P(H_k = 1) = p_k` over `K` latent
    compromise hypotheses (e.g., `SQLi_RCE`, `SSRF_IMDS_Takeover`, `AuthZ_BOLA`,
    `SupplyChain_PPE`, `Container_Escape`, `Secret_Leakage`, `Memory_Corruption`).
  - Each candidate first-order security stage `s` has known empirical sensitivity (TPR `tp_sk`),
    specificity (`1 - fp_sk`), and latency cost `c_s` for each hypothesis `k`.
  - Computes **exact Shannon Entropy reduction (Expected Information Gain — EIG in bits)**:
      `EIG(s) = sum_k [ H(p_k) - (P(obs=1) * H(P(H_k|obs=1)) + P(obs=0) * H(P(H_k|obs=0))) ]`
    and **Value-of-Information per Second (`VoI_rate = (EIG(s) * ImpactWeight) / cost_s`)**!
  - Dynamically selects the mathematically highest-VoI next security probe, executes Bayes'
    Theorem posterior update after observing the stage result, and emits a complete
    information-theoretic trajectory!
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import utc_now_iso


@dataclass(frozen=True)
class StageInformationProfile:
    stage_id: str
    cost_ms: float
    # hypothesis_id -> (true_positive_rate, false_positive_rate)
    detection_matrix: Dict[str, Tuple[float, float]]


DEFAULT_HYPOTHESIS_PRIORS: Dict[str, Tuple[float, float]] = {
    # hypothesis_id -> (prior_prob, business_impact_weight)
    "web_injection_rce": (0.42, 10.0),
    "ssrf_cloud_imds": (0.35, 9.5),
    "auth_jwt_bola": (0.48, 8.5),
    "secrets_leakage": (0.55, 8.0),
    "k8s_container_escape": (0.30, 9.5),
    "cicd_supply_chain_ppe": (0.38, 9.0),
    "memory_corruption": (0.22, 9.0),
}

DEFAULT_STAGE_PROFILES: Tuple[StageInformationProfile, ...] = (
    StageInformationProfile("web_injection", 180.0, {"web_injection_rce": (0.92, 0.05), "auth_jwt_bola": (0.20, 0.05)}),
    StageInformationProfile("web_ssrf_deser", 190.0, {"ssrf_cloud_imds": (0.90, 0.04), "web_injection_rce": (0.35, 0.06)}),
    StageInformationProfile("auth_access", 170.0, {"auth_jwt_bola": (0.91, 0.05)}),
    StageInformationProfile("secrets_dlp", 150.0, {"secrets_leakage": (0.95, 0.04), "cicd_supply_chain_ppe": (0.30, 0.05)}),
    StageInformationProfile("kubernetes_container", 160.0, {"k8s_container_escape": (0.93, 0.04)}),
    StageInformationProfile("cicd_ppe_graph", 140.0, {"cicd_supply_chain_ppe": (0.94, 0.03), "secrets_leakage": (0.40, 0.05)}),
    StageInformationProfile("live_sandbox_dast", 620.0, {"web_injection_rce": (0.97, 0.01), "ssrf_cloud_imds": (0.95, 0.01), "auth_jwt_bola": (0.94, 0.02)}),
    StageInformationProfile("memory_exploitability", 210.0, {"memory_corruption": (0.91, 0.04)}),
)


class BayesianExperimentDesigner:
    """Sequential Bayesian Optimal Experimental Design (EIG + VoI) controller for Harness²."""

    def __init__(
        self,
        priors: Optional[Dict[str, Tuple[float, float]]] = None,
        stage_profiles: Optional[Sequence[StageInformationProfile]] = None,
    ) -> None:
        base_priors = priors or DEFAULT_HYPOTHESIS_PRIORS
        self.beliefs: Dict[str, float] = {k: float(v[0]) for k, v in base_priors.items()}
        self.impacts: Dict[str, float] = {k: float(v[1]) for k, v in base_priors.items()}
        self.stages: Dict[str, StageInformationProfile] = {
            s.stage_id: s for s in (stage_profiles or DEFAULT_STAGE_PROFILES)
        }
        self.executed_stages: List[str] = []
        self.trajectory: List[Dict[str, Any]] = []

    @staticmethod
    def binary_entropy_bits(p: float) -> float:
        p = max(1e-9, min(1.0 - 1e-9, float(p)))
        return -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))

    def total_entropy_bits(self) -> float:
        return round(sum(self.binary_entropy_bits(p) for p in self.beliefs.values()), 5)

    def expected_information_gain(self, stage_id: str) -> Dict[str, Any]:
        """Compute exact EIG (bits) and impact-weighted Value-of-Information per second for a stage."""
        prof = self.stages[stage_id]
        total_eig_bits = 0.0
        weighted_voi = 0.0
        per_hyp: Dict[str, float] = {}

        for hid, (tpr, fpr) in prof.detection_matrix.items():
            if hid not in self.beliefs:
                continue
            p = self.beliefs[hid]
            h_prior = self.binary_entropy_bits(p)

            # P(obs=1) and posteriors via Bayes' rule
            p_pos = p * tpr + (1.0 - p) * fpr
            p_neg = 1.0 - p_pos
            post_given_pos = (p * tpr) / max(1e-9, p_pos)
            post_given_neg = (p * (1.0 - tpr)) / max(1e-9, p_neg)

            h_expected_post = p_pos * self.binary_entropy_bits(post_given_pos) + p_neg * self.binary_entropy_bits(post_given_neg)
            eig_h = max(0.0, h_prior - h_expected_post)
            per_hyp[hid] = round(eig_h, 5)
            total_eig_bits += eig_h
            weighted_voi += eig_h * self.impacts.get(hid, 1.0)

        voi_per_sec = (weighted_voi / max(10.0, prof.cost_ms)) * 1000.0
        return {
            "stage_id": stage_id,
            "cost_ms": prof.cost_ms,
            "eig_bits": round(total_eig_bits, 5),
            "impact_weighted_voi": round(weighted_voi, 5),
            "voi_per_second": round(voi_per_sec, 4),
            "per_hypothesis_eig": per_hyp,
        }

    def recommend_next_stage(self, candidate_stage_ids: Optional[Sequence[str]] = None) -> Dict[str, Any]:
        """Rank all unexecuted candidate stages by VoI per second and pick the optimal next experiment."""
        pool = (
            [s for s in candidate_stage_ids if s in self.stages and s not in self.executed_stages]
            if candidate_stage_ids is not None
            else [s for s in self.stages if s not in self.executed_stages]
        )
        scored = [self.expected_information_gain(sid) for sid in pool]
        scored.sort(key=lambda x: (-x["voi_per_second"], -x["eig_bits"]))
        return {
            "current_entropy_bits": self.total_entropy_bits(),
            "recommended_stage": scored[0] if scored else None,
            "ranked_candidates": scored,
        }

    def observe_stage_outcome(self, stage_id: str, observed_findings_by_hypothesis: Dict[str, bool]) -> Dict[str, Any]:
        """Update multi-hypothesis beliefs using exact Bayes' Theorem after executing a stage."""
        prof = self.stages[stage_id]
        entropy_before = self.total_entropy_bits()
        updates: Dict[str, Dict[str, float]] = {}

        for hid, (tpr, fpr) in prof.detection_matrix.items():
            if hid not in self.beliefs:
                continue
            prior = self.beliefs[hid]
            detected = bool(observed_findings_by_hypothesis.get(hid, False))
            if detected:
                num = prior * tpr
                den = prior * tpr + (1.0 - prior) * fpr
            else:
                num = prior * (1.0 - tpr)
                den = prior * (1.0 - tpr) + (1.0 - prior) * (1.0 - fpr)
            post = max(0.001, min(0.999, num / max(1e-9, den)))
            self.beliefs[hid] = post
            updates[hid] = {"prior": round(prior, 4), "posterior": round(post, 4), "detected": float(detected)}

        if stage_id not in self.executed_stages:
            self.executed_stages.append(stage_id)
        entropy_after = self.total_entropy_bits()
        record = {
            "step": len(self.trajectory) + 1,
            "stage_id": stage_id,
            "entropy_before_bits": entropy_before,
            "entropy_after_bits": entropy_after,
            "realized_info_gain_bits": round(entropy_before - entropy_after, 5),
            "posterior_updates": updates,
        }
        self.trajectory.append(record)
        return record

    def plan_greedy_optimal_sequence(
        self,
        budget_ms: float = 900.0,
        simulated_ground_truth: Optional[Dict[str, bool]] = None,
    ) -> Dict[str, Any]:
        """Simulate a complete budget-constrained optimal Bayesian experiment sequence."""
        gt = simulated_ground_truth or {
            "web_injection_rce": True,
            "ssrf_cloud_imds": True,
            "auth_jwt_bola": True,
            "secrets_leakage": True,
            "k8s_container_escape": False,
            "cicd_supply_chain_ppe": True,
            "memory_corruption": False,
        }
        initial_entropy = self.total_entropy_bits()
        spent = 0.0
        while True:
            rec = self.recommend_next_stage()
            picked = None
            for cand in rec["ranked_candidates"]:
                if spent + cand["cost_ms"] <= budget_ms:
                    picked = cand
                    break
            if not picked:
                break
            sid = picked["stage_id"]
            spent += picked["cost_ms"]
            self.observe_stage_outcome(sid, gt)

        final_entropy = self.total_entropy_bits()
        reduction_pct = round(((initial_entropy - final_entropy) / max(1e-9, initial_entropy)) * 100.0, 2)
        return {
            "planned_at": utc_now_iso(),
            "budget_ms": budget_ms,
            "budget_spent_ms": round(spent, 2),
            "stages_selected": list(self.executed_stages),
            "initial_entropy_bits": initial_entropy,
            "final_entropy_bits": final_entropy,
            "entropy_reduction_pct": reduction_pct,
            "final_posterior_beliefs": {k: round(v, 4) for k, v in self.beliefs.items()},
            "trajectory": list(self.trajectory),
        }
