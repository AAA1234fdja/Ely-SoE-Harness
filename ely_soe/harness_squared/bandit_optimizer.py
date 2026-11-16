"""
Harness² Contextual Multi-Armed Bandit Optimizer (Pure-Python Disjoint LinUCB + Thompson Sampling).

Selects and tunes first-order `HarnessGenome` configurations and per-domain stage
priorities online with zero external dependencies (pure-Python linear algebra):
  1. **Disjoint LinUCB Contextual Bandit** (`LinUCBGenomeBandit`):
       - Maintains per-arm ridge-regression precision inverse $A_a^{-1} \in \mathbb{R}^{d \times d}$
         and reward projection vector $b_a \in \mathbb{R}^d$ ($d = 16$ from `TargetFingerprint.feature_vector`).
       - Uses exact **Sherman-Morrison Rank-1 Matrix Inverse Updates** in $O(d^2)$ time:
           $$A^{-1}_{\text{new}} = A^{-1} - \frac{(A^{-1} x)(x^\top A^{-1})}{1 + x^\top A^{-1} x}$$
       - Computes UCB score $\hat{p}_a = \hat{\theta}_a^\top x + \alpha \sqrt{x^\top A_a^{-1} x}$
         across 6 distinct genome policy archetypes (`fast_ci`, `balanced_enterprise`,
         `deep_adversarial`, `web_api_specialist`, `cloud_k8s_specialist`, `ai_supply_chain_specialist`).
  2. **Beta-Bernoulli Thompson Sampling** (`DomainThompsonScheduler`):
       - Tracks posterior $(\alpha_d, \beta_d)$ success/failure counts for every security stage
         adapter to continuously prioritize high-yield domains and deprioritize noisy ones.
  3. **JSON State Serialization** for seamless persistence in `MetaMemoryStore`.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import new_id
from ely_soe.harness_squared.models import HarnessGenome, TargetFingerprint


# ---------------------------------------------------------------------------
# Pure-Python Linear Algebra Helpers (Zero NumPy Dependency)
# ---------------------------------------------------------------------------

def _identity_matrix(d: int, scale: float = 1.0) -> List[List[float]]:
    return [[scale if i == j else 0.0 for j in range(d)] for i in range(d)]


def _mat_vec(mat: List[List[float]], vec: List[float]) -> List[float]:
    return [sum(row[j] * vec[j] for j in range(len(vec))) for row in mat]


def _dot(a: Sequence[float], b: Sequence[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _sherman_morrison_update(a_inv: List[List[float]], x: List[float]) -> List[List[float]]:
    """Exact rank-1 inverse update: (A + x x^T)^-1 = A^-1 - (A^-1 x x^T A^-1) / (1 + x^T A^-1 x)."""
    d = len(x)
    ax = _mat_vec(a_inv, x)
    denom = 1.0 + _dot(x, ax)
    if denom <= 1e-12:
        return a_inv
    inv_d = 1.0 / denom
    return [
        [a_inv[i][j] - (ax[i] * ax[j] * inv_d) for j in range(d)]
        for i in range(d)
    ]


# ---------------------------------------------------------------------------
# Built-In Seed Genome Policy Archetypes (Bandit Arms)
# ---------------------------------------------------------------------------

GENOME_ARM_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "fast_ci": {
        "name": "Fast CI/PR Security Gate",
        "profile_family": "fast_ci",
        "enabled_stages": [
            "web_injection", "web_ssrf_deser", "auth_access", "secrets_dlp",
            "iac_cicd", "supply_chain_sbom", "tls_crypto",
        ],
        "total_budget_ms": 12_000,
        "enable_live_sandbox_dast": False,
        "enable_enterprise_graph_sim": False,
        "enable_mitre_emulation": False,
        "enable_ai_redteam": False,
        "enable_grammar_fuzzing": False,
        "fuzz_iterations_per_grammar": 6,
        "drilldown_aggressiveness": 0.45,
        "prune_threshold_yield": 0.12,
        "max_adaptation_rounds": 4,
    },
    "balanced_enterprise": {
        "name": "Balanced Full-Stack Enterprise Harness",
        "profile_family": "balanced_enterprise",
        "enabled_stages": [
            "web_injection", "web_client_protocol", "web_ssrf_deser", "auth_access",
            "api_microservices", "secrets_dlp", "tls_crypto", "iac_cicd",
            "kubernetes_container", "supply_chain_sbom", "live_sandbox_dast",
            "cloud_iam_graph", "mitre_sigma_purple",
        ],
        "total_budget_ms": 30_000,
        "enable_live_sandbox_dast": True,
        "enable_enterprise_graph_sim": True,
        "enable_mitre_emulation": True,
        "enable_ai_redteam": False,
        "enable_grammar_fuzzing": True,
        "fuzz_iterations_per_grammar": 10,
        "drilldown_aggressiveness": 0.65,
        "prune_threshold_yield": 0.06,
        "max_adaptation_rounds": 8,
    },
    "deep_adversarial": {
        "name": "Deep Adversarial Red-Team & BAS Harness",
        "profile_family": "deep_adversarial",
        "enabled_stages": [
            "web_injection", "web_client_protocol", "web_ssrf_deser", "auth_access",
            "api_microservices", "secrets_dlp", "tls_crypto", "iac_cicd",
            "kubernetes_container", "supply_chain_sbom", "binary_memory", "firmware_iot_ot",
            "live_sandbox_dast", "cloud_iam_graph", "active_directory_graph",
            "network_zero_trust", "mitre_sigma_purple", "bas_campaigns",
            "ai_llm_redteam", "grammar_fuzzer",
        ],
        "total_budget_ms": 60_000,
        "enable_live_sandbox_dast": True,
        "enable_enterprise_graph_sim": True,
        "enable_mitre_emulation": True,
        "enable_ai_redteam": True,
        "enable_grammar_fuzzing": True,
        "fuzz_iterations_per_grammar": 18,
        "drilldown_aggressiveness": 0.85,
        "prune_threshold_yield": 0.02,
        "max_adaptation_rounds": 12,
    },
    "web_api_specialist": {
        "name": "Web / OWASP / API & Live DAST Specialist",
        "profile_family": "web_api_specialist",
        "enabled_stages": [
            "web_injection", "web_client_protocol", "web_ssrf_deser", "auth_access",
            "api_microservices", "secrets_dlp", "tls_crypto", "live_sandbox_dast",
            "grammar_fuzzer", "supply_chain_sbom",
        ],
        "total_budget_ms": 25_000,
        "enable_live_sandbox_dast": True,
        "enable_enterprise_graph_sim": False,
        "enable_mitre_emulation": False,
        "enable_ai_redteam": False,
        "enable_grammar_fuzzing": True,
        "fuzz_iterations_per_grammar": 16,
        "drilldown_aggressiveness": 0.75,
        "prune_threshold_yield": 0.07,
        "max_adaptation_rounds": 8,
    },
    "cloud_k8s_specialist": {
        "name": "Cloud IAM, Kubernetes, Container Runtime & Supply-Chain Specialist",
        "profile_family": "cloud_k8s_specialist",
        "enabled_stages": [
            "iac_cicd", "kubernetes_container", "container_runtime_ebpf", "cloud_iam_graph",
            "secrets_dlp", "supply_chain_sbom", "network_zero_trust", "active_directory_graph",
            "mitre_sigma_purple", "bas_campaigns",
        ],
        "total_budget_ms": 35_000,
        "enable_live_sandbox_dast": False,
        "enable_enterprise_graph_sim": True,
        "enable_mitre_emulation": True,
        "enable_ai_redteam": False,
        "enable_grammar_fuzzing": False,
        "fuzz_iterations_per_grammar": 8,
        "drilldown_aggressiveness": 0.72,
        "prune_threshold_yield": 0.05,
        "max_adaptation_rounds": 9,
    },
    "ai_supply_chain_specialist": {
        "name": "AI / LLM Agent Red-Team & Supply-Chain Integrity Specialist",
        "profile_family": "ai_supply_chain_specialist",
        "enabled_stages": [
            "ai_llm_redteam", "secrets_dlp", "supply_chain_sbom", "web_injection",
            "web_ssrf_deser", "auth_access", "iac_cicd", "live_sandbox_dast",
            "mitre_sigma_purple",
        ],
        "total_budget_ms": 30_000,
        "enable_live_sandbox_dast": True,
        "enable_enterprise_graph_sim": True,
        "enable_mitre_emulation": True,
        "enable_ai_redteam": True,
        "enable_grammar_fuzzing": True,
        "fuzz_iterations_per_grammar": 12,
        "drilldown_aggressiveness": 0.78,
        "prune_threshold_yield": 0.05,
        "max_adaptation_rounds": 9,
    },
}


class LinUCBGenomeBandit:
    """Disjoint LinUCB contextual bandit selecting optimal `HarnessGenome` arms from 16-dim target vectors."""

    def __init__(self, dim: int = 16, alpha: float = 0.45, ridge_lambda: float = 1.0) -> None:
        self.dim = dim
        self.alpha = alpha
        self.ridge_lambda = ridge_lambda
        self.arm_ids: List[str] = list(GENOME_ARM_TEMPLATES.keys())
        self.a_inv: Dict[str, List[List[float]]] = {
            arm: _identity_matrix(dim, 1.0 / ridge_lambda) for arm in self.arm_ids
        }
        self.b_vec: Dict[str, List[float]] = {arm: [0.0] * dim for arm in self.arm_ids}
        self.pulls: Dict[str, int] = {arm: 0 for arm in self.arm_ids}
        self.reward_sum: Dict[str, float] = {arm: 0.0 for arm in self.arm_ids}
        self._initialize_domain_priors()

    def _initialize_domain_priors(self) -> None:
        """Warm-start ridge weights with expert domain priors so even pull #1 makes smart decisions."""
        # Feature indices: [0:files,1:loc,2:sinks,3:web,4:api,5:k8s,6:docker,7:iac,8:cicd,9:cloud,10:ai,11:native,12:iot,13:sbom,14:env,15:fw]
        priors = {
            "fast_ci": [0.1, 0.1, 0.2, 0.3, 0.2, 0.1, 0.1, 0.2, 0.3, 0.1, 0.1, 0.0, 0.0, 0.3, 0.3, 0.1],
            "balanced_enterprise": [0.3, 0.3, 0.45, 0.55, 0.45, 0.4, 0.35, 0.4, 0.4, 0.45, 0.25, 0.2, 0.2, 0.45, 0.45, 0.4],
            "deep_adversarial": [0.4, 0.4, 0.55, 0.45, 0.45, 0.45, 0.4, 0.45, 0.45, 0.5, 0.45, 0.5, 0.5, 0.4, 0.5, 0.5],
            "web_api_specialist": [0.2, 0.2, 0.4, 0.75, 0.75, 0.05, 0.1, 0.1, 0.1, 0.1, 0.1, 0.0, 0.0, 0.3, 0.4, 0.5],
            "cloud_k8s_specialist": [0.2, 0.2, 0.3, 0.1, 0.2, 0.85, 0.75, 0.8, 0.75, 0.85, 0.1, 0.0, 0.1, 0.4, 0.4, 0.2],
            "ai_supply_chain_specialist": [0.2, 0.2, 0.4, 0.35, 0.3, 0.15, 0.15, 0.25, 0.45, 0.2, 0.95, 0.0, 0.0, 0.7, 0.5, 0.4],
        }
        for arm, w in priors.items():
            if arm in self.b_vec:
                self.b_vec[arm] = list(w)

    def _pad_context(self, context: Sequence[float]) -> List[float]:
        vec = [float(v) for v in context[: self.dim]]
        if len(vec) < self.dim:
            vec.extend([0.0] * (self.dim - len(vec)))
        return vec

    def score_arms(self, context: Sequence[float]) -> List[Dict[str, Any]]:
        x = self._pad_context(context)
        scored: List[Dict[str, Any]] = []
        for arm in self.arm_ids:
            theta = _mat_vec(self.a_inv[arm], self.b_vec[arm])
            expected = _dot(theta, x)
            ax = _mat_vec(self.a_inv[arm], x)
            uncertainty = math.sqrt(max(0.0, _dot(x, ax)))
            ucb = expected + self.alpha * uncertainty
            scored.append(
                {
                    "arm_id": arm,
                    "expected_reward": round(expected, 4),
                    "uncertainty_bonus": round(self.alpha * uncertainty, 4),
                    "ucb_score": round(ucb, 4),
                    "pulls": self.pulls[arm],
                    "mean_observed_reward": round(self.reward_sum[arm] / self.pulls[arm], 4) if self.pulls[arm] else 0.0,
                }
            )
        scored.sort(key=lambda r: -r["ucb_score"])
        return scored

    def select_genome(
        self,
        fingerprint: TargetFingerprint,
        preferred_profile: Optional[str] = None,
    ) -> Tuple[HarnessGenome, Dict[str, Any]]:
        """Select the highest-UCB arm (or an explicit profile) and synthesize a target-tailored `HarnessGenome`."""
        arm_scores = self.score_arms(fingerprint.feature_vector)
        chosen_arm = preferred_profile if (preferred_profile in GENOME_ARM_TEMPLATES) else arm_scores[0]["arm_id"]
        tpl = GENOME_ARM_TEMPLATES[chosen_arm]

        # Tailor stage priorities directly using TargetFingerprint domain affinities
        priorities: Dict[str, float] = {}
        budgets: Dict[str, int] = {}
        stage_list = list(tpl["enabled_stages"])

        # Automatically include high-affinity specialist stages even in balanced profiles
        if fingerprint.has_ai_llm_components and "ai_llm_redteam" not in stage_list:
            stage_list.append("ai_llm_redteam")
        if fingerprint.has_native_c_cpp_binaries and "binary_memory" not in stage_list:
            stage_list.append("binary_memory")
        if fingerprint.has_iot_ot_artifacts and "firmware_iot_ot" not in stage_list:
            stage_list.append("firmware_iot_ot")

        stage_to_domain = {
            "web_injection": "web_injection",
            "web_client_protocol": "web_client_protocol",
            "web_ssrf_deser": "web_ssrf_xxe_ssti_deser",
            "auth_access": "auth_access_control",
            "api_microservices": "api_microservices",
            "secrets_dlp": "auth_access_control",
            "tls_crypto": "tls_cryptography",
            "iac_cicd": "iac_cicd",
            "kubernetes_container": "kubernetes_container",
            "container_runtime_ebpf": "kubernetes_container",
            "supply_chain_sbom": "iac_cicd",
            "cloud_iam_graph": "cloud_iam",
            "active_directory_graph": "identity_active_directory",
            "network_zero_trust": "network_protocol",
            "binary_memory": "binary_memory_safety",
            "firmware_iot_ot": "firmware_iot_ot",
            "live_sandbox_dast": "web_injection",
            "mitre_sigma_purple": "adversary_emulation",
            "bas_campaigns": "adversary_emulation",
            "ai_llm_redteam": "adversary_emulation",
            "grammar_fuzzer": "threat_modeling",
        }
        per_stage_base = max(800, int(tpl["total_budget_ms"] / max(1, len(stage_list) + 2)))
        for st in stage_list:
            dom = stage_to_domain.get(st, "threat_modeling")
            aff = float(fingerprint.domain_affinities.get(dom, 0.5))
            priorities[st] = round(min(0.99, max(0.15, aff)), 3)
            budgets[st] = int(per_stage_base * (0.7 + 0.6 * aff))

        genome = HarnessGenome(
            genome_id=new_id("gen"),
            name=f"{tpl['name']} ({fingerprint.target_name})",
            profile_family=chosen_arm,
            enabled_stages=stage_list,
            stage_priorities=priorities,
            stage_budgets_ms=budgets,
            total_budget_ms=int(tpl["total_budget_ms"]),
            enable_live_sandbox_dast=bool(tpl["enable_live_sandbox_dast"]),
            enable_enterprise_graph_sim=bool(tpl["enable_enterprise_graph_sim"]),
            enable_mitre_emulation=bool(tpl["enable_mitre_emulation"]),
            enable_ai_redteam=bool(tpl["enable_ai_redteam"] or fingerprint.has_ai_llm_components),
            enable_grammar_fuzzing=bool(tpl["enable_grammar_fuzzing"]),
            fuzz_iterations_per_grammar=int(tpl["fuzz_iterations_per_grammar"]),
            drilldown_aggressiveness=float(tpl["drilldown_aggressiveness"]),
            prune_threshold_yield=float(tpl["prune_threshold_yield"]),
            max_adaptation_rounds=int(tpl["max_adaptation_rounds"]),
            exploration_alpha=self.alpha,
        )

        decision_meta = {
            "selected_arm": chosen_arm,
            "override_applied": preferred_profile in GENOME_ARM_TEMPLATES,
            "arm_rankings": arm_scores,
        }
        return genome, decision_meta

    def update(self, arm_id: str, context: Sequence[float], reward: float) -> None:
        """Perform exact Sherman-Morrison LinUCB posterior update with normalized reward in [0, 1]."""
        if arm_id not in self.a_inv:
            return
        x = self._pad_context(context)
        r = max(0.0, min(1.0, float(reward)))
        self.a_inv[arm_id] = _sherman_morrison_update(self.a_inv[arm_id], x)
        self.b_vec[arm_id] = [self.b_vec[arm_id][i] + r * x[i] for i in range(self.dim)]
        self.pulls[arm_id] += 1
        self.reward_sum[arm_id] += r

    def export_state(self) -> Dict[str, Any]:
        return {
            "dim": self.dim,
            "alpha": self.alpha,
            "a_inv": self.a_inv,
            "b_vec": self.b_vec,
            "pulls": self.pulls,
            "reward_sum": self.reward_sum,
        }

    def load_state(self, state: Dict[str, Any]) -> None:
        if not state:
            return
        for arm in self.arm_ids:
            if arm in state.get("a_inv", {}):
                self.a_inv[arm] = state["a_inv"][arm]
            if arm in state.get("b_vec", {}):
                self.b_vec[arm] = state["b_vec"][arm]
            if arm in state.get("pulls", {}):
                self.pulls[arm] = int(state["pulls"][arm])
            if arm in state.get("reward_sum", {}):
                self.reward_sum[arm] = float(state["reward_sum"][arm])


class DomainThompsonScheduler:
    """Beta-Bernoulli Thompson Sampling scheduler tracking per-stage empirical discovery efficacy."""

    def __init__(self, seed: int = 20261115) -> None:
        self._rng = random.Random(seed)
        self.alphas: Dict[str, float] = {}
        self.betas: Dict[str, float] = {}

    def sample_priority(self, adapter_name: str, prior_affinity: float = 0.5) -> float:
        a = self.alphas.get(adapter_name, 1.0 + prior_affinity * 2.0)
        b = self.betas.get(adapter_name, 1.0 + (1.0 - prior_affinity) * 2.0)
        sampled = self._rng.betavariate(max(0.1, a), max(0.1, b))
        return round(0.55 * sampled + 0.45 * prior_affinity, 4)

    def observe_outcome(self, adapter_name: str, yielded_risk: float) -> None:
        a = self.alphas.get(adapter_name, 1.5)
        b = self.betas.get(adapter_name, 1.5)
        if yielded_risk >= 5.0:
            a += min(3.0, yielded_risk / 10.0)
        elif yielded_risk > 0.0:
            a += 0.5
        else:
            b += 1.0
        self.alphas[adapter_name] = round(a, 4)
        self.betas[adapter_name] = round(b, 4)

    def posterior_means(self) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for k in sorted(set(self.alphas) | set(self.betas)):
            a = self.alphas.get(k, 1.5)
            b = self.betas.get(k, 1.5)
            out[k] = round(a / (a + b), 4)
        return out
