"""
Harness² Cross-Target Meta-Feature Transfer Learning & Zero-Shot Warm-Start Recommender.

Projects `TargetFingerprint` (dataclass OR dict returned by `HarnessSquaredEngine`) into
a normalized 16-dimensional security-surface embedding, retrieves top-K nearest historical
engagements via cosine similarity + softmax weighting, and synthesizes zero-shot stage
priorities, LinUCB exploration `alpha`, and expected high-value MAPE-K rules!
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import utc_now_iso


@dataclass
class HistoricalEngagementTrace:
    engagement_id: str
    target_name: str
    fingerprint: Dict[str, Any]
    winning_profile: str
    winning_genome_id: str
    stage_yield_map: Dict[str, float]
    triggered_high_value_rules: List[str] = field(default_factory=list)
    total_risk_yield: float = 0.0
    total_duration_ms: float = 100.0


@dataclass
class TransferWarmStartRecommendation:
    target_name: str
    generated_at: str
    recommended_seed_profile: str
    transfer_confidence: float
    recommended_linucb_alpha: float
    nearest_source_engagements: List[Dict[str, Any]]
    warm_start_stage_priorities: Dict[str, float]
    recommended_pre_enabled_stages: List[str]
    expected_high_value_mapek_rules: List[str]
    novelty_warning: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_name": self.target_name,
            "generated_at": self.generated_at,
            "recommended_seed_profile": self.recommended_seed_profile,
            "transfer_confidence": round(self.transfer_confidence, 4),
            "recommended_linucb_alpha": round(self.recommended_linucb_alpha, 3),
            "nearest_source_engagements": list(self.nearest_source_engagements),
            "warm_start_stage_priorities": {k: round(v, 3) for k, v in self.warm_start_stage_priorities.items()},
            "recommended_pre_enabled_stages": list(self.recommended_pre_enabled_stages),
            "expected_high_value_mapek_rules": list(self.expected_high_value_mapek_rules),
            "novelty_warning": self.novelty_warning,
        }


class CrossTargetTransferEngine:
    """Computes architectural embeddings and transfers Harness² priors across engagements."""

    def __init__(self, temperature: float = 0.25, top_k: int = 5) -> None:
        self.temperature = max(0.05, temperature)
        self.top_k = max(1, top_k)
        self._knowledge_base: List[HistoricalEngagementTrace] = []
        self._seed_canonical_archetypes()

    def register_experience(self, trace: HistoricalEngagementTrace) -> None:
        self._knowledge_base.append(trace)

    @staticmethod
    def embed_fingerprint(fp: Any) -> List[float]:
        """Project `TargetFingerprint` (dataclass or dict) into a 16-D architectural embedding."""
        def _get(k: str, default: Any = None) -> Any:
            if isinstance(fp, dict):
                return fp.get(k, default)
            return getattr(fp, k, default)

        lang_dist = _get("language_distribution", {}) or {}
        langs = {str(l).lower() for l in lang_dist.keys()}
        frameworks = {str(f).lower() for f in (_get("detected_frameworks", []) or [])}
        clouds = {str(c).lower() for c in (_get("detected_cloud_providers", []) or [])}

        return [
            min(1.0, math.log1p(max(0, int(_get("total_files", 0)))) / 7.0),
            min(1.0, math.log1p(max(0, int(_get("total_loc", 0)))) / 12.0),
            1.0 if "python" in langs else 0.0,
            1.0 if ("javascript" in langs or "typescript" in langs) else 0.0,
            1.0 if ("go" in langs or "rust" in langs) else 0.0,
            1.0 if ("c" in langs or "cpp" in langs or _get("has_native_c_cpp_binaries")) else 0.0,
            1.0 if ("java" in langs or "kotlin" in langs) else 0.0,
            1.0 if bool(frameworks) or "python" in langs or "javascript" in langs else 0.0,
            1.0 if _get("has_openapi_or_graphql") else 0.0,
            1.0 if bool(clouds) else 0.0,
            1.0 if (_get("has_kubernetes") or _get("has_dockerfile")) else 0.0,
            1.0 if (_get("has_terraform_or_iac") or _get("has_cicd_workflows")) else 0.0,
            1.0 if _get("has_ai_llm_components") else 0.0,
            1.0 if _get("has_lockfiles_or_sbom") else 0.0,
            1.0 if _get("has_env_or_secret_files") else 0.0,
            min(1.0, float(_get("estimated_risk_prior", 0.5))),
        ]

    @staticmethod
    def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na <= 1e-12 or nb <= 1e-12:
            return 0.0
        return max(0.0, min(1.0, dot / (na * nb)))

    def recommend_warm_start(
        self,
        target_fingerprint: Any,
        target_name: str = "unseen_target",
    ) -> TransferWarmStartRecommendation:
        q_vec = self.embed_fingerprint(target_fingerprint)
        scored: List[Tuple[float, HistoricalEngagementTrace]] = []
        for tr in self._knowledge_base:
            sim = self.cosine_similarity(q_vec, self.embed_fingerprint(tr.fingerprint))
            scored.append((sim, tr))
        scored.sort(key=lambda x: x[0], reverse=True)
        neighbors = scored[: self.top_k]

        if not neighbors:
            return TransferWarmStartRecommendation(
                target_name=target_name,
                generated_at=utc_now_iso(),
                recommended_seed_profile="balanced_enterprise",
                transfer_confidence=0.0,
                recommended_linucb_alpha=1.5,
                nearest_source_engagements=[],
                warm_start_stage_priorities={},
                recommended_pre_enabled_stages=[],
                expected_high_value_mapek_rules=[],
                novelty_warning="Empty transfer memory; using high-exploration cold start.",
            )

        max_sim = neighbors[0][0]
        raw_w = [math.exp((sim - max_sim) / self.temperature) * max(0.01, sim) for sim, _ in neighbors]
        sum_w = sum(raw_w) or 1.0
        weights = [w / sum_w for w in raw_w]

        profile_votes: Dict[str, float] = {}
        stage_priors: Dict[str, float] = {}
        rule_votes: Dict[str, float] = {}
        nearest_info: List[Dict[str, Any]] = []

        for (sim, tr), w in zip(neighbors, weights):
            profile_votes[tr.winning_profile] = profile_votes.get(tr.winning_profile, 0.0) + w
            for sid, yld in tr.stage_yield_map.items():
                stage_priors[sid] = stage_priors.get(sid, 0.0) + w * yld
            for r in tr.triggered_high_value_rules:
                rule_votes[r] = rule_votes.get(r, 0.0) + w
            nearest_info.append({
                "engagement_id": tr.engagement_id,
                "target_name": tr.target_name,
                "cosine_similarity": round(sim, 4),
                "transfer_weight": round(w, 4),
                "winning_profile": tr.winning_profile,
                "observed_risk_yield": round(tr.total_risk_yield, 2),
            })

        best_profile = max(profile_votes.items(), key=lambda kv: kv[1])[0]
        top_sim = neighbors[0][0]
        mean_top3 = sum(s for s, _ in neighbors[:3]) / max(1, min(3, len(neighbors)))
        transfer_conf = max(0.0, min(1.0, 0.65 * top_sim + 0.35 * mean_top3))
        rec_alpha = round(1.65 - 1.20 * transfer_conf, 3)

        sorted_stages = sorted(stage_priors.items(), key=lambda kv: kv[1], reverse=True)
        pre_enabled = [sid for sid, score in sorted_stages if score >= 8.0][:8]
        top_rules = [r for r, w in sorted(rule_votes.items(), key=lambda kv: kv[1], reverse=True) if w >= 0.25]

        novelty_warn = None
        if transfer_conf < 0.55:
            novelty_warn = (
                f"Novel target architecture (transfer_confidence={transfer_conf:.2f} < 0.55). "
                f"Increasing LinUCB exploration alpha to {rec_alpha}."
            )

        return TransferWarmStartRecommendation(
            target_name=target_name,
            generated_at=utc_now_iso(),
            recommended_seed_profile=best_profile,
            transfer_confidence=transfer_conf,
            recommended_linucb_alpha=rec_alpha,
            nearest_source_engagements=nearest_info,
            warm_start_stage_priorities=dict(sorted_stages),
            recommended_pre_enabled_stages=pre_enabled,
            expected_high_value_mapek_rules=top_rules,
            novelty_warning=novelty_warn,
        )

    def _seed_canonical_archetypes(self) -> None:
        self._knowledge_base.extend([
            HistoricalEngagementTrace(
                engagement_id="ARCH-WEB-SAAS-001",
                target_name="archetype_python_web_saas",
                fingerprint={"total_files": 35, "total_loc": 4200, "language_distribution": {"python": 20, "javascript": 10}, "detected_frameworks": ["flask", "fastapi"], "has_openapi_or_graphql": True, "has_env_or_secret_files": True, "estimated_risk_prior": 0.72},
                winning_profile="balanced_enterprise",
                winning_genome_id="genome-web-saas-champion",
                stage_yield_map={"web_injection": 42.0, "auth_access": 31.0, "web_ssrf_deser": 28.0, "live_sandbox_dast": 36.0, "secrets_dlp": 19.0},
                triggered_high_value_rules=["MAPEK-R01-SQLI-DAST", "MAPEK-R08-CRIT-VALIDATE"],
                total_risk_yield=178.0,
                total_duration_ms=480.0,
            ),
            HistoricalEngagementTrace(
                engagement_id="ARCH-CLOUD-K8S-002",
                target_name="archetype_cloud_native_k8s_iac",
                fingerprint={"total_files": 48, "total_loc": 3100, "language_distribution": {"go": 15, "yaml": 20}, "detected_cloud_providers": ["aws", "gcp"], "has_kubernetes": True, "has_dockerfile": True, "has_terraform_or_iac": True, "has_cicd_workflows": True, "estimated_risk_prior": 0.75},
                winning_profile="cloud_iac_zero_trust",
                winning_genome_id="genome-cloud-k8s-champion",
                stage_yield_map={"k8s_container": 45.0, "iac_cicd": 38.0, "cloud_iam_graph": 34.0, "container_runtime_ebpf": 26.0, "secrets_dlp": 20.0},
                triggered_high_value_rules=["MAPEK-R03-SSRF-IAM", "MAPEK-R04-SECRET-SBOM"],
                total_risk_yield=177.0,
                total_duration_ms=410.0,
            ),
            HistoricalEngagementTrace(
                engagement_id="ARCH-AI-AGENT-003",
                target_name="archetype_agentic_llm_mcp_platform",
                fingerprint={"total_files": 28, "total_loc": 5600, "language_distribution": {"python": 20, "typescript": 8}, "detected_frameworks": ["fastapi"], "has_ai_llm_components": True, "has_openapi_or_graphql": True, "has_env_or_secret_files": True, "estimated_risk_prior": 0.85},
                winning_profile="deep_redteam",
                winning_genome_id="genome-ai-redteam-champion",
                stage_yield_map={"ai_llm_redteam": 49.0, "web_ssrf_deser": 32.0, "web_injection": 29.0, "auth_access": 27.0, "secrets_dlp": 21.0},
                triggered_high_value_rules=["MAPEK-R06-AI-REDTEAM", "MAPEK-R08-CRIT-VALIDATE"],
                total_risk_yield=182.0,
                total_duration_ms=590.0,
            ),
            HistoricalEngagementTrace(
                engagement_id="ARCH-SYSTEMS-BIN-004",
                target_name="archetype_systems_native_crypto",
                fingerprint={"total_files": 60, "total_loc": 14000, "language_distribution": {"c": 30, "cpp": 20, "rust": 10}, "has_native_c_cpp_binaries": True, "has_lockfiles_or_sbom": True, "estimated_risk_prior": 0.68},
                winning_profile="deep_redteam",
                winning_genome_id="genome-native-crypto-champion",
                stage_yield_map={"binary_memory": 46.0, "tls_crypto": 34.0, "grammar_fuzzer": 31.0, "supply_chain_sbom": 18.0},
                triggered_high_value_rules=["MAPEK-R05-FUZZ-ESCALATE"],
                total_risk_yield=129.0,
                total_duration_ms=520.0,
            ),
        ])
