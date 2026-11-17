"""
Harness² Multi-Genome Portfolio Ensemble Coordinator & Noisy-OR Bayesian Consensus Arbiter.

Orchestrates diverse specialist Harness² profiles (`fast_ci`, `cloud_iac_zero_trust`,
`balanced_enterprise`, `deep_redteam`), deduplicates cross-genome findings, fuses
confidence via Noisy-OR (`1 - prod(1 - p_i)`), measures pairwise Jaccard portfolio
diversity, and computes the minimal hitting set of profiles covering 100% of union criticals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import utc_now_iso
from ely_soe.harness_squared.policy_compiler import HarnessWorkflowPolicyCompiler


@dataclass
class ConsensusFindingRecord:
    fingerprint: str
    rule_id: str
    title: str
    severity: str
    cwe_ids: List[str]
    detecting_profiles: List[str]
    agreement_ratio: float
    noisy_or_confidence: float
    sandbox_verified_by_any: bool
    consensus_tier: str  # UNANIMOUS | MAJORITY_CONSENSUS | SPECIALIST_UNIQUE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "cwe_ids": list(self.cwe_ids),
            "detecting_profiles": list(self.detecting_profiles),
            "agreement_ratio": round(self.agreement_ratio, 3),
            "noisy_or_confidence": round(self.noisy_or_confidence, 4),
            "sandbox_verified_by_any": self.sandbox_verified_by_any,
            "consensus_tier": self.consensus_tier,
        }


@dataclass
class EnsembleCoordinationReport:
    ensemble_id: str
    target_path: str
    executed_at: str
    member_profiles: List[str]
    member_summaries: List[Dict[str, Any]]
    union_vulnerability_count: int
    union_critical_count: int
    unanimous_count: int
    majority_count: int
    specialist_unique_count: int
    ensemble_gate_verdict: str
    mean_pairwise_diversity: float
    pairwise_jaccard_matrix: Dict[str, Dict[str, float]]
    minimal_critical_covering_profiles: List[str]
    consensus_findings: List[ConsensusFindingRecord] = field(default_factory=list)
    total_portfolio_duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ensemble_id": self.ensemble_id,
            "target_path": self.target_path,
            "executed_at": self.executed_at,
            "member_profiles": list(self.member_profiles),
            "member_summaries": list(self.member_summaries),
            "union_vulnerability_count": self.union_vulnerability_count,
            "union_critical_count": self.union_critical_count,
            "unanimous_count": self.unanimous_count,
            "majority_count": self.majority_count,
            "specialist_unique_count": self.specialist_unique_count,
            "ensemble_gate_verdict": self.ensemble_gate_verdict,
            "mean_pairwise_diversity": round(self.mean_pairwise_diversity, 4),
            "pairwise_jaccard_matrix": self.pairwise_jaccard_matrix,
            "minimal_critical_covering_profiles": list(self.minimal_critical_covering_profiles),
            "total_portfolio_duration_ms": round(self.total_portfolio_duration_ms, 2),
            "top_consensus_findings": [c.to_dict() for c in self.consensus_findings[:30]],
        }


class HarnessEnsembleCoordinator:
    """Coordinates a portfolio of Harness² profiles/genomes and fuses findings via Noisy-OR."""

    def __init__(self, compiler: Optional[HarnessWorkflowPolicyCompiler] = None) -> None:
        self.compiler = compiler or HarnessWorkflowPolicyCompiler()

    def fuse_runs(
        self,
        member_runs: Sequence[Tuple[str, Dict[str, Any]]],
        ensemble_id: str = "h2-ensemble-001",
    ) -> EnsembleCoordinationReport:
        n_members = len(member_runs)
        if n_members == 0:
            return EnsembleCoordinationReport(
                ensemble_id=ensemble_id,
                target_path="",
                executed_at=utc_now_iso(),
                member_profiles=[],
                member_summaries=[],
                union_vulnerability_count=0,
                union_critical_count=0,
                unanimous_count=0,
                majority_count=0,
                specialist_unique_count=0,
                ensemble_gate_verdict="APPROVED",
                mean_pairwise_diversity=0.0,
                pairwise_jaccard_matrix={},
                minimal_critical_covering_profiles=[],
            )

        target_path = str(member_runs[0][1].get("target_fingerprint", {}).get("target_root", ""))
        profiles = [p for p, _ in member_runs]
        member_summaries: List[Dict[str, Any]] = []
        per_member_keys: Dict[str, Set[str]] = {}
        per_member_crit_keys: Dict[str, Set[str]] = {}
        bucket_vulns: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
        total_ms = 0.0

        for prof, rep in member_runs:
            dur = float(rep.get("duration_ms", 0.0))
            total_ms += dur
            keys: Set[str] = set()
            crit_keys: Set[str] = set()
            for v in rep.get("vulnerabilities", []):
                k = str(v.get("fingerprint") or f"{v.get('rule_id','')}|{v.get('file_path','')}:{v.get('line_start',0)}")
                keys.add(k)
                if str(v.get("severity", "")).lower() == "critical":
                    crit_keys.add(k)
                bucket_vulns.setdefault(k, []).append((prof, v))

            per_member_keys[prof] = keys
            per_member_crit_keys[prof] = crit_keys
            member_summaries.append({
                "profile": prof,
                "genome_id": rep.get("selected_genome", {}).get("genome_id", ""),
                "run_id": rep.get("run_id", ""),
                "vuln_count": len(keys),
                "critical_count": len(crit_keys),
                "risk_yield": round(float(rep.get("telemetry", {}).get("total_risk_weighted_yield", 0.0)), 2),
                "duration_ms": round(dur, 2),
                "gate_verdict": rep.get("gate_verdict", "BLOCKED"),
            })

        sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        consensus_records: List[ConsensusFindingRecord] = []

        for fp, entries in bucket_vulns.items():
            best_by_prof: Dict[str, Dict[str, Any]] = {}
            for prof, v in entries:
                if prof not in best_by_prof or float(v.get("confidence", 0.8)) > float(best_by_prof[prof].get("confidence", 0.8)):
                    best_by_prof[prof] = v

            detecting = sorted(best_by_prof.keys())
            agreement = len(detecting) / float(n_members)
            miss_prob = 1.0
            for v in best_by_prof.values():
                p_i = max(0.05, min(0.99, float(v.get("confidence", 0.85))))
                miss_prob *= (1.0 - p_i)
            noisy_or = min(0.999, 1.0 - miss_prob)

            rep_v = max(
                best_by_prof.values(),
                key=lambda v: (sev_rank.get(str(v.get("severity", "medium")).lower(), 0), bool(v.get("sandbox_reproduced")), float(v.get("confidence", 0.8))),
            )
            verified_any = any(bool(v.get("sandbox_reproduced")) for v in best_by_prof.values())
            if len(detecting) == n_members and n_members > 1:
                tier = "UNANIMOUS"
            elif agreement >= 0.5 and len(detecting) > 1:
                tier = "MAJORITY_CONSENSUS"
            else:
                tier = "SPECIALIST_UNIQUE"

            consensus_records.append(
                ConsensusFindingRecord(
                    fingerprint=fp,
                    rule_id=str(rep_v.get("rule_id", "")),
                    title=str(rep_v.get("title", "")),
                    severity=str(rep_v.get("severity", "medium")).upper(),
                    cwe_ids=list(rep_v.get("cwe_ids", [])),
                    detecting_profiles=detecting,
                    agreement_ratio=agreement,
                    noisy_or_confidence=noisy_or,
                    sandbox_verified_by_any=verified_any,
                    consensus_tier=tier,
                )
            )

        consensus_records.sort(
            key=lambda c: (sev_rank.get(c.severity.lower(), 0), c.noisy_or_confidence, c.agreement_ratio),
            reverse=True,
        )

        jaccard: Dict[str, Dict[str, float]] = {}
        div_vals: List[float] = []
        for i, p1 in enumerate(profiles):
            jaccard[p1] = {}
            for j, p2 in enumerate(profiles):
                s1, s2 = per_member_keys[p1], per_member_keys[p2]
                union = s1 | s2
                sim = (len(s1 & s2) / len(union)) if union else 1.0
                jaccard[p1][p2] = round(sim, 4)
                if j > i:
                    div_vals.append(1.0 - sim)
        mean_div = sum(div_vals) / len(div_vals) if div_vals else 0.0

        all_crits: Set[str] = set()
        for ck in per_member_crit_keys.values():
            all_crits.update(ck)
        uncovered = set(all_crits)
        min_cover: List[str] = []
        while uncovered:
            best_p = max(profiles, key=lambda p: len(per_member_crit_keys[p] & uncovered))
            gain = per_member_crit_keys[best_p] & uncovered
            if not gain:
                break
            min_cover.append(best_p)
            uncovered -= gain

        union_crits = sum(1 for c in consensus_records if c.severity == "CRITICAL")
        any_blocked = any(str(rep.get("gate_verdict", "")).upper() == "BLOCKED" for _, rep in member_runs)
        gate = "BLOCKED" if (union_crits > 0 or any_blocked) else (
            "CONDITIONAL" if any(str(rep.get("gate_verdict", "")).upper() == "CONDITIONAL" for _, rep in member_runs) else "APPROVED"
        )

        return EnsembleCoordinationReport(
            ensemble_id=ensemble_id,
            target_path=target_path,
            executed_at=utc_now_iso(),
            member_profiles=profiles,
            member_summaries=member_summaries,
            union_vulnerability_count=len(consensus_records),
            union_critical_count=union_crits,
            unanimous_count=sum(1 for c in consensus_records if c.consensus_tier == "UNANIMOUS"),
            majority_count=sum(1 for c in consensus_records if c.consensus_tier == "MAJORITY_CONSENSUS"),
            specialist_unique_count=sum(1 for c in consensus_records if c.consensus_tier == "SPECIALIST_UNIQUE"),
            ensemble_gate_verdict=gate,
            mean_pairwise_diversity=mean_div,
            pairwise_jaccard_matrix=jaccard,
            minimal_critical_covering_profiles=min_cover,
            consensus_findings=consensus_records,
            total_portfolio_duration_ms=total_ms,
        )

    def run_portfolio(
        self,
        engine: Any,
        target_path: Path,
        profiles: Sequence[str] = ("fast_ci", "cloud_iac_zero_trust", "balanced_enterprise"),
    ) -> EnsembleCoordinationReport:
        runs: List[Tuple[str, Dict[str, Any]]] = []
        for prof in profiles:
            rep = engine.run_adaptive_assessment(
                target_path=target_path,
                preferred_profile=prof,
                enable_adaptation=True,
            )
            runs.append((prof, rep))
        return self.fuse_runs(runs, ensemble_id=f"h2-portfolio-{target_path.name}")
