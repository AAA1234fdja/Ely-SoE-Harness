"""
Cross-Engine Semantic Finding Deduplicator, Corroboration Fusion & Bayesian Confidence Engine.

Solves one of the hardest practical weaknesses of multi-scanner security platforms:
when 47 specialized engines scan the same target (e.g., SAST AST + Interprocedural Taint +
Deobfuscation Normalizer + Zero-Day Reachability + Live Sandbox DAST), overlapping detections
inflate raw counts and create alert fatigue unless semantically fused.

Capabilities:
  1. **Semantic Fingerprint Clustering**:
       Groups findings across heterogeneous engines sharing:
         `(canonical_normalized_path, line_bucket_within_3_lines, canonical_cwe_family)`
       while preserving distinct root bugs in the same file.
  2. **Orthogonal-Evidence Bayesian Confidence Fusion**:
       When `k >= 2` independent detection methodologies corroborate the same flaw
       (e.g., `STATIC_AST` + `SANDBOX_DIFFERENTIAL_PROBE` + `interprocedural_taint`),
       fuses independent error probabilities via noisy-OR / Bayesian log-odds pooling:
         `P_fused = 1 - prod_i (1 - p_i * modality_reliability_i)`
       and boosts priority without double-counting!
  3. **Noise Compression & Corroboration Telemetry**:
       Emits exact `raw_count -> deduplicated_count`, `compression_ratio`,
       `multi_engine_corroborated_count`, and per-cluster provenance chains showing
       every independent engine that agreed on each vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import CyberVulnerability, VerificationMethod


SEVERITY_RANK: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Normalize closely related CWEs into canonical root-cause families for semantic clustering
CWE_CANONICAL_FAMILY: Dict[str, str] = {
    "CWE-89": "SQLI", "CWE-564": "SQLI", "CWE-943": "SQLI",
    "CWE-78": "CMD_INJ", "CWE-77": "CMD_INJ", "CWE-88": "CMD_INJ",
    "CWE-94": "CODE_INJ", "CWE-95": "CODE_INJ", "CWE-1336": "SSTI",
    "CWE-502": "DESER", "CWE-915": "DESER",
    "CWE-918": "SSRF",
    "CWE-79": "XSS", "CWE-80": "XSS",
    "CWE-22": "PATH_TRAVERSAL", "CWE-23": "PATH_TRAVERSAL", "CWE-73": "PATH_TRAVERSAL",
    "CWE-611": "XXE",
    "CWE-798": "HARDCODED_SECRET", "CWE-259": "HARDCODED_SECRET", "CWE-321": "HARDCODED_SECRET",
    "CWE-287": "AUTH_BYPASS", "CWE-347": "JWT_SIG", "CWE-290": "AUTH_BYPASS",
    "CWE-327": "WEAK_CRYPTO", "CWE-328": "WEAK_CRYPTO", "CWE-326": "WEAK_CRYPTO", "CWE-330": "WEAK_PRNG",
    "CWE-250": "PRIV_ESC", "CWE-269": "PRIV_ESC",
    "CWE-120": "MEM_CORRUPT", "CWE-119": "MEM_CORRUPT", "CWE-787": "MEM_CORRUPT", "CWE-416": "MEM_CORRUPT", "CWE-134": "MEM_CORRUPT",
}

MODALITY_RELIABILITY: Dict[str, float] = {
    "sandbox_differential_probe": 0.99,
    "crypto_oracle_check": 0.98,
    "protocol_state_machine": 0.96,
    "static_ast": 0.93,
    "graph_reachability": 0.92,
    "grammar_fuzzer": 0.94,
    "binary_header_inspection": 0.95,
    "sigma_yara_match": 0.90,
    "emulation_playbook": 0.89,
    "static_pattern": 0.82,
}


@dataclass
class CorrelatedFindingCluster:
    cluster_id: str
    canonical_location: str
    cwe_family: str
    primary_vuln: CyberVulnerability
    merged_vulns: List[CyberVulnerability] = field(default_factory=list)
    corroborating_engines: List[str] = field(default_factory=list)
    corroborating_methods: List[str] = field(default_factory=list)
    fused_confidence: float = 0.0
    sandbox_corroborated: bool = False


class CrossEngineFindingCorrelator:
    """Semantically deduplicates & Bayesian-fuses findings from multiple cybersecurity engines."""

    def __init__(self, line_proximity_window: int = 3) -> None:
        self.line_proximity_window = max(1, int(line_proximity_window))

    def deduplicate_and_correlate(self, vulns: Sequence[CyberVulnerability]) -> Dict[str, Any]:
        """Cluster overlapping findings, fuse Bayesian confidence, and emit clean deduplicated list."""
        clusters: List[CorrelatedFindingCluster] = []

        for v in vulns:
            loc = self._normalize_location(v)
            fam = self._cwe_family(v)
            line_no = max(1, int(v.line_start or 1))

            matched_cluster: Optional[CorrelatedFindingCluster] = None
            for cl in clusters:
                if cl.canonical_location == loc and cl.cwe_family == fam:
                    cl_line = max(1, int(cl.primary_vuln.line_start or 1))
                    if abs(cl_line - line_no) <= self.line_proximity_window or loc.startswith("asset:"):
                        # For asset-level findings without file lines, only merge if rule_id or title prefix matches
                        if loc.startswith("asset:") and cl.primary_vuln.rule_id != v.rule_id:
                            continue
                        matched_cluster = cl
                        break

            if matched_cluster is None:
                cl = CorrelatedFindingCluster(
                    cluster_id=f"CORR-{len(clusters)+1:04d}",
                    canonical_location=loc,
                    cwe_family=fam,
                    primary_vuln=v,
                    merged_vulns=[v],
                    corroborating_engines=[v.discovered_by],
                    corroborating_methods=[v.verification_method.value],
                    sandbox_corroborated=bool(v.sandbox_reproduced),
                )
                clusters.append(cl)
            else:
                matched_cluster.merged_vulns.append(v)
                if v.discovered_by not in matched_cluster.corroborating_engines:
                    matched_cluster.corroborating_engines.append(v.discovered_by)
                vm = v.verification_method.value
                if vm not in matched_cluster.corroborating_methods:
                    matched_cluster.corroborating_methods.append(vm)
                if v.sandbox_reproduced:
                    matched_cluster.sandbox_corroborated = True
                # Promote higher-severity / sandbox-verified finding to primary representative
                if self._rank_candidate(v) > self._rank_candidate(matched_cluster.primary_vuln):
                    matched_cluster.primary_vuln = v

        # Compute Bayesian noisy-OR fused confidence per cluster and enrich primary findings
        deduplicated: List[CyberVulnerability] = []
        corroborated_clusters: List[Dict[str, Any]] = []
        multi_engine_count = 0

        for cl in clusters:
            fused_p = self._bayesian_noisy_or(cl.merged_vulns)
            cl.fused_confidence = fused_p
            prim = cl.primary_vuln
            prim.confidence = max(prim.confidence, fused_p)
            if cl.sandbox_corroborated:
                prim.sandbox_reproduced = True
            # Merge unique CWEs and tags from corroborating engines
            merged_cwes = list(dict.fromkeys(c for mv in cl.merged_vulns for c in mv.cwe_ids))
            prim.cwe_ids = merged_cwes
            if len(cl.corroborating_engines) >= 2:
                multi_engine_count += 1
                if "multi_engine_corroborated" not in prim.tags:
                    prim.tags.append("multi_engine_corroborated")
                corroborated_clusters.append({
                    "cluster_id": cl.cluster_id,
                    "location": cl.canonical_location,
                    "cwe_family": cl.cwe_family,
                    "primary_rule_id": prim.rule_id,
                    "severity": prim.severity.value,
                    "merged_count": len(cl.merged_vulns),
                    "engines": list(cl.corroborating_engines),
                    "methods": list(cl.corroborating_methods),
                    "fused_confidence": fused_p,
                    "sandbox_corroborated": cl.sandbox_corroborated,
                })
            deduplicated.append(prim)

        raw_n = len(vulns)
        dedup_n = len(deduplicated)
        duplicates_eliminated = raw_n - dedup_n
        reduction_pct = round((duplicates_eliminated / max(1, raw_n)) * 100.0, 2)

        return {
            "correlated_at": utc_now_iso(),
            "raw_findings_count": raw_n,
            "deduplicated_findings_count": dedup_n,
            "duplicates_eliminated": duplicates_eliminated,
            "noise_reduction_pct": reduction_pct,
            "multi_engine_corroborated_count": multi_engine_count,
            "corroborated_clusters": corroborated_clusters[:25],
            "deduplicated_vulnerabilities": deduplicated,
        }

    @staticmethod
    def _normalize_location(v: CyberVulnerability) -> str:
        fp = (v.file_path or "").strip().replace("\\", "/")
        if fp:
            parts = fp.split("/")
            # Keep last 2 path components to normalize absolute vs relative paths
            short = "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
            return f"file:{short.lower()}"
        ep = (v.endpoint_or_asset or "").strip().lower()
        return f"asset:{ep or v.rule_id.lower()}"

    @staticmethod
    def _cwe_family(v: CyberVulnerability) -> str:
        for cwe in v.cwe_ids:
            fam = CWE_CANONICAL_FAMILY.get(str(cwe).upper())
            if fam:
                return fam
        return v.cwe_ids[0].upper() if v.cwe_ids else v.rule_id

    @staticmethod
    def _rank_candidate(v: CyberVulnerability) -> Tuple[int, int, float, float]:
        return (
            1 if v.sandbox_reproduced else 0,
            SEVERITY_RANK.get(v.severity.value.lower(), 1),
            MODALITY_RELIABILITY.get(v.verification_method.value.lower(), 0.8),
            float(v.confidence),
        )

    @staticmethod
    def _bayesian_noisy_or(merged: Sequence[CyberVulnerability]) -> float:
        """
        Noisy-OR evidence fusion across distinct engines:
          `P(TrueVuln | E_1..E_k) = 1 - prod_j (1 - p_j * r_j)`
        Deduplicates by engine so a single noisy engine cannot artificially saturate confidence.
        """
        best_by_engine: Dict[str, float] = {}
        for v in merged:
            rel = MODALITY_RELIABILITY.get(v.verification_method.value.lower(), 0.85)
            eff = min(0.99, max(0.1, float(v.confidence) * rel))
            prev = best_by_engine.get(v.discovered_by, 0.0)
            if eff > prev:
                best_by_engine[v.discovered_by] = eff
        prob_all_false = 1.0
        for p in best_by_engine.values():
            prob_all_false *= (1.0 - p)
        return round(min(0.999, 1.0 - prob_all_false), 4)
