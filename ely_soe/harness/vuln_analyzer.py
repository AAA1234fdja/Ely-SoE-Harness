"""
Component 3 of the 6-Stage Security Harness: Vulnerability Analyzer.

Orchestrates all discovery engines over the isolated Temporary Adversarial Snapshot:
  - Core Agentic Domain Analyzer (Agent Isolation, Tool Execution, Memory, Prompt Injection, API)
  - Infrastructure Domain Analyzer (Filesystem, Process Management, Network)
  - Python Interprocedural AST Taint Engine
  - Rust Core Deep Unsafe/FFI/Concurrency Analyzer
  - Supply Chain & CycloneDX SBOM Analyzer
  - Pluggable Frontier / GLM 5.3 Semantic Model Adapter

Strictly enforces the separation of Discovery and Validation:
  - Every emitted `Finding` is asserted to have `status == FindingStatus.HYPOTHESIS`.
  - Deduplicates overlapping findings across analyzers while merging multi-tool evidence
    artifacts and elevating discovery confidence when corroborated by >= 2 independent signals.
  - Enriches every hypothesis with CVSS v3.1, Agentic Risk Score, CWE, OWASP Agentic Top 10,
    and MITRE ATLAS metadata via `RiskScoringEngine`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ely_soe.analyzers.domain_analyzers import CoreAgenticDomainAnalyzer
from ely_soe.analyzers.infra_analyzers import InfrastructureDomainAnalyzer
from ely_soe.analyzers.rust_core import RustCoreAnalyzer
from ely_soe.analyzers.supply_chain import SupplyChainAnalyzer
from ely_soe.analyzers.taint_engine import PythonTaintAnalyzer
from ely_soe.core.config import HarnessProfileConfig
from ely_soe.core.crypto_ledger import ForensicAuditLedger
from ely_soe.core.models import (
    AttackSurfaceGraph,
    Finding,
    FindingStatus,
    SecurityDomain,
    SeparationOfDutiesViolation,
)
from ely_soe.core.scoring import RiskScoringEngine
from ely_soe.harness.model_adapters import BaseCyberModelAdapter


class VulnerabilityAnalyzer:
    """
    Discovery-only vulnerability aggregation, deduplication, and risk-enrichment engine.
    Cannot confirm findings under any circumstance.
    """

    def __init__(
        self,
        model_adapter: BaseCyberModelAdapter,
        ledger: Optional[ForensicAuditLedger] = None,
    ) -> None:
        self.model_adapter = model_adapter
        self.ledger = ledger
        self.core_analyzer = CoreAgenticDomainAnalyzer()
        self.infra_analyzer = InfrastructureDomainAnalyzer()
        self.taint_analyzer = PythonTaintAnalyzer()
        self.rust_analyzer = RustCoreAnalyzer()
        self.supply_chain_analyzer = SupplyChainAnalyzer()
        self.scorer = RiskScoringEngine()

    def discover(
        self,
        snapshot_root: Path,
        domains: List[SecurityDomain],
        profile: HarnessProfileConfig,
        attack_surface: Optional[AttackSurfaceGraph] = None,
    ) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Execute configured discovery analyzers and return `(deduped_hypotheses, discovery_metadata)`.
        """
        domain_set = set(domains)
        raw_findings: List[Finding] = []
        sbom_doc: Dict[str, Any] = {}
        engine_counts: Dict[str, int] = {}

        if profile.use_static_analyzers:
            core_hits = self.core_analyzer.analyze_directory(snapshot_root, domains=domains)
            infra_hits = self.infra_analyzer.analyze_directory(snapshot_root, domains=domains)
            raw_findings.extend(core_hits)
            raw_findings.extend(infra_hits)
            engine_counts["core_domain_analyzer"] = len(core_hits)
            engine_counts["infra_domain_analyzer"] = len(infra_hits)

        if profile.use_taint_engine:
            taint_hits = [
                f for f in self.taint_analyzer.analyze_directory(snapshot_root) if f.domain in domain_set
            ]
            raw_findings.extend(taint_hits)
            engine_counts["python_taint_engine"] = len(taint_hits)

        if profile.use_rust_analyzer and SecurityDomain.RUST_CORE in domain_set:
            rust_hits = self.rust_analyzer.analyze_directory(snapshot_root)
            raw_findings.extend(rust_hits)
            engine_counts["rust_core_analyzer"] = len(rust_hits)

        if profile.use_supply_chain_scanner and SecurityDomain.SUPPLY_CHAIN in domain_set:
            sc_hits, sbom_doc = self.supply_chain_analyzer.analyze_directory(snapshot_root)
            raw_findings.extend(sc_hits)
            engine_counts["supply_chain_analyzer"] = len(sc_hits)

        if profile.use_llm_reasoning:
            llm_hits = self.model_adapter.analyze_code_semantics(
                snapshot_root=snapshot_root,
                attack_surface=attack_surface,
                domains=domains,
                existing_findings=raw_findings,
            )
            raw_findings.extend(llm_hits)
            engine_counts[f"model:{self.model_adapter.model_id}"] = len(llm_hits)

        # Hard architectural guard: verify NO discovery engine produced a CONFIRMED finding
        for f in raw_findings:
            if f.status != FindingStatus.HYPOTHESIS:
                raise SeparationOfDutiesViolation(
                    f"Discovery component '{f.discovered_by}' attempted to emit finding {f.finding_id} "
                    f"with illegal status '{f.status.value}' (ONLY HYPOTHESIS allowed)."
                )

        deduped = self._deduplicate_and_enrich(raw_findings)

        if self.ledger is not None:
            self.ledger.append(
                actor="vulnerability_analyzer",
                event_type="hypotheses_discovered",
                payload={
                    "raw_count": len(raw_findings),
                    "deduped_count": len(deduped),
                    "engine_counts": engine_counts,
                    "model_id": self.model_adapter.model_id,
                    "all_status_hypothesis": all(f.status == FindingStatus.HYPOTHESIS for f in deduped),
                },
            )

        meta = {
            "raw_candidates": len(raw_findings),
            "deduped_candidates": len(deduped),
            "engine_counts": engine_counts,
            "sbom": sbom_doc,
            "model_usage": self.model_adapter.usage.to_dict(),
        }
        return deduped, meta

    def merge_external_hypotheses(
        self,
        existing: List[Finding],
        additional: List[Finding],
    ) -> List[Finding]:
        """Merge hypotheses from Fuzzer, RedTeam, and UntrustedAgentArena while preserving HYPOTHESIS invariant."""
        for f in additional:
            if f.status != FindingStatus.HYPOTHESIS:
                raise SeparationOfDutiesViolation(
                    f"External discovery source '{f.discovered_by}' emitted non-HYPOTHESIS finding {f.finding_id}"
                )
        return self._deduplicate_and_enrich(list(existing) + list(additional))

    def _deduplicate_and_enrich(self, findings: List[Finding]) -> List[Finding]:
        by_key: Dict[str, Finding] = {}
        for f in findings:
            self.scorer.enrich_finding(f)
            # Deduplicate by (domain, file_path, rule_id) or close-line same-domain fingerprint
            dedup_key = f"{f.domain.value}|{f.location.file_path}|{f.rule_id}|{f.location.line_start // 6}"
            if dedup_key not in by_key:
                by_key[dedup_key] = f
            else:
                existing = by_key[dedup_key]
                # Corroboration merges evidence & boosts discovery confidence (still HYPOTHESIS!)
                existing.evidence.extend(f.evidence)
                existing.confidence = min(0.95, round(max(existing.confidence, f.confidence) + 0.05, 3))
                if f.severity.rank > existing.severity.rank:
                    existing.severity = f.severity
                    self.scorer.enrich_finding(existing)
                for tag in f.tags:
                    if tag not in existing.tags:
                        existing.tags.append(tag)
        # Sort highest risk first
        return sorted(
            by_key.values(),
            key=lambda x: (-x.severity.rank, -x.cvss_score, -x.agentic_risk_score, x.location.file_path, x.location.line_start),
        )
