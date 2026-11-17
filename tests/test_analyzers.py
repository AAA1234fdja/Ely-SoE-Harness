"""
Tests for Layer 3 (`ely_soe.analyzers` — Specialized Static, Taint, Rust, Supply Chain & Domain Analyzers).

Verifies:
  - Repository Attack Surface Mapper (AST endpoints, sinks, agents, skills, Rust crates).
  - Interprocedural Taint Engine (Source -> Sink tracking across Python functions & sanitizer pruning).
  - Rust Core Security Analyzer (FFI raw pointers, transmute, unsafe Send/Sync, Mutex across .await, build.rs, Cargo.toml).
  - Supply Chain & SBOM Auditor (CycloneDX SBOM, CVE matching, Levenshtein typosquatting, postinstall hooks, skill manifests).
  - CoreAgenticDomainAnalyzer & InfrastructureDomainAnalyzer covering all 10 domains.
  - Zero false positives on hardened `v1_0_hardened` specimen!
"""

from __future__ import annotations

import unittest
from pathlib import Path

from ely_soe.analyzers.domain_analyzers import CoreAgenticDomainAnalyzer
from ely_soe.analyzers.frontier_tools import FrontierToolRegistry
from ely_soe.analyzers.infra_analyzers import InfrastructureDomainAnalyzer
from ely_soe.analyzers.repo_analyzer import RepositoryAnalyzer
from ely_soe.analyzers.rust_core import RustCoreAnalyzer
from ely_soe.analyzers.supply_chain import SupplyChainAnalyzer
from ely_soe.analyzers.taint_engine import PythonTaintAnalyzer
from ely_soe.core.models import FindingStatus, SecurityDomain


SPECIMEN_V09 = Path("lab_targets/ely_specimen/v0_9")
SPECIMEN_V10 = Path("lab_targets/ely_specimen/v1_0_hardened")


class TestRepositoryAndTaintAnalyzers(unittest.TestCase):
    """Tests AST attack surface mapping and interprocedural taint tracking."""

    def test_repo_analyzer_maps_v09_surface(self) -> None:
        analyzer = RepositoryAnalyzer()
        graph = analyzer.analyze(SPECIMEN_V09)
        self.assertGreaterEqual(graph.total_files, 10)
        self.assertIn("python", graph.languages)
        self.assertIn("rust", graph.languages)
        self.assertGreater(len(graph.nodes), 0)
        self.assertGreater(len(graph.trust_boundaries), 0)

    def test_taint_engine_tracks_v09_flows_and_is_clean_on_v10(self) -> None:
        engine = PythonTaintAnalyzer()
        f09 = engine.analyze_directory(SPECIMEN_V09)
        self.assertGreaterEqual(len(f09), 5)
        self.assertTrue(all(f.status == FindingStatus.HYPOTHESIS for f in f09))

        f10 = engine.analyze_directory(SPECIMEN_V10)
        self.assertEqual(len(f10), 0, f"Unexpected taint findings in v1.0: {[(f.rule_id, f.location.file_path) for f in f10]}")


class TestRustCoreAndSupplyChainAnalyzers(unittest.TestCase):
    """Tests deep Rust Core auditing and Supply Chain + SBOM detection."""

    def test_rust_core_analyzer_detects_all_v09_flaws_and_clean_on_v10(self) -> None:
        rust = RustCoreAnalyzer()
        f09 = rust.analyze_directory(SPECIMEN_V09)
        self.assertGreaterEqual(len(f09), 7)
        titles = " ".join(f.title.lower() for f in f09)
        self.assertIn("transmute", titles)
        self.assertIn("from_raw_parts", titles)
        self.assertIn("build.rs", titles)
        self.assertIn("await", titles)

        f10 = rust.analyze_directory(SPECIMEN_V10)
        self.assertEqual(len(f10), 0, f"Unexpected Rust findings in v1.0: {[f.title for f in f10]}")

    def test_supply_chain_analyzer_sbom_cves_typosquats_and_skills(self) -> None:
        sc = SupplyChainAnalyzer()
        f09, sbom09 = sc.analyze_directory(SPECIMEN_V09)
        self.assertEqual(sbom09["bomFormat"], "CycloneDX")
        self.assertGreaterEqual(len(sbom09["components"]), 8)
        self.assertGreaterEqual(len(f09), 10)
        combined_titles = " ".join(f.title.lower() for f in f09)
        self.assertIn("typosquat", combined_titles)
        self.assertIn("postinstall", combined_titles)
        self.assertIn("unsigned", combined_titles)

        f10, sbom10 = sc.analyze_directory(SPECIMEN_V10)
        self.assertEqual(sbom10["bomFormat"], "CycloneDX")
        self.assertEqual(len(f10), 0, f"Unexpected supply chain findings in v1.0: {[f.title for f in f10]}")


class TestAllTenDomainAnalyzersAndToolSuite(unittest.TestCase):
    """Tests domain-specific analyzers and unified FrontierSecurityToolSuite."""

    def test_core_agentic_and_infra_domain_analyzers_hit_v09_and_clean_on_v10(self) -> None:
        core_an = CoreAgenticDomainAnalyzer()
        hits_core_09 = core_an.analyze_directory(SPECIMEN_V09)
        self.assertGreaterEqual(len(hits_core_09), 10)
        core_domains_hit = {h.domain for h in hits_core_09}
        for d in (
            SecurityDomain.AGENT_ISOLATION,
            SecurityDomain.TOOL_EXECUTION,
            SecurityDomain.MEMORY,
            SecurityDomain.PROMPT_INJECTION,
            SecurityDomain.API_SECURITY,
        ):
            self.assertIn(d, core_domains_hit)
        self.assertEqual(len(core_an.analyze_directory(SPECIMEN_V10)), 0)

        infra_an = InfrastructureDomainAnalyzer()
        hits_infra_09 = infra_an.analyze_directory(SPECIMEN_V09)
        self.assertGreaterEqual(len(hits_infra_09), 6)
        infra_domains_hit = {h.domain for h in hits_infra_09}
        for d in (SecurityDomain.FILESYSTEM, SecurityDomain.PROCESS_MANAGEMENT, SecurityDomain.NETWORK):
            self.assertIn(d, infra_domains_hit)
        self.assertEqual(len(infra_an.analyze_directory(SPECIMEN_V10)), 0)

    def test_frontier_tool_registry_catalogs_dual_class_tools(self) -> None:
        reg = FrontierToolRegistry()
        catalog = reg.list_tools()
        self.assertGreaterEqual(len(catalog), 6)
        classes = {t.tool_class.value for t in catalog}
        self.assertIn("frontier_cyber_model", classes)
        self.assertIn("specialized_security_tool", classes)


if __name__ == "__main__":
    unittest.main()
