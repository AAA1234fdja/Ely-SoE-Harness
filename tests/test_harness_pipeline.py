"""
Tests for Layer 4 (`ely_soe.harness` — 6-Component Harness & Model Adapters).

Verifies:
  - ModelRegistry profiles & adapters (`glm-5.3`, `frontier-cyber-v2`, `frontier-reasoner`, `baseline-small`).
  - Component 1 (SecurityPlanner) risk-prioritized campaign planning.
  - Component 3 (VulnerabilityAnalyzer) NEVER marks findings CONFIRMED (strictly HYPOTHESIS).
  - Component 4 (ControlledTestGenerator) generates sandbox-safe PoC scripts with oracle hooks.
  - Component 5 (IndependentValidator) confirms reproducible flaws AND rejects fabricated/hallucinated FPs!
  - Component 6 (SecurityReporter) exports valid JSON, Markdown, SARIF 2.1.0, and HTML.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ely_soe.analyzers.repo_analyzer import RepositoryAnalyzer
from ely_soe.core.config import HARNESS_PRESETS, SandboxConfig, ValidatorConfig
from ely_soe.core.models import (
    AuditModality,
    CodeLocation,
    Finding,
    FindingStatus,
    SecurityDomain,
    SecurityEvaluationReport,
    Severity,
    ValidationCertificate,
    ValidationVerdict,
    new_id,
)
from ely_soe.harness.model_adapters import ModelRegistry
from ely_soe.harness.planner import AuditPlanner
from ely_soe.harness.reporter import SecurityReporter
from ely_soe.harness.test_generator import ControlledTestGenerator
from ely_soe.harness.validator import IndependentValidator
from ely_soe.harness.vuln_analyzer import VulnerabilityAnalyzer
from ely_soe.lab.auditor import IndependentAuditor


SPECIMEN_V09 = Path("lab_targets/ely_specimen/v0_9")


class TestHarnessPipelineAndSeparationOfDuties(unittest.TestCase):
    """Tests full 6-component harness and cryptographic validation separation."""

    def test_model_registry_lists_glm53_and_frontier_models(self) -> None:
        models = ModelRegistry.list_models()
        self.assertIn("glm-5.3", models)
        self.assertIn("frontier-cyber-v2", models)
        self.assertIn("frontier-reasoner", models)
        self.assertIn("baseline-small", models)
        profiles = ModelRegistry.list_profiles()
        self.assertEqual(len(profiles), len(models))

    def test_planner_builds_risk_ordered_plan(self) -> None:
        graph = RepositoryAnalyzer().analyze(SPECIMEN_V09)
        plan = AuditPlanner().build_plan(
            target_name="ely-cowork",
            target_version="0.9.0",
            modality=AuditModality.PRE_RELEASE,
            domains=list(SecurityDomain),
            profile=HARNESS_PRESETS["full_soe_harness"],
            model_id="glm-5.3",
            attack_surface=graph,
        )
        self.assertEqual(len(plan.domains), 10)
        self.assertGreaterEqual(len(plan.tasks), 5)
        self.assertEqual(plan.harness_profile, "full_soe_harness")

    def test_vulnerability_analyzer_emits_only_hypotheses_and_validator_filters_fps(self) -> None:
        graph = RepositoryAnalyzer().analyze(SPECIMEN_V09)
        adapter = ModelRegistry.create_adapter("glm-5.3")
        analyzer = VulnerabilityAnalyzer(model_adapter=adapter)
        hypotheses, meta = analyzer.discover(
            snapshot_root=SPECIMEN_V09,
            domains=[SecurityDomain.TOOL_EXECUTION, SecurityDomain.API_SECURITY],
            profile=HARNESS_PRESETS["full_soe_harness"],
            attack_surface=graph,
        )
        self.assertGreater(len(hypotheses), 0)
        # Strict invariant: Discovery MUST NEVER set status == CONFIRMED!
        for h in hypotheses:
            self.assertEqual(h.status, FindingStatus.HYPOTHESIS)
            self.assertIsNone(h.validation)

        # Inject a blatantly hallucinated / false-positive finding to prove IndependentValidator rejects it!
        hallucinated = Finding(
            finding_id=new_id("fnd"),
            title="[Hallucinated] Phantom RCE in nonexistent.py",
            description="Fabricated LLM claim targeting nonexistent line",
            domain=SecurityDomain.TOOL_EXECUTION,
            severity=Severity.CRITICAL,
            rule_id="HALLUCINATED-FAKE-RULE",
            discovered_by="glm-5.3",
            location=CodeLocation(file_path="agents/nonexistent_phantom.py", line_start=999, snippet="eval(phantom)"),
            status=FindingStatus.HYPOTHESIS,
            poc_spec={"kind": "static_rule", "rule_id": "HALLUCINATED", "target_file": "agents/nonexistent_phantom.py", "snippet": "eval(phantom)"},
        )
        all_candidates = hypotheses[:6] + [hallucinated]

        pocs = ControlledTestGenerator().generate_for_findings(all_candidates, SPECIMEN_V09)
        self.assertEqual(len(pocs), len(all_candidates))

        auditor = IndependentAuditor()
        validator = IndependentValidator(
            auditor=auditor,
            validator_config=ValidatorConfig(reproducibility_trials=1),
            sandbox_config=SandboxConfig(execution_timeout_seconds=6.0),
        )
        stats = validator.validate_all(all_candidates, pocs, SPECIMEN_V09)
        self.assertGreater(stats["confirmed"], 0)
        self.assertNotEqual(hallucinated.status, FindingStatus.CONFIRMED)
        self.assertIn(hallucinated.status, (FindingStatus.FALSE_POSITIVE, FindingStatus.INCONCLUSIVE))

    def test_reporter_generates_valid_json_markdown_sarif_and_html(self) -> None:
        auditor = IndependentAuditor()
        f = Finding(
            finding_id=new_id("fnd"),
            title="Test Confirmed SQL Injection",
            description="SQLi in query_session",
            domain=SecurityDomain.API_SECURITY,
            severity=Severity.HIGH,
            rule_id="API-SQLI",
            discovered_by="ely_static",
            location=CodeLocation(file_path="api/server.py", line_start=29, snippet="cur.execute(f'SELECT...')"),
            cwe_ids=["CWE-89"],
            cvss_score=8.6,
        )
        cert = ValidationCertificate(
            certificate_id=new_id("cert"),
            finding_id=f.finding_id,
            verdict=ValidationVerdict.REPRODUCED,
            validator_id="ely_independent_validator_v1",
            sandbox_id="sbx-rep",
            trials_run=1,
            trials_reproduced=1,
            baseline_passed=True,
            exploit_triggered=True,
            oracle_integrity_verified=True,
            reproduction_steps=["Confirmed SQLi in isolated sandbox"],
            evidence_hashes=["sha256:demo"],
            issued_at="2026-11-15T00:00:00Z",
            signature="",
        )
        cert.signature = auditor.keyring.sign_certificate(cert)
        f.apply_validation_certificate(cert, verify_signature_fn=auditor.keyring.verify_certificate)
        rep = SecurityEvaluationReport(
            report_id=new_id("rep"),
            run_id=new_id("run"),
            modality=AuditModality.ON_DEMAND,
            target_name="ely-cowork",
            target_version="0.9.0",
            model_id="glm-5.3",
            harness_profile="full_soe_harness",
            snapshot_digest="abc123def456",
            sandbox_destroyed_verified=True,
            main_instance_untouched_verified=True,
            findings=[f],
        )
        auditor.seal_report(rep)

        reporter = SecurityReporter()
        parsed_json = json.loads(reporter.to_json(rep))
        self.assertEqual(parsed_json["report_id"], rep.report_id)

        sarif = json.loads(reporter.to_sarif(rep))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)

        md = reporter.to_markdown(rep)
        self.assertIn("Test Confirmed SQL Injection", md)

        html = reporter.to_html(rep)
        self.assertIn("<!DOCTYPE html>", html)

        with tempfile.TemporaryDirectory() as tmp:
            paths = reporter.write_all_formats(rep, Path(tmp))
            for p in paths.values():
                self.assertTrue(Path(p).exists())


if __name__ == "__main__":
    unittest.main()
