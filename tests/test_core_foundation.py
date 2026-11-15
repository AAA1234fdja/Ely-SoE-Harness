"""
Unit & Security Invariant Tests for Layer 1 (`ely_soe.core`).

Verifies:
  - Strict Separation of Duties (`SeparationOfDutiesViolation` whenever discovery
    attempts to mark a Finding CONFIRMED without a signed IndependentAuditor certificate).
  - Cryptographic Merkle Tree & HMAC Forensic Audit Ledger integrity & tamper detection.
  - CaMeL Capability Lattice, provenance non-interference, delegation attenuation,
    and Auditor-plane isolation.
  - ScopeGuard authorization boundaries, secret scrubbing, and tree SHA-256 integrity.
  - CVSS v3.1 scoring, OWASP Agentic Top 10 & MITRE ATLAS mappings, and SOEConfig presets.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ely_soe.core.capability_lattice import (
    CapabilityGrant,
    CapabilityPolicyEngine,
    ProvenanceTag,
    TrustLevel,
)
from ely_soe.core.config import HARNESS_PRESETS, SOEConfig
from ely_soe.core.crypto_ledger import AuditorKeyring, ForensicAuditLedger, MerkleTree
from ely_soe.core.models import (
    AuditModality,
    CodeLocation,
    Finding,
    FindingStatus,
    MaturityCriterionId,
    RemediationProposal,
    SecurityDomain,
    SeparationOfDutiesViolation,
    Severity,
    ValidationCertificate,
    ValidationVerdict,
    new_id,
    utc_now_iso,
)
from ely_soe.core.scope_guard import (
    ScopeGuard,
    ScopeManifesto,
    ScopeViolationError,
    SecretScrubber,
    compute_directory_tree_digest,
)
from ely_soe.core.scoring import RiskScoringEngine


def _make_cert(
    finding_id: str,
    verdict: ValidationVerdict = ValidationVerdict.REPRODUCED,
    validator_id: str = "ely_independent_validator_v1",
    signature: str = "",
) -> ValidationCertificate:
    return ValidationCertificate(
        certificate_id=new_id("cert"),
        finding_id=finding_id,
        verdict=verdict,
        validator_id=validator_id,
        sandbox_id="sbx-unit-01",
        trials_run=3,
        trials_reproduced=3 if verdict == ValidationVerdict.REPRODUCED else 0,
        baseline_passed=True,
        exploit_triggered=(verdict == ValidationVerdict.REPRODUCED),
        oracle_integrity_verified=(verdict == ValidationVerdict.REPRODUCED),
        reproduction_steps=["Isolated clean-room sandbox replay"],
        evidence_hashes=["sha256:unit-test-evidence"],
        issued_at=utc_now_iso(),
        signature=signature,
    )


class TestSeparationOfDutiesAndModels(unittest.TestCase):
    """Tests strict Discovery vs Validation separation on Finding objects."""

    def _make_hypothesis(self) -> Finding:
        return Finding(
            finding_id=new_id("fnd"),
            title="Shell Injection via subprocess shell=True",
            description="Untrusted input reaches subprocess.run(..., shell=True)",
            domain=SecurityDomain.TOOL_EXECUTION,
            severity=Severity.CRITICAL,
            rule_id="TOOL-SHELL-TRUE",
            discovered_by="glm-5.3",
            location=CodeLocation(file_path="agents/executor.py", line_start=42, snippet="subprocess.run(cmd, shell=True)"),
            status=FindingStatus.HYPOTHESIS,
            confidence=0.92,
        )

    def test_discovery_cannot_self_confirm_unsigned_certificate(self) -> None:
        finding = self._make_hypothesis()
        self.assertEqual(finding.status, FindingStatus.HYPOTHESIS)
        unsigned_cert = _make_cert(finding.finding_id, signature="")
        with self.assertRaises(SeparationOfDutiesViolation):
            finding.apply_validation_certificate(unsigned_cert)
        self.assertEqual(finding.status, FindingStatus.HYPOTHESIS)

    def test_same_actor_as_discoverer_cannot_confirm(self) -> None:
        keyring = AuditorKeyring.from_passphrase("test-auditor-key")
        finding = self._make_hypothesis()
        same_actor_cert = _make_cert(finding.finding_id, validator_id="glm-5.3")
        same_actor_cert.signature = keyring.sign_certificate(same_actor_cert)
        with self.assertRaises(SeparationOfDutiesViolation):
            finding.apply_validation_certificate(same_actor_cert, verify_signature_fn=keyring.verify_certificate)

    def test_independent_validator_with_auditor_signature_confirms(self) -> None:
        keyring = AuditorKeyring.from_passphrase("test-auditor-key")
        finding = self._make_hypothesis()
        cert = _make_cert(finding.finding_id)
        cert.signature = keyring.sign_certificate(cert)
        finding.apply_validation_certificate(cert, verify_signature_fn=keyring.verify_certificate)
        self.assertEqual(finding.status, FindingStatus.CONFIRMED)
        self.assertIsNotNone(finding.validation)

    def test_forged_signature_rejected_with_separation_violation(self) -> None:
        k1 = AuditorKeyring.from_passphrase("real-auditor")
        k2 = AuditorKeyring.from_passphrase("forged-attacker")
        finding = self._make_hypothesis()
        cert = _make_cert(finding.finding_id)
        cert.signature = k2.sign_certificate(cert)
        with self.assertRaises(SeparationOfDutiesViolation):
            finding.apply_validation_certificate(cert, verify_signature_fn=k1.verify_certificate)

    def test_independent_validator_rejects_unreproduced_as_false_positive(self) -> None:
        keyring = AuditorKeyring.from_passphrase("test-auditor-key")
        finding = self._make_hypothesis()
        fp_cert = _make_cert(finding.finding_id, verdict=ValidationVerdict.NOT_REPRODUCED)
        fp_cert.signature = keyring.sign_certificate(fp_cert)
        finding.apply_validation_certificate(fp_cert, verify_signature_fn=keyring.verify_certificate)
        self.assertEqual(finding.status, FindingStatus.FALSE_POSITIVE)

    def test_all_10_mandatory_domains_and_9_maturity_criteria_present(self) -> None:
        expected = {
            "agent_isolation",
            "tool_execution",
            "memory",
            "prompt_injection",
            "api_security",
            "filesystem",
            "process_management",
            "supply_chain",
            "network",
            "rust_core",
        }
        self.assertEqual({d.value for d in SecurityDomain}, expected)
        self.assertEqual(len(SecurityDomain), 10)
        self.assertEqual(len(MaturityCriterionId), 9)

    def test_mark_mitigated_promotes_confirmed_finding(self) -> None:
        keyring = AuditorKeyring.from_passphrase("test-auditor-key")
        finding = self._make_hypothesis()
        cert = _make_cert(finding.finding_id)
        cert.signature = keyring.sign_certificate(cert)
        finding.apply_validation_certificate(cert, verify_signature_fn=keyring.verify_certificate)
        rem = RemediationProposal(
            proposal_id=new_id("rem"),
            finding_id=finding.finding_id,
            summary="Replace shell=True with shell=False",
            strategy="code_patch",
            diff_preview="- subprocess.run(cmd, shell=True)\n+ subprocess.run(cmd, shell=False)",
            verified_neutralizes_poc=True,
            verified_no_regression=True,
        )
        finding.mark_mitigated(rem)
        self.assertEqual(finding.status, FindingStatus.MITIGATED)


class TestCryptoLedgerAndMerkleTree(unittest.TestCase):
    """Tests cryptographic tamper-evidence of the Auditor plane."""

    def test_merkle_root_deterministic_and_inclusion_proof(self) -> None:
        leaves = [f"event-{i}" for i in range(7)]
        tree = MerkleTree(leaves)
        self.assertEqual(len(tree.root), 64)
        for idx, item in enumerate(leaves):
            proof = tree.proof(idx)
            self.assertTrue(MerkleTree.verify_proof(item, proof, tree.root))
        self.assertFalse(MerkleTree.verify_proof("tampered-event", tree.proof(0), tree.root))

    def test_ledger_verifies_valid_chain_and_detects_tampering(self) -> None:
        keyring = AuditorKeyring.from_passphrase("unit-test-auditor-key")
        ledger = ForensicAuditLedger(keyring=keyring)
        ledger.append("snapshot", "snapshot_created", {"files": 12})
        ledger.append("validator", "finding_confirmed", {"finding_id": "fnd-1"})
        ledger.append("lifecycle", "sandbox_destroyed", {"verified": True})

        ver = ledger.verify()
        self.assertTrue(ver.valid)
        self.assertEqual(ver.entries_checked, 3)

        # Simulate compromised agent silently altering a ledger payload
        ledger.entries[1].payload["finding_id"] = "fnd-tampered"
        ver_tampered = ledger.verify()
        self.assertFalse(ver_tampered.valid)
        self.assertGreater(len(ver_tampered.errors), 0)

    def test_hmac_report_digest_rejects_wrong_key(self) -> None:
        k1 = AuditorKeyring.from_passphrase("key-alpha")
        k2 = AuditorKeyring.from_passphrase("key-beta")
        sig = k1.sign_report_digest("digest-abc-123")
        self.assertTrue(k1.verify_report_digest("digest-abc-123", sig))
        self.assertFalse(k2.verify_report_digest("digest-abc-123", sig))
        self.assertFalse(k1.verify_report_digest("digest-tampered", sig))


class TestCapabilityLatticeAndCaMeL(unittest.TestCase):
    """Tests CaMeL control/data plane separation & multi-agent capability lattice."""

    def test_default_policy_blocks_external_untrusted_tool_execution(self) -> None:
        engine = CapabilityPolicyEngine.build_default_ely_policy()
        untrusted = ProvenanceTag(
            trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
            source_id="web:attacker.invalid",
        )
        decision = engine.evaluate_action(
            principal_id="ely-executor",
            action="proc_spawn",
            target="pytest",
            input_provenance=untrusted,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("UNTRUSTED", (decision.violation_code or decision.reason).upper())

    def test_researcher_cannot_write_to_executor_workspace(self) -> None:
        engine = CapabilityPolicyEngine.build_default_ely_policy()
        decision = engine.evaluate_action(
            principal_id="ely-researcher",
            action="fs_write",
            target="/workspace/proj_alpha/app.py",
            input_provenance=ProvenanceTag(TrustLevel.AGENT_INTERNAL, "internal"),
        )
        self.assertFalse(decision.allowed)

    def test_non_auditor_cannot_modify_validation_plane(self) -> None:
        engine = CapabilityPolicyEngine.build_default_ely_policy()
        for pid in ("ely-researcher", "ely-executor", "ely-skill-sandboxed"):
            decision = engine.evaluate_action(
                principal_id=pid,
                action="audit_write",
                target="validation/verdicts/fnd-1",
                input_provenance=ProvenanceTag(TrustLevel.AGENT_INTERNAL, "internal"),
            )
            self.assertFalse(decision.allowed)

    def test_delegation_attenuation_prevents_privilege_amplification(self) -> None:
        engine = CapabilityPolicyEngine.build_default_ely_policy()
        decision = engine.evaluate_delegation(
            delegator_id="ely-researcher",
            delegatee_id="ely-planner",
            requested_grant=CapabilityGrant("proc_spawn", "*"),
            context_provenance=ProvenanceTag(TrustLevel.AGENT_INTERNAL, "internal"),
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.violation_code, "DELEGATION_ESCALATION_BLOCKED")

    def test_wildcard_detection(self) -> None:
        self.assertTrue(CapabilityGrant("fs_write", "/**").is_wildcard_overreach())
        self.assertTrue(CapabilityGrant("proc_spawn", "*").is_wildcard_overreach())
        self.assertFalse(CapabilityGrant("fs_read", "/workspace/docs/*.md").is_wildcard_overreach())


class TestScopeGuardSecretScrubberAndScoring(unittest.TestCase):
    """Tests authorization guardrails, secret redaction, and CVSS v3.1 scoring."""

    def test_scope_guard_blocks_external_networks_and_out_of_scope_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            sbx = root / "sandbox"
            sbx.mkdir()
            manifesto = ScopeManifesto(
                manifest_id="scope-unit-test",
                authorized_by="photon-labs-sec",
                target_root=str(root),
                sandbox_root=str(sbx),
                allow_external_network=False,
            )
            keyring = AuditorKeyring.from_passphrase("scope-test")
            manifesto.sign(keyring)
            guard = ScopeGuard(manifesto, keyring=keyring)

            sub = root / "app.py"
            sub.write_text("print('ok')\n", encoding="utf-8")
            guard.assert_read_path_in_scope(sub)

            with self.assertRaises(ScopeViolationError):
                guard.assert_network_target_authorized("api.stripe.com")

            with self.assertRaises(ScopeViolationError):
                guard.assert_network_target_authorized("169.254.169.254")

            with self.assertRaises(ScopeViolationError):
                guard.assert_read_path_in_scope(Path("/etc/passwd"))

    def test_secret_scrubber_identifies_sensitive_files_and_redacts_tokens(self) -> None:
        scrubber = SecretScrubber()
        self.assertTrue(scrubber.is_sensitive_file(Path(".env")))
        self.assertTrue(scrubber.is_sensitive_file(Path("certs/id_rsa")))
        self.assertFalse(scrubber.is_sensitive_file(Path("agents/executor.py")))

        sample = 'API_KEY = "sk-1234567890abcdef1234567890abcdef"\nGH = "ghp_abcdef1234567890abcdef1234567890abcd"\n'
        redacted, count = scrubber.scrub_text(sample)
        self.assertGreaterEqual(count, 2)
        self.assertNotIn("sk-1234567890", redacted)
        self.assertNotIn("ghp_abcdef1234", redacted)

    def test_tree_sha256_detects_single_byte_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root / "sample.py"
            f.write_text("x = 1\n", encoding="utf-8")
            h1 = compute_directory_tree_digest(root)
            f.write_text("x = 2\n", encoding="utf-8")
            h2 = compute_directory_tree_digest(root)
            self.assertNotEqual(h1, h2)

    def test_risk_scoring_engine_and_soe_config_presets(self) -> None:
        scorer = RiskScoringEngine()
        f = Finding(
            finding_id=new_id("fnd"),
            title="Indirect Prompt Injection",
            description="Untrusted text injected into system prompt",
            domain=SecurityDomain.PROMPT_INJECTION,
            severity=Severity.CRITICAL,
            rule_id="PI-001",
            discovered_by="test",
            location=CodeLocation("a.py", 1),
        )
        scorer.enrich_finding(f)
        self.assertGreaterEqual(f.cvss_score, 8.0)
        self.assertTrue(f.cvss_vector.startswith("CVSS:3.1/"))
        self.assertTrue(len(f.owasp_agentic_ids) > 0)
        self.assertTrue(len(f.mitre_atlas_ids) > 0)

        self.assertIn("full_soe_harness", HARNESS_PRESETS)
        self.assertIn("bare_model", HARNESS_PRESETS)
        cfg = SOEConfig.for_modality(AuditModality.PRE_RELEASE)
        self.assertEqual(cfg.default_harness_profile, "frontier_deep")


if __name__ == "__main__":
    unittest.main()
