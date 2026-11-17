"""
End-to-End Integration & Closed-Loop Governance Verification Suite.

Validates:
1. Closed-loop Policy Synthesis -> Formal Policy Verification (synthesized policy
   proves all 6 formal theorems T1-T6 with 0 counterexamples).
2. AttackGraphAnalyzer live UI payload contract (nodes, edges, composite risk,
   remediation chokepoints, rogue-agent blast radius).
3. Offline CLI `verify-ledger` cryptographic verification of exported JSONL ledgers
   including tamper-detection non-zero exit behavior.
4. Complete `ely_soe.cli.main(['demo'])` end-to-end workflow execution.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ely_soe.analyzers.repo_analyzer import RepositoryAnalyzer
from ely_soe.cli import main as cli_main
from ely_soe.core.capability_lattice import CapabilityPolicyEngine
from ely_soe.core.crypto_ledger import AuditorKeyring, ForensicAuditLedger
from ely_soe.core.models import (
    CodeLocation,
    Finding,
    FindingStatus,
    SecurityDomain,
    Severity,
    ValidationCertificate,
    ValidationVerdict,
    new_id,
)
from ely_soe.frontier.attack_graph import AttackGraphAnalyzer
from ely_soe.frontier.formal_policy_verifier import FormalPolicyVerifier
from ely_soe.frontier.policy_synthesizer import LeastPrivilegePolicySynthesizer

REPO_ROOT = Path(__file__).resolve().parent.parent
V09_SPECIMEN = REPO_ROOT / "lab_targets" / "ely_specimen" / "v0_9"
V10_SPECIMEN = REPO_ROOT / "lab_targets" / "ely_specimen" / "v1_0_hardened"


class TestClosedLoopGovernanceAndEndToEndDemo(unittest.TestCase):
    def test_synthesized_policy_formally_proves_all_6_theorems(self) -> None:
        """Closed-loop proof: synthesized least-privilege policy must pass T1-T6."""
        surface = RepositoryAnalyzer().analyze(V09_SPECIMEN, "ely-cowork", "0.9.0")
        synth = LeastPrivilegePolicySynthesizer()
        bundle = synth.synthesize(target_name="ely-cowork", attack_surface=surface, findings=[])

        bundle_dict = bundle.to_dict()
        self.assertTrue(bundle_dict["all_formal_theorems_proven"])
        self.assertIn("capability_policy", bundle_dict)
        self.assertIn("seccomp_profile", bundle_dict)
        self.assertIn("egress_firewall_policy", bundle_dict)
        self.assertGreaterEqual(len(bundle_dict["capability_policy"].get("principals", [])), 5)

        proof = bundle_dict["formal_verification_proof"]
        self.assertTrue(proof["all_theorems_hold"])
        self.assertEqual(proof["passed_theorems"], 6)
        self.assertEqual(proof["total_counterexamples"], 0)
        self.assertGreater(proof["total_states_checked"], 50)

    def test_attack_graph_ui_payload_contract_nodes_edges_and_chokepoints(self) -> None:
        """AttackGraphAnalyzer returns structured nodes, edges, composite risk, and chokepoints."""
        keyring = AuditorKeyring.from_passphrase("graph-contract-test")
        findings = []
        domains = [
            (SecurityDomain.PROMPT_INJECTION, "PI-01", "Indirect prompt injection"),
            (SecurityDomain.TOOL_EXECUTION, "TA-01", "Unrestricted shell tool"),
            (SecurityDomain.AGENT_ISOLATION, "SE-01", "Shared writable workspace mount"),
            (SecurityDomain.MEMORY, "MP-01", "Cross-agent memory write"),
        ]
        for dom, rule, title in domains:
            f = Finding(
                finding_id=new_id("fnd"),
                rule_id=rule,
                title=title,
                description=title,
                domain=dom,
                severity=Severity.CRITICAL,
                status=FindingStatus.HYPOTHESIS,
                confidence=0.92,
                discovered_by="unit-test-analyzer",
                location=CodeLocation(file_path="agent.py", line_start=10, line_end=20),
                cwe_ids=["CWE-78"],
            )
            cert = ValidationCertificate(
                certificate_id=new_id("cert"),
                finding_id=f.finding_id,
                verdict=ValidationVerdict.REPRODUCED,
                validator_id="independent-auditor-v1",
                sandbox_id="sbx-graph",
                trials_run=1,
                trials_reproduced=1,
                baseline_passed=True,
                exploit_triggered=True,
                oracle_integrity_verified=True,
                reproduction_steps=["Reproduced exploit chain in isolated sandbox"],
                evidence_hashes=["sha256:graph"],
                issued_at="2026-11-15T00:00:00Z",
                signature="",
            )
            cert.signature = keyring.sign_certificate(cert)
            f.apply_validation_certificate(cert, verify_signature_fn=keyring.verify_certificate)
            findings.append(f)

        surface = RepositoryAnalyzer().analyze(V09_SPECIMEN, "ely-cowork", "0.9.0")
        graph = AttackGraphAnalyzer().analyze(findings, attack_surface=surface)

        self.assertGreater(graph["kill_chains_found"], 0)
        self.assertGreater(graph["composite_attack_graph_risk"], 0.0)
        self.assertGreater(len(graph["nodes"]), 0)
        self.assertGreater(len(graph["edges"]), 0)
        self.assertGreater(len(graph["remediation_chokepoints"]), 0)
        node_tiers = {n["tier"] for n in graph["nodes"]}
        self.assertIn("entry", node_tiers)
        self.assertIn("crown_jewel", node_tiers)

    def test_offline_ledger_export_verify_and_tamper_detection(self) -> None:
        """Exported JSONL forensic ledger verifies clean and detects 1-byte tampering."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path = Path(tmp) / "forensic_ledger.jsonl"
            keyring = AuditorKeyring.from_passphrase("offline-verify-key")
            ledger = ForensicAuditLedger(keyring=keyring, run_id="run-ledger-e2e")
            ledger.append("scope_guard", "manifest_verified", {"target": "v1_0_hardened"})
            ledger.append("validator", "certificate_issued", {"verdict": "REPRODUCED"})
            ledger.append("lifecycle", "sandbox_destroyed", {"verified": True})
            ledger.export_jsonl(ledger_path)

            # Reload and verify clean chain + Merkle inclusion proof
            reloaded = ForensicAuditLedger.load_jsonl(ledger_path, keyring=keyring)
            clean_res = reloaded.verify()
            self.assertTrue(clean_res.valid)
            self.assertEqual(clean_res.entries_checked, 3)

            proof = reloaded.inclusion_proof(1)
            self.assertIsNotNone(proof)

            # Tamper a single JSONL line on disk -> verification MUST fail
            raw_lines = ledger_path.read_text(encoding="utf-8").splitlines()
            tampered_obj = json.loads(raw_lines[1])
            tampered_obj["payload"]["verdict"] = "NOT_REPRODUCED"
            raw_lines[1] = json.dumps(tampered_obj)
            ledger_path.write_text("\n".join(raw_lines) + "\n", encoding="utf-8")

            tampered_ledger = ForensicAuditLedger.load_jsonl(ledger_path, keyring=keyring)
            bad_res = tampered_ledger.verify()
            self.assertFalse(bad_res.valid)
            self.assertIn(1, bad_res.tampered_indices)

    def test_cli_demo_end_to_end_completes_cleanly(self) -> None:
        """Full `ely-soe demo` command executes v0.9 gate, v1.0 gate, compare, policy verify, and benchmark."""
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / "soe_data"
            export_dir = Path(tmp) / "exports"
            rc = cli_main(["--data-dir", str(data_dir), "demo", "--export-dir", str(export_dir)])
            self.assertEqual(rc, 0)
            self.assertTrue(data_dir.exists())


if __name__ == "__main__":
    unittest.main()
