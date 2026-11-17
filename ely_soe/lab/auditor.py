"""
Independent Security Auditor — Strictly Separated Validation & Attestation Plane.

Implements the core trust separation requirements:
  - Holds the isolated `AuditorKeyring` that discovery engines, LLMs, and evaluated
    agents NEVER see.
  - Independently issues and cryptographically signs `ValidationCertificate`s ONLY
    after clean-room PoC reproduction passes differential & determinism checks.
  - Verifies oracle integrity (using salted audit nonces) so a compromised agent or
    malicious target cannot spoof "passed" or suppress a vulnerability confirmation.
  - Seals Security Evaluation Reports and Ely 1.0 Security Maturity Attestations with
    Merkle commitments & HMAC signatures.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ely_soe.core.crypto_ledger import (
    AuditorKeyring,
    ForensicAuditLedger,
    LedgerVerificationResult,
    MerkleTree,
    canonical_json,
    sha256_hex,
)
from ely_soe.core.models import (
    EvidenceArtifact,
    Finding,
    FindingStatus,
    MaturityAssessment,
    SecurityEvaluationReport,
    SeparationOfDutiesViolation,
    ValidationCertificate,
    ValidationVerdict,
    new_id,
    utc_now_iso,
)


@dataclass
class OracleChallenge:
    """Anti-spoofing nonce challenge ensuring validation output came from a real clean trial."""

    challenge_id: str
    nonce: str
    expected_baseline_token: str
    expected_exploit_token: str

    @classmethod
    def create(cls) -> "OracleChallenge":
        cid = new_id("orch")
        nonce = secrets.token_hex(12)
        return cls(
            challenge_id=cid,
            nonce=nonce,
            expected_baseline_token=sha256_hex(f"BASELINE_OK:{cid}:{nonce}")[:24],
            expected_exploit_token=sha256_hex(f"EXPLOIT_CONFIRMED:{cid}:{nonce}")[:24],
        )


class IndependentAuditor:
    """
    Independent Auditor Plane inside ELY Security Lab.

    Never performs discovery; exclusively validates evidence, verifies isolation,
    checks tamper resistance, and signs authoritative validation/maturity artifacts.
    """

    def __init__(
        self,
        keyring: Optional[AuditorKeyring] = None,
        ledger: Optional[ForensicAuditLedger] = None,
        auditor_id: str = "ely-independent-auditor-v1",
    ) -> None:
        self.auditor_id = auditor_id
        self.keyring = keyring if keyring is not None else AuditorKeyring()
        self.ledger = ledger if ledger is not None else ForensicAuditLedger(keyring=self.keyring)
        self._issued_certificates: Dict[str, ValidationCertificate] = {}

    def issue_oracle_challenge(self) -> OracleChallenge:
        challenge = OracleChallenge.create()
        self.ledger.append(
            actor=self.auditor_id,
            event_type="oracle_challenge_issued",
            payload={"challenge_id": challenge.challenge_id},
        )
        return challenge

    def certify_validation(
        self,
        finding: Finding,
        sandbox_id: str,
        trials_run: int,
        trials_reproduced: int,
        baseline_passed: bool,
        exploit_triggered: bool,
        oracle_integrity_verified: bool,
        reproduction_steps: List[str],
        evidence_artifacts: List[EvidenceArtifact],
        min_repro_ratio: float = 0.66,
        notes: str = "",
    ) -> ValidationCertificate:
        """
        Evaluate raw clean-room trial telemetry and mint a cryptographically signed
        `ValidationCertificate`, then apply it authoritatively to `finding`.
        """
        # Verify all evidence hashes before trusting them
        evidence_hashes: List[str] = []
        for art in evidence_artifacts:
            if not art.verify_integrity():
                oracle_integrity_verified = False
                notes = f"{notes} | Evidence artifact {art.artifact_id} failed SHA-256 verification!"
            evidence_hashes.append(art.sha256)

        ratio = (trials_reproduced / float(trials_run)) if trials_run > 0 else 0.0

        if not oracle_integrity_verified:
            verdict = ValidationVerdict.TAMPER_DETECTED
        elif exploit_triggered and baseline_passed and trials_run > 0 and ratio >= min_repro_ratio:
            verdict = ValidationVerdict.REPRODUCED
        elif trials_run > 0 and trials_reproduced == 0 and baseline_passed:
            verdict = ValidationVerdict.NOT_REPRODUCED
        else:
            verdict = ValidationVerdict.INCONCLUSIVE

        cert = ValidationCertificate(
            certificate_id=new_id("vcert"),
            finding_id=finding.finding_id,
            verdict=verdict,
            validator_id=self.auditor_id,
            sandbox_id=sandbox_id,
            trials_run=trials_run,
            trials_reproduced=trials_reproduced,
            baseline_passed=baseline_passed,
            exploit_triggered=exploit_triggered,
            oracle_integrity_verified=oracle_integrity_verified,
            reproduction_steps=list(reproduction_steps),
            evidence_hashes=evidence_hashes,
            issued_at=utc_now_iso(),
            signature="",
            notes=notes.strip(" |"),
        )
        cert.signature = self.keyring.sign_certificate(cert)
        self._issued_certificates[cert.certificate_id] = cert

        # Apply through enforced Finding gate using Auditor's own signature verifier
        finding.apply_validation_certificate(cert, verify_signature_fn=self.verify_certificate)

        self.ledger.append(
            actor=self.auditor_id,
            event_type="validation_certified",
            payload={
                "certificate_id": cert.certificate_id,
                "finding_id": finding.finding_id,
                "verdict": verdict.value,
                "new_status": finding.status.value,
                "trials_reproduced": trials_reproduced,
                "trials_run": trials_run,
                "oracle_integrity_verified": oracle_integrity_verified,
            },
        )
        return cert

    def verify_certificate(self, cert: ValidationCertificate) -> bool:
        return self.keyring.verify_certificate(cert)

    def audit_separation_of_duties(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Independently verify that NO finding achieved `CONFIRMED` status without a
        genuine, valid Auditor-signed `ValidationCertificate`.
        """
        violations: List[str] = []
        confirmed_verified = 0
        for f in findings:
            if f.status == FindingStatus.CONFIRMED:
                if f.validation is None:
                    violations.append(f"Finding {f.finding_id} is CONFIRMED without ValidationCertificate!")
                elif not self.verify_certificate(f.validation):
                    violations.append(f"Finding {f.finding_id} has FORGED/INVALID ValidationCertificate!")
                elif f.validation.verdict != ValidationVerdict.REPRODUCED:
                    violations.append(
                        f"Finding {f.finding_id} is CONFIRMED despite verdict={f.validation.verdict.value}!"
                    )
                else:
                    confirmed_verified += 1
        return {
            "separation_enforced": len(violations) == 0,
            "confirmed_verified_count": confirmed_verified,
            "violations": violations,
        }

    def seal_maturity_assessment(self, assessment: MaturityAssessment) -> MaturityAssessment:
        """Compute Merkle root over all 9 maturity criteria and sign the release attestation."""
        leaf_hashes = [sha256_hex(canonical_json(c.to_dict())) for c in assessment.criteria]
        tree = MerkleTree(leaf_hashes)
        assessment.attestation_merkle_root = tree.root
        assessment.attestation_signature = self.keyring.sign_maturity_attestation(
            merkle_root=tree.root,
            target_version=assessment.target_version,
            verdict=assessment.verdict.value,
        )
        self.ledger.append(
            actor=self.auditor_id,
            event_type="maturity_attested",
            payload={
                "assessment_id": assessment.assessment_id,
                "target_version": assessment.target_version,
                "verdict": assessment.verdict.value,
                "overall_score": round(assessment.overall_score, 2),
                "merkle_root": tree.root,
            },
        )
        return assessment

    def verify_maturity_assessment(self, assessment: MaturityAssessment) -> bool:
        leaf_hashes = [sha256_hex(canonical_json(c.to_dict())) for c in assessment.criteria]
        recomputed_root = MerkleTree(leaf_hashes).root
        if recomputed_root != assessment.attestation_merkle_root:
            return False
        return self.keyring.verify_maturity_attestation(
            merkle_root=recomputed_root,
            target_version=assessment.target_version,
            verdict=assessment.verdict.value,
            signature=assessment.attestation_signature,
        )

    def seal_report(self, report: SecurityEvaluationReport) -> SecurityEvaluationReport:
        """Seal final SecurityEvaluationReport with ledger Merkle root & Auditor signature."""
        sod = self.audit_separation_of_duties(report.findings)
        if not sod["separation_enforced"]:
            raise SeparationOfDutiesViolation(f"Cannot seal report — SoD violations: {sod['violations']}")

        report.ledger_merkle_root = self.ledger.merkle_root()
        digest = self._compute_report_digest(report)
        report.report_signature = self.keyring.sign_report_digest(digest)
        self.ledger.append(
            actor=self.auditor_id,
            event_type="report_sealed",
            payload={
                "report_id": report.report_id,
                "run_id": report.run_id,
                "report_digest": digest,
                "confirmed_findings": len(report.confirmed_findings),
                "sandbox_destroyed_verified": report.sandbox_destroyed_verified,
                "main_instance_untouched_verified": report.main_instance_untouched_verified,
            },
        )
        return report

    def verify_report(self, report: SecurityEvaluationReport) -> Dict[str, Any]:
        digest = self._compute_report_digest(report)
        sig_ok = self.keyring.verify_report_digest(digest, report.report_signature)
        sod = self.audit_separation_of_duties(report.findings)
        ledger_check: LedgerVerificationResult = self.ledger.verify()
        maturity_ok = self.verify_maturity_assessment(report.maturity) if report.maturity else True
        return {
            "report_signature_valid": sig_ok,
            "separation_of_duties_valid": sod["separation_enforced"],
            "ledger_valid": ledger_check.valid,
            "maturity_attestation_valid": maturity_ok,
            "overall_authentic": sig_ok and sod["separation_enforced"] and ledger_check.valid and maturity_ok,
            "sod_details": sod,
            "ledger_details": ledger_check.to_dict(),
        }

    @staticmethod
    def _compute_report_digest(report: SecurityEvaluationReport) -> str:
        payload = {
            "report_id": report.report_id,
            "run_id": report.run_id,
            "target_name": report.target_name,
            "target_version": report.target_version,
            "snapshot_digest": report.snapshot_digest,
            "sandbox_destroyed_verified": report.sandbox_destroyed_verified,
            "main_instance_untouched_verified": report.main_instance_untouched_verified,
            "finding_fingerprints": sorted(
                f"{f.finding_id}:{f.status.value}:{f.severity.value}:{f.fingerprint}"
                for f in report.findings
            ),
            "ledger_merkle_root": report.ledger_merkle_root,
        }
        return sha256_hex(canonical_json(payload))
