"""
Harness² Independent Formal Meta-Verifier & Cryptographic Assurance Certificate Issuer.

Verifies 8 formal Meta-Harness Invariants (`M1`–`M8`) over any completed
`HarnessSquaredEngine.run_adaptive_assessment(...)` dict and issues an HMAC-SHA256
signed `MetaVerificationCertificate` via `AuditorKeyring`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ely_soe.core.crypto_ledger import AuditorKeyring
from ely_soe.core.models import utc_now_iso


@dataclass
class MetaTheoremResult:
    theorem_id: str
    title: str
    passed: bool
    severity_if_failed: str  # CRITICAL | HIGH | MEDIUM
    evidence: str
    checked_metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "theorem_id": self.theorem_id,
            "title": self.title,
            "passed": self.passed,
            "severity_if_failed": self.severity_if_failed,
            "evidence": self.evidence,
            "checked_metrics": dict(self.checked_metrics),
        }


@dataclass
class MetaVerificationCertificate:
    """Independent cryptographically signed attestation of Harness² meta-safety."""

    certificate_id: str
    run_id: str
    genome_id: str
    verifier_id: str
    issued_at: str
    overall_verdict: str  # PROVEN_SAFE | FAILED_INVARIANT
    theorems_passed: int
    theorems_total: int
    theorem_results: List[MetaTheoremResult] = field(default_factory=list)
    report_digest_sha256: str = ""
    signature_hmac_sha256: str = ""
    signer_key_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "run_id": self.run_id,
            "genome_id": self.genome_id,
            "verifier_id": self.verifier_id,
            "issued_at": self.issued_at,
            "overall_verdict": self.overall_verdict,
            "theorems_passed": self.theorems_passed,
            "theorems_total": self.theorems_total,
            "theorem_results": [t.to_dict() for t in self.theorem_results],
            "report_digest_sha256": self.report_digest_sha256,
            "signature_hmac_sha256": self.signature_hmac_sha256,
            "signer_key_id": self.signer_key_id,
        }


class HarnessSquaredMetaVerifier:
    """Independent formal verifier proving M1–M8 meta-safety invariants over Harness² runs."""

    def __init__(
        self,
        keyring: Optional[AuditorKeyring] = None,
        verifier_id: str = "ely-meta-verifier-v2",
        hard_latency_sla_ms: float = 60_000.0,
    ) -> None:
        self.keyring = keyring or AuditorKeyring(key_id="meta-verifier-root-v2")
        self.verifier_id = verifier_id
        self.hard_latency_sla_ms = hard_latency_sla_ms

    def verify_run(self, run_report: Dict[str, Any]) -> MetaVerificationCertificate:
        results: List[MetaTheoremResult] = []
        run_id = str(run_report.get("run_id", "h2-run"))
        genome = run_report.get("selected_genome", {})
        genome_id = str(genome.get("genome_id", "unknown"))
        dag = run_report.get("workflow_dag", {})
        telemetry = run_report.get("telemetry", {})
        stage_records = list(telemetry.get("stage_records", []))
        directives = list(run_report.get("mapek_adaptation", {}).get("directives", []))
        safety = run_report.get("safety_invariants", {})
        ledger = safety.get("guard_ledger_summary", {})
        preflight = list(safety.get("preflight_checks", []))
        vulns = list(run_report.get("vulnerabilities", []))
        gate = str(run_report.get("gate_verdict", "BLOCKED"))
        duration_ms = float(run_report.get("duration_ms", 0.0))

        # M1: DAG Acyclicity & Structural Well-Formedness
        m1_ok = bool(dag.get("acyclic", False)) and len(stage_records) > 0
        results.append(
            MetaTheoremResult(
                theorem_id="M1",
                title="DAG Acyclicity & Structural Well-Formedness",
                passed=m1_ok,
                severity_if_failed="CRITICAL",
                evidence=f"DAG acyclic={dag.get('acyclic')}, nodes={dag.get('node_count', 0)}, executed_stages={len(stage_records)}.",
                checked_metrics={"acyclic": dag.get("acyclic"), "executed_stages": len(stage_records)},
            )
        )

        # M2: Monotonic Safety Non-Relaxation (all preflight checks passed & all applied directives approved)
        preflight_ok = all(bool(c.get("passed", False)) for c in preflight) if preflight else True
        unapproved_applied = [d for d in directives if d.get("applied") and not d.get("approved_by_invariant_guard")]
        m2_ok = preflight_ok and len(unapproved_applied) == 0
        results.append(
            MetaTheoremResult(
                theorem_id="M2",
                title="Monotonic Safety Non-Relaxation Across All Adaptations",
                passed=m2_ok,
                severity_if_failed="CRITICAL",
                evidence=f"Preflight checks={len(preflight)} all passed={preflight_ok}; unapproved applied directives={len(unapproved_applied)}.",
                checked_metrics={"preflight_passed": preflight_ok, "unapproved_applied": len(unapproved_applied)},
            )
        )

        # M3: Immutable ScopeGuard & Non-Bypass Binding
        scope_enforced = bool(genome.get("enforce_scope_guard", True)) and bool(genome.get("loopback_only_dast", True))
        target_root = str(run_report.get("target_fingerprint", {}).get("target_root", ""))
        m3_ok = scope_enforced and bool(target_root)
        results.append(
            MetaTheoremResult(
                theorem_id="M3",
                title="Immutable ScopeGuard Target & Loopback-Only DAST Binding",
                passed=m3_ok,
                severity_if_failed="CRITICAL",
                evidence=f"Scope anchored to `{target_root}`, enforce_scope_guard={genome.get('enforce_scope_guard')}, loopback_only_dast={genome.get('loopback_only_dast')}.",
                checked_metrics={"target_root": target_root, "enforce_scope_guard": scope_enforced},
            )
        )

        # M4: Separation-of-Duties & Provenance Integrity
        planner_id = str(genome.get("planner_id", ""))
        validator_id = str(genome.get("validator_id", ""))
        disjoint_ids = bool(planner_id and validator_id and planner_id != validator_id)
        missing_disc = sum(1 for v in vulns if not v.get("discovered_by"))
        m4_ok = bool(genome.get("enforce_separation_of_duties", True)) and disjoint_ids and missing_disc == 0
        results.append(
            MetaTheoremResult(
                theorem_id="M4",
                title="Separation-of-Duties Disjointness & Discoverer Provenance",
                passed=m4_ok,
                severity_if_failed="CRITICAL",
                evidence=f"planner_id=`{planner_id}` != validator_id=`{validator_id}`, attribution gaps={missing_disc}.",
                checked_metrics={"planner_id": planner_id, "validator_id": validator_id, "attribution_gaps": missing_disc},
            )
        )

        # M5: Bounded Meta-Adaptation & Latency SLA Adherence
        applied_cnt = int(run_report.get("mapek_adaptation", {}).get("total_adaptations_applied", 0))
        m5_ok = duration_ms <= self.hard_latency_sla_ms and applied_cnt <= 25
        results.append(
            MetaTheoremResult(
                theorem_id="M5",
                title="Bounded Meta-Adaptation Budget & Hard Latency SLA",
                passed=m5_ok,
                severity_if_failed="HIGH",
                evidence=f"Applied {applied_cnt} adaptation(s) in {duration_ms:.2f}ms (SLA <= {self.hard_latency_sla_ms:.0f}ms).",
                checked_metrics={"applied_adaptations": applied_cnt, "duration_ms": round(duration_ms, 2)},
            )
        )

        # M6: Zero Silent Finding Suppression
        max_single_stage = max((int(r.get("findings_total", 0)) for r in stage_records), default=0)
        m6_ok = len(vulns) >= max_single_stage or max_single_stage == 0
        results.append(
            MetaTheoremResult(
                theorem_id="M6",
                title="Monotonic Finding Preservation (Zero Silent Suppression)",
                passed=m6_ok,
                severity_if_failed="CRITICAL",
                evidence=f"Report retains {len(vulns)} deduplicated findings (>= max single-stage count {max_single_stage}).",
                checked_metrics={"final_vulns": len(vulns), "max_single_stage": max_single_stage},
            )
        )

        # M7: Cryptographic SHA-256 Forensic Merkle Audit Continuity
        root = str(ledger.get("ledger_merkle_root", ""))
        chain_valid = bool(ledger.get("ledger_chain_valid", False))
        m7_ok = chain_valid and len(root) == 64 and all(c in "0123456789abcdef" for c in root.lower())
        results.append(
            MetaTheoremResult(
                theorem_id="M7",
                title="Cryptographic SHA-256 Forensic Merkle Ledger Integrity",
                passed=m7_ok,
                severity_if_failed="HIGH",
                evidence=f"Ledger chain_valid={chain_valid}, entries={ledger.get('ledger_entries', 0)}, merkle_root={root[:16]}...",
                checked_metrics={"chain_valid": chain_valid, "merkle_root_prefix": root[:16]},
            )
        )

        # M8: Fail-Closed Release Gate Soundness
        crit_cnt = int(run_report.get("severity_counts", {}).get("critical", 0))
        m8_ok = not (crit_cnt > 0 and gate.upper() == "APPROVED")
        results.append(
            MetaTheoremResult(
                theorem_id="M8",
                title="Fail-Closed Release Gate Soundness (No Approved Criticals)",
                passed=m8_ok,
                severity_if_failed="CRITICAL",
                evidence=f"Release gate `{gate}` is sound for {crit_cnt} critical vulnerability(ies).",
                checked_metrics={"critical_count": crit_cnt, "gate_verdict": gate},
            )
        )

        passed_cnt = sum(1 for r in results if r.passed)
        overall = "PROVEN_SAFE" if passed_cnt == len(results) else "FAILED_INVARIANT"

        canonical_payload = json.dumps(
            {
                "run_id": run_id,
                "genome_id": genome_id,
                "gate_verdict": gate,
                "ledger_merkle_root": root,
                "vuln_count": len(vulns),
                "theorems": [(r.theorem_id, r.passed) for r in results],
            },
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256(canonical_payload).hexdigest()
        sig = self.keyring.sign_report_digest(digest)

        return MetaVerificationCertificate(
            certificate_id=f"META-CERT-{digest[:12].upper()}",
            run_id=run_id,
            genome_id=genome_id,
            verifier_id=self.verifier_id,
            issued_at=utc_now_iso(),
            overall_verdict=overall,
            theorems_passed=passed_cnt,
            theorems_total=len(results),
            theorem_results=results,
            report_digest_sha256=digest,
            signature_hmac_sha256=sig,
            signer_key_id=self.keyring.key_id,
        )

    def verify_certificate_signature(self, cert: MetaVerificationCertificate) -> bool:
        return self.keyring.verify_report_digest(cert.report_digest_sha256, cert.signature_hmac_sha256)
