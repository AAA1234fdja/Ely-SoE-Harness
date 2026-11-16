"""
Harness² Enterprise Multi-Tenant Policy Governance, Compliance SLA Gatekeeper,
SARIF v2.1.0 Exporter & Cryptographically Signed Executive Assurance Bundle Builder.

Translates Harness² adaptive assessment outputs into enterprise DevSecOps governance artifacts:
  1. **Declarative Policy-as-Code Gate Evaluator (`EnterpriseReleasePolicy`)**:
       Evaluates a completed `HarnessSquaredEngine` run + `MetaVerificationCertificate` +
       optional FAIR ALE simulation against enforceable organizational rules:
         - Max allowed CRITICAL / HIGH / KEV-listed findings
         - Max allowed multi-step exploit chains
         - Minimum Cyber Posture score & Compliance readiness %
         - Mandatory `MetaVerifier M1–M8 == PROVEN_SAFE`
         - Optional maximum FAIR Mean ALE USD ceiling
         - Optional strict Zero-Sandbox-Reproduced-Exploit gate.
  2. **Spec-Compliant SARIF v2.1.0 Export (`export_sarif_2_1`)**:
       Converts Harness² findings into standard GitHub Code Scanning / VS Code / Azure DevOps
       SARIF 2.1.0 JSON with CWE taxa, CVSS v4.0 security-severity properties, and locations.
  3. **Signed Governance Attestation Bundle**:
       Hashes and HMAC-signs the complete governance decision via `AuditorKeyring` for
       immutable CI/CD release promotion pipelines.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ely_soe.core.crypto_ledger import AuditorKeyring
from ely_soe.core.models import utc_now_iso
from ely_soe.harness_squared.meta_verifier import HarnessSquaredMetaVerifier


@dataclass
class EnterpriseReleasePolicy:
    policy_id: str = "ELY-CORP-PROD-STRICT-V2"
    max_critical_findings: int = 0
    max_high_findings: int = 2
    max_kev_findings: int = 0
    max_sandbox_reproduced: int = 0
    max_exploit_chains: int = 0
    min_cyber_posture_score: float = 85.0
    min_compliance_readiness_pct: float = 80.0
    require_meta_verifier_proven_safe: bool = True
    max_fair_mean_ale_usd: Optional[float] = None


@dataclass
class PolicyRuleCheck:
    rule_name: str
    passed: bool
    observed_value: Any
    threshold_value: Any
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "passed": self.passed,
            "observed_value": self.observed_value,
            "threshold_value": self.threshold_value,
            "message": self.message,
        }


class HarnessPolicyGovernanceEngine:
    """Evaluates enterprise release policies over Harness² runs and emits SARIF 2.1 + signed bundles."""

    def __init__(
        self,
        keyring: Optional[AuditorKeyring] = None,
        meta_verifier: Optional[HarnessSquaredMetaVerifier] = None,
    ) -> None:
        self.keyring = keyring or AuditorKeyring(key_id="ely-policy-gov-v2")
        self.meta_verifier = meta_verifier or HarnessSquaredMetaVerifier(keyring=self.keyring)

    def evaluate_governance_gate(
        self,
        h2_run: Dict[str, Any],
        policy: Optional[EnterpriseReleasePolicy] = None,
        fair_ale_usd: Optional[float] = None,
    ) -> Dict[str, Any]:
        pol = policy or EnterpriseReleasePolicy()
        cert = self.meta_verifier.verify_run(h2_run)
        sev = h2_run.get("severity_counts", {})
        prisk = h2_run.get("portfolio_risk", {})
        chains = int(h2_run.get("exploit_chains", {}).get("kill_chains_found", 0))
        posture = float(h2_run.get("overall_cyber_posture", 0.0))
        comp_pct = float(h2_run.get("compliance", {}).get("overall_compliance_readiness_pct", 0.0))

        crit_cnt = int(sev.get("critical", 0))
        high_cnt = int(sev.get("high", 0))
        kev_cnt = int(prisk.get("kev_flagged_count", 0))
        repro_cnt = int(prisk.get("sandbox_reproduced_count", 0))

        checks: List[PolicyRuleCheck] = [
            PolicyRuleCheck("max_critical_findings", crit_cnt <= pol.max_critical_findings, crit_cnt, pol.max_critical_findings, f"Critical findings {crit_cnt} <= {pol.max_critical_findings}"),
            PolicyRuleCheck("max_high_findings", high_cnt <= pol.max_high_findings, high_cnt, pol.max_high_findings, f"High findings {high_cnt} <= {pol.max_high_findings}"),
            PolicyRuleCheck("max_kev_findings", kev_cnt <= pol.max_kev_findings, kev_cnt, pol.max_kev_findings, f"CISA KEV findings {kev_cnt} <= {pol.max_kev_findings}"),
            PolicyRuleCheck("max_sandbox_reproduced", repro_cnt <= pol.max_sandbox_reproduced, repro_cnt, pol.max_sandbox_reproduced, f"Sandbox-reproduced exploits {repro_cnt} <= {pol.max_sandbox_reproduced}"),
            PolicyRuleCheck("max_exploit_chains", chains <= pol.max_exploit_chains, chains, pol.max_exploit_chains, f"Multi-step exploit chains {chains} <= {pol.max_exploit_chains}"),
            PolicyRuleCheck("min_cyber_posture_score", posture >= pol.min_cyber_posture_score, round(posture, 2), pol.min_cyber_posture_score, f"Cyber posture {posture:.2f} >= {pol.min_cyber_posture_score}"),
            PolicyRuleCheck("min_compliance_readiness_pct", comp_pct >= pol.min_compliance_readiness_pct, round(comp_pct, 2), pol.min_compliance_readiness_pct, f"Compliance readiness {comp_pct:.2f}% >= {pol.min_compliance_readiness_pct}%"),
        ]
        if pol.require_meta_verifier_proven_safe:
            meta_ok = cert.overall_verdict == "PROVEN_SAFE"
            checks.append(PolicyRuleCheck("meta_verifier_m1_m8_proven_safe", meta_ok, cert.overall_verdict, "PROVEN_SAFE", f"Harness² Meta-Verifier {cert.theorems_passed}/{cert.theorems_total} = {cert.overall_verdict}"))
        if pol.max_fair_mean_ale_usd is not None and fair_ale_usd is not None:
            checks.append(PolicyRuleCheck("max_fair_mean_ale_usd", fair_ale_usd <= pol.max_fair_mean_ale_usd, round(fair_ale_usd, 2), pol.max_fair_mean_ale_usd, f"FAIR Mean ALE ${fair_ale_usd:,.0f} <= ${pol.max_fair_mean_ale_usd:,.0f}"))

        passed_cnt = sum(1 for c in checks if c.passed)
        all_pass = passed_cnt == len(checks)
        verdict = "PROMOTE_RELEASE" if all_pass else "BLOCK_RELEASE"

        attestation_payload = json.dumps(
            {
                "policy_id": pol.policy_id,
                "run_id": h2_run.get("run_id"),
                "verdict": verdict,
                "checks": [(c.rule_name, c.passed) for c in checks],
                "meta_cert_id": cert.certificate_id,
            },
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256(attestation_payload).hexdigest()
        sig = self.keyring.sign_report_digest(digest)

        return {
            "evaluated_at": utc_now_iso(),
            "policy_id": pol.policy_id,
            "run_id": h2_run.get("run_id"),
            "governance_verdict": verdict,
            "checks_passed": passed_cnt,
            "checks_total": len(checks),
            "checks": [c.to_dict() for c in checks],
            "meta_verification_certificate": cert.to_dict(),
            "attestation_digest_sha256": digest,
            "attestation_signature_hmac": sig,
            "signer_key_id": self.keyring.key_id,
        }

    def export_sarif_2_1(self, h2_run: Dict[str, Any]) -> Dict[str, Any]:
        """Export Harness² findings to OASIS SARIF v2.1.0 JSON for GitHub Code Scanning / IDEs."""
        vulns = list(h2_run.get("vulnerabilities", []))
        rules_map: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []
        level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

        for v in vulns:
            rid = str(v.get("rule_id", "ELY-CYB-RULE"))
            sev_l = str(v.get("severity", "medium")).lower()
            cvss = float(v.get("cvss4_score", 0.0)) or (9.5 if sev_l == "critical" else (7.5 if sev_l == "high" else 5.0))
            if rid not in rules_map:
                rules_map[rid] = {
                    "id": rid,
                    "name": rid,
                    "shortDescription": {"text": str(v.get("title", rid))[:160]},
                    "fullDescription": {"text": str(v.get("description", ""))[:500]},
                    "help": {"text": str(v.get("remediation_guidance", ""))[:500]},
                    "properties": {
                        "security-severity": f"{cvss:.1f}",
                        "tags": ["security", "ely-harness-squared"] + list(v.get("cwe_ids", [])),
                    },
                }

            fpath = str(v.get("file_path") or v.get("endpoint_or_asset") or "target")
            line_s = max(1, int(v.get("line_start", 1) or 1))
            results.append({
                "ruleId": rid,
                "level": level_map.get(sev_l, "warning"),
                "message": {"text": f"{v.get('title', rid)} — {v.get('remediation_guidance', '')}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": fpath},
                        "region": {"startLine": line_s},
                    }
                }],
                "partialFingerprints": {"primaryLocationLineHash": str(v.get("fingerprint", rid))},
            })

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ELY-SoE Harness² Second-Order Security Engine",
                        "version": "2.0.0",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }],
        }
