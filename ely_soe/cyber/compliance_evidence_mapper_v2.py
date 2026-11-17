"""
Regulatory Compliance Evidence Mapper v2 (NIST CSF 2.0, OWASP ASVS v4.0.3, SOC 2 Type II,
ISO/IEC 27001:2022 Annex A, PCI-DSS v4.0, EU AI Act Art. 9/15).

Links concrete technical security evidence (SAST, Interprocedural Taint, DAST runtime
probes, Contextual Secret Scans, OpenSSF Scorecard, Network/TLS Zero-Trust, AI Firewall,
and Formal M1–M8 Invariants) directly to auditable regulatory control clauses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import utc_now_iso


@dataclass(frozen=True)
class RegulatoryControlClause:
    framework: str
    control_id: str
    title: str
    blocking_cwes: Tuple[str, ...]
    blocking_rule_prefixes: Tuple[str, ...]
    weight: float = 1.0


REGULATORY_CLAUSES: Tuple[RegulatoryControlClause, ...] = (
    # NIST CSF 2.0
    RegulatoryControlClause("NIST_CSF_2_0", "PR.AA-01", "Identity, Credential & Secret Lifecycle Management", ("CWE-798", "CWE-287", "CWE-347", "CWE-321"), ("CYB-SEC-", "CYB-IAM-"), 1.3),
    RegulatoryControlClause("NIST_CSF_2_0", "PR.DS-02", "Data-in-Transit TLS/Cryptographic Protection", ("CWE-295", "CWE-319", "CWE-327", "CWE-328"), ("CYB-NET-LEGACY-TLS", "CYB-NET-CERT-VERIFY"), 1.2),
    RegulatoryControlClause("NIST_CSF_2_0", "PR.PS-02", "Secure Software Development & Injection Prevention", ("CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-95", "CWE-502"), ("CYB-WEB-", "CYB-POLY-", "CYB-TAINT-"), 1.5),
    RegulatoryControlClause("NIST_CSF_2_0", "GV.SC-07", "Software Supply-Chain & SBOM Risk Management", ("CWE-829", "CWE-1104", "CWE-1395"), ("CYB-SC-", "CYB-CICD-"), 1.2),
    # OWASP ASVS v4.0.3
    RegulatoryControlClause("OWASP_ASVS_4_0_3", "V5.3", "Output Encoding & Injection Defense (SQLi/CMDi/XSS)", ("CWE-78", "CWE-79", "CWE-89", "CWE-94"), ("CYB-WEB-", "CYB-AST-DEOBF"), 1.5),
    RegulatoryControlClause("OWASP_ASVS_4_0_3", "V12.3", "File & Path Traversal Confinement", ("CWE-22",), ("CYB-DAST-PATH-TRAVERSAL",), 1.2),
    RegulatoryControlClause("OWASP_ASVS_4_0_3", "V14.4", "HTTP Security Response Headers & CORS Hardening", ("CWE-693", "CWE-942", "CWE-16"), ("CYB-DAST-HDR", "CYB-DAST-CORS"), 1.0),
    RegulatoryControlClause("OWASP_ASVS_4_0_3", "V12.6", "SSRF & Outbound Destination Validation", ("CWE-918",), ("CYB-SSRF-", "MCP_SSRF"), 1.3),
    # SOC 2 Type II
    RegulatoryControlClause("SOC2_TYPE_II", "CC6.1", "Logical Access Controls & Least-Privilege Boundaries", ("CWE-250", "CWE-284", "CWE-732", "CWE-863"), ("CYB-K8S-", "CYB-NET-WORLD-OPEN", "CYB-POLY-DOCKER-ROOT"), 1.4),
    RegulatoryControlClause("SOC2_TYPE_II", "CC6.7", "Transmission Encryption & Certificate Verification", ("CWE-295", "CWE-319", "CWE-327"), ("CYB-NET-",), 1.2),
    RegulatoryControlClause("SOC2_TYPE_II", "CC7.1", "Continuous Vulnerability Detection & Threat Monitoring", ("CWE-1104", "CWE-1395"), ("CYB-SC-",), 1.0),
    # ISO/IEC 27001:2022 Annex A
    RegulatoryControlClause("ISO_27001_2022", "A.8.24", "Use of Strong Cryptography & Key Protection", ("CWE-321", "CWE-327", "CWE-328", "CWE-338"), ("CYB-CRYPTO-", "CYB-SEC-PRIVATE-KEY"), 1.3),
    RegulatoryControlClause("ISO_27001_2022", "A.8.25", "Secure Development Lifecycle & Static/Dynamic Assurance", ("CWE-78", "CWE-89", "CWE-94", "CWE-502"), ("CYB-WEB-", "CYB-TAINT-"), 1.4),
    RegulatoryControlClause("ISO_27001_2022", "A.8.20", "Network Segmentation & Zero-Trust Controls", ("CWE-284", "CWE-306"), ("CYB-NET-WORLD-OPEN", "CYB-NET-ISTIO"), 1.2),
    # PCI-DSS v4.0
    RegulatoryControlClause("PCI_DSS_4_0", "Req 6.2.4", "Prevent Common Software Attacks (Injection/Deser/XSS)", ("CWE-78", "CWE-79", "CWE-89", "CWE-502", "CWE-611"), ("CYB-WEB-", "CYB-POLY-"), 1.5),
    RegulatoryControlClause("PCI_DSS_4_0", "Req 4.2.1", "Strong Cryptography Over Open Public Networks", ("CWE-295", "CWE-319", "CWE-327"), ("CYB-NET-LEGACY-TLS", "CYB-NET-BROKEN-CIPHER"), 1.3),
    # EU AI Act (Autonomous Agent Robustness & Cybersecurity)
    RegulatoryControlClause("EU_AI_ACT", "Art. 15(4)", "AI Robustness Against Prompt Injection & Manipulation", ("CWE-77", "CWE-94"), ("CYB-LLM-", "CAMEL_"), 1.5),
    RegulatoryControlClause("EU_AI_ACT", "Art. 9", "Continuous Risk Management & Traceable Audit Logging", ("CWE-209", "CWE-863"), ("CYB-DAST-SCOPEGUARD",), 1.2),
)


class RegulatoryComplianceEvidenceMapperV2:
    """Computes control-by-control regulatory compliance posture across 6 global frameworks."""

    def evaluate_compliance(
        self,
        vulnerabilities: Sequence[Any],
        *,
        merkle_ledger_verified: bool = True,
        formal_invariants_passed: int = 8,
    ) -> Dict[str, Any]:
        observed_cwes: Set[str] = set()
        observed_rules: List[str] = []
        cwe_to_findings: Dict[str, List[str]] = {}

        for v in vulnerabilities:
            rid = str(v.get("rule_id") if isinstance(v, dict) else getattr(v, "rule_id", ""))
            cwes = (v.get("cwe_ids") if isinstance(v, dict) else getattr(v, "cwe_ids", None)) or []
            if rid:
                observed_rules.append(rid)
            for c in cwes:
                cu = str(c).upper()
                observed_cwes.add(cu)
                cwe_to_findings.setdefault(cu, []).append(rid)

        frameworks: Dict[str, Dict[str, Any]] = {}
        clause_results: List[Dict[str, Any]] = []

        for cl in REGULATORY_CLAUSES:
            violating_cwes = [c for c in cl.blocking_cwes if c in observed_cwes]
            violating_rules = [
                r for r in observed_rules
                if any(r.startswith(pref) for pref in cl.blocking_rule_prefixes)
            ]
            evidence_hits = sorted(set(
                violating_rules + [r for c in violating_cwes for r in cwe_to_findings.get(c, [])]
            ))
            status = "PASS" if not evidence_hits else ("FAIL" if len(evidence_hits) >= 2 else "PARTIAL_GAP")
            score = 1.0 if status == "PASS" else (0.45 if status == "PARTIAL_GAP" else 0.0)

            clause_results.append({
                "framework": cl.framework,
                "control_id": cl.control_id,
                "title": cl.title,
                "status": status,
                "blocking_evidence_count": len(evidence_hits),
                "sample_blocking_rules": evidence_hits[:6],
            })

            fw = frameworks.setdefault(cl.framework, {"weighted_sum": 0.0, "weight_total": 0.0, "passed": 0, "failed": 0, "partial": 0, "total": 0})
            fw["weighted_sum"] += score * cl.weight
            fw["weight_total"] += cl.weight
            fw["total"] += 1
            if status == "PASS":
                fw["passed"] += 1
            elif status == "PARTIAL_GAP":
                fw["partial"] += 1
            else:
                fw["failed"] += 1

        framework_summary: Dict[str, Any] = {}
        all_pcts: List[float] = []
        for fname, stats in frameworks.items():
            pct = round((stats["weighted_sum"] / max(1e-6, stats["weight_total"])) * 100.0, 2)
            all_pcts.append(pct)
            framework_summary[fname] = {
                "readiness_pct": pct,
                "controls_passed": stats["passed"],
                "controls_partial": stats["partial"],
                "controls_failed": stats["failed"],
                "controls_total": stats["total"],
            }

        overall_pct = round(sum(all_pcts) / max(1, len(all_pcts)), 2)
        return {
            "evaluated_at": utc_now_iso(),
            "overall_multi_framework_readiness_pct": overall_pct,
            "frameworks_evaluated": len(framework_summary),
            "cryptographic_audit_trail_verified": merkle_ledger_verified,
            "formal_invariants_proven": formal_invariants_passed,
            "frameworks": framework_summary,
            "control_matrix": clause_results,
        }
