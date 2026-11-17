"""
Enterprise Multi-Framework Security Compliance Mapper & Control Harmonization Engine.

Automatically maps discovered `CyberVulnerability` findings (by CWE, CyberDomain, and
OWASP category) onto concrete regulatory & industry controls across **7 major frameworks**:
  1. **OWASP ASVS v4.0.3** (Application Security Verification Standard, L1/L2/L3)
  2. **NIST SP 800-53 Rev 5** (Security and Privacy Controls for Information Systems)
  3. **CIS Critical Security Controls v8**
  4. **ISO/IEC 27001:2022 Annex A**
  5. **PCI-DSS v4.0** (Payment Card Industry Data Security Standard)
  6. **SOC 2 Trust Services Criteria (TSC)**
  7. **OWASP Top 10 (2021) + API Top 10 (2023) + LLM Top 10 (2025)**

Produces:
  - Per-framework Readiness % & Control Status (`PASS`, `FAIL`, `PARTIAL`)
  - Cross-framework **Control Harmonization** ("Fix Once, Comply Everywhere" impact multiplier)
  - Executive GRC Readiness Matrix & Audit Evidence Package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Set, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import CyberDomain, CyberVulnerability


@dataclass(frozen=True)
class ComplianceControl:
    framework: str
    control_id: str
    title: str
    category: str
    level: str  # e.g. L1/L2/L3, Baseline High, IG1/IG2/IG3
    mapped_cwes: Tuple[str, ...]
    mapped_domains: Tuple[CyberDomain, ...]
    weight: float = 1.0


COMPLIANCE_CATALOG: Tuple[ComplianceControl, ...] = (
    # ---- OWASP ASVS v4.0.3 ----
    ComplianceControl("OWASP_ASVS_4.0.3", "V2.1.1", "Password Security & Credential Verification", "Authentication", "L1", ("CWE-287", "CWE-798", "CWE-521", "CWE-307"), (CyberDomain.AUTH_ACCESS_CONTROL,), 1.5),
    ComplianceControl("OWASP_ASVS_4.0.3", "V3.5.3", "Cryptographic Token / JWT Integrity & Algorithm Pinning", "Session Management", "L1", ("CWE-347", "CWE-345", "CWE-384", "CWE-613"), (CyberDomain.AUTH_ACCESS_CONTROL,), 1.5),
    ComplianceControl("OWASP_ASVS_4.0.3", "V4.1.3", "Least Privilege & Server-Side Object Access Control (BOLA/BFLA)", "Access Control", "L1", ("CWE-639", "CWE-862", "CWE-863", "CWE-285", "CWE-915"), (CyberDomain.AUTH_ACCESS_CONTROL, CyberDomain.API_MICROSERVICES), 1.8),
    ComplianceControl("OWASP_ASVS_4.0.3", "V5.3.4", "Parameterized Queries & Injection Defense (SQLi/Cmd/LDAP/SSTI)", "Validation & Sanitization", "L1", ("CWE-89", "CWE-78", "CWE-77", "CWE-90", "CWE-94", "CWE-943", "CWE-1336"), (CyberDomain.WEB_INJECTION, CyberDomain.WEB_SSRF_XXE_SSTI_DESER), 2.0),
    ComplianceControl("OWASP_ASVS_4.0.3", "V5.3.3", "Context-Aware Output Encoding & XSS Prevention", "Encoding", "L1", ("CWE-79", "CWE-80", "CWE-352", "CWE-601"), (CyberDomain.WEB_CLIENT_PROTOCOL,), 1.5),
    ComplianceControl("OWASP_ASVS_4.0.3", "V5.5.2", "Safe XML Parsing (XXE) & Deserialization Hardening", "Deserialization", "L1", ("CWE-611", "CWE-502", "CWE-918", "CWE-22"), (CyberDomain.WEB_SSRF_XXE_SSTI_DESER,), 1.8),
    ComplianceControl("OWASP_ASVS_4.0.3", "V6.2.1", "Approved Cryptographic Algorithms & Key Management", "Cryptography", "L1", ("CWE-327", "CWE-328", "CWE-326", "CWE-321", "CWE-338"), (CyberDomain.TLS_CRYPTOGRAPHY,), 1.5),
    ComplianceControl("OWASP_ASVS_4.0.3", "V9.1.1", "TLS 1.2+/1.3 Transport Security & Certificate Validation", "Communications", "L1", ("CWE-295", "CWE-319", "CWE-757"), (CyberDomain.TLS_CRYPTOGRAPHY, CyberDomain.NETWORK_PROTOCOL), 1.5),
    ComplianceControl("OWASP_ASVS_4.0.3", "V13.1.1", "REST / GraphQL / gRPC API Security & Complexity Controls", "API & Web Service", "L2", ("CWE-400", "CWE-770", "CWE-200"), (CyberDomain.API_MICROSERVICES,), 1.4),
    ComplianceControl("OWASP_ASVS_4.0.3", "V14.2.1", "Dependency Hygiene, Build Pipeline & Security Headers", "Configuration", "L1", ("CWE-829", "CWE-693", "CWE-942", "CWE-444"), (CyberDomain.IAC_CICD, CyberDomain.WEB_CLIENT_PROTOCOL), 1.4),

    # ---- NIST SP 800-53 Rev 5 ----
    ComplianceControl("NIST_800_53_R5", "AC-3", "Access Enforcement (RBAC / ABAC / Object-Level Checks)", "Access Control", "High", ("CWE-639", "CWE-862", "CWE-863", "CWE-285", "CWE-284"), (CyberDomain.AUTH_ACCESS_CONTROL, CyberDomain.CLOUD_IAM), 1.8),
    ComplianceControl("NIST_800_53_R5", "AC-6", "Least Privilege Across Cloud IAM, Kubernetes & Active Directory", "Access Control", "High", ("CWE-269", "CWE-250", "CWE-732", "CWE-276"), (CyberDomain.CLOUD_IAM, CyberDomain.KUBERNETES_CONTAINER, CyberDomain.IDENTITY_ACTIVE_DIRECTORY), 2.0),
    ComplianceControl("NIST_800_53_R5", "AU-9", "Protection of Audit Information & Tamper-Evident Logging", "Audit & Accountability", "High", ("CWE-778", "CWE-532"), (CyberDomain.DETECTION_ENGINEERING, CyberDomain.ADVERSARY_EMULATION), 1.4),
    ComplianceControl("NIST_800_53_R5", "CM-6", "Configuration Settings & Hardened IaC / Container Baselines", "Configuration Management", "High", ("CWE-16", "CWE-250", "CWE-693", "CWE-276"), (CyberDomain.KUBERNETES_CONTAINER, CyberDomain.IAC_CICD), 1.5),
    ComplianceControl("NIST_800_53_R5", "IA-2", "Identification and Authentication (MFA, Kerberos AES, OIDC)", "Identification & Auth", "High", ("CWE-287", "CWE-306", "CWE-347", "CWE-798"), (CyberDomain.AUTH_ACCESS_CONTROL, CyberDomain.IDENTITY_ACTIVE_DIRECTORY), 1.8),
    ComplianceControl("NIST_800_53_R5", "SC-7", "Boundary Protection, Zero-Trust Segmentation & SSRF Egress Controls", "System & Comms Protection", "High", ("CWE-918", "CWE-284", "CWE-942", "CWE-444"), (CyberDomain.NETWORK_PROTOCOL, CyberDomain.WEB_SSRF_XXE_SSTI_DESER), 1.7),
    ComplianceControl("NIST_800_53_R5", "SC-8", "Transmission Confidentiality & Integrity (TLS 1.3 / mTLS / SMB Signing)", "System & Comms Protection", "High", ("CWE-319", "CWE-295", "CWE-327", "CWE-345"), (CyberDomain.TLS_CRYPTOGRAPHY, CyberDomain.NETWORK_PROTOCOL), 1.6),
    ComplianceControl("NIST_800_53_R5", "SC-13", "FIPS-Validated Cryptographic Protection & Key Hygiene", "System & Comms Protection", "High", ("CWE-327", "CWE-328", "CWE-326", "CWE-321", "CWE-338"), (CyberDomain.TLS_CRYPTOGRAPHY,), 1.5),
    ComplianceControl("NIST_800_53_R5", "SI-10", "Information Input Validation (Injection, XXE, Path Traversal, Memory Safety)", "System & Info Integrity", "High", ("CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-502", "CWE-611", "CWE-120", "CWE-787", "CWE-416"), (CyberDomain.WEB_INJECTION, CyberDomain.BINARY_MEMORY_SAFETY), 2.0),
    ComplianceControl("NIST_800_53_R5", "SR-3", "Supply Chain Controls, SBOM & CI/CD Artifact Integrity", "Supply Chain Risk Mgmt", "High", ("CWE-829", "CWE-494", "CWE-506"), (CyberDomain.IAC_CICD, CyberDomain.FIRMWARE_IOT_OT), 1.6),

    # ---- CIS Critical Security Controls v8 ----
    ComplianceControl("CIS_CONTROLS_V8", "CIS-3", "Data Protection & Secret / DLP Prevention", "Data Security", "IG1", ("CWE-312", "CWE-319", "CWE-359", "CWE-798", "CWE-200"), (CyberDomain.TLS_CRYPTOGRAPHY, CyberDomain.AUTH_ACCESS_CONTROL), 1.6),
    ComplianceControl("CIS_CONTROLS_V8", "CIS-4", "Secure Configuration of Enterprise Assets, Cloud & Containers", "Configuration", "IG1", ("CWE-16", "CWE-250", "CWE-693", "CWE-732"), (CyberDomain.KUBERNETES_CONTAINER, CyberDomain.IAC_CICD), 1.6),
    ComplianceControl("CIS_CONTROLS_V8", "CIS-5", "Account Management & Privileged Identity Hygiene (AD/IAM)", "Identity", "IG1", ("CWE-269", "CWE-287", "CWE-521", "CWE-798"), (CyberDomain.IDENTITY_ACTIVE_DIRECTORY, CyberDomain.CLOUD_IAM), 1.8),
    ComplianceControl("CIS_CONTROLS_V8", "CIS-6", "Access Control Management (MFA & RBAC Enforcement)", "Access Control", "IG1", ("CWE-639", "CWE-862", "CWE-863", "CWE-306"), (CyberDomain.AUTH_ACCESS_CONTROL, CyberDomain.CLOUD_IAM), 1.7),
    ComplianceControl("CIS_CONTROLS_V8", "CIS-8", "Audit Log Management & SIEM/Sigma Detection Coverage", "Detection", "IG2", ("CWE-778",), (CyberDomain.DETECTION_ENGINEERING,), 1.4),
    ComplianceControl("CIS_CONTROLS_V8", "CIS-12", "Network Infrastructure Management & Zero-Trust Segmentation", "Network", "IG2", ("CWE-284", "CWE-319", "CWE-406"), (CyberDomain.NETWORK_PROTOCOL, CyberDomain.FIRMWARE_IOT_OT), 1.5),
    ComplianceControl("CIS_CONTROLS_V8", "CIS-16", "Application Software Security (SAST/DAST/Memory Safety/API)", "AppSec", "IG2", ("CWE-89", "CWE-78", "CWE-79", "CWE-502", "CWE-918", "CWE-787", "CWE-416"), (CyberDomain.WEB_INJECTION, CyberDomain.WEB_CLIENT_PROTOCOL, CyberDomain.BINARY_MEMORY_SAFETY, CyberDomain.API_MICROSERVICES), 2.0),
    ComplianceControl("CIS_CONTROLS_V8", "CIS-18", "Penetration Testing & Adversarial Breach Simulation", "Validation", "IG2", ("CWE-269", "CWE-119"), (CyberDomain.ADVERSARY_EMULATION,), 1.4),

    # ---- ISO/IEC 27001:2022 Annex A ----
    ComplianceControl("ISO_27001_2022", "A.5.15", "Access Control Policy & Identity Governance", "Organizational", "Mandatory", ("CWE-639", "CWE-862", "CWE-863", "CWE-285", "CWE-269"), (CyberDomain.AUTH_ACCESS_CONTROL, CyberDomain.CLOUD_IAM, CyberDomain.IDENTITY_ACTIVE_DIRECTORY), 1.7),
    ComplianceControl("ISO_27001_2022", "A.5.21", "Managing Information Security in the ICT Supply Chain", "Organizational", "Mandatory", ("CWE-829", "CWE-494", "CWE-506"), (CyberDomain.IAC_CICD,), 1.5),
    ComplianceControl("ISO_27001_2022", "A.8.9", "Configuration Management (Containers, Cloud, OS)", "Technological", "Mandatory", ("CWE-16", "CWE-250", "CWE-693"), (CyberDomain.KUBERNETES_CONTAINER, CyberDomain.IAC_CICD), 1.5),
    ComplianceControl("ISO_27001_2022", "A.8.16", "Monitoring Activities & Anomaly/SIEM Detection", "Technological", "Mandatory", ("CWE-778",), (CyberDomain.DETECTION_ENGINEERING, CyberDomain.ADVERSARY_EMULATION), 1.4),
    ComplianceControl("ISO_27001_2022", "A.8.20", "Networks Security & Micro-Segmentation", "Technological", "Mandatory", ("CWE-284", "CWE-319", "CWE-918"), (CyberDomain.NETWORK_PROTOCOL, CyberDomain.FIRMWARE_IOT_OT), 1.6),
    ComplianceControl("ISO_27001_2022", "A.8.24", "Use of Cryptography & Key Lifecycle Protection", "Technological", "Mandatory", ("CWE-327", "CWE-328", "CWE-326", "CWE-321", "CWE-295"), (CyberDomain.TLS_CRYPTOGRAPHY,), 1.6),
    ComplianceControl("ISO_27001_2022", "A.8.28", "Secure Coding Across Web, API & Native Binaries", "Technological", "Mandatory", ("CWE-89", "CWE-78", "CWE-79", "CWE-502", "CWE-611", "CWE-787", "CWE-120", "CWE-416"), (CyberDomain.WEB_INJECTION, CyberDomain.WEB_CLIENT_PROTOCOL, CyberDomain.WEB_SSRF_XXE_SSTI_DESER, CyberDomain.BINARY_MEMORY_SAFETY), 2.0),

    # ---- PCI-DSS v4.0 ----
    ComplianceControl("PCI_DSS_4.0", "Req-1.2", "Network Security Controls & Restrictive Firewall Segmentation", "Network Security", "Mandatory", ("CWE-284", "CWE-918"), (CyberDomain.NETWORK_PROTOCOL,), 1.6),
    ComplianceControl("PCI_DSS_4.0", "Req-3.5", "Protect Stored Account Data / PAN Encryption & DLP", "Data Protection", "Mandatory", ("CWE-312", "CWE-359", "CWE-798", "CWE-321"), (CyberDomain.TLS_CRYPTOGRAPHY,), 1.8),
    ComplianceControl("PCI_DSS_4.0", "Req-4.2", "Strong Cryptography (TLS 1.2+/1.3) Over Open Public Networks", "Transmission", "Mandatory", ("CWE-319", "CWE-327", "CWE-295", "CWE-757"), (CyberDomain.TLS_CRYPTOGRAPHY,), 1.7),
    ComplianceControl("PCI_DSS_4.0", "Req-6.2", "Bespoke & Custom Software Developed Securely (Injection/XSS/Auth)", "Secure Dev", "Mandatory", ("CWE-89", "CWE-78", "CWE-79", "CWE-352", "CWE-502", "CWE-611", "CWE-639"), (CyberDomain.WEB_INJECTION, CyberDomain.WEB_CLIENT_PROTOCOL, CyberDomain.WEB_SSRF_XXE_SSTI_DESER), 2.0),
    ComplianceControl("PCI_DSS_4.0", "Req-6.3", "Software Supply-Chain Vulnerabilities & Component Inventory", "Vuln Mgmt", "Mandatory", ("CWE-829", "CWE-494"), (CyberDomain.IAC_CICD,), 1.5),
    ComplianceControl("PCI_DSS_4.0", "Req-8.3", "Strong Authentication, MFA & Non-Default Credentials", "Access Control", "Mandatory", ("CWE-287", "CWE-306", "CWE-347", "CWE-798"), (CyberDomain.AUTH_ACCESS_CONTROL, CyberDomain.IDENTITY_ACTIVE_DIRECTORY), 1.8),
    ComplianceControl("PCI_DSS_4.0", "Req-10.2", "Audit Logs & Automated Intrusion Detection Mechanisms", "Logging", "Mandatory", ("CWE-778",), (CyberDomain.DETECTION_ENGINEERING,), 1.4),

    # ---- SOC 2 Trust Services Criteria ----
    ComplianceControl("SOC2_TSC", "CC6.1", "Logical Access Security Software, Infrastructure & Cryptography", "Security", "Core", ("CWE-287", "CWE-639", "CWE-862", "CWE-863", "CWE-269", "CWE-327"), (CyberDomain.AUTH_ACCESS_CONTROL, CyberDomain.CLOUD_IAM, CyberDomain.TLS_CRYPTOGRAPHY), 1.8),
    ComplianceControl("SOC2_TSC", "CC6.6", "Logical Access Boundary Protection Against External Threats", "Security", "Core", ("CWE-89", "CWE-78", "CWE-79", "CWE-918", "CWE-444", "CWE-284"), (CyberDomain.WEB_INJECTION, CyberDomain.NETWORK_PROTOCOL, CyberDomain.API_MICROSERVICES), 1.9),
    ComplianceControl("SOC2_TSC", "CC6.8", "Prevention & Detection of Unauthorized/Malicious Software", "Security", "Core", ("CWE-502", "CWE-506", "CWE-829", "CWE-494"), (CyberDomain.IAC_CICD, CyberDomain.KUBERNETES_CONTAINER), 1.6),
    ComplianceControl("SOC2_TSC", "CC7.2", "Continuous System Monitoring for Anomalies & Security Events", "Operations", "Core", ("CWE-778",), (CyberDomain.DETECTION_ENGINEERING, CyberDomain.ADVERSARY_EMULATION), 1.5),
    ComplianceControl("SOC2_TSC", "CC8.1", "Secure Change Management, CI/CD Integrity & Pre-Release Gates", "Change Mgmt", "Core", ("CWE-829", "CWE-16", "CWE-250"), (CyberDomain.IAC_CICD,), 1.5),
)


class EnterpriseComplianceMapper:
    """Evaluates multi-framework compliance posture and computes cross-framework fix leverage."""

    def __init__(self, controls: Sequence[ComplianceControl] = COMPLIANCE_CATALOG) -> None:
        self.controls = list(controls)

    def evaluate(self, vulnerabilities: Sequence[CyberVulnerability]) -> Dict[str, Any]:
        active = [v for v in vulnerabilities if v.severity != Severity.INFO]
        frameworks: Dict[str, List[Dict[str, Any]]] = {}
        finding_to_controls: Dict[str, Set[str]] = {}

        for ctrl in self.controls:
            matched: List[CyberVulnerability] = []
            cwe_set = set(ctrl.mapped_cwes)
            dom_set = set(ctrl.mapped_domains)
            for v in active:
                if (set(v.cwe_ids) & cwe_set) or (v.cyber_domain in dom_set and v.severity in (Severity.CRITICAL, Severity.HIGH)):
                    matched.append(v)
                    finding_to_controls.setdefault(v.rule_id, set()).add(f"{ctrl.framework}:{ctrl.control_id}")

            has_crit_high = any(v.severity in (Severity.CRITICAL, Severity.HIGH) for v in matched)
            if not matched:
                status = "PASS"
                score = 100.0
            elif has_crit_high:
                status = "FAIL"
                score = 0.0
            else:
                status = "PARTIAL"
                score = 50.0

            frameworks.setdefault(ctrl.framework, []).append(
                {
                    "control_id": ctrl.control_id,
                    "title": ctrl.title,
                    "category": ctrl.category,
                    "level": ctrl.level,
                    "weight": ctrl.weight,
                    "status": status,
                    "score": score,
                    "violating_finding_count": len(matched),
                    "sample_rule_ids": sorted({v.rule_id for v in matched})[:5],
                }
            )

        framework_summaries: Dict[str, Any] = {}
        for fw_name, rows in sorted(frameworks.items()):
            total_w = sum(r["weight"] for r in rows) or 1.0
            weighted_score = sum(r["score"] * r["weight"] for r in rows) / total_w
            passed = sum(1 for r in rows if r["status"] == "PASS")
            partial = sum(1 for r in rows if r["status"] == "PARTIAL")
            failed = sum(1 for r in rows if r["status"] == "FAIL")
            framework_summaries[fw_name] = {
                "readiness_pct": round(weighted_score, 2),
                "total_controls": len(rows),
                "passed": passed,
                "partial": partial,
                "failed": failed,
                "controls": rows,
            }

        overall_readiness = round(
            sum(s["readiness_pct"] for s in framework_summaries.values()) / max(1, len(framework_summaries)),
            2,
        )

        # Harmonized high-leverage remediation: fixes that unblock the highest count of compliance controls
        harmonization_leverage = [
            {
                "rule_id": rid,
                "controls_impacted": len(ctrls),
                "frameworks_impacted": sorted({c.split(":", 1)[0] for c in ctrls}),
                "sample_controls": sorted(ctrls)[:8],
            }
            for rid, ctrls in sorted(finding_to_controls.items(), key=lambda kv: -len(kv[1]))[:15]
        ]

        return {
            "evaluated_at": utc_now_iso(),
            "overall_compliance_readiness_pct": overall_readiness,
            "frameworks_evaluated": sorted(framework_summaries.keys()),
            "framework_summaries": framework_summaries,
            "harmonized_fix_leverage": harmonization_leverage,
        }
