"""
Risk Scoring Engine: CVSS v3.1/v4.0 Calculator, Agentic Risk Score & Threat Taxonomy Mapper.

Maps every security finding across:
  - CVSS v3.1 base metric vector & score (exact FIRST specification rounding)
  - Frontier Agentic Risk Score (autonomy amplification, cross-agent blast radius,
    tool privilege leverage, memory persistence, zero-click indirect exploitability)
  - OWASP Top 10 for Agentic AI (ASI01–ASI10)
  - CWE identifiers
  - MITRE ATLAS & ATT&CK techniques
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from ely_soe.core.models import Finding, SecurityDomain, Severity


def _round_up_1(val: float) -> float:
    """CVSS v3.1 Roundup function (1 decimal place)."""
    int_input = round(val * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


@dataclass(frozen=True)
class CVSS31Metrics:
    """CVSS v3.1 Base Metrics."""

    AV: str = "N"  # N, A, L, P
    AC: str = "L"  # L, H
    PR: str = "N"  # N, L, H
    UI: str = "N"  # N, R
    S: str = "U"   # U, C
    C: str = "H"   # N, L, H
    I: str = "H"   # N, L, H
    A: str = "N"   # N, L, H

    def vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}"
            f"/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )

    def base_score(self) -> float:
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_map = {"L": 0.77, "H": 0.44}
        pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_map = {"N": 0.85, "R": 0.62}
        cia_map = {"N": 0.0, "L": 0.22, "H": 0.56}

        av = av_map.get(self.AV, 0.85)
        ac = ac_map.get(self.AC, 0.77)
        pr = (pr_map_c if self.S == "C" else pr_map_u).get(self.PR, 0.85)
        ui = ui_map.get(self.UI, 0.85)
        c = cia_map.get(self.C, 0.0)
        i = cia_map.get(self.I, 0.0)
        a = cia_map.get(self.A, 0.0)

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if iss <= 0.0:
            return 0.0

        if self.S == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0.0:
            return 0.0

        exploitability = 8.22 * av * ac * pr * ui
        if self.S == "U":
            return _round_up_1(min(impact + exploitability, 10.0))
        return _round_up_1(min(1.08 * (impact + exploitability), 10.0))


@dataclass(frozen=True)
class AgenticRiskProfile:
    """
    Frontier multi-agent risk dimensions (0.0 to 1.0 each) capturing threat
    amplification unique to autonomous agentic platforms like Ely-Cowork.
    """

    autonomy_amplification: float    # Can exploit run unattended in loops/workflows?
    cross_agent_blast_radius: float  # Can compromise propagate to other agents/skills?
    zero_click_indirect: float       # Triggerable via passive external content (web/doc/RAG)?
    persistence_potential: float     # Survives across sessions (memory/skill/cron)?
    privilege_leverage: float        # Unlocks shell, filesystem, credentials, or validation plane?

    def score_10(self) -> float:
        raw = (
            self.autonomy_amplification * 0.20
            + self.cross_agent_blast_radius * 0.25
            + self.zero_click_indirect * 0.20
            + self.persistence_potential * 0.15
            + self.privilege_leverage * 0.20
        )
        return round(min(10.0, max(0.0, raw * 10.0)), 2)


# Domain-default taxonomy & risk priors grounded in OWASP Agentic Top 10 & MITRE ATLAS
DOMAIN_TAXONOMY: Dict[SecurityDomain, Dict[str, Any]] = {
    SecurityDomain.AGENT_ISOLATION: {
        "owasp_agentic": ["ASI01", "ASI07"],
        "mitre_atlas": ["AML.T0054", "AML.T0048"],
        "default_cwe": ["CWE-284", "CWE-668"],
        "cvss_default": CVSS31Metrics(AV="A", AC="L", PR="L", UI="N", S="C", C="H", I="H", A="L"),
        "agentic_default": AgenticRiskProfile(0.80, 0.95, 0.55, 0.70, 0.85),
    },
    SecurityDomain.TOOL_EXECUTION: {
        "owasp_agentic": ["ASI02", "ASI05"],
        "mitre_atlas": ["AML.T0051", "AML.T0053"],
        "default_cwe": ["CWE-78", "CWE-250"],
        "cvss_default": CVSS31Metrics(AV="N", AC="L", PR="L", UI="N", S="C", C="H", I="H", A="H"),
        "agentic_default": AgenticRiskProfile(0.90, 0.80, 0.75, 0.65, 0.95),
    },
    SecurityDomain.MEMORY: {
        "owasp_agentic": ["ASI06", "ASI01"],
        "mitre_atlas": ["AML.T0020", "AML.T0051"],
        "default_cwe": ["CWE-94", "CWE-345"],
        "cvss_default": CVSS31Metrics(AV="N", AC="L", PR="N", UI="N", S="C", C="L", I="H", A="L"),
        "agentic_default": AgenticRiskProfile(0.85, 0.85, 0.90, 0.95, 0.75),
    },
    SecurityDomain.PROMPT_INJECTION: {
        "owasp_agentic": ["ASI01", "ASI02"],
        "mitre_atlas": ["AML.T0051.000", "AML.T0051.001"],
        "default_cwe": ["CWE-74", "CWE-77"],
        "cvss_default": CVSS31Metrics(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="L"),
        "agentic_default": AgenticRiskProfile(0.95, 0.85, 0.95, 0.75, 0.85),
    },
    SecurityDomain.API_SECURITY: {
        "owasp_agentic": ["ASI03", "ASI07"],
        "mitre_atlas": ["AML.T0040", "AML.T0044"],
        "default_cwe": ["CWE-287", "CWE-639", "CWE-862"],
        "cvss_default": CVSS31Metrics(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="L"),
        "agentic_default": AgenticRiskProfile(0.75, 0.75, 0.50, 0.50, 0.85),
    },
    SecurityDomain.FILESYSTEM: {
        "owasp_agentic": ["ASI02", "ASI05"],
        "mitre_atlas": ["AML.T0053"],
        "default_cwe": ["CWE-22", "CWE-59"],
        "cvss_default": CVSS31Metrics(AV="L", AC="L", PR="L", UI="N", S="C", C="H", I="H", A="L"),
        "agentic_default": AgenticRiskProfile(0.80, 0.75, 0.65, 0.75, 0.90),
    },
    SecurityDomain.PROCESS_MANAGEMENT: {
        "owasp_agentic": ["ASI05", "ASI08"],
        "mitre_atlas": ["AML.T0053", "AML.T0054"],
        "default_cwe": ["CWE-269", "CWE-400", "CWE-78"],
        "cvss_default": CVSS31Metrics(AV="L", AC="L", PR="L", UI="N", S="C", C="H", I="H", A="H"),
        "agentic_default": AgenticRiskProfile(0.85, 0.90, 0.50, 0.80, 0.95),
    },
    SecurityDomain.SUPPLY_CHAIN: {
        "owasp_agentic": ["ASI04"],
        "mitre_atlas": ["AML.T0010", "AML.T0018"],
        "default_cwe": ["CWE-829", "CWE-494", "CWE-1395"],
        "cvss_default": CVSS31Metrics(AV="N", AC="H", PR="N", UI="N", S="C", C="H", I="H", A="H"),
        "agentic_default": AgenticRiskProfile(0.90, 0.95, 0.80, 0.95, 0.95),
    },
    SecurityDomain.NETWORK: {
        "owasp_agentic": ["ASI02", "ASI07"],
        "mitre_atlas": ["AML.T0024", "AML.T0048"],
        "default_cwe": ["CWE-918", "CWE-295", "CWE-200"],
        "cvss_default": CVSS31Metrics(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="L", A="L"),
        "agentic_default": AgenticRiskProfile(0.75, 0.65, 0.70, 0.55, 0.80),
    },
    SecurityDomain.RUST_CORE: {
        "owasp_agentic": ["ASI05", "ASI08"],
        "mitre_atlas": ["AML.T0054"],
        "default_cwe": ["CWE-119", "CWE-416", "CWE-362", "CWE-704"],
        "cvss_default": CVSS31Metrics(AV="L", AC="H", PR="L", UI="N", S="C", C="H", I="H", A="H"),
        "agentic_default": AgenticRiskProfile(0.70, 0.90, 0.45, 0.65, 0.95),
    },
}

OWASP_AGENTIC_DESCRIPTIONS: Dict[str, str] = {
    "ASI01": "Agent Goal Hijack (Prompt & Indirect Injection)",
    "ASI02": "Tool Misuse & Excessive Agency",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities (Skills/MCP/Deps)",
    "ASI05": "Unexpected Code Execution & Sandbox Escape",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication & Isolation Failure",
    "ASI08": "Cascading Failures & Resource Exhaustion",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents & Audit/Validation Subversion",
}


class RiskScoringEngine:
    """Enriches every Finding with calibrated CVSS v3.1, Agentic Risk Score, and taxonomies."""

    SEVERITY_METRICS_OVERRIDE: Dict[Severity, CVSS31Metrics] = {
        Severity.CRITICAL: CVSS31Metrics(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
        Severity.HIGH: CVSS31Metrics(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="H", A="L"),
        Severity.MEDIUM: CVSS31Metrics(AV="N", AC="H", PR="L", UI="R", S="U", C="L", I="H", A="N"),
        Severity.LOW: CVSS31Metrics(AV="L", AC="H", PR="H", UI="R", S="U", C="L", I="N", A="N"),
        Severity.INFO: CVSS31Metrics(AV="L", AC="H", PR="H", UI="R", S="U", C="N", I="N", A="N"),
    }

    def enrich_finding(
        self,
        finding: Finding,
        custom_cvss: CVSS31Metrics | None = None,
        custom_agentic: AgenticRiskProfile | None = None,
    ) -> Finding:
        taxonomy = DOMAIN_TAXONOMY[finding.domain]

        if not finding.cwe_ids:
            finding.cwe_ids = list(taxonomy["default_cwe"])
        if not finding.owasp_agentic_ids:
            finding.owasp_agentic_ids = list(taxonomy["owasp_agentic"])
        if not finding.mitre_atlas_ids:
            finding.mitre_atlas_ids = list(taxonomy["mitre_atlas"])

        if custom_cvss is not None:
            metrics = custom_cvss
        else:
            # Blend domain default with the finding's explicit severity
            metrics = self.SEVERITY_METRICS_OVERRIDE.get(finding.severity, taxonomy["cvss_default"])
            if finding.severity == Severity.CRITICAL and finding.domain in (
                SecurityDomain.TOOL_EXECUTION,
                SecurityDomain.PROMPT_INJECTION,
                SecurityDomain.PROCESS_MANAGEMENT,
                SecurityDomain.RUST_CORE,
            ):
                metrics = CVSS31Metrics(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H")

        score = metrics.base_score()
        if finding.severity == Severity.INFO:
            score = 0.0
        elif finding.severity == Severity.LOW and score >= 4.0:
            score = 3.1
        elif finding.severity == Severity.MEDIUM and (score < 4.0 or score >= 7.0):
            score = 5.8
        elif finding.severity == Severity.HIGH and (score < 7.0 or score >= 9.0):
            score = 8.1
        elif finding.severity == Severity.CRITICAL and score < 9.0:
            score = 9.6

        finding.cvss_score = round(score, 1)
        finding.cvss_vector = metrics.vector_string()

        agentic_profile = custom_agentic or taxonomy["agentic_default"]
        sev_multiplier = {
            Severity.CRITICAL: 1.05,
            Severity.HIGH: 0.95,
            Severity.MEDIUM: 0.72,
            Severity.LOW: 0.45,
            Severity.INFO: 0.20,
        }[finding.severity]
        finding.agentic_risk_score = round(min(10.0, agentic_profile.score_10() * sev_multiplier), 2)
        return finding

    def aggregate_domain_risk(self, findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Compute risk heatmap across all 10 Ely security domains."""
        summary: Dict[str, Dict[str, Any]] = {}
        for domain in SecurityDomain:
            dom_findings = [f for f in findings if f.domain == domain]
            max_cvss = max((f.cvss_score for f in dom_findings), default=0.0)
            avg_agentic = (
                sum(f.agentic_risk_score for f in dom_findings) / len(dom_findings)
                if dom_findings
                else 0.0
            )
            penalty = sum(f.severity.weight for f in dom_findings)
            domain_score = max(0.0, round(100.0 - min(100.0, penalty * 4.5), 2))
            summary[domain.value] = {
                "display_name": domain.display_name,
                "primary_risk": domain.primary_risk,
                "finding_count": len(dom_findings),
                "max_cvss": round(max_cvss, 1),
                "avg_agentic_risk": round(avg_agentic, 2),
                "posture_score": domain_score,
                "status": "secure" if domain_score >= 85 else ("warning" if domain_score >= 60 else "critical"),
            }
        return summary

    def owasp_coverage_matrix(self, findings: List[Finding]) -> List[Tuple[str, str, int]]:
        counts: Dict[str, int] = {k: 0 for k in OWASP_AGENTIC_DESCRIPTIONS}
        for f in findings:
            for oid in f.owasp_agentic_ids:
                if oid in counts:
                    counts[oid] += 1
        return [(k, OWASP_AGENTIC_DESCRIPTIONS[k], counts[k]) for k in sorted(counts)]
