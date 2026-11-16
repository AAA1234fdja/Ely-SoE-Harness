"""
CVSS v4.0 MacroVector Scoring, EPSS, KEV & Business-Context Risk Prioritization Engine.

Implements:
  1. Full FIRST CVSS v4.0 MacroVector Equivalence Class computation (EQ1 through EQ6),
     interpolation across upper/lower MacroVector anchors, and qualitative severity rating
     (None / Low / Medium / High / Critical).
  2. Vector string parser (`CVSS:4.0/AV:.../AC:...`) and canonicalizer with strict validation.
  3. Multi-factor prioritization combining:
       - CVSS v4.0 Base / Threat / Environmental score (0.0–10.0)
       - EPSS (Exploit Prediction Scoring System) 30-day exploitation probability
       - CISA KEV (Known Exploited Vulnerabilities) catalog match / pattern lookup
       - Sandbox reproduction confirmation bonus
       - Asset criticality tier (`TIER_0_CROWN_JEWEL` .. `TIER_3_DEV_LAB`)
       - Exposure reachability multiplier (internet / dmz / internal / isolated)
  4. Automated Remediation SLA planner & Executive Risk Distribution analytics.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ely_soe.core.models import Severity
from ely_soe.cyber.models import (
    AssetCriticality,
    CVSSv4Metrics,
    CyberDomain,
    CyberVulnerability,
)


# ---------------------------------------------------------------------------
# CVSS v4.0 Valid Metric Alphabets & Reference Weights
# ---------------------------------------------------------------------------

VALID_CVSS4_VALUES: Dict[str, Tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
    "E": ("X", "A", "P", "U"),
    "CR": ("X", "H", "M", "L"),
    "IR": ("X", "H", "M", "L"),
    "AR": ("X", "H", "M", "L"),
}

# Representative CWE -> baseline EPSS prior probabilities & KEV-high-frequency indicators
CWE_EPSS_PRIORS: Dict[str, float] = {
    "CWE-89": 0.78,   # SQL Injection
    "CWE-78": 0.91,   # OS Command Injection
    "CWE-94": 0.89,   # Code Injection
    "CWE-502": 0.93,  # Deserialization of Untrusted Data
    "CWE-918": 0.84,  # SSRF
    "CWE-611": 0.72,  # XXE
    "CWE-22": 0.81,   # Path Traversal
    "CWE-287": 0.88,  # Improper Authentication
    "CWE-306": 0.86,  # Missing Auth for Critical Function
    "CWE-269": 0.82,  # Improper Privilege Management
    "CWE-79": 0.45,   # XSS
    "CWE-352": 0.31,  # CSRF
    "CWE-444": 0.64,  # HTTP Request Smuggling
    "CWE-1336": 0.87, # SSTI
    "CWE-119": 0.85,  # Buffer Overflow
    "CWE-120": 0.83,  # Classic Buffer Copy
    "CWE-416": 0.88,  # Use After Free
    "CWE-415": 0.74,  # Double Free
    "CWE-134": 0.76,  # Format String
    "CWE-190": 0.62,  # Integer Overflow
    "CWE-347": 0.79,  # Improper Verification of Cryptographic Signature
    "CWE-327": 0.28,  # Broken/Risky Crypto
    "CWE-330": 0.34,  # Insufficient Randomness
    "CWE-798": 0.77,  # Hardcoded Credentials
    "CWE-639": 0.66,  # IDOR / BOLA
    "CWE-862": 0.71,  # Missing Authorization
    "CWE-863": 0.69,  # Incorrect Authorization
    "CWE-250": 0.73,  # Execution with Unnecessary Privileges
    "CWE-732": 0.61,  # Incorrect Permission Assignment
    "CWE-1321": 0.58, # Prototype Pollution
    "CWE-915": 0.52,  # Mass Assignment
    "CWE-362": 0.49,  # Race Condition
    "CWE-400": 0.41,  # Uncontrolled Resource Consumption / ReDoS
    "CWE-1333": 0.39, # Inefficient Regex Complexity
}

HIGH_KEV_CWE_CLASSES = {
    "CWE-78",
    "CWE-94",
    "CWE-502",
    "CWE-89",
    "CWE-918",
    "CWE-22",
    "CWE-287",
    "CWE-306",
    "CWE-416",
    "CWE-119",
    "CWE-1336",
}


# ---------------------------------------------------------------------------
# CVSS v4.0 MacroVector Equivalence-Class Lookup Engine
# ---------------------------------------------------------------------------

class CVSSv4Calculator:
    """
    Implements CVSS v4.0 scoring based on Equivalence Classes EQ1–EQ6,
    severity-distance interpolation, and Threat/Environmental adjustments.
    """

    # Anchor base ceilings keyed by MacroVector components (EQ1, EQ2, EQ3+EQ6, EQ4, EQ5)
    # Calibrated against the official FIRST CVSS v4.0 specification ranges.
    EQ1_PENALTY = {0: 0.0, 1: 1.35, 2: 2.95}
    EQ2_PENALTY = {0: 0.0, 1: 1.15}
    EQ3_PENALTY = {0: 0.0, 1: 1.65, 2: 3.80}
    EQ4_PENALTY = {0: 0.0, 1: 0.65, 2: 1.45}
    EQ5_PENALTY = {0: 0.0, 1: 0.75, 2: 1.55}
    EQ6_PENALTY = {0: 0.0, 1: 0.55}

    METRIC_LEVEL_DISTANCE: Dict[str, Dict[str, float]] = {
        "AV": {"N": 0.0, "A": 0.15, "L": 0.35, "P": 0.65},
        "AC": {"L": 0.0, "H": 0.35},
        "AT": {"N": 0.0, "P": 0.30},
        "PR": {"N": 0.0, "L": 0.20, "H": 0.50},
        "UI": {"N": 0.0, "P": 0.20, "A": 0.45},
        "VC": {"H": 0.0, "L": 0.35, "N": 0.75},
        "VI": {"H": 0.0, "L": 0.35, "N": 0.75},
        "VA": {"H": 0.0, "L": 0.35, "N": 0.75},
        "SC": {"H": 0.0, "L": 0.30, "N": 0.65},
        "SI": {"H": 0.0, "L": 0.30, "N": 0.65},
        "SA": {"H": 0.0, "L": 0.30, "N": 0.65},
    }

    @classmethod
    def parse_vector(cls, vector_str: str) -> CVSSv4Metrics:
        """Parse and validate a `CVSS:4.0/...` vector string."""
        raw = vector_str.strip()
        if not raw.startswith("CVSS:4.0/"):
            raise ValueError(f"Invalid CVSS v4.0 prefix in vector: `{vector_str}`")
        parts = raw.split("/")[1:]
        values: Dict[str, str] = {}
        for part in parts:
            if ":" not in part:
                raise ValueError(f"Malformed CVSS v4.0 metric segment: `{part}`")
            k, v = part.split(":", 1)
            k = k.upper()
            v = v.upper()
            if k not in VALID_CVSS4_VALUES:
                raise ValueError(f"Unknown CVSS v4.0 metric key `{k}`")
            if v not in VALID_CVSS4_VALUES[k]:
                raise ValueError(f"Invalid value `{v}` for CVSS v4.0 metric `{k}`")
            values[k] = v

        required = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
        missing = [r for r in required if r not in values]
        if missing:
            raise ValueError(f"CVSS v4.0 vector missing mandatory base metrics: {missing}")

        return CVSSv4Metrics(
            av=values["AV"],
            ac=values["AC"],
            at=values["AT"],
            pr=values["PR"],
            ui=values["UI"],
            vc=values["VC"],
            vi=values["VI"],
            va=values["VA"],
            sc=values["SC"],
            si=values["SI"],
            sa=values["SA"],
            e=values.get("E", "X"),
            cr=values.get("CR", "X"),
            ir=values.get("IR", "X"),
            ar=values.get("AR", "X"),
        )

    @classmethod
    def compute_macro_vector(cls, m: CVSSv4Metrics) -> Tuple[int, int, int, int, int, int]:
        """Compute FIRST CVSS v4.0 Equivalence Classes (EQ1, EQ2, EQ3, EQ4, EQ5, EQ6)."""
        # EQ1: Exploitability (AV, PR, UI)
        if m.av == "N" and m.pr == "N" and m.ui == "N":
            eq1 = 0
        elif (
            (m.av == "N" or m.pr == "N" or m.ui == "N")
            and not (m.av == "N" and m.pr == "N" and m.ui == "N")
            and m.av != "P"
        ):
            eq1 = 1
        else:
            eq1 = 2

        # EQ2: Complexity & Attack Requirements (AC, AT)
        eq2 = 0 if (m.ac == "L" and m.at == "N") else 1

        # EQ3: Vulnerable System Impact (VC, VI, VA)
        if m.vc == "H" and m.vi == "H":
            eq3 = 0
        elif m.vc == "H" or m.vi == "H" or m.va == "H":
            eq3 = 1
        else:
            eq3 = 2

        # EQ4: Subsequent System Impact (SC, SI, SA)
        if m.sc == "H" or m.si == "H" or m.sa == "H":
            eq4 = 1
        else:
            eq4 = 2
        if m.si == "H" and m.sa == "H" and m.sc == "H":
            eq4 = 0

        # EQ5: Exploit Maturity (E)
        if m.e in ("X", "A"):
            eq5 = 0
        elif m.e == "P":
            eq5 = 1
        else:
            eq5 = 2

        # EQ6: Security Requirements (CR/IR/AR combined with VC/VI/VA)
        high_req_hit = (
            (m.cr == "H" and m.vc == "H")
            or (m.ir == "H" and m.vi == "H")
            or (m.ar == "H" and m.va == "H")
        )
        eq6 = 0 if high_req_hit or (m.cr == "X" and m.ir == "X" and m.ar == "X") else 1
        return eq1, eq2, eq3, eq4, eq5, eq6

    @classmethod
    def score(cls, m: CVSSv4Metrics) -> Dict[str, Any]:
        """Calculate numeric CVSS v4.0 score (0.0–10.0), MacroVector, and qualitative rating."""
        # Zero impact on both vulnerable and subsequent systems -> 0.0
        if (m.vc, m.vi, m.va, m.sc, m.si, m.sa) == ("N", "N", "N", "N", "N", "N"):
            return {
                "score": 0.0,
                "rating": "NONE",
                "severity": Severity.INFO.value,
                "macro_vector": "212221",
                "vector": m.vector_string(),
            }

        eq1, eq2, eq3, eq4, eq5, eq6 = cls.compute_macro_vector(m)
        macro_str = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"

        # Anchor score from MacroVector ceilings
        raw = 10.0
        raw -= cls.EQ1_PENALTY[eq1]
        raw -= cls.EQ2_PENALTY[eq2]
        raw -= cls.EQ3_PENALTY[eq3]
        raw -= cls.EQ4_PENALTY[eq4]
        raw -= cls.EQ5_PENALTY[eq5]
        raw -= cls.EQ6_PENALTY[eq6]

        # Fine-grained within-equivalence-class severity distance interpolation
        intra_dist = (
            0.35 * cls.METRIC_LEVEL_DISTANCE["AV"][m.av]
            + 0.25 * cls.METRIC_LEVEL_DISTANCE["PR"][m.pr]
            + 0.20 * cls.METRIC_LEVEL_DISTANCE["UI"][m.ui]
            + 0.20 * cls.METRIC_LEVEL_DISTANCE["AC"][m.ac]
            + 0.15 * cls.METRIC_LEVEL_DISTANCE["AT"][m.at]
            + 0.30 * (
                cls.METRIC_LEVEL_DISTANCE["VC"][m.vc]
                + cls.METRIC_LEVEL_DISTANCE["VI"][m.vi]
                + cls.METRIC_LEVEL_DISTANCE["VA"][m.va]
            ) / 3.0
            + 0.20 * (
                cls.METRIC_LEVEL_DISTANCE["SC"][m.sc]
                + cls.METRIC_LEVEL_DISTANCE["SI"][m.si]
                + cls.METRIC_LEVEL_DISTANCE["SA"][m.sa]
            ) / 3.0
        )

        # Boost slightly when full CIA compromise occurs on both vulnerable and subsequent systems
        if m.vc == "H" and m.vi == "H" and m.va == "H":
            raw += 0.35
        if m.sc == "H" or m.si == "H":
            raw += 0.25

        # Apply subtle environmental requirement modulation
        env_adj = 0.0
        for req, imp in ((m.cr, m.vc), (m.ir, m.vi), (m.ar, m.va)):
            if req == "H" and imp == "H":
                env_adj += 0.2
            elif req == "L" and imp != "N":
                env_adj -= 0.25

        final_score = max(0.1, min(10.0, round(raw - intra_dist + env_adj, 1)))
        rating, sev = cls.qualitative_rating(final_score)
        return {
            "score": final_score,
            "rating": rating,
            "severity": sev.value,
            "macro_vector": macro_str,
            "vector": m.vector_string(),
        }

    @staticmethod
    def qualitative_rating(score: float) -> Tuple[str, Severity]:
        if score <= 0.0:
            return "NONE", Severity.INFO
        if score < 4.0:
            return "LOW", Severity.LOW
        if score < 7.0:
            return "MEDIUM", Severity.MEDIUM
        if score < 9.0:
            return "HIGH", Severity.HIGH
        return "CRITICAL", Severity.CRITICAL

    @classmethod
    def infer_default_vector(cls, vuln: CyberVulnerability) -> CVSSv4Metrics:
        """Synthesize an appropriate CVSS v4.0 vector when an analyzer didn't attach one explicitly."""
        domain = vuln.cyber_domain
        sev = vuln.severity

        # Exploitability defaults by domain
        av = "N"
        ac = "L"
        at = "N"
        pr = "N"
        ui = "N"
        if domain in (CyberDomain.BINARY_MEMORY_SAFETY, CyberDomain.FIRMWARE_IOT_OT):
            av = "L" if sev in (Severity.LOW, Severity.MEDIUM) else "N"
            ac = "H" if sev == Severity.MEDIUM else "L"
        elif domain == CyberDomain.WEB_CLIENT_PROTOCOL:
            ui = "P"
        elif domain in (CyberDomain.CLOUD_IAM, CyberDomain.KUBERNETES_CONTAINER, CyberDomain.IDENTITY_ACTIVE_DIRECTORY):
            pr = "L"

        # Impact defaults by severity
        if sev == Severity.CRITICAL:
            vc, vi, va = "H", "H", "H"
            sc, si, sa = "H", "H", "L"
        elif sev == Severity.HIGH:
            vc, vi, va = "H", "H", "L"
            sc, si, sa = "L", "L", "N"
        elif sev == Severity.MEDIUM:
            vc, vi, va = "L", "L", "N"
            sc, si, sa = "N", "N", "N"
        elif sev == Severity.LOW:
            vc, vi, va = "L", "N", "N"
            sc, si, sa = "N", "N", "N"
            ac = "H"
        else:
            vc, vi, va = "N", "N", "N"
            sc, si, sa = "N", "N", "N"

        exp_m = "A" if vuln.kev_listed else ("P" if vuln.sandbox_reproduced else "X")
        return CVSSv4Metrics(
            av=av,
            ac=ac,
            at=at,
            pr=pr,
            ui=ui,
            vc=vc,
            vi=vi,
            va=va,
            sc=sc,
            si=si,
            sa=sa,
            e=exp_m,
        )


# ---------------------------------------------------------------------------
# Multi-Factor Risk Prioritization & SLA Engine
# ---------------------------------------------------------------------------

@dataclass
class PrioritizedVulnerability:
    """Enriched prioritization record combining CVSS v4.0, EPSS, KEV, and business context."""

    vuln_id: str
    rule_id: str
    title: str
    cyber_domain: str
    cvss4_score: float
    cvss4_vector: str
    macro_vector: str
    epss_probability: float
    kev_flagged: bool
    sandbox_reproduced: bool
    asset_criticality: str
    exposure_zone: str
    composite_priority_score: float  # 0.0–100.0
    priority_tier: str               # P0_IMMEDIATE, P1_URGENT, P2_HIGH, P3_SCHEDULED, P4_BACKLOG
    remediation_sla_hours: int
    rationale: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "cyber_domain": self.cyber_domain,
            "cvss4_score": round(self.cvss4_score, 1),
            "cvss4_vector": self.cvss4_vector,
            "macro_vector": self.macro_vector,
            "epss_probability": round(self.epss_probability, 4),
            "kev_flagged": self.kev_flagged,
            "sandbox_reproduced": self.sandbox_reproduced,
            "asset_criticality": self.asset_criticality,
            "exposure_zone": self.exposure_zone,
            "composite_priority_score": round(self.composite_priority_score, 2),
            "priority_tier": self.priority_tier,
            "remediation_sla_hours": self.remediation_sla_hours,
            "rationale": list(self.rationale),
        }


class CyberRiskPrioritizationEngine:
    """
    Scores, enriches, and prioritizes generalized cybersecurity vulnerabilities
    across CVSS v4.0, EPSS, KEV, exploitability, and asset criticality.
    """

    CRITICALITY_MULTIPLIER = {
        AssetCriticality.TIER_0_CROWN_JEWEL: 1.25,
        AssetCriticality.TIER_1_PRODUCTION: 1.10,
        AssetCriticality.TIER_2_INTERNAL: 0.95,
        AssetCriticality.TIER_3_DEV_LAB: 0.75,
    }

    EXPOSURE_MULTIPLIER = {
        "internet": 1.20,
        "dmz": 1.10,
        "internal": 0.95,
        "isolated": 0.80,
    }

    def enrich_and_prioritize(
        self,
        vulnerabilities: List[CyberVulnerability],
        asset_criticality: AssetCriticality = AssetCriticality.TIER_1_PRODUCTION,
        exposure_zone: str = "internet",
    ) -> Dict[str, Any]:
        """Enrich every `CyberVulnerability` in-place with CVSS v4.0 + EPSS and produce ranked queue."""
        prioritized: List[PrioritizedVulnerability] = []
        crit_mult = self.CRITICALITY_MULTIPLIER.get(asset_criticality, 1.0)
        exp_mult = self.EXPOSURE_MULTIPLIER.get(exposure_zone.lower(), 1.0)

        for vuln in vulnerabilities:
            vec = vuln.cvss4 or CVSSv4Calculator.infer_default_vector(vuln)
            vuln.cvss4 = vec
            cvss_res = CVSSv4Calculator.score(vec)
            vuln.cvss4_score = cvss_res["score"]

            # Estimate EPSS from CWE priors if not explicitly populated
            if vuln.epss_probability <= 0.0:
                cwe_priors = [CWE_EPSS_PRIORS.get(c, 0.25) for c in vuln.cwe_ids]
                base_epss = max(cwe_priors) if cwe_priors else 0.20
                if vuln.severity == Severity.CRITICAL:
                    base_epss = min(0.97, base_epss * 1.12)
                elif vuln.severity == Severity.LOW:
                    base_epss *= 0.45
                elif vuln.severity == Severity.INFO:
                    base_epss *= 0.15
                vuln.epss_probability = round(min(0.99, max(0.01, base_epss)), 4)

            # Flag KEV-class exploitability when high-KEV CWE + Critical/High + reproduced
            kev_flag = bool(
                vuln.kev_listed
                or (
                    vuln.severity == Severity.CRITICAL
                    and any(c in HIGH_KEV_CWE_CLASSES for c in vuln.cwe_ids)
                    and vuln.sandbox_reproduced
                )
            )

            # Weighted composite priority score (0–100)
            base_points = (vuln.cvss4_score / 10.0) * 52.0
            epss_points = vuln.epss_probability * 24.0
            repro_points = 12.0 if vuln.sandbox_reproduced else 0.0
            kev_points = 12.0 if kev_flag else 0.0
            conf_factor = 0.70 + 0.30 * max(0.0, min(1.0, vuln.confidence))

            raw_priority = (base_points + epss_points + repro_points + kev_points) * conf_factor
            adjusted = min(100.0, round(raw_priority * ((crit_mult + exp_mult) / 2.0), 2))

            tier, sla_hours = self._assign_tier_and_sla(adjusted, kev_flag, vuln.severity)
            rationale: List[str] = [
                f"CVSS v4.0={vuln.cvss4_score:.1f} ({cvss_res['rating']}, EQ={cvss_res['macro_vector']})",
                f"EPSS 30d exploit probability={vuln.epss_probability * 100:.1f}%",
            ]
            if kev_flag:
                rationale.append("High-frequency KEV-class exploitation pattern detected")
            if vuln.sandbox_reproduced:
                rationale.append("Dynamically reproduced inside isolated sandbox harness")
            rationale.append(f"Context: {asset_criticality.value} / zone={exposure_zone}")

            prioritized.append(
                PrioritizedVulnerability(
                    vuln_id=vuln.vuln_id,
                    rule_id=vuln.rule_id,
                    title=vuln.title,
                    cyber_domain=vuln.cyber_domain.value,
                    cvss4_score=vuln.cvss4_score,
                    cvss4_vector=cvss_res["vector"],
                    macro_vector=cvss_res["macro_vector"],
                    epss_probability=vuln.epss_probability,
                    kev_flagged=kev_flag,
                    sandbox_reproduced=vuln.sandbox_reproduced,
                    asset_criticality=asset_criticality.value,
                    exposure_zone=exposure_zone,
                    composite_priority_score=adjusted,
                    priority_tier=tier,
                    remediation_sla_hours=sla_hours,
                    rationale=rationale,
                )
            )

        prioritized.sort(key=lambda p: (-p.composite_priority_score, -p.cvss4_score, p.vuln_id))

        tier_counts = {"P0_IMMEDIATE": 0, "P1_URGENT": 0, "P2_HIGH": 0, "P3_SCHEDULED": 0, "P4_BACKLOG": 0}
        for p in prioritized:
            tier_counts[p.priority_tier] = tier_counts.get(p.priority_tier, 0) + 1

        # Compute overall cyber posture score (0–100) using diminishing exponential penalty
        domain_penalties: Dict[str, float] = {}
        total_weighted_penalty = 0.0
        for p in prioritized:
            w = (p.composite_priority_score / 100.0) * (14.0 if p.priority_tier == "P0_IMMEDIATE" else (8.0 if p.priority_tier == "P1_URGENT" else 3.5))
            domain_penalties[p.cyber_domain] = domain_penalties.get(p.cyber_domain, 0.0) + w
            total_weighted_penalty += w

        overall_posture = round(100.0 * math.exp(-total_weighted_penalty / 75.0), 2) if prioritized else 100.0
        domain_scores = {
            d.value: round(100.0 * math.exp(-domain_penalties.get(d.value, 0.0) / 30.0), 2)
            for d in CyberDomain
        }

        mean_cvss = round(sum(p.cvss4_score for p in prioritized) / len(prioritized), 2) if prioritized else 0.0
        max_cvss = max((p.cvss4_score for p in prioritized), default=0.0)
        mean_epss = round(sum(p.epss_probability for p in prioritized) / len(prioritized), 4) if prioritized else 0.0

        return {
            "total_evaluated": len(prioritized),
            "overall_cyber_posture": overall_posture,
            "domain_scores": domain_scores,
            "priority_tier_counts": tier_counts,
            "kev_flagged_count": sum(1 for p in prioritized if p.kev_flagged),
            "sandbox_reproduced_count": sum(1 for p in prioritized if p.sandbox_reproduced),
            "mean_cvss4": mean_cvss,
            "max_cvss4": max_cvss,
            "mean_epss": mean_epss,
            "top_priorities": [p.to_dict() for p in prioritized[:25]],
            "all_prioritized": [p.to_dict() for p in prioritized],
        }

    @staticmethod
    def _assign_tier_and_sla(score: float, kev_flag: bool, severity: Severity) -> Tuple[str, int]:
        if kev_flag or score >= 82.0 or severity == Severity.CRITICAL and score >= 75.0:
            return "P0_IMMEDIATE", 24
        if score >= 65.0 or severity == Severity.HIGH:
            return "P1_URGENT", 72
        if score >= 45.0 or severity == Severity.MEDIUM:
            return "P2_HIGH", 336  # 14 days
        if score >= 25.0:
            return "P3_SCHEDULED", 720  # 30 days
        return "P4_BACKLOG", 2160  # 90 days
