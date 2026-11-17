"""
Frontier Research Module 7: MITRE ATLAS, OWASP Agentic Top 10, NIST AI RMF & EU AI Act Mapper.

Translates raw ELY Security Lab findings & maturity attestations into executive
compliance intelligence and industry-standard threat-intelligence interchange formats:
  1. OWASP Top 10 for Agentic AI (ASI01–ASI10) Coverage & Exposure Matrix
  2. MITRE ATLAS Navigator JSON Layer Export (compatible with MITRE ATT&CK / ATLAS Navigator!)
  3. NIST AI RMF (Govern / Map / Measure / Manage) Security Control Alignment
  4. EU AI Act Article 15 (Accuracy, Robustness & Cybersecurity for High-Risk AI) Readiness
  5. Executive Risk Forecast & Remediation ROI Summary
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ely_soe.core.models import (
    Finding,
    FindingStatus,
    MaturityAssessment,
    SecurityDomain,
    SecurityEvaluationReport,
    Severity,
    utc_now_iso,
)
from ely_soe.core.scoring import OWASP_AGENTIC_DESCRIPTIONS


MITRE_ATLAS_CATALOG: Dict[str, Dict[str, str]] = {
    "AML.T0010": {"name": "ML Supply Chain Compromise", "tactic": "Initial Access"},
    "AML.T0018": {"name": "Backdoor ML / Agent Skill Artifact", "tactic": "Persistence"},
    "AML.T0020": {"name": "Poison Training / Long-Term Memory Data", "tactic": "Persistence"},
    "AML.T0024": {"name": "Exfiltration via Cyber / Agent Means", "tactic": "Exfiltration"},
    "AML.T0040": {"name": "AI Model / Agent API Inference & Auth Abuse", "tactic": "Initial Access"},
    "AML.T0044": {"name": "Full API Access & Denial of Service", "tactic": "Impact"},
    "AML.T0048": {"name": "Societal / Cross-Tenant External Harms", "tactic": "Impact"},
    "AML.T0051": {"name": "LLM Prompt Injection", "tactic": "Execution"},
    "AML.T0051.000": {"name": "Direct Prompt Injection", "tactic": "Execution"},
    "AML.T0051.001": {"name": "Indirect Prompt Injection", "tactic": "Initial Access"},
    "AML.T0053": {"name": "LLM Plugin / Tool Execution Compromise", "tactic": "Execution"},
    "AML.T0054": {"name": "Agent Sandbox / Boundary Jailbreak", "tactic": "Privilege Escalation"},
}

NIST_AI_RMF_CONTROLS: List[Dict[str, Any]] = [
    {
        "control_id": "GOVERN-1.2",
        "function": "GOVERN",
        "title": "Trustworthy AI Security Governance & Separation of Duties",
        "mapped_domains": [SecurityDomain.AGENT_ISOLATION, SecurityDomain.SUPPLY_CHAIN],
        "mapped_criteria": ["independent_audit", "granular_permissions"],
    },
    {
        "control_id": "MAP-3.4",
        "function": "MAP",
        "title": "Attack Surface & Multi-Agent Trust Boundary Identification",
        "mapped_domains": [SecurityDomain.AGENT_ISOLATION, SecurityDomain.API_SECURITY, SecurityDomain.NETWORK],
        "mapped_criteria": ["agent_isolation", "dependency_audit"],
    },
    {
        "control_id": "MEASURE-2.7",
        "function": "MEASURE",
        "title": "Continuous Red-Teaming, Fuzzing & Adversarial Robustness Evaluation",
        "mapped_domains": [SecurityDomain.PROMPT_INJECTION, SecurityDomain.TOOL_EXECUTION, SecurityDomain.RUST_CORE],
        "mapped_criteria": ["automated_adversarial_testing", "prompt_injection_defense", "io_validation"],
    },
    {
        "control_id": "MANAGE-4.1",
        "function": "MANAGE",
        "title": "Post-Compromise Incident Containment, Memory Rollback & Recovery",
        "mapped_domains": [SecurityDomain.MEMORY, SecurityDomain.FILESYSTEM, SecurityDomain.PROCESS_MANAGEMENT],
        "mapped_criteria": ["memory_security", "compromise_recovery"],
    },
]

EU_AI_ACT_ART15_CHECKS: List[Dict[str, Any]] = [
    {
        "article": "Art. 15(4) — Robustness against Errors & Faults",
        "domains": [SecurityDomain.RUST_CORE, SecurityDomain.PROCESS_MANAGEMENT, SecurityDomain.FILESYSTEM],
        "criterion": "io_validation",
    },
    {
        "article": "Art. 15(5) — Resilience Against Adversarial Manipulation & Poisoning",
        "domains": [SecurityDomain.PROMPT_INJECTION, SecurityDomain.MEMORY, SecurityDomain.AGENT_ISOLATION],
        "criterion": "prompt_injection_defense",
    },
    {
        "article": "Art. 15(5) — Protection Against Unauthorized Third-Party Alteration",
        "domains": [SecurityDomain.SUPPLY_CHAIN, SecurityDomain.API_SECURITY, SecurityDomain.NETWORK],
        "criterion": "independent_audit",
    },
]


class ThreatIntelComplianceMapper:
    """Produces OWASP Agentic, MITRE ATLAS Navigator, NIST AI RMF & EU AI Act mappings."""

    def build_compliance_package(
        self,
        report: SecurityEvaluationReport,
    ) -> Dict[str, Any]:
        confirmed = report.confirmed_findings
        owasp = self._map_owasp_agentic(confirmed)
        atlas_layer = self.build_atlas_navigator_layer(report)
        nist = self._map_nist_ai_rmf(confirmed, report.maturity)
        eu_ai = self._map_eu_ai_act(confirmed, report.maturity)

        return {
            "generated_at": utc_now_iso(),
            "report_id": report.report_id,
            "target_version": report.target_version,
            "owasp_agentic_top_10": owasp,
            "mitre_atlas_navigator_layer": atlas_layer,
            "nist_ai_rmf_alignment": nist,
            "eu_ai_act_art15_readiness": eu_ai,
        }

    def build_atlas_navigator_layer(self, report: SecurityEvaluationReport) -> Dict[str, Any]:
        """Export MITRE ATLAS Navigator v4.5 compatible layer JSON."""
        counts: Dict[str, List[Finding]] = {}
        for f in report.confirmed_findings:
            for tid in f.mitre_atlas_ids:
                counts.setdefault(tid, []).append(f)

        techniques: List[Dict[str, Any]] = []
        for tid, info in sorted(MITRE_ATLAS_CATALOG.items()):
            hits = counts.get(tid, [])
            max_sev = max((h.severity.rank for h in hits), default=0)
            color = "#22c55e" if not hits else ("#ef4444" if max_sev >= 5 else ("#f97316" if max_sev == 4 else "#eab308"))
            techniques.append(
                {
                    "techniqueID": tid,
                    "techniqueName": info["name"],
                    "tactic": info["tactic"],
                    "score": len(hits),
                    "color": color,
                    "comment": ", ".join(f"{h.rule_id}({h.severity.value})" for h in hits[:4]) if hits else "No confirmed exposure",
                    "enabled": True,
                }
            )

        return {
            "name": f"ELY Security Lab — {report.target_name}@{report.target_version}",
            "versions": {"navigator": "4.9.1", "layer": "4.5"},
            "domain": "mitre-atlas",
            "description": f"Confirmed adversarial threat exposure from SOE run {report.run_id}",
            "techniques": techniques,
        }

    def _map_owasp_agentic(self, confirmed: List[Finding]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for code, title in sorted(OWASP_AGENTIC_DESCRIPTIONS.items()):
            hits = [f for f in confirmed if code in f.owasp_agentic_ids]
            max_cvss = max((f.cvss_score for f in hits), default=0.0)
            rows.append(
                {
                    "code": code,
                    "title": title,
                    "confirmed_findings": len(hits),
                    "max_cvss": max_cvss,
                    "status": "COMPLIANT" if not hits else ("AT_RISK" if max_cvss < 7.0 else "NON_COMPLIANT"),
                    "finding_ids": [f.finding_id for f in hits[:6]],
                }
            )
        return rows

    def _map_nist_ai_rmf(
        self, confirmed: List[Finding], maturity: Optional[MaturityAssessment]
    ) -> List[Dict[str, Any]]:
        crit_by_id = {c.criterion_id.value: c for c in maturity.criteria} if maturity else {}
        out: List[Dict[str, Any]] = []
        for ctrl in NIST_AI_RMF_CONTROLS:
            dom_hits = [
                f for f in confirmed if f.domain in ctrl["mapped_domains"] and f.severity in (Severity.CRITICAL, Severity.HIGH)
            ]
            crit_passed = all(
                crit_by_id[cid].passed for cid in ctrl["mapped_criteria"] if cid in crit_by_id
            ) if crit_by_id else (len(dom_hits) == 0)
            aligned = len(dom_hits) == 0 and crit_passed
            out.append(
                {
                    "control_id": ctrl["control_id"],
                    "function": ctrl["function"],
                    "title": ctrl["title"],
                    "aligned": aligned,
                    "high_crit_findings": len(dom_hits),
                    "status": "ALIGNED" if aligned else "GAP_DETECTED",
                }
            )
        return out

    def _map_eu_ai_act(
        self, confirmed: List[Finding], maturity: Optional[MaturityAssessment]
    ) -> Dict[str, Any]:
        crit_by_id = {c.criterion_id.value: c for c in maturity.criteria} if maturity else {}
        checks: List[Dict[str, Any]] = []
        passed_n = 0
        for spec in EU_AI_ACT_ART15_CHECKS:
            hits = [f for f in confirmed if f.domain in spec["domains"] and f.severity in (Severity.CRITICAL, Severity.HIGH)]
            c_ok = crit_by_id[spec["criterion"]].passed if spec["criterion"] in crit_by_id else (len(hits) == 0)
            ok = len(hits) == 0 and c_ok
            if ok:
                passed_n += 1
            checks.append(
                {
                    "article": spec["article"],
                    "ready": ok,
                    "blocking_findings": len(hits),
                }
            )
        readiness_pct = round((passed_n / float(len(EU_AI_ACT_ART15_CHECKS))) * 100.0, 1)
        return {
            "readiness_pct": readiness_pct,
            "ready_for_high_risk_deployment": passed_n == len(EU_AI_ACT_ART15_CHECKS),
            "checks": checks,
        }

    def export_atlas_json(self, report: SecurityEvaluationReport) -> str:
        return json.dumps(self.build_atlas_navigator_layer(report), indent=2)
