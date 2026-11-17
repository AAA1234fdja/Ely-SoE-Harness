"""
Threat Intelligence STIX 2.1 Bundle Builder, Diamond Model Analyzer,
MITRE ATT&CK Navigator Layer v4.5 Exporter & Adversary TTP Matcher.

Operationalizes ELY Cyber & Harness² assessment outputs into standardized CTI artifacts:
  - Generates spec-compliant **STIX 2.1 JSON Bundles** (`identity`, `vulnerability`,
    `attack-pattern`, `indicator`, `course-of-action`, `relationship` SDOs/SROs).
  - Exports **MITRE ATT&CK Navigator v4.5 JSON Layers** colored by observed finding severity
    and kill-chain criticality for immediate SOC / Red-Blue team visualization.
  - Evaluates **Diamond Model of Intrusion Analysis** tuples (`Adversary`, `Capability`,
    `Infrastructure`, `Victim`) across detected vulnerabilities and exploit chains.
  - Matches observed MITRE ATT&CK technique sets against known adversary TTP profiles
    via Jaccard + weighted-overlap similarity for threat-informed prioritization.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import Severity, utc_now_iso
from ely_soe.cyber.models import CyberVulnerability, GeneralizedExploitChain


@dataclass(frozen=True)
class AdversaryProfile:
    actor_id: str
    name: str
    aliases: Tuple[str, ...]
    motivation: str
    target_sectors: Tuple[str, ...]
    techniques: Tuple[str, ...]


ADVERSARY_TTP_CATALOG: Tuple[AdversaryProfile, ...] = (
    AdversaryProfile(
        "INTRUSION-SET-CLOUD-VIPER", "CloudViper (Synthetic Threat Profile)", ("UNC-CV01",),
        "cloud_credential_theft_and_exfiltration", ("saas", "fintech", "ai_infrastructure"),
        ("T1190", "T1552.005", "T1078.004", "T1530", "T1098", "T1528"),
    ),
    AdversaryProfile(
        "INTRUSION-SET-SUPPLY-FORGE", "SupplyForge (Synthetic Threat Profile)", ("UNC-SF02",),
        "ci_cd_pipeline_poisoning", ("software", "open_source", "defense"),
        ("T1195.002", "T1552.001", "T1059", "T1610", "T1078", "T1525"),
    ),
    AdversaryProfile(
        "INTRUSION-SET-K8S-PHANTOM", "K8sPhantom (Synthetic Threat Profile)", ("UNC-KP03",),
        "container_escape_and_cryptojacking", ("cloud_native", "ml_ops", "telecom"),
        ("T1611", "T1609", "T1613", "T1552.007", "T1068", "T1496"),
    ),
    AdversaryProfile(
        "INTRUSION-SET-AD-SPECTER", "ADSpecter (Synthetic Threat Profile)", ("UNC-AS04",),
        "enterprise_domain_dominance_ransomware", ("enterprise", "healthcare", "finance"),
        ("T1558.003", "T1649", "T1550.002", "T1003.006", "T1484.001", "T1486"),
    ),
    AdversaryProfile(
        "INTRUSION-SET-AI-MIRAGE", "AIMirage (Synthetic Threat Profile)", ("UNC-AM05",),
        "agentic_llm_hijacking_and_data_exfil", ("ai_labs", "enterprise_copilot"),
        ("T1190", "T1059", "T1567", "T1552", "T1041", "T1204"),
    ),
)


def _deterministic_stix_id(stix_type: str, seed: str) -> str:
    digest = hashlib.sha256(f"ely-stix:{stix_type}:{seed}".encode("utf-8")).hexdigest()
    return f"{stix_type}--{uuid.UUID(digest[:32])}"


class ThreatIntelSTIXEngine:
    """Builds STIX 2.1 bundles, ATT&CK Navigator v4.5 layers, Diamond Models, and TTP overlaps."""

    def build_stix_2_1_bundle(
        self,
        vulns: Sequence[CyberVulnerability],
        chains: Sequence[GeneralizedExploitChain] = (),
        target_name: str = "ELY-Specimen",
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        objects: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()

        def _add(obj: Dict[str, Any]) -> None:
            if obj["id"] not in seen_ids:
                seen_ids.add(obj["id"])
                objects.append(obj)

        producer_id = _deterministic_stix_id("identity", "ELY-Security-Lab-SOE")
        _add({
            "type": "identity",
            "spec_version": "2.1",
            "id": producer_id,
            "created": now,
            "modified": now,
            "name": "ELY Security Lab & Harness² Intelligence Producer",
            "identity_class": "system",
        })

        for v in vulns:
            vid = _deterministic_stix_id("vulnerability", f"{v.rule_id}:{v.vuln_id}")
            _add({
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": vid,
                "created": now,
                "modified": now,
                "created_by_ref": producer_id,
                "name": v.title,
                "description": v.description,
                "external_references": [
                    {"source_name": "cwe", "external_id": cwe} for cwe in v.cwe_ids
                ] + [{"source_name": "ely_rule", "external_id": v.rule_id}],
                "x_ely_severity": v.severity.value,
                "x_ely_cvss4_score": v.cvss4_score,
                "x_ely_target": target_name,
            })

            coa_id = _deterministic_stix_id("course-of-action", f"coa:{v.rule_id}")
            _add({
                "type": "course-of-action",
                "spec_version": "2.1",
                "id": coa_id,
                "created": now,
                "modified": now,
                "created_by_ref": producer_id,
                "name": f"Mitigate {v.rule_id}",
                "description": v.remediation_guidance,
            })
            _add({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _deterministic_stix_id("relationship", f"{coa_id}:mitigates:{vid}"),
                "created": now,
                "modified": now,
                "relationship_type": "mitigates",
                "source_ref": coa_id,
                "target_ref": vid,
            })

            for m in v.mitre_techniques:
                ap_id = _deterministic_stix_id("attack-pattern", m.technique_id)
                _add({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "created": now,
                    "modified": now,
                    "created_by_ref": producer_id,
                    "name": m.name,
                    "external_references": [{"source_name": "mitre-attack", "external_id": m.technique_id}],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": m.tactic.value.lower().replace("_", "-")}],
                })
                _add({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _deterministic_stix_id("relationship", f"{ap_id}:targets:{vid}"),
                    "created": now,
                    "modified": now,
                    "relationship_type": "targets",
                    "source_ref": ap_id,
                    "target_ref": vid,
                })

        return {
            "type": "bundle",
            "id": _deterministic_stix_id("bundle", f"{target_name}:{len(vulns)}:{len(chains)}"),
            "spec_version": "2.1",
            "objects": objects,
            "x_ely_summary": {
                "generated_at": now,
                "stix_object_count": len(objects),
                "vulnerability_count": len(vulns),
                "exploit_chain_count": len(chains),
            },
        }

    def export_attack_navigator_layer(
        self,
        vulns: Sequence[CyberVulnerability],
        layer_name: str = "ELY Cyber Exposure Heatmap",
    ) -> Dict[str, Any]:
        """Export a MITRE ATT&CK Navigator v4.5 compatible JSON layer."""
        sev_score = {Severity.CRITICAL: 100, Severity.HIGH: 75, Severity.MEDIUM: 45, Severity.LOW: 20, Severity.INFO: 5}
        tech_scores: Dict[str, Tuple[int, List[str]]] = {}
        for v in vulns:
            s = sev_score.get(v.severity, 10)
            for m in v.mitre_techniques:
                prev_s, prev_rules = tech_scores.get(m.technique_id, (0, []))
                tech_scores[m.technique_id] = (max(prev_s, s), prev_rules + [v.rule_id])

        techniques_list = []
        for tid, (score, rules) in sorted(tech_scores.items()):
            color = "#ff3b30" if score >= 90 else ("#ff9500" if score >= 70 else ("#ffcc00" if score >= 40 else "#34c759"))
            techniques_list.append({
                "techniqueID": tid,
                "score": score,
                "color": color,
                "comment": f"Triggered by {len(set(rules))} ELY rule(s): {', '.join(sorted(set(rules))[:5])}",
                "enabled": True,
            })

        return {
            "name": layer_name,
            "versions": {"attack": "15", "navigator": "4.9.5", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Generated by ELY Security Lab ThreatIntelSTIXEngine ({len(techniques_list)} exposed techniques).",
            "sorting": 3,
            "gradient": {"colors": ["#34c759", "#ffcc00", "#ff3b30"], "minValue": 0, "maxValue": 100},
            "techniques": techniques_list,
        }

    def match_adversary_profiles(self, vulns: Sequence[CyberVulnerability]) -> List[Dict[str, Any]]:
        """Rank threat profiles whose historical TTPs best match the target's observed vulnerabilities."""
        observed: Set[str] = set()
        for v in vulns:
            for m in v.mitre_techniques:
                observed.add(m.technique_id)
                if "." in m.technique_id:
                    observed.add(m.technique_id.split(".")[0])

        matches: List[Dict[str, Any]] = []
        for prof in ADVERSARY_TTP_CATALOG:
            pset = set(prof.techniques)
            overlap = sorted(observed & pset)
            union = observed | pset
            jaccard = round(len(overlap) / max(1, len(union)), 4)
            coverage = round(len(overlap) / max(1, len(pset)), 4)
            matches.append({
                "actor_id": prof.actor_id,
                "name": prof.name,
                "motivation": prof.motivation,
                "overlap_techniques": overlap,
                "ttp_coverage_ratio": coverage,
                "jaccard_similarity": jaccard,
                "exposure_level": "HIGH" if coverage >= 0.4 else ("MEDIUM" if coverage >= 0.2 else "LOW"),
            })
        matches.sort(key=lambda m: (m["ttp_coverage_ratio"], m["jaccard_similarity"]), reverse=True)
        return matches

    def analyze_diamond_models(
        self,
        chains: Sequence[GeneralizedExploitChain],
        target_name: str = "ELY-Target",
    ) -> List[Dict[str, Any]]:
        """Derive Diamond Model of Intrusion Analysis records from verified multi-step exploit chains."""
        diamonds: List[Dict[str, Any]] = []
        for ch in chains:
            diamonds.append({
                "chain_id": ch.chain_id,
                "adversary": "Opportunistic-to-Targeted External/Internal Threat Actor",
                "capability": f"{ch.title} ({len(ch.steps)} chained primitives; techniques={ch.mitre_chain})",
                "infrastructure": "Public HTTP/API ingress -> Internal metadata/VPC/Container control plane",
                "victim": target_name,
                "meta_features": {
                    "composite_risk_score": ch.composite_risk_score,
                    "blast_radius": ch.blast_radius_summary,
                    "tactic_progression": ch.mitre_chain,
                },
            })
        return diamonds
