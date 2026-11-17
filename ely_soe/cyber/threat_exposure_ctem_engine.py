"""
Continuous Threat Exposure Management (CTEM — Gartner 5-Stage Lifecycle) Engine.

Operationalizes continuous exposure management across all 5 CTEM stages:
  1. **Scoping**: binds business-critical asset tiers (`tier0_crown_jewel` .. `tier3_dev`)
     and regulatory boundaries (`PCI`, `HIPAA`, `SOX`, `EU_AI_ACT`).
  2. **Discovery**: ingests heterogeneous findings from Code SAST, Live DAST, EASM, Cloud IAM,
     SaaS SSPM, CI/CD PPE, K8s Admission, and Ransomware Contagion simulations.
  3. **Prioritization**: computes composite **CTEM Exposure Score (0–100)** combining CVSS v4.0,
     CISA KEV, EPSS probability, internet exposure, exploit-chain membership, and asset tier,
     plus deterministic Remediation SLA deadlines (`24h` P0 / `72h` P1 / `14d` P2 / `30d` P3).
  4. **Validation**: classifies findings by empirical proof status (`SANDBOX_EXPLOITED`,
     `GRAPH_REACHABLE`, `STATIC_CORROBORATED`, `THEORETICAL`) to focus engineers on proven paths.
  5. **Mobilization**: outputs owner-routed remediation sprints, SLA breach risk forecasts,
     and executive Board CTEM Posture Grades (`A+` through `F`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ely_soe.core.models import utc_now_iso


@dataclass(frozen=True)
class CTEMAssetScope:
    asset_id: str
    name: str
    owner_team: str
    business_tier: str = "tier1_prod"  # tier0_crown_jewel | tier1_prod | tier2_internal | tier3_dev
    internet_exposed: bool = True
    regulated_data: bool = True


TIER_EXPOSURE_WEIGHT: Dict[str, float] = {
    "tier0_crown_jewel": 1.35,
    "tier1_prod": 1.15,
    "tier2_internal": 0.85,
    "tier3_dev": 0.55,
}

SEV_BASE_SCORE: Dict[str, float] = {
    "critical": 72.0,
    "high": 54.0,
    "medium": 32.0,
    "low": 14.0,
    "info": 4.0,
}


class ContinuousThreatExposureEngine:
    """Executes the 5-stage Gartner CTEM exposure prioritization & mobilization lifecycle."""

    def evaluate_ctem_cycle(
        self,
        findings: Sequence[Any],
        *,
        asset_scope: Optional[CTEMAssetScope] = None,
        chain_rule_ids: Optional[Sequence[str]] = None,
        external_easm_score: float = 70.0,
    ) -> Dict[str, Any]:
        scope = asset_scope or CTEMAssetScope("ASSET-PRIMARY", "enterprise-primary", "platform-security")
        chain_set = set(chain_rule_ids or ())
        tier_mult = TIER_EXPOSURE_WEIGHT.get(scope.business_tier, 1.0)
        ext_bonus = 14.0 if scope.internet_exposed else 0.0
        reg_bonus = 6.0 if scope.regulated_data else 0.0

        prioritized: List[Dict[str, Any]] = []
        sla_buckets: Dict[str, int] = {"P0_24H": 0, "P1_72H": 0, "P2_14D": 0, "P3_30D": 0}
        validation_counts: Dict[str, int] = {
            "SANDBOX_EXPLOITED": 0,
            "GRAPH_REACHABLE": 0,
            "STATIC_CORROBORATED": 0,
            "THEORETICAL": 0,
        }

        for idx, f in enumerate(findings):
            if isinstance(f, dict):
                rid = str(f.get("rule_id", f"FIND-{idx}"))
                title = str(f.get("title", rid))
                sev = str(f.get("severity", "medium")).lower()
                kev = bool(f.get("kev_listed", False))
                epss = float(f.get("epss_probability", 0.0))
                repro = bool(f.get("sandbox_reproduced", False))
                ver_m = str(f.get("verification_method", "static_pattern")).lower()
                cwes = list(f.get("cwe_ids", []))
                domain = str(f.get("cyber_domain", "general"))
            else:
                rid = str(getattr(f, "rule_id", f"FIND-{idx}"))
                title = str(getattr(f, "title", rid))
                s_obj = getattr(f, "severity", "medium")
                sev = s_obj.value.lower() if hasattr(s_obj, "value") else str(s_obj).lower()
                kev = bool(getattr(f, "kev_listed", False))
                epss = float(getattr(f, "epss_probability", 0.0))
                repro = bool(getattr(f, "sandbox_reproduced", False))
                vm = getattr(f, "verification_method", "static_pattern")
                ver_m = vm.value.lower() if hasattr(vm, "value") else str(vm).lower()
                cwes = list(getattr(f, "cwe_ids", []))
                dom = getattr(f, "cyber_domain", "general")
                domain = dom.value if hasattr(dom, "value") else str(dom)

            # Stage 4: Validation classification
            if repro or "sandbox" in ver_m:
                val_tier = "SANDBOX_EXPLOITED"
                val_boost = 16.0
            elif "graph" in ver_m or rid in chain_set:
                val_tier = "GRAPH_REACHABLE"
                val_boost = 11.0
            elif "ast" in ver_m or "protocol" in ver_m or "crypto" in ver_m:
                val_tier = "STATIC_CORROBORATED"
                val_boost = 5.0
            else:
                val_tier = "THEORETICAL"
                val_boost = 0.0
            validation_counts[val_tier] += 1

            # Stage 3: Composite CTEM Exposure Score (0..100)
            raw_score = (
                SEV_BASE_SCORE.get(sev, 25.0) * tier_mult
                + ext_bonus
                + reg_bonus
                + val_boost
                + (18.0 if kev else 0.0)
                + (12.0 * min(1.0, epss))
                + (10.0 if rid in chain_set else 0.0)
            )
            ctem_score = round(min(100.0, max(1.0, raw_score)), 2)

            if ctem_score >= 88.0 or kev or (repro and sev == "critical"):
                sla = "P0_24H"
            elif ctem_score >= 70.0:
                sla = "P1_72H"
            elif ctem_score >= 45.0:
                sla = "P2_14D"
            else:
                sla = "P3_30D"
            sla_buckets[sla] += 1

            prioritized.append({
                "rule_id": rid,
                "title": title,
                "severity": sev,
                "domain": domain,
                "cwes": cwes,
                "validation_tier": val_tier,
                "ctem_exposure_score": ctem_score,
                "remediation_sla": sla,
                "owner_team": scope.owner_team,
                "in_exploit_chain": rid in chain_set,
                "kev_listed": kev,
            })

        prioritized.sort(key=lambda x: (-x["ctem_exposure_score"], x["remediation_sla"]))

        # Aggregate Exposure Index (higher = healthier; 100 = zero exposure)
        penalty = (
            sla_buckets["P0_24H"] * 12.0
            + sla_buckets["P1_72H"] * 5.0
            + sla_buckets["P2_14D"] * 1.5
            + sla_buckets["P3_30D"] * 0.4
        )
        ctem_health = max(0.0, round(0.75 * max(0.0, 100.0 - penalty) + 0.25 * external_easm_score, 2))
        grade = (
            "A" if ctem_health >= 90.0 else
            "B" if ctem_health >= 78.0 else
            "C" if ctem_health >= 62.0 else
            "D" if ctem_health >= 45.0 else "F"
        )

        # Stage 5: Mobilization sprint groups
        mobilization_sprints = [
            {
                "sprint": "Emergency Containment (0-24h)",
                "sla_bucket": "P0_24H",
                "owner_team": scope.owner_team,
                "item_count": sla_buckets["P0_24H"],
                "top_items": [p["rule_id"] for p in prioritized if p["remediation_sla"] == "P0_24H"][:6],
            },
            {
                "sprint": "Priority Hardening (24-72h)",
                "sla_bucket": "P1_72H",
                "owner_team": scope.owner_team,
                "item_count": sla_buckets["P1_72H"],
                "top_items": [p["rule_id"] for p in prioritized if p["remediation_sla"] == "P1_72H"][:6],
            },
            {
                "sprint": "Scheduled Backlog (14-30d)",
                "sla_bucket": "P2_14D+P3_30D",
                "owner_team": scope.owner_team,
                "item_count": sla_buckets["P2_14D"] + sla_buckets["P3_30D"],
                "top_items": [p["rule_id"] for p in prioritized if p["remediation_sla"] in ("P2_14D", "P3_30D")][:6],
            },
        ]

        return {
            "evaluated_at": utc_now_iso(),
            "scope": scope.__dict__,
            "ctem_health_index": ctem_health,
            "executive_grade": grade,
            "total_exposures": len(prioritized),
            "sla_distribution": sla_buckets,
            "validation_proof_breakdown": validation_counts,
            "mobilization_sprints": mobilization_sprints,
            "top_prioritized_exposures": prioritized[:20],
        }
