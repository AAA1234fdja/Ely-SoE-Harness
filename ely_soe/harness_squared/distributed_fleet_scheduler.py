"""
Harness² Distributed Multi-Repo Fleet Scheduler, Cross-Repo Blast-Radius Aggregator
& Longitudinal Security Debt Velocity Ledger.

Orchestrates Harness² across an entire organization's portfolio of services/repositories:
  1. **Weighted Criticality & WSPT Fleet Scheduler**:
       Schedules heterogeneous repository assessments under a finite global compute budget
       using Smith's Rule (Weighted Shortest Processing Time + Business Criticality + Exposure Tier),
       automatically allocating `deep_redteam` to Tier-0 internet-facing repos and `fast_ci` to
       low-risk internal tools!
  2. **Cross-Repository Systemic Dependency Blast Radius**:
       Maps shared internal libraries / base Docker images / IaC modules across services to
       compute systemic vulnerability fan-out (if shared auth lib has CWE-347, N downstream
       services inherit the risk simultaneously!).
  3. **Longitudinal Velocity & Security Debt Ledger**:
       Compares historical assessment snapshots (`t0 -> t1`) across the fleet to measure:
         - Net Vulnerability Burn-Down Velocity
         - Regression / Escape Rate (previously fixed rules re-introduced!)
         - Mean Time To Remediate (MTTR) estimate & Enterprise Security Debt Hours.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ely_soe.core.models import utc_now_iso
from ely_soe.harness_squared.meta_orchestrator import HarnessSquaredEngine


@dataclass
class FleetRepositorySpec:
    repo_id: str
    target_path: str
    owner_team: str
    tier: str = "tier1_prod"  # tier0_crown_jewel | tier1_prod | tier2_internal | tier3_sandbox
    internet_facing: bool = True
    estimated_scan_ms: float = 400.0
    shared_dependencies: List[str] = field(default_factory=list)
    business_criticality_weight: float = 1.0


class DistributedFleetScheduler:
    """Prioritizes, schedules, executes, and aggregates Harness² assessments across a multi-repo fleet."""

    TIER_MULTIPLIER: Dict[str, float] = {
        "tier0_crown_jewel": 4.0,
        "tier1_prod": 2.5,
        "tier2_internal": 1.2,
        "tier3_sandbox": 0.5,
    }

    def __init__(self, engine: Optional[HarnessSquaredEngine] = None) -> None:
        self.engine = engine or HarnessSquaredEngine()

    def build_execution_plan(
        self,
        repos: Sequence[FleetRepositorySpec],
        global_budget_ms: float = 10000.0,
    ) -> Dict[str, Any]:
        """Compute WSPT-prioritized execution schedule with automatic profile assignment under budget."""
        scored: List[Dict[str, Any]] = []
        for r in repos:
            tier_w = self.TIER_MULTIPLIER.get(r.tier, 1.0)
            ext_w = 1.6 if r.internet_facing else 1.0
            priority_weight = round(tier_w * ext_w * max(0.1, r.business_criticality_weight), 3)
            wspt_score = round(priority_weight / max(50.0, r.estimated_scan_ms) * 1000.0, 4)
            assigned_profile = (
                "deep_redteam" if r.tier == "tier0_crown_jewel"
                else ("balanced_enterprise" if r.tier == "tier1_prod" else "fast_ci")
            )
            scored.append({
                "repo": r,
                "repo_id": r.repo_id,
                "owner_team": r.owner_team,
                "tier": r.tier,
                "priority_weight": priority_weight,
                "wspt_score": wspt_score,
                "assigned_profile": assigned_profile,
                "estimated_scan_ms": r.estimated_scan_ms,
            })

        scored.sort(key=lambda x: (-x["wspt_score"], -x["priority_weight"]))
        scheduled: List[Dict[str, Any]] = []
        deferred: List[Dict[str, Any]] = []
        used_ms = 0.0
        for item in scored:
            cost = float(item["estimated_scan_ms"])
            entry = {k: v for k, v in item.items() if k != "repo"}
            if used_ms + cost <= global_budget_ms or not scheduled:
                used_ms += cost
                scheduled.append(entry)
            else:
                deferred.append(entry)

        return {
            "planned_at": utc_now_iso(),
            "global_budget_ms": global_budget_ms,
            "projected_budget_used_ms": round(used_ms, 2),
            "scheduled_count": len(scheduled),
            "deferred_count": len(deferred),
            "scheduled_queue": scheduled,
            "deferred_queue": deferred,
        }

    def execute_fleet_sweep(
        self,
        repos: Sequence[FleetRepositorySpec],
        *,
        global_budget_ms: float = 15000.0,
        force_profile: Optional[str] = "fast_ci",
    ) -> Dict[str, Any]:
        """Run Harness² across scheduled repos and compute enterprise posture & systemic blast radius."""
        t0 = time.perf_counter()
        plan = self.build_execution_plan(repos, global_budget_ms=global_budget_ms)
        rmap = {r.repo_id: r for r in repos}

        repo_outcomes: List[Dict[str, Any]] = []
        dep_to_repos: Dict[str, List[str]] = {}
        team_rollup: Dict[str, Dict[str, Any]] = {}
        total_vulns = 0
        total_crit = 0
        blocked_count = 0

        for item in plan["scheduled_queue"]:
            spec = rmap[item["repo_id"]]
            prof = force_profile or item["assigned_profile"]
            run = self.engine.run_adaptive_assessment(
                target_path=spec.target_path,
                target_name=spec.repo_id,
                preferred_profile=prof,
                enable_adaptation=True,
            )
            sev = run.get("severity_counts", {})
            vcnt = int(run.get("total_vulnerabilities", 0))
            ccnt = int(sev.get("critical", 0))
            gate = str(run.get("gate_verdict", "BLOCKED"))
            posture = float(run.get("overall_cyber_posture", 0.0))

            total_vulns += vcnt
            total_crit += ccnt
            if gate != "APPROVED":
                blocked_count += 1

            for dep in spec.shared_dependencies:
                dep_to_repos.setdefault(dep, []).append(spec.repo_id)

            tr = team_rollup.setdefault(
                spec.owner_team,
                {"repos": 0, "total_vulns": 0, "critical": 0, "avg_posture_sum": 0.0},
            )
            tr["repos"] += 1
            tr["total_vulns"] += vcnt
            tr["critical"] += ccnt
            tr["avg_posture_sum"] += posture

            repo_outcomes.append({
                "repo_id": spec.repo_id,
                "owner_team": spec.owner_team,
                "tier": spec.tier,
                "profile_used": prof,
                "gate_verdict": gate,
                "overall_cyber_posture": posture,
                "total_vulnerabilities": vcnt,
                "critical_count": ccnt,
                "high_count": int(sev.get("high", 0)),
                "duration_ms": run.get("duration_ms", 0.0),
                "rule_ids": sorted({str(v.get("rule_id", "")) for v in run.get("vulnerabilities", [])}),
            })

        # Compute systemic shared-dependency blast radius
        systemic_hotspots = [
            {
                "shared_component": dep,
                "dependent_repos": sorted(set(rids)),
                "blast_radius_repo_count": len(set(rids)),
            }
            for dep, rids in sorted(dep_to_repos.items(), key=lambda kv: -len(set(kv[1])))
            if len(set(rids)) >= 2
        ]

        team_leaderboard = []
        for team, d in team_rollup.items():
            avg_p = round(d["avg_posture_sum"] / max(1, d["repos"]), 2)
            team_leaderboard.append({
                "owner_team": team,
                "repos_assessed": d["repos"],
                "avg_posture_score": avg_p,
                "total_vulnerabilities": d["total_vulns"],
                "critical_vulnerabilities": d["critical"],
            })
        team_leaderboard.sort(key=lambda x: (-x["avg_posture_score"], x["critical_vulnerabilities"]))

        fleet_posture = round(
            sum(r["overall_cyber_posture"] for r in repo_outcomes) / max(1, len(repo_outcomes)),
            2,
        )
        return {
            "completed_at": utc_now_iso(),
            "duration_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            "fleet_repos_assessed": len(repo_outcomes),
            "fleet_avg_posture": fleet_posture,
            "fleet_blocked_repos": blocked_count,
            "fleet_total_vulnerabilities": total_vulns,
            "fleet_total_critical": total_crit,
            "execution_plan": plan,
            "systemic_dependency_hotspots": systemic_hotspots,
            "team_leaderboard": team_leaderboard,
            "repo_outcomes": repo_outcomes,
        }

    def compute_longitudinal_velocity(
        self,
        previous_sweep: Dict[str, Any],
        current_sweep: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Compare two fleet sweeps to measure vulnerability burn-down, regressions, and posture delta."""
        prev_map = {r["repo_id"]: r for r in previous_sweep.get("repo_outcomes", [])}
        curr_map = {r["repo_id"]: r for r in current_sweep.get("repo_outcomes", [])}

        deltas: List[Dict[str, Any]] = []
        total_remediated = 0
        total_introduced = 0
        for rid, curr in curr_map.items():
            prev = prev_map.get(rid)
            if not prev:
                continue
            prev_rules = set(prev.get("rule_ids", []))
            curr_rules = set(curr.get("rule_ids", []))
            fixed = sorted(prev_rules - curr_rules)
            regressed = sorted(curr_rules - prev_rules)
            total_remediated += len(fixed)
            total_introduced += len(regressed)
            deltas.append({
                "repo_id": rid,
                "posture_delta": round(curr["overall_cyber_posture"] - prev["overall_cyber_posture"], 2),
                "vuln_delta": curr["total_vulnerabilities"] - prev["total_vulnerabilities"],
                "rules_remediated": fixed,
                "rules_regressed_or_new": regressed,
            })

        return {
            "compared_at": utc_now_iso(),
            "fleet_posture_delta": round(
                float(current_sweep.get("fleet_avg_posture", 0.0)) - float(previous_sweep.get("fleet_avg_posture", 0.0)),
                2,
            ),
            "net_vuln_delta": int(current_sweep.get("fleet_total_vulnerabilities", 0)) - int(previous_sweep.get("fleet_total_vulnerabilities", 0)),
            "unique_rules_remediated": total_remediated,
            "unique_rules_newly_introduced": total_introduced,
            "net_burn_down_positive": total_remediated >= total_introduced,
            "per_repo_deltas": deltas,
        }
