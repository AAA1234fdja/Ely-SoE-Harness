"""
Harness² Cross-Run Meta-Learning Analytics, Regret Convergence & Drift Intelligence.

Analyzes historical Harness² executions persisted in `MetaMemoryStore` to expose:
  - **Meta-Learning Reward Trajectory & Cumulative Regret Trend**
  - **Arm Performance Leaderboard** (average reward, latency, and critical yield per genome arm)
  - **MAPE-K Adaptation Rule ROI Matrix** (which dynamic drilldown rules discover the most real risk)
  - **Target Posture Drift Detector** (tracks whether a target's security posture improved or
    regressed across sequential pre-release evaluations).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ely_soe.core.models import utc_now_iso
from ely_soe.harness_squared.meta_memory import MetaMemoryStore


class HarnessSquaredMetaAnalytics:
    """Computes longitudinal meta-learning, regret, rule-ROI, and security-posture drift analytics."""

    def __init__(self, memory: MetaMemoryStore) -> None:
        self.memory = memory

    def build_dashboard_summary(self, limit: int = 50) -> Dict[str, Any]:
        runs = list(reversed(self.memory.list_runs(limit=limit)))  # chronological order
        rule_eff = self.memory.get_rule_efficacy()

        arm_stats: Dict[str, Dict[str, Any]] = {}
        reward_curve: List[Dict[str, Any]] = []
        target_trajectories: Dict[str, List[Dict[str, Any]]] = {}

        best_reward_so_far = 0.0
        cumulative_regret = 0.0

        for idx, r in enumerate(runs, start=1):
            arm = str(r["genome_arm"])
            rew = float(r["reward"])
            best_reward_so_far = max(best_reward_so_far, rew)
            instant_regret = max(0.0, best_reward_so_far - rew)
            cumulative_regret += instant_regret

            st = arm_stats.setdefault(
                arm,
                {"arm_id": arm, "runs": 0, "reward_sum": 0.0, "duration_sum_ms": 0.0, "criticals_sum": 0, "adaptations_sum": 0},
            )
            st["runs"] += 1
            st["reward_sum"] += rew
            st["duration_sum_ms"] += float(r["duration_ms"])
            st["criticals_sum"] += int(r["critical_vulns"])
            st["adaptations_sum"] += int(r["adaptations_applied"])

            reward_curve.append(
                {
                    "step": idx,
                    "run_id": r["run_id"],
                    "target_name": r["target_name"],
                    "arm": arm,
                    "reward": round(rew, 4),
                    "mean_regret": round(cumulative_regret / idx, 4),
                    "adaptations_applied": int(r["adaptations_applied"]),
                }
            )
            target_trajectories.setdefault(str(r["target_name"]), []).append(
                {
                    "run_id": r["run_id"],
                    "created_at": r["created_at"],
                    "posture_score": float(r["posture_score"]),
                    "total_vulns": int(r["total_vulns"]),
                    "critical_vulns": int(r["critical_vulns"]),
                }
            )

        arm_leaderboard = [
            {
                "arm_id": s["arm_id"],
                "runs": s["runs"],
                "mean_reward": round(s["reward_sum"] / max(1, s["runs"]), 4),
                "mean_duration_ms": round(s["duration_sum_ms"] / max(1, s["runs"]), 2),
                "mean_criticals": round(s["criticals_sum"] / max(1, s["runs"]), 2),
                "mean_adaptations": round(s["adaptations_sum"] / max(1, s["runs"]), 2),
            }
            for s in sorted(arm_stats.values(), key=lambda x: -(x["reward_sum"] / max(1, x["runs"])))
        ]

        # Compute per-target posture drift (latest vs earliest)
        drift_alerts: List[Dict[str, Any]] = []
        for tname, pts in target_trajectories.items():
            if len(pts) >= 2:
                delta_posture = round(pts[-1]["posture_score"] - pts[0]["posture_score"], 2)
                delta_crit = pts[-1]["critical_vulns"] - pts[0]["critical_vulns"]
                drift_alerts.append(
                    {
                        "target_name": tname,
                        "runs_observed": len(pts),
                        "posture_delta": delta_posture,
                        "critical_delta": delta_crit,
                        "trend": "IMPROVED" if delta_posture > 2.0 else ("REGRESSED" if delta_posture < -2.0 else "STABLE"),
                    }
                )

        return {
            "generated_at": utc_now_iso(),
            "total_runs_recorded": len(runs),
            "cumulative_regret": round(cumulative_regret, 4),
            "arm_leaderboard": arm_leaderboard,
            "reward_and_regret_curve": reward_curve,
            "mapek_rule_efficacy": rule_eff,
            "posture_drift": drift_alerts,
        }
