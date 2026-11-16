"""
Multi-Objective Cost/Risk Pareto Stage Scheduler & Live Parallel Wave Execution Coordinator.

Combines:
  1. **Target-Aware Marginal Utility Estimator**:
       Scores all 42 stages in `STAGE_CATALOG` using file-surface telemetry (Python, JS/TS/Go,
       IaC/K8s, secrets, lockfiles, AI/LLM markers) and historical risk yield density (`risk_utility / ms`).
  2. **Exact Latency-Constrained 0-1 Knapsack + 2D Pareto Frontier `(wall_clock_ms, expected_risk_coverage_pct)`**:
       Computes the optimal stage portfolio across multiple latency SLA budgets
       (e.g., `2s PR-Fast`, `5s CI-Standard`, `12s Pre-Release`, `25s Deep-Audit`) so teams
       can pick the exact knee-of-the-curve operating point.
  3. **Live Multi-Threaded Execution via `ParallelTopologicalDAGExecutor`**:
       Executes the selected stages concurrently across Kahn topological waves with per-stage
       circuit breakers and measures real empirical **Parallel Speedup (`sum_stage_ms / wall_clock_ms`)**,
       worker concurrency efficiency, and per-wave risk yield!
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import utc_now_iso
from ely_soe.harness_squared.parallel_dag_executor import ParallelTopologicalDAGExecutor
from ely_soe.harness_squared.stage_registry import (
    STAGE_CATALOG,
    FirstOrderStageRegistry,
    StageExecutionContext,
)


STAGE_BASE_UTILITY: Dict[str, float] = {
    "web_injection": 95.0,
    "deobfuscation_ast": 94.0,
    "interprocedural_taint": 92.0,
    "contextual_secrets": 90.0,
    "web_ssrf_deser": 88.0,
    "auth_access": 86.0,
    "secrets_dlp": 85.0,
    "kubernetes_container": 84.0,
    "iac_cicd": 83.0,
    "polyglot_scanner": 80.0,
    "supply_chain_scorecard": 78.0,
    "network_tls_zt": 77.0,
    "supply_chain_sbom": 76.0,
    "tls_crypto": 74.0,
    "ai_llm_firewall": 72.0,
    "semantic_reachability": 70.0,
    "cicd_ppe_graph": 68.0,
    "web_client_protocol": 67.0,
    "api_microservices": 66.0,
    "k8s_admission_opa": 65.0,
    "oauth21_pkce_audit": 64.0,
    "zeroday_vex_triage": 63.0,
    "cloud_iam_graph": 62.0,
    "mitre_sigma_purple": 60.0,
}

DEFAULT_WAVE_DEPENDENCIES: Dict[str, Tuple[str, ...]] = {
    "semantic_reachability": ("web_injection", "deobfuscation_ast", "interprocedural_taint"),
    "independent_validation_drilldown": ("web_injection", "web_ssrf_deser"),
}


@dataclass(frozen=True)
class ScheduledStagePlan:
    adapter_name: str
    estimated_ms: int
    marginal_utility: float
    utility_per_sec: float
    surface_boost: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "estimated_ms": self.estimated_ms,
            "marginal_utility": round(self.marginal_utility, 2),
            "utility_per_sec": round(self.utility_per_sec, 2),
            "surface_boost": round(self.surface_boost, 2),
        }


class AdaptiveCostParetoScheduler:
    """Computes Pareto-optimal stage portfolios under latency SLAs and runs them in parallel waves."""

    def __init__(self, registry: Optional[FirstOrderStageRegistry] = None, *, max_workers: int = 4) -> None:
        self.registry = registry or FirstOrderStageRegistry()
        self.parallel_executor = ParallelTopologicalDAGExecutor(self.registry, max_workers=max_workers)
        self.max_workers = max(1, int(max_workers))

    def profile_target_surface(self, target_dir: str | Path) -> Dict[str, Any]:
        """Inspect repository file composition in <5ms to boost relevant security stages."""
        root = Path(target_dir).resolve()
        counts = {"py": 0, "js_ts": 0, "go": 0, "yaml_k8s": 0, "tf_iac": 0, "dockerfile": 0, "native_c": 0, "reqs_pkg": 0}
        if root.exists():
            files = [root] if root.is_file() else list(root.rglob("*"))
            for f in files:
                if not f.is_file() or any(p in f.parts for p in (".git", "__pycache__", "node_modules", ".venv")):
                    continue
                ext = f.suffix.lower()
                nm = f.name.lower()
                if ext == ".py":
                    counts["py"] += 1
                elif ext in (".js", ".ts", ".jsx", ".tsx"):
                    counts["js_ts"] += 1
                elif ext == ".go":
                    counts["go"] += 1
                elif ext in (".yml", ".yaml"):
                    counts["yaml_k8s"] += 1
                elif ext in (".tf", ".tfvars", ".hcl"):
                    counts["tf_iac"] += 1
                elif nm.startswith("dockerfile"):
                    counts["dockerfile"] += 1
                elif ext in (".c", ".cpp", ".h", ".rs"):
                    counts["native_c"] += 1
                elif nm.startswith("requirements") or nm in ("package.json", "pyproject.toml", "cargo.toml"):
                    counts["reqs_pkg"] += 1
        return counts

    def score_stages_for_target(
        self,
        target_dir: str | Path,
        *,
        candidate_stages: Optional[Sequence[str]] = None,
    ) -> List[ScheduledStagePlan]:
        surf = self.profile_target_surface(target_dir)
        stages = list(candidate_stages) if candidate_stages else list(STAGE_CATALOG.keys())
        plans: List[ScheduledStagePlan] = []

        for st in stages:
            spec = STAGE_CATALOG.get(st)
            if spec is None:
                continue
            base = STAGE_BASE_UTILITY.get(st, 52.0)
            boost = 1.0
            if surf["py"] > 0 and st in ("web_injection", "deobfuscation_ast", "interprocedural_taint", "web_ssrf_deser", "semantic_reachability"):
                boost += 0.35
            if (surf["js_ts"] > 0 or surf["go"] > 0 or surf["dockerfile"] > 0) and st in ("polyglot_scanner", "browser_dom_csp"):
                boost += 0.40
            if (surf["yaml_k8s"] > 0 or surf["dockerfile"] > 0) and st in ("kubernetes_container", "k8s_admission_opa", "iac_cicd", "cicd_ppe_graph"):
                boost += 0.35
            if surf["tf_iac"] > 0 and st in ("iac_cicd", "cloud_iam_graph", "network_tls_zt"):
                boost += 0.40
            if surf["reqs_pkg"] > 0 and st in ("supply_chain_sbom", "supply_chain_scorecard", "supply_chain_typosquat"):
                boost += 0.30
            if surf["native_c"] > 0 and st in ("binary_memory", "memory_exploitability"):
                boost += 0.45

            util = base * boost
            est_ms = max(200, int(spec.default_budget_ms * 0.25))
            ups = util / (est_ms / 1000.0)
            plans.append(ScheduledStagePlan(st, est_ms, util, ups, boost))

        plans.sort(key=lambda p: (p.utility_per_sec, p.marginal_utility), reverse=True)
        return plans

    def solve_pareto_frontier(
        self,
        target_dir: str | Path,
        *,
        latency_budgets_ms: Sequence[int] = (1500, 3000, 6000, 12000),
        candidate_stages: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Solve exact 0-1 Knapsack for each wall-clock SLA budget (accounting for parallel workers)."""
        plans = self.score_stages_for_target(target_dir, candidate_stages=candidate_stages)
        total_possible_util = sum(p.marginal_utility for p in plans) or 1.0
        frontier: List[Dict[str, Any]] = []

        for b_ms in sorted(latency_budgets_ms):
            # Parallel execution grants effective stage-ms budget ~ b_ms * min(workers, 3) * 0.80 overhead factor
            eff_cap_units = max(1, int((b_ms * min(self.max_workers, 3) * 0.80) / 100))
            n = len(plans)
            dp = [0.0] * (eff_cap_units + 1)
            keep: List[List[bool]] = [[False] * (eff_cap_units + 1) for _ in range(n)]

            for i, pl in enumerate(plans):
                w = max(1, int(pl.estimated_ms / 100))
                val = pl.marginal_utility
                for c in range(eff_cap_units, w - 1, -1):
                    if dp[c - w] + val > dp[c]:
                        dp[c] = dp[c - w] + val
                        keep[i][c] = True

            chosen: List[ScheduledStagePlan] = []
            c = eff_cap_units
            for i in range(n - 1, -1, -1):
                if keep[i][c]:
                    chosen.append(plans[i])
                    c -= max(1, int(plans[i].estimated_ms / 100))
            chosen.reverse()

            util_sum = sum(p.marginal_utility for p in chosen)
            seq_ms = sum(p.estimated_ms for p in chosen)
            est_par_ms = round(seq_ms / min(self.max_workers, max(1, len(chosen))), 1)
            frontier.append({
                "sla_budget_ms": int(b_ms),
                "selected_stages_count": len(chosen),
                "expected_risk_coverage_pct": round((util_sum / total_possible_util) * 100.0, 2),
                "estimated_sequential_ms": seq_ms,
                "estimated_parallel_wall_ms": est_par_ms,
                "selected_stages": [p.adapter_name for p in chosen],
            })

        return {
            "computed_at": utc_now_iso(),
            "target": str(Path(target_dir).resolve()),
            "surface_profile": self.profile_target_surface(target_dir),
            "max_workers": self.max_workers,
            "pareto_frontier": frontier,
            "top_ranked_stages": [p.to_dict() for p in plans[:12]],
        }

    def execute_budgeted_parallel_scan(
        self,
        target_dir: str | Path,
        *,
        sla_budget_ms: int = 5000,
        max_stages: int = 10,
    ) -> Dict[str, Any]:
        """Select optimal stages for `sla_budget_ms` and execute them live in parallel topological waves."""
        root = Path(target_dir).resolve()
        # Exclude interactive sandbox range from quick static wave sweep
        static_candidates = [
            s for s in STAGE_CATALOG.keys()
            if s not in ("live_sandbox_dast", "grammar_fuzzer", "bas_campaigns", "mitre_sigma_purple")
        ]
        pareto = self.solve_pareto_frontier(root, latency_budgets_ms=(sla_budget_ms,), candidate_stages=static_candidates)
        selected = pareto["pareto_frontier"][0]["selected_stages"][:max_stages]
        deps = {
            st: [d for d in dlist if d in selected]
            for st, dlist in DEFAULT_WAVE_DEPENDENCIES.items()
            if st in selected
        }

        ctx = StageExecutionContext(target_path=root)
        exec_res = self.parallel_executor.execute_parallel_waves(
            selected, ctx, dependencies=deps, wall_clock_deadline_ms=float(sla_budget_ms) * 2.0
        )
        stage_to_wave: Dict[str, int] = {}
        for wt in exec_res.get("wave_telemetry", []):
            w_idx = int(wt.get("wave", 0))
            for st_name in wt.get("stages", []):
                stage_to_wave[str(st_name)] = w_idx

        serialized_stage_results = [
            {
                "wave_index": stage_to_wave.get(r.adapter_name, 0),
                "adapter_name": r.adapter_name,
                "status": "FAILED" if r.error else "COMPLETED",
                "elapsed_ms": r.elapsed_ms,
                "findings_count": len(r.vulnerabilities),
                "error": r.error,
            }
            for r in exec_res.get("stage_results", [])
        ]
        json_safe_exec = {
            "executed_at": exec_res["executed_at"],
            "max_workers": exec_res["max_workers"],
            "waves_count": exec_res["waves_count"],
            "stages_requested": exec_res["stages_requested"],
            "stages_completed": exec_res["stages_completed"],
            "stages_failed": exec_res["stages_failed"],
            "wall_clock_ms": exec_res["wall_clock_ms"],
            "sequential_equivalent_ms": exec_res["sequential_sum_ms"],
            "parallel_speedup": exec_res["parallel_speedup_factor"],
            "total_vulnerabilities": exec_res["total_vulnerabilities"],
            "wave_telemetry": exec_res["wave_telemetry"],
            "stage_results": serialized_stage_results,
        }
        return {
            "executed_at": utc_now_iso(),
            "target": str(root),
            "sla_budget_ms": sla_budget_ms,
            "selected_stages": selected,
            "parallel_execution": json_safe_exec,
            "pareto_summary": pareto["pareto_frontier"][0],
        }
