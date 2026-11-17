"""
Formal AND/OR Attack-Defense Tree (ADTree) Probabilistic Risk Modeler
& Budget-Constrained Optimal Countermeasure Portfolio Solver.

Grounded in Kordy et al.'s Attack-Defense Tree formalism:
  1. **Exact Bottom-Up ADTree Quantitative Evaluation**:
       - `OR` attack nodes: `P(OR) = 1 - prod(1 - P(child))` (independent attack alternatives);
         `min_attacker_cost = min(cost(child))`.
       - `AND` attack nodes: `P(AND) = prod(P(child))` (all sub-steps required in kill chain);
         `min_attacker_cost = sum(cost(child))`.
       - `DEFENSE` countermeasure attachments: each active defense `d` with efficacy `e_d in [0, 1]`
         attenuates the guarded node's compromise probability by `(1 - e_d)` (multiplicative
         defense-in-depth)!
  2. **Automatic ADTree Construction From Harness² / Cyber Assessment Runs**:
       Builds a formal root-compromise ADTree directly from discovered multi-step exploit chains
       and critical/high vulnerabilities.
  3. **Exact Optimal Countermeasure Portfolio Solver (Budget-Constrained Subset Optimization)**:
       Given candidate defensive controls `(defense_id, cost_usd, efficacy, guarded_nodes)` and a
       security engineering budget `B_usd`, solves for the exact subset of controls maximizing
       root-breach probability reduction (and Expected Annual Loss saved!) within budget `B_usd`!
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ely_soe.core.models import utc_now_iso


@dataclass
class ADTreeNode:
    node_id: str
    label: str
    gate: str  # LEAF | OR | AND
    base_probability: float = 0.0  # used when gate == LEAF
    attacker_cost_usd: float = 1000.0
    children: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class DefensiveCountermeasure:
    defense_id: str
    name: str
    implementation_cost_usd: float
    efficacy: float  # 0.0 to 0.99 reduction fraction on guarded nodes
    guarded_node_ids: Tuple[str, ...]


class FormalAttackDefenseTreeSolver:
    """Evaluates AND/OR Attack-Defense Trees and solves optimal defense portfolios under budget."""

    def evaluate_tree(
        self,
        root_id: str,
        nodes: Dict[str, ADTreeNode],
        active_defenses: Sequence[DefensiveCountermeasure] = (),
        breach_impact_usd: float = 5_000_000.0,
    ) -> Dict[str, Any]:
        """Compute exact root compromise probability, min attacker cost, and expected loss."""
        def_by_node: Dict[str, List[DefensiveCountermeasure]] = {}
        for d in active_defenses:
            for nid in d.guarded_node_ids:
                def_by_node.setdefault(nid, []).append(d)

        memo_prob: Dict[str, float] = {}
        memo_cost: Dict[str, float] = {}

        def _eval(nid: str) -> Tuple[float, float]:
            if nid in memo_prob:
                return memo_prob[nid], memo_cost[nid]
            node = nodes[nid]
            if node.gate == "LEAF" or not node.children:
                p = max(0.0, min(1.0, float(node.base_probability)))
                c = float(node.attacker_cost_usd)
            elif node.gate == "OR":
                no_hit = 1.0
                c_list = []
                for cid in node.children:
                    cp, cc = _eval(cid)
                    no_hit *= (1.0 - cp)
                    c_list.append(cc)
                p = 1.0 - no_hit
                c = min(c_list) if c_list else node.attacker_cost_usd
            elif node.gate == "AND":
                p = 1.0
                c = 0.0
                for cid in node.children:
                    cp, cc = _eval(cid)
                    p *= cp
                    c += cc
            else:
                raise ValueError(f"Unsupported ADTree gate: {node.gate}")

            # Apply multiplicative defense-in-depth countermeasures guarding this node
            for d in def_by_node.get(nid, []):
                p *= (1.0 - max(0.0, min(0.995, d.efficacy)))
                c += d.implementation_cost_usd * 0.25  # raises attacker difficulty

            p = max(0.0, min(1.0, p))
            memo_prob[nid] = p
            memo_cost[nid] = c
            return p, c

        root_p, min_att_cost = _eval(root_id)
        expected_loss = round(root_p * breach_impact_usd, 2)
        defense_spend = round(sum(d.implementation_cost_usd for d in active_defenses), 2)
        return {
            "root_id": root_id,
            "root_compromise_probability": round(root_p, 6),
            "min_attacker_cost_usd": round(min_att_cost, 2),
            "expected_loss_usd": expected_loss,
            "defense_spend_usd": defense_spend,
            "active_defense_ids": [d.defense_id for d in active_defenses],
            "node_probabilities": {k: round(v, 5) for k, v in memo_prob.items()},
        }

    def solve_optimal_defense_portfolio(
        self,
        root_id: str,
        nodes: Dict[str, ADTreeNode],
        candidate_defenses: Sequence[DefensiveCountermeasure],
        budget_usd: float,
        breach_impact_usd: float = 5_000_000.0,
    ) -> Dict[str, Any]:
        """Solve for the exact (<=14 controls) or greedy-refined optimal defense subset under `budget_usd`."""
        baseline = self.evaluate_tree(root_id, nodes, (), breach_impact_usd=breach_impact_usd)
        defs = list(candidate_defenses)

        best_subset: List[DefensiveCountermeasure] = []
        best_eval = baseline
        best_net_benefit = 0.0

        if len(defs) <= 14:
            # Exact exhaustive branch-and-bound over all 2^N subsets
            for r in range(1, len(defs) + 1):
                for combo in itertools.combinations(defs, r):
                    cost = sum(d.implementation_cost_usd for d in combo)
                    if cost > budget_usd:
                        continue
                    ev = self.evaluate_tree(root_id, nodes, combo, breach_impact_usd=breach_impact_usd)
                    loss_saved = baseline["expected_loss_usd"] - ev["expected_loss_usd"]
                    net_ben = loss_saved - cost
                    if ev["root_compromise_probability"] < best_eval["root_compromise_probability"] - 1e-9 or (
                        abs(ev["root_compromise_probability"] - best_eval["root_compromise_probability"]) <= 1e-9
                        and cost < best_eval["defense_spend_usd"]
                    ):
                        best_subset = list(combo)
                        best_eval = ev
                        best_net_benefit = net_ben
        else:
            # Greedy marginal risk-reduction per dollar for large control catalogs
            remaining = list(defs)
            chosen: List[DefensiveCountermeasure] = []
            spent = 0.0
            cur_ev = baseline
            while remaining:
                best_cand = None
                best_ratio = 0.0
                for d in remaining:
                    if spent + d.implementation_cost_usd > budget_usd:
                        continue
                    trial = self.evaluate_tree(root_id, nodes, chosen + [d], breach_impact_usd=breach_impact_usd)
                    red = cur_ev["expected_loss_usd"] - trial["expected_loss_usd"]
                    ratio = red / max(1.0, d.implementation_cost_usd)
                    if ratio > best_ratio:
                        best_ratio = ratio
                        best_cand = (d, trial)
                if not best_cand:
                    break
                d_pick, cur_ev = best_cand
                chosen.append(d_pick)
                remaining.remove(d_pick)
                spent += d_pick.implementation_cost_usd
            best_subset = chosen
            best_eval = cur_ev
            best_net_benefit = (baseline["expected_loss_usd"] - best_eval["expected_loss_usd"]) - spent

        risk_reduction_pct = round(
            ((baseline["root_compromise_probability"] - best_eval["root_compromise_probability"]) / max(1e-9, baseline["root_compromise_probability"])) * 100.0,
            2,
        )
        loss_avoided = round(baseline["expected_loss_usd"] - best_eval["expected_loss_usd"], 2)
        roi_pct = round(((loss_avoided - best_eval["defense_spend_usd"]) / max(1.0, best_eval["defense_spend_usd"])) * 100.0, 2) if best_subset else 0.0

        return {
            "solved_at": utc_now_iso(),
            "solver_mode": "exact_subset_optimal" if len(defs) <= 14 else "greedy_marginal_roi",
            "budget_usd": budget_usd,
            "baseline_compromise_probability": baseline["root_compromise_probability"],
            "optimized_compromise_probability": best_eval["root_compromise_probability"],
            "relative_risk_reduction_pct": risk_reduction_pct,
            "baseline_expected_loss_usd": baseline["expected_loss_usd"],
            "optimized_expected_loss_usd": best_eval["expected_loss_usd"],
            "expected_loss_avoided_usd": loss_avoided,
            "optimal_defense_spend_usd": best_eval["defense_spend_usd"],
            "portfolio_roi_pct": roi_pct,
            "selected_defenses": [
                {
                    "defense_id": d.defense_id,
                    "name": d.name,
                    "cost_usd": d.implementation_cost_usd,
                    "efficacy": d.efficacy,
                    "guarded_node_ids": list(d.guarded_node_ids),
                }
                for d in best_subset
            ],
        }

    def build_and_solve_from_h2_run(
        self,
        h2_run: Dict[str, Any],
        budget_usd: float = 40_000.0,
        breach_impact_usd: float = 6_000_000.0,
    ) -> Dict[str, Any]:
        """Automatically construct an enterprise ADTree from a Harness² run and solve optimal defenses."""
        nodes: Dict[str, ADTreeNode] = {
            "ROOT": ADTreeNode("ROOT", "Enterprise Crown-Jewel Compromise", "OR", children=[]),
        }
        vulns = list(h2_run.get("vulnerabilities", []))
        chains = list(h2_run.get("exploit_chains", {}).get("chains", []))

        domain_buckets: Dict[str, List[Dict[str, Any]]] = {}
        for v in vulns:
            sev = str(v.get("severity", "medium")).lower()
            if sev in ("critical", "high"):
                dom = str(v.get("cyber_domain", "general"))
                domain_buckets.setdefault(dom, []).append(v)

        defenses: List[DefensiveCountermeasure] = []
        # Add exploit-chain AND subtrees
        for idx, ch in enumerate(chains[:6], start=1):
            cid = f"CHAIN_{idx}"
            nodes["ROOT"].children.append(cid)
            step_ids = []
            steps = ch.get("steps", []) or ["initial_access", "lateral_pivot", "impact"]
            for s_idx, st in enumerate(steps[:4], start=1):
                sid = f"{cid}_S{s_idx}"
                step_ids.append(sid)
                nodes[sid] = ADTreeNode(sid, str(st)[:64], "LEAF", base_probability=0.68, attacker_cost_usd=2500.0)
            nodes[cid] = ADTreeNode(cid, str(ch.get("title", cid))[:64], "AND", children=step_ids)
            defenses.append(
                DefensiveCountermeasure(
                    defense_id=f"DEF-BREAK-{cid}",
                    name=f"Break Kill-Chain `{str(ch.get('title', cid))[:48]}`",
                    implementation_cost_usd=8_000.0 + idx * 1_500.0,
                    efficacy=0.92,
                    guarded_node_ids=(step_ids[0],),
                )
            )

        # Add direct critical/high domain attack OR leaves
        for idx, (dom, items) in enumerate(sorted(domain_buckets.items(), key=lambda kv: -len(kv[1]))[:6], start=1):
            did = f"DOM_{idx}"
            nodes["ROOT"].children.append(did)
            crit_n = sum(1 for x in items if str(x.get("severity", "")).lower() == "critical")
            base_p = min(0.88, 0.25 + 0.14 * crit_n + 0.05 * len(items))
            nodes[did] = ADTreeNode(did, f"Direct {dom} Exploitation ({len(items)} high/crit)", "LEAF", base_probability=base_p, attacker_cost_usd=1800.0)
            defenses.append(
                DefensiveCountermeasure(
                    defense_id=f"DEF-HARDEN-{dom.upper()[:16]}",
                    name=f"Systematic Hardening Guardrail for `{dom}`",
                    implementation_cost_usd=6_500.0 + len(items) * 600.0,
                    efficacy=0.88,
                    guarded_node_ids=(did,),
                )
            )

        if not nodes["ROOT"].children:
            nodes["LEAF_RESIDUAL"] = ADTreeNode("LEAF_RESIDUAL", "Residual Zero-Day Risk", "LEAF", base_probability=0.02, attacker_cost_usd=50000.0)
            nodes["ROOT"].children.append("LEAF_RESIDUAL")

        solved = self.solve_optimal_defense_portfolio("ROOT", nodes, defenses, budget_usd=budget_usd, breach_impact_usd=breach_impact_usd)
        solved["tree_node_count"] = len(nodes)
        solved["candidate_defense_count"] = len(defenses)
        return solved
