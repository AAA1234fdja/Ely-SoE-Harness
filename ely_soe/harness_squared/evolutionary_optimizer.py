"""
Harness² NSGA-II Multi-Objective Pareto Evolutionary Genome Optimizer.

Evolves a population of `HarnessGenome` configurations to discover the **Pareto-Optimal
Frontier** balancing 4 competing cybersecurity testing objectives simultaneously:
  1. **Maximize Recall & Confirmed Critical Yield** (`recall_yield_score`)
  2. **Maximize Cross-Domain Exploit-Chain & Compliance Coverage** (`chain_coverage_score`)
  3. **Maximize Speed & Compute Efficiency** (`efficiency_speed_score`)
  4. **Maximize Precision / Signal-to-Noise Ratio** (`precision_signal_score`)

Implements real **NSGA-II (Deb et al.)**:
  - Fast Non-Dominated Sorting (`rank 0` = exact Pareto front)
  - Objective-normalized Crowding Distance preservation for diversity along the frontier
  - Binary Tournament Selection + Safety-Gated Uniform Crossover & Adaptive Mutation
  - Every offspring passes `MetaSafetyInvariantGuard` verification — safety flags are
    immutable chromosomes that can NEVER mutate to `False`!
"""

from __future__ import annotations

import random
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import new_id
from ely_soe.harness_squared.bandit_optimizer import GENOME_ARM_TEMPLATES
from ely_soe.harness_squared.models import (
    HarnessGenome,
    ParetoFrontierPoint,
    TargetFingerprint,
)
from ely_soe.harness_squared.safety_invariant_guard import MetaSafetyInvariantGuard


ALL_EVOLVABLE_STAGES: Tuple[str, ...] = (
    "web_injection", "web_client_protocol", "web_ssrf_deser", "auth_access",
    "api_microservices", "secrets_dlp", "tls_crypto", "iac_cicd",
    "kubernetes_container", "container_runtime_ebpf", "supply_chain_sbom",
    "binary_memory", "firmware_iot_ot", "live_sandbox_dast",
    "cloud_iam_graph", "active_directory_graph", "network_zero_trust",
    "mitre_sigma_purple", "bas_campaigns", "ai_llm_redteam", "grammar_fuzzer",
)

STAGE_ESTIMATED_COST_MS: Dict[str, int] = {
    "web_injection": 140,
    "web_client_protocol": 110,
    "web_ssrf_deser": 120,
    "auth_access": 110,
    "api_microservices": 90,
    "secrets_dlp": 130,
    "tls_crypto": 95,
    "iac_cicd": 120,
    "kubernetes_container": 100,
    "container_runtime_ebpf": 85,
    "supply_chain_sbom": 110,
    "binary_memory": 150,
    "firmware_iot_ot": 90,
    "live_sandbox_dast": 420,
    "cloud_iam_graph": 80,
    "active_directory_graph": 90,
    "network_zero_trust": 75,
    "mitre_sigma_purple": 160,
    "bas_campaigns": 140,
    "ai_llm_redteam": 130,
    "grammar_fuzzer": 190,
}

STAGE_TO_DOMAIN_KEY: Dict[str, str] = {
    "web_injection": "web_injection",
    "web_client_protocol": "web_client_protocol",
    "web_ssrf_deser": "web_ssrf_xxe_ssti_deser",
    "auth_access": "auth_access_control",
    "api_microservices": "api_microservices",
    "secrets_dlp": "auth_access_control",
    "tls_crypto": "tls_cryptography",
    "iac_cicd": "iac_cicd",
    "kubernetes_container": "kubernetes_container",
    "container_runtime_ebpf": "kubernetes_container",
    "supply_chain_sbom": "iac_cicd",
    "binary_memory": "binary_memory_safety",
    "firmware_iot_ot": "firmware_iot_ot",
    "live_sandbox_dast": "web_injection",
    "cloud_iam_graph": "cloud_iam",
    "active_directory_graph": "identity_active_directory",
    "network_zero_trust": "network_protocol",
    "mitre_sigma_purple": "adversary_emulation",
    "bas_campaigns": "adversary_emulation",
    "ai_llm_redteam": "adversary_emulation",
    "grammar_fuzzer": "threat_modeling",
}


class NSGA2GenomeOptimizer:
    """Multi-objective NSGA-II evolutionary optimizer for `HarnessGenome` populations."""

    def __init__(
        self,
        invariant_guard: Optional[MetaSafetyInvariantGuard] = None,
        seed: int = 20261115,
    ) -> None:
        self.invariant_guard = invariant_guard or MetaSafetyInvariantGuard()
        self._rng = random.Random(seed)

    @staticmethod
    def dominates(a: ParetoFrontierPoint, b: ParetoFrontierPoint) -> bool:
        """Return True iff objective vector `a` Pareto-dominates `b` (all >= and at least one >)."""
        va, vb = a.objective_vector(), b.objective_vector()
        return all(x >= y for x, y in zip(va, vb)) and any(x > y for x, y in zip(va, vb))

    def fast_non_dominated_sort(self, points: List[ParetoFrontierPoint]) -> List[List[ParetoFrontierPoint]]:
        """Deb et al. NSGA-II fast non-dominated sorting into Pareto fronts F_0, F_1, ..."""
        n = len(points)
        dom_sets: List[List[int]] = [[] for _ in range(n)]
        dom_counts: List[int] = [0] * n
        fronts_idx: List[List[int]] = [[]]

        for p in range(n):
            for q in range(n):
                if p == q:
                    continue
                if self.dominates(points[p], points[q]):
                    dom_sets[p].append(q)
                elif self.dominates(points[q], points[p]):
                    dom_counts[p] += 1
            if dom_counts[p] == 0:
                points[p].pareto_rank = 0
                fronts_idx[0].append(p)

        i = 0
        while i < len(fronts_idx) and fronts_idx[i]:
            nxt: List[int] = []
            for p in fronts_idx[i]:
                for q in dom_sets[p]:
                    dom_counts[q] -= 1
                    if dom_counts[q] == 0:
                        points[q].pareto_rank = i + 1
                        nxt.append(q)
            i += 1
            if nxt:
                fronts_idx.append(nxt)

        return [[points[idx] for idx in f] for f in fronts_idx if f]

    @staticmethod
    def assign_crowding_distance(front: List[ParetoFrontierPoint]) -> None:
        if not front:
            return
        for p in front:
            p.crowding_distance = 0.0
        if len(front) <= 2:
            for p in front:
                p.crowding_distance = float("inf")
            return

        for obj_idx in range(4):
            front.sort(key=lambda p: p.objective_vector()[obj_idx])
            front[0].crowding_distance = float("inf")
            front[-1].crowding_distance = float("inf")
            lo = front[0].objective_vector()[obj_idx]
            hi = front[-1].objective_vector()[obj_idx]
            span = max(1e-9, hi - lo)
            for k in range(1, len(front) - 1):
                if front[k].crowding_distance != float("inf"):
                    prev_v = front[k - 1].objective_vector()[obj_idx]
                    next_v = front[k + 1].objective_vector()[obj_idx]
                    front[k].crowding_distance += (next_v - prev_v) / span

    def evaluate_surrogate(
        self,
        genome: HarnessGenome,
        fingerprint: TargetFingerprint,
        empirical_stage_means: Optional[Dict[str, float]] = None,
    ) -> ParetoFrontierPoint:
        """Deterministic physics-informed surrogate evaluating a candidate genome on a target fingerprint."""
        means = empirical_stage_means or {}
        stages = set(genome.enabled_stages)
        if not stages:
            return ParetoFrontierPoint(genome.genome_id, genome.name, genome.generation, 0.0, 0.0, 100.0, 0.0, genome_dict=genome.to_dict())

        # Objective 1: Recall & Critical Yield aligned with target affinities + empirical Thompson means
        weighted_recall = 0.0
        max_possible = 0.0
        for st in ALL_EVOLVABLE_STAGES:
            dom = STAGE_TO_DOMAIN_KEY.get(st, "threat_modeling")
            aff = float(fingerprint.domain_affinities.get(dom, 0.4))
            emp = float(means.get(st, 0.55))
            val = aff * (0.65 + 0.35 * emp)
            max_possible += val
            if st in stages:
                weighted_recall += val

        dast_boost = 1.08 if ("live_sandbox_dast" in stages and genome.enable_live_sandbox_dast) else 1.0
        agg_boost = 1.0 + 0.10 * genome.drilldown_aggressiveness
        recall_score = min(100.0, ((weighted_recall / max(1e-6, max_possible)) * 100.0) * dast_boost * agg_boost)

        # Objective 2: Multi-domain Exploit-Chain & Compliance Coverage
        distinct_domains = {STAGE_TO_DOMAIN_KEY.get(s, "other") for s in stages}
        chain_bonus = 12.0 if ({"cloud_iam_graph", "mitre_sigma_purple"} & stages) else 0.0
        coverage_score = min(100.0, (len(distinct_domains) / 14.0) * 88.0 + chain_bonus)

        # Objective 3: Speed / Compute Efficiency (fewer low-affinity stages + pruning = higher score)
        est_ms = sum(STAGE_ESTIMATED_COST_MS.get(s, 100) for s in stages)
        est_ms *= max(0.70, 1.0 - 0.30 * genome.prune_threshold_yield)
        if genome.enable_grammar_fuzzing:
            est_ms += genome.fuzz_iterations_per_grammar * 8.0
        max_cost = sum(STAGE_ESTIMATED_COST_MS.values()) + 200.0
        speed_score = max(5.0, min(100.0, (1.0 - (est_ms / max_cost)) * 100.0))

        # Objective 4: Precision / Signal-to-Noise Ratio (penalize running irrelevant low-affinity stages)
        aff_values = [float(fingerprint.domain_affinities.get(STAGE_TO_DOMAIN_KEY.get(s, "threat_modeling"), 0.3)) for s in stages]
        mean_aff = sum(aff_values) / len(aff_values)
        dast_prec_bonus = 10.0 if genome.enable_live_sandbox_dast else 0.0
        prune_bonus = 8.0 * min(1.0, genome.prune_threshold_yield * 5.0)
        precision_score = min(100.0, mean_aff * 86.0 + dast_prec_bonus + prune_bonus)

        return ParetoFrontierPoint(
            genome_id=genome.genome_id,
            genome_name=genome.name,
            generation=genome.generation,
            recall_yield_score=round(recall_score, 2),
            chain_coverage_score=round(coverage_score, 2),
            efficiency_speed_score=round(speed_score, 2),
            precision_signal_score=round(precision_score, 2),
            genome_dict=genome.to_dict(),
        )

    def crossover_and_mutate(self, p1: HarnessGenome, p2: HarnessGenome, gen_idx: int) -> HarnessGenome:
        """Safety-gated uniform crossover & bounded mutation preserving all non-relaxable invariants."""
        s1, s2 = set(p1.enabled_stages), set(p2.enabled_stages)
        union = sorted(s1 | s2)
        child_stages = [s for s in union if (s in s1 and s in s2) or self._rng.random() < 0.5]

        # Mutation: toggle 1–2 stages
        if self._rng.random() < 0.45:
            cand = self._rng.choice(ALL_EVOLVABLE_STAGES)
            if cand in child_stages and len(child_stages) > 4:
                child_stages.remove(cand)
            elif cand not in child_stages:
                child_stages.append(cand)
        if not child_stages:
            child_stages = ["web_injection", "secrets_dlp", "auth_access", "iac_cicd"]

        agg = min(0.95, max(0.20, ((p1.drilldown_aggressiveness + p2.drilldown_aggressiveness) / 2.0) + self._rng.uniform(-0.10, 0.10)))
        prune = min(0.25, max(0.01, ((p1.prune_threshold_yield + p2.prune_threshold_yield) / 2.0) + self._rng.uniform(-0.03, 0.03)))
        budget = min(65_000, max(10_000, int((p1.total_budget_ms + p2.total_budget_ms) / 2) + self._rng.randint(-3000, 3000)))
        fuzz_n = min(24, max(4, int((p1.fuzz_iterations_per_grammar + p2.fuzz_iterations_per_grammar) / 2) + self._rng.randint(-3, 3)))

        child = HarnessGenome(
            genome_id=new_id("gen"),
            name=f"Evolved-G{gen_idx}-{len(child_stages)}st",
            profile_family="evolved",
            enabled_stages=sorted(set(child_stages)),
            stage_priorities={s: round(self._rng.uniform(0.4, 0.95), 3) for s in child_stages},
            stage_budgets_ms={s: max(800, int(budget / max(1, len(child_stages)))) for s in child_stages},
            total_budget_ms=budget,
            enable_live_sandbox_dast="live_sandbox_dast" in child_stages,
            enable_enterprise_graph_sim=bool({"cloud_iam_graph", "active_directory_graph", "network_zero_trust"} & set(child_stages)),
            enable_mitre_emulation="mitre_sigma_purple" in child_stages,
            enable_ai_redteam="ai_llm_redteam" in child_stages,
            enable_grammar_fuzzing="grammar_fuzzer" in child_stages,
            fuzz_iterations_per_grammar=fuzz_n,
            drilldown_aggressiveness=round(agg, 3),
            prune_threshold_yield=round(prune, 3),
            max_adaptation_rounds=min(12, max(4, int((p1.max_adaptation_rounds + p2.max_adaptation_rounds) / 2))),
            generation=gen_idx,
            parent_ids=[p1.genome_id, p2.genome_id],
        )
        # Non-negotiable invariant verification on every offspring
        self.invariant_guard.verify_genome(child, raise_on_violation=True)
        return child

    def evolve_pareto_frontier(
        self,
        fingerprint: TargetFingerprint,
        *,
        population_size: int = 16,
        generations: int = 6,
        empirical_stage_means: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """Run NSGA-II multi-objective evolution and return the exact rank-0 Pareto frontier."""
        # Seed initial population from built-in archetypes + randomized valid perturbations
        pop_genomes: Dict[str, HarnessGenome] = {}
        for arm_id, tpl in GENOME_ARM_TEMPLATES.items():
            g = HarnessGenome(
                genome_id=new_id("gen"),
                name=f"Seed-{arm_id}",
                profile_family=arm_id,
                enabled_stages=list(tpl["enabled_stages"]),
                stage_priorities={s: 0.7 for s in tpl["enabled_stages"]},
                stage_budgets_ms={s: max(900, int(tpl["total_budget_ms"] / max(1, len(tpl["enabled_stages"])))) for s in tpl["enabled_stages"]},
                total_budget_ms=int(tpl["total_budget_ms"]),
                enable_live_sandbox_dast=bool(tpl["enable_live_sandbox_dast"]),
                enable_enterprise_graph_sim=bool(tpl["enable_enterprise_graph_sim"]),
                enable_mitre_emulation=bool(tpl["enable_mitre_emulation"]),
                enable_ai_redteam=bool(tpl["enable_ai_redteam"]),
                enable_grammar_fuzzing=bool(tpl["enable_grammar_fuzzing"]),
                fuzz_iterations_per_grammar=int(tpl["fuzz_iterations_per_grammar"]),
                drilldown_aggressiveness=float(tpl["drilldown_aggressiveness"]),
                prune_threshold_yield=float(tpl["prune_threshold_yield"]),
                max_adaptation_rounds=int(tpl["max_adaptation_rounds"]),
                generation=0,
            )
            pop_genomes[g.genome_id] = g

        seed_list = list(pop_genomes.values())
        while len(pop_genomes) < population_size:
            p1, p2 = self._rng.sample(seed_list, 2)
            child = self.crossover_and_mutate(p1, p2, 0)
            pop_genomes[child.genome_id] = child

        evaluated: List[ParetoFrontierPoint] = [
            self.evaluate_surrogate(g, fingerprint, empirical_stage_means) for g in pop_genomes.values()
        ]

        for gen in range(1, generations + 1):
            fronts = self.fast_non_dominated_sort(evaluated)
            for f in fronts:
                self.assign_crowding_distance(f)

            # Generate offspring population via binary tournament selection
            offspring_pts: List[ParetoFrontierPoint] = []
            for _ in range(population_size):
                p1_pt = self._tournament(evaluated)
                p2_pt = self._tournament(evaluated)
                g1, g2 = pop_genomes[p1_pt.genome_id], pop_genomes[p2_pt.genome_id]
                child = self.crossover_and_mutate(g1, g2, gen)
                pop_genomes[child.genome_id] = child
                offspring_pts.append(self.evaluate_surrogate(child, fingerprint, empirical_stage_means))

            # Elitist survival selection (NSGA-II)
            combined = evaluated + offspring_pts
            new_fronts = self.fast_non_dominated_sort(combined)
            next_pop: List[ParetoFrontierPoint] = []
            for f in new_fronts:
                self.assign_crowding_distance(f)
                if len(next_pop) + len(f) <= population_size:
                    next_pop.extend(f)
                else:
                    f.sort(key=lambda p: -p.crowding_distance)
                    next_pop.extend(f[: population_size - len(next_pop)])
                    break
            evaluated = next_pop

        final_fronts = self.fast_non_dominated_sort(evaluated)
        for f in final_fronts:
            self.assign_crowding_distance(f)
        pareto_front = final_fronts[0] if final_fronts else []
        pareto_front.sort(key=lambda p: -(p.recall_yield_score + p.chain_coverage_score + p.efficiency_speed_score + p.precision_signal_score))

        # Pick 3 named knee/extreme recommendations from the Pareto front
        best_fast = max(pareto_front, key=lambda p: p.efficiency_speed_score) if pareto_front else None
        best_recall = max(pareto_front, key=lambda p: p.recall_yield_score + p.chain_coverage_score) if pareto_front else None
        best_balanced = pareto_front[0] if pareto_front else None

        return {
            "generations_evolved": generations,
            "population_size": population_size,
            "pareto_front_size": len(pareto_front),
            "recommendations": {
                "balanced_knee": best_balanced.to_dict() if best_balanced else None,
                "max_recall_deep": best_recall.to_dict() if best_recall else None,
                "max_speed_ci": best_fast.to_dict() if best_fast else None,
            },
            "pareto_frontier": [p.to_dict() for p in pareto_front],
            "recommended_genome": pop_genomes[best_balanced.genome_id] if best_balanced else None,
        }

    def _tournament(self, pop: List[ParetoFrontierPoint]) -> ParetoFrontierPoint:
        a, b = self._rng.sample(pop, 2)
        if a.pareto_rank != b.pareto_rank:
            return a if a.pareto_rank < b.pareto_rank else b
        return a if a.crowding_distance >= b.crowding_distance else b
