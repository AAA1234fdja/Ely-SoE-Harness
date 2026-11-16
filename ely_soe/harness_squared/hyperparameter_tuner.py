"""
Harness² Tree-Structured Parzen Estimator (TPE) & Successive-Halving Hyperparameter Tuner.

Optimizes continuous, integer, and categorical meta-harness hyperparameters without any
external ML/optimization packages:
  - Search space examples:
      * `linucb_alpha` (exploration coefficient in `[0.1, 2.5]`)
      * `mapek_confidence_threshold` (`[0.55, 0.95]`)
      * `fuzzer_mutations_per_seed` (`[10, 200]`)
      * `mutation_rate` (`[0.05, 0.45]`)
      * `max_parallel_stages` (`[1, 8]`)
      * `priority_boost_delta` (`[5, 35]`)
  - Implements **real TPE density-ratio acquisition** (`l(x) / g(x)` using 1D Gaussian Kernel
    Density Estimation on the top-gamma good trials vs remaining trials) to propose
    high-expected-improvement configurations.
  - Implements **Successive Halving / Hyperband brackets** to quickly discard poor
    configurations at low resource fidelity and allocate full evaluation budget to winners.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import utc_now_iso


@dataclass(frozen=True)
class HyperparamSpec:
    """Definition of a single tunable meta-harness hyperparameter."""

    name: str
    param_type: str  # float | int | categorical
    low: float = 0.0
    high: float = 1.0
    choices: Tuple[Any, ...] = ()
    log_scale: bool = False

    def sample_random(self, rng: random.Random) -> Any:
        if self.param_type == "categorical":
            return rng.choice(self.choices)
        if self.log_scale and self.low > 0:
            val = math.exp(rng.uniform(math.log(self.low), math.log(self.high)))
        else:
            val = rng.uniform(self.low, self.high)
        if self.param_type == "int":
            return int(round(max(self.low, min(self.high, val))))
        return round(max(self.low, min(self.high, val)), 5)

    def clip(self, val: float) -> Any:
        c = max(self.low, min(self.high, val))
        return int(round(c)) if self.param_type == "int" else round(c, 5)


@dataclass
class TuningTrial:
    trial_id: int
    params: Dict[str, Any]
    fidelity: float
    objective_score: float
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trial_id": self.trial_id,
            "params": dict(self.params),
            "fidelity": round(self.fidelity, 3),
            "objective_score": round(self.objective_score, 4),
            "metrics": dict(self.metrics),
        }


DEFAULT_HARNESS2_SEARCH_SPACE: Tuple[HyperparamSpec, ...] = (
    HyperparamSpec("linucb_alpha", "float", 0.15, 2.25),
    HyperparamSpec("mapek_confidence_threshold", "float", 0.55, 0.92),
    HyperparamSpec("nsga2_mutation_rate", "float", 0.05, 0.40),
    HyperparamSpec("fuzzer_mutations_per_seed", "int", 12, 160),
    HyperparamSpec("priority_boost_delta", "int", 5, 35),
    HyperparamSpec("selection_strategy", "categorical", choices=("linucb", "thompson", "ucb1_hybrid")),
)


class TPEHyperparameterTuner:
    """
    Zero-dependency Tree-structured Parzen Estimator (TPE) + Successive Halving tuner
    for Harness² meta-parameters.
    """

    def __init__(
        self,
        search_space: Sequence[HyperparamSpec] = DEFAULT_HARNESS2_SEARCH_SPACE,
        gamma: float = 0.25,
        n_startup_trials: int = 6,
        n_ei_candidates: int = 24,
        seed: int = 2026,
    ) -> None:
        self.search_space = list(search_space)
        self.gamma = max(0.1, min(0.5, gamma))
        self.n_startup_trials = max(2, n_startup_trials)
        self.n_ei_candidates = max(8, n_ei_candidates)
        self.rng = random.Random(seed)
        self.trials: List[TuningTrial] = []

    def suggest(self) -> Dict[str, Any]:
        """Propose next hyperparameter configuration maximizing TPE ratio l(x) / g(x)."""
        if len(self.trials) < self.n_startup_trials:
            return {spec.name: spec.sample_random(self.rng) for spec in self.search_space}

        ordered = sorted(self.trials, key=lambda t: t.objective_score, reverse=True)
        n_good = max(2, int(math.ceil(len(ordered) * self.gamma)))
        good_trials = ordered[:n_good]
        bad_trials = ordered[n_good:] or ordered[-1:]

        best_cfg: Dict[str, Any] = {}
        best_log_ratio = -1e18

        for _ in range(self.n_ei_candidates):
            cand: Dict[str, Any] = {}
            log_ratio = 0.0
            for spec in self.search_space:
                val, lr = self._sample_and_score_param(spec, good_trials, bad_trials)
                cand[spec.name] = val
                log_ratio += lr
            if log_ratio > best_log_ratio:
                best_log_ratio = log_ratio
                best_cfg = cand

        return best_cfg

    def report_trial(
        self,
        params: Dict[str, Any],
        objective_score: float,
        fidelity: float = 1.0,
        metrics: Optional[Dict[str, Any]] = None,
    ) -> TuningTrial:
        trial = TuningTrial(
            trial_id=len(self.trials) + 1,
            params=dict(params),
            fidelity=fidelity,
            objective_score=float(objective_score),
            metrics=dict(metrics or {}),
        )
        self.trials.append(trial)
        return trial

    def optimize(
        self,
        objective_fn: Callable[[Dict[str, Any], float], Tuple[float, Dict[str, Any]]],
        n_trials: int = 20,
        fidelity: float = 1.0,
    ) -> Dict[str, Any]:
        """Run sequential TPE optimization loop for `n_trials` evaluations."""
        for _ in range(max(1, n_trials)):
            cfg = self.suggest()
            score, meta = objective_fn(cfg, fidelity)
            self.report_trial(cfg, score, fidelity=fidelity, metrics=meta)

        best = max(self.trials, key=lambda t: t.objective_score)
        return {
            "completed_at": utc_now_iso(),
            "algorithm": "TPE_KDE_DensityRatio",
            "total_trials": len(self.trials),
            "best_trial": best.to_dict(),
            "score_progression": [round(t.objective_score, 4) for t in self.trials],
            "param_importance": self.estimate_param_importance(),
        }

    def run_successive_halving(
        self,
        objective_fn: Callable[[Dict[str, Any], float], Tuple[float, Dict[str, Any]]],
        n_initial_configs: int = 12,
        min_fidelity: float = 0.25,
        max_fidelity: float = 1.0,
        eta: int = 2,
    ) -> Dict[str, Any]:
        """
        Hyperband-style Successive Halving bracket: evaluates many configurations at cheap
        fidelity and promotes top `1/eta` fraction to progressively higher fidelities.
        """
        configs = [self.suggest() for _ in range(max(2, n_initial_configs))]
        fidelity = min_fidelity
        rounds_log: List[Dict[str, Any]] = []

        while configs:
            scored: List[Tuple[float, Dict[str, Any], TuningTrial]] = []
            for cfg in configs:
                score, meta = objective_fn(cfg, fidelity)
                tr = self.report_trial(cfg, score, fidelity=fidelity, metrics=meta)
                scored.append((score, cfg, tr))

            scored.sort(key=lambda x: x[0], reverse=True)
            rounds_log.append({
                "fidelity": round(fidelity, 3),
                "evaluated": len(scored),
                "top_score": round(scored[0][0], 4),
                "median_score": round(scored[len(scored) // 2][0], 4),
            })

            if fidelity >= max_fidelity - 1e-6 or len(scored) <= 1:
                break

            keep_n = max(1, len(scored) // max(2, eta))
            configs = [c for _, c, _ in scored[:keep_n]]
            fidelity = min(max_fidelity, fidelity * eta)

        best = max(self.trials, key=lambda t: (t.fidelity, t.objective_score))
        return {
            "completed_at": utc_now_iso(),
            "algorithm": "TPE_Successive_Halving",
            "rounds": rounds_log,
            "total_evaluations": len(self.trials),
            "best_trial": best.to_dict(),
            "param_importance": self.estimate_param_importance(),
        }

    def estimate_param_importance(self) -> Dict[str, float]:
        """Estimate univariate rank-correlation importance for each numeric hyperparameter."""
        if len(self.trials) < 4:
            return {}
        scores = [t.objective_score for t in self.trials]
        s_mean = sum(scores) / len(scores)
        s_var = sum((s - s_mean) ** 2 for s in scores)
        if s_var <= 1e-12:
            return {spec.name: 0.0 for spec in self.search_space}

        imp: Dict[str, float] = {}
        for spec in self.search_space:
            if spec.param_type == "categorical":
                # Variance of group means / total variance (eta-squared)
                groups: Dict[Any, List[float]] = {}
                for t in self.trials:
                    groups.setdefault(t.params.get(spec.name), []).append(t.objective_score)
                between = sum(len(vs) * ((sum(vs) / len(vs)) - s_mean) ** 2 for vs in groups.values())
                imp[spec.name] = round(min(1.0, between / s_var), 4)
            else:
                xs = [float(t.params.get(spec.name, spec.low)) for t in self.trials]
                x_mean = sum(xs) / len(xs)
                x_var = sum((x - x_mean) ** 2 for x in xs)
                if x_var <= 1e-12:
                    imp[spec.name] = 0.0
                else:
                    cov = sum((x - x_mean) * (s - s_mean) for x, s in zip(xs, scores))
                    r = abs(cov / math.sqrt(x_var * s_var))
                    imp[spec.name] = round(min(1.0, r), 4)
        return imp

    def _sample_and_score_param(
        self,
        spec: HyperparamSpec,
        good: Sequence[TuningTrial],
        bad: Sequence[TuningTrial],
    ) -> Tuple[Any, float]:
        if spec.param_type == "categorical":
            counts_g = {c: 1.0 for c in spec.choices}
            counts_b = {c: 1.0 for c in spec.choices}
            for t in good:
                v = t.params.get(spec.name)
                if v in counts_g:
                    counts_g[v] += 1.0
            for t in bad:
                v = t.params.get(spec.name)
                if v in counts_b:
                    counts_b[v] += 1.0
            tot_g = sum(counts_g.values())
            tot_b = sum(counts_b.values())
            # Sample proportional to good distribution
            r = self.rng.random() * tot_g
            acc = 0.0
            chosen = spec.choices[0]
            for c, w in counts_g.items():
                acc += w
                if r <= acc:
                    chosen = c
                    break
            p_g = counts_g[chosen] / tot_g
            p_b = counts_b[chosen] / tot_b
            return chosen, math.log(max(1e-9, p_g) / max(1e-9, p_b))

        # Numeric parameter: 1D Gaussian KDE over good vs bad trials
        g_vals = [float(t.params.get(spec.name, spec.low)) for t in good]
        b_vals = [float(t.params.get(spec.name, spec.low)) for t in bad]
        span = max(1e-6, spec.high - spec.low)
        bw_g = max(span * 0.06, self._silverman_bw(g_vals, span))
        bw_b = max(span * 0.08, self._silverman_bw(b_vals, span))

        center = self.rng.choice(g_vals)
        raw = self.rng.gauss(center, bw_g)
        cand_val = spec.clip(raw)
        x = float(cand_val)

        l_x = self._kde_pdf(x, g_vals, bw_g) + 1e-6 / span
        g_x = self._kde_pdf(x, b_vals, bw_b) + 1e-6 / span
        return cand_val, math.log(l_x / g_x)

    @staticmethod
    def _silverman_bw(vals: Sequence[float], span: float) -> float:
        n = len(vals)
        if n < 2:
            return span * 0.2
        m = sum(vals) / n
        sd = math.sqrt(sum((v - m) ** 2 for v in vals) / (n - 1))
        if sd <= 1e-9:
            return span * 0.15
        return 1.06 * sd * (n ** -0.2)

    @staticmethod
    def _kde_pdf(x: float, samples: Sequence[float], bw: float) -> float:
        inv_norm = 1.0 / (len(samples) * bw * math.sqrt(2.0 * math.pi))
        total = 0.0
        for s in samples:
            z = (x - s) / bw
            total += math.exp(-0.5 * z * z)
        return total * inv_norm
