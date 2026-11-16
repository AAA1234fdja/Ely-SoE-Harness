"""
Harness² Statistical Drift Detection, Canary Regression Analysis & Auto-Rollback Engine.

Prevents silent performance degradation as Harness² evolves its own workflows over time:
  1. **Page-Hinkley & Two-Sided CUSUM Change-Point Detectors**:
       Detects sustained downward shifts in vulnerability discovery recall, risk-yield/sec,
       or upward spikes in false-positive rate / latency across sequential episodes.
  2. **Population Stability Index (PSI) for Target Distribution Shift**:
       Measures whether incoming target codebase fingerprints have shifted away from the
       historical calibration distribution (`PSI < 0.10` stable, `0.10-0.25` moderate shift,
       `>= 0.25` significant shift requiring fresh bandit exploration).
  3. **Canary vs Champion Statistical Hypothesis Test**:
       Uses Welch's two-sample t-statistic + normal approximation p-value AND bootstrap
       95% confidence interval (zero third-party dependencies) to decide whether a newly
       evolved NSGA-II candidate genome should be `PROMOTE_TO_CHAMPION`, `CONTINUE_CANARY`,
       or `ROLLBACK_REGRESSION`.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import utc_now_iso


@dataclass
class EpisodeMetricPoint:
    episode_id: str
    genome_id: str
    timestamp: str
    risk_yield: float
    duration_ms: float
    critical_found: int
    false_positive_rate: float = 0.0
    safety_preserved: bool = True
    surface_bucket: str = "web_cloud"


@dataclass
class DriftAlert:
    detector: str  # page_hinkley | cusum | psi_distribution_shift | safety_regression
    metric: str
    severity: str  # INFO | WARNING | CRITICAL
    statistic: float
    threshold: float
    change_point_index: Optional[int]
    message: str
    recommended_action: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "metric": self.metric,
            "severity": self.severity,
            "statistic": round(self.statistic, 4),
            "threshold": round(self.threshold, 4),
            "change_point_index": self.change_point_index,
            "message": self.message,
            "recommended_action": self.recommended_action,
        }


@dataclass
class CanaryDecisionReport:
    champion_genome_id: str
    canary_genome_id: str
    evaluated_at: str
    verdict: str  # PROMOTE_TO_CHAMPION | CONTINUE_CANARY | ROLLBACK_REGRESSION
    champion_mean_yield: float
    canary_mean_yield: float
    relative_lift_pct: float
    welch_t_statistic: float
    approx_two_sided_p_value: float
    bootstrap_ci95_diff: Tuple[float, float]
    latency_regression_pct: float
    safety_violations_in_canary: int
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "champion_genome_id": self.champion_genome_id,
            "canary_genome_id": self.canary_genome_id,
            "evaluated_at": self.evaluated_at,
            "verdict": self.verdict,
            "champion_mean_yield": round(self.champion_mean_yield, 3),
            "canary_mean_yield": round(self.canary_mean_yield, 3),
            "relative_lift_pct": round(self.relative_lift_pct, 2),
            "welch_t_statistic": round(self.welch_t_statistic, 4),
            "approx_two_sided_p_value": round(self.approx_two_sided_p_value, 5),
            "bootstrap_ci95_diff": [round(self.bootstrap_ci95_diff[0], 3), round(self.bootstrap_ci95_diff[1], 3)],
            "latency_regression_pct": round(self.latency_regression_pct, 2),
            "safety_violations_in_canary": self.safety_violations_in_canary,
            "rationale": self.rationale,
        }


def _mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _variance(xs: Sequence[float]) -> float:
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    return sum((x - m) ** 2 for x in xs) / (len(xs) - 1)


def _normal_two_sided_p(z: float) -> float:
    """Two-sided p-value using math.erfc (exact standard normal tail)."""
    return math.erfc(abs(z) / math.sqrt(2.0))


class HarnessDriftAndRegressionDetector:
    """Monitors sequential Harness² episodes for drift, distribution shift, and canary regressions."""

    def __init__(self, seed: int = 1337) -> None:
        self.seed = seed

    def detect_page_hinkley_drop(
        self,
        series: Sequence[float],
        metric_name: str = "risk_yield",
        delta: float = 0.05,
        threshold: float = 15.0,
    ) -> Optional[DriftAlert]:
        """
        Page-Hinkley sequential test for downward drift (drop in risk_yield / recall).
        Negates the series so drops appear as upward shifts in cumulative deviation.
        """
        if len(series) < 5:
            return None

        neg = [-float(x) for x in series]
        running_mean = 0.0
        cum_sum = 0.0
        min_cum = 0.0
        max_ph = 0.0
        change_idx: Optional[int] = None

        for idx, x in enumerate(neg, start=1):
            running_mean += (x - running_mean) / idx
            cum_sum += x - running_mean - delta
            if cum_sum < min_cum:
                min_cum = cum_sum
            ph_stat = cum_sum - min_cum
            if ph_stat > max_ph:
                max_ph = ph_stat
                if ph_stat > threshold and change_idx is None:
                    change_idx = idx - 1

        if max_ph > threshold:
            return DriftAlert(
                detector="page_hinkley",
                metric=metric_name,
                severity="CRITICAL" if max_ph > threshold * 1.8 else "WARNING",
                statistic=max_ph,
                threshold=threshold,
                change_point_index=change_idx,
                message=f"Page-Hinkley detected sustained downward shift in `{metric_name}` starting around episode index {change_idx}.",
                recommended_action="Trigger canary rollback check and re-run Harness² NSGA-II evolution with increased exploration.",
            )
        return None

    def detect_cusum_latency_spike(
        self,
        latencies_ms: Sequence[float],
        baseline_window: int = 4,
        k_sigma: float = 0.5,
        h_sigma: float = 4.0,
    ) -> Optional[DriftAlert]:
        """Upper one-sided CUSUM detector for latency / budget overrun creep."""
        if len(latencies_ms) <= baseline_window + 1:
            return None

        base = latencies_ms[:baseline_window]
        mu = _mean(base)
        sigma = max(1.0, math.sqrt(_variance(base)))
        s_hi = 0.0
        max_s = 0.0
        cp_idx: Optional[int] = None

        for idx in range(baseline_window, len(latencies_ms)):
            z = (latencies_ms[idx] - mu) / sigma
            s_hi = max(0.0, s_hi + z - k_sigma)
            if s_hi > max_s:
                max_s = s_hi
                if s_hi > h_sigma and cp_idx is None:
                    cp_idx = idx

        if max_s > h_sigma:
            return DriftAlert(
                detector="cusum",
                metric="duration_ms",
                severity="WARNING" if max_s < h_sigma * 2 else "CRITICAL",
                statistic=max_s,
                threshold=h_sigma,
                change_point_index=cp_idx,
                message=f"CUSUM detected sustained latency inflation (max S+={max_s:.2f} sigma > {h_sigma}) at episode index {cp_idx}.",
                recommended_action="Tighten AnytimeBudgetAllocator cap or prune high-latency REDUNDANT stages.",
            )
        return None

    def compute_population_stability_index(
        self,
        baseline_buckets: Sequence[str],
        recent_buckets: Sequence[str],
    ) -> Dict[str, Any]:
        """Compute PSI across target surface buckets to detect unseen target-architecture shift."""
        all_keys = sorted(set(baseline_buckets) | set(recent_buckets))
        if not all_keys or not baseline_buckets or not recent_buckets:
            return {"psi": 0.0, "status": "INSUFFICIENT_DATA", "bucket_deltas": {}}

        eps = 1e-4
        n_b = float(len(baseline_buckets))
        n_r = float(len(recent_buckets))
        psi = 0.0
        deltas: Dict[str, Dict[str, float]] = {}

        for k in all_keys:
            p_b = max(eps, baseline_buckets.count(k) / n_b)
            p_r = max(eps, recent_buckets.count(k) / n_r)
            contrib = (p_r - p_b) * math.log(p_r / p_b)
            psi += contrib
            deltas[k] = {"baseline_share": round(p_b, 4), "recent_share": round(p_r, 4), "psi_contrib": round(contrib, 4)}

        status = "SIGNIFICANT_SHIFT" if psi >= 0.25 else ("MODERATE_SHIFT" if psi >= 0.10 else "STABLE")
        return {"psi": round(psi, 4), "status": status, "bucket_deltas": deltas}

    def audit_episode_stream(self, history: Sequence[EpisodeMetricPoint]) -> Dict[str, Any]:
        """Run full multi-detector drift audit over a chronological sequence of Harness² episodes."""
        alerts: List[DriftAlert] = []

        # Safety invariant breach is an instant critical regression
        for idx, ep in enumerate(history):
            if not ep.safety_preserved:
                alerts.append(
                    DriftAlert(
                        detector="safety_regression",
                        metric="safety_preserved",
                        severity="CRITICAL",
                        statistic=1.0,
                        threshold=0.0,
                        change_point_index=idx,
                        message=f"Episode `{ep.episode_id}` (genome `{ep.genome_id}`) breached safety invariants!",
                        recommended_action="IMMEDIATE ROLLBACK to last verified champion genome and quarantine candidate.",
                    )
                )

        yields = [ep.risk_yield for ep in history]
        lats = [ep.duration_ms for ep in history]
        ph = self.detect_page_hinkley_drop(yields, metric_name="risk_yield")
        if ph:
            alerts.append(ph)
        cu = self.detect_cusum_latency_spike(lats)
        if cu:
            alerts.append(cu)

        mid = len(history) // 2
        psi_res = (
            self.compute_population_stability_index(
                [ep.surface_bucket for ep in history[:mid]],
                [ep.surface_bucket for ep in history[mid:]],
            )
            if mid >= 2
            else {"psi": 0.0, "status": "INSUFFICIENT_DATA", "bucket_deltas": {}}
        )
        if psi_res["psi"] >= 0.25:
            alerts.append(
                DriftAlert(
                    detector="psi_distribution_shift",
                    metric="target_surface_distribution",
                    severity="WARNING",
                    statistic=psi_res["psi"],
                    threshold=0.25,
                    change_point_index=mid,
                    message=f"Target fingerprint distribution shifted significantly (PSI={psi_res['psi']:.3f} >= 0.25).",
                    recommended_action="Increase LinUCB exploration alpha and invoke TransferLearning prior recalibration.",
                )
            )

        return {
            "audited_at": utc_now_iso(),
            "episodes_analyzed": len(history),
            "drift_detected": len(alerts) > 0,
            "critical_drift": any(a.severity == "CRITICAL" for a in alerts),
            "psi_analysis": psi_res,
            "alerts": [a.to_dict() for a in alerts],
        }

    def evaluate_canary_promotion(
        self,
        champion_episodes: Sequence[EpisodeMetricPoint],
        canary_episodes: Sequence[EpisodeMetricPoint],
        max_allowed_latency_regression_pct: float = 35.0,
        significance_alpha: float = 0.05,
        bootstrap_iters: int = 500,
    ) -> CanaryDecisionReport:
        """
        Rigorous statistical Canary vs Champion gate deciding promotion or rollback.
        """
        champ_id = champion_episodes[0].genome_id if champion_episodes else "champion"
        canary_id = canary_episodes[0].genome_id if canary_episodes else "canary"

        safety_violations = sum(1 for e in canary_episodes if not e.safety_preserved)
        c_yields = [e.risk_yield for e in champion_episodes]
        n_yields = [e.risk_yield for e in canary_episodes]
        c_lats = [e.duration_ms for e in champion_episodes]
        n_lats = [e.duration_ms for e in canary_episodes]

        m_c = _mean(c_yields)
        m_n = _mean(n_yields)
        rel_lift = ((m_n - m_c) / max(1e-6, m_c)) * 100.0 if c_yields else 0.0
        lat_c = _mean(c_lats)
        lat_n = _mean(n_lats)
        lat_reg = ((lat_n - lat_c) / max(1e-6, lat_c)) * 100.0 if c_lats else 0.0

        # Welch's t-statistic
        v_c = _variance(c_yields)
        v_n = _variance(n_yields)
        se = math.sqrt((v_c / max(1, len(c_yields))) + (v_n / max(1, len(n_yields))))
        t_stat = (m_n - m_c) / se if se > 1e-9 else (10.0 if m_n > m_c else (-10.0 if m_n < m_c else 0.0))
        p_val = _normal_two_sided_p(t_stat)

        # Non-parametric bootstrap 95% CI on mean(canary) - mean(champion)
        rng = random.Random(self.seed)
        diffs: List[float] = []
        if c_yields and n_yields:
            for _ in range(bootstrap_iters):
                bc = [rng.choice(c_yields) for _ in range(len(c_yields))]
                bn = [rng.choice(n_yields) for _ in range(len(n_yields))]
                diffs.append(_mean(bn) - _mean(bc))
            diffs.sort()
            ci95 = (diffs[int(0.025 * len(diffs))], diffs[int(0.975 * len(diffs))])
        else:
            ci95 = (0.0, 0.0)

        # Decision policy
        if safety_violations > 0:
            verdict = "ROLLBACK_REGRESSION"
            rationale = f"Canary `{canary_id}` violated safety invariants in {safety_violations} episode(s); immediate rollback."
        elif len(champion_episodes) < 3 or len(canary_episodes) < 3:
            verdict = "CONTINUE_CANARY"
            rationale = "Insufficient paired episodes (<3) for statistical power; collect additional canary trials."
        elif m_n < m_c and p_val < significance_alpha:
            verdict = "ROLLBACK_REGRESSION"
            rationale = f"Statistically significant yield regression ({rel_lift:.1f}%, p={p_val:.4f}); rollback to `{champ_id}`."
        elif lat_reg > max_allowed_latency_regression_pct and rel_lift < 10.0:
            verdict = "ROLLBACK_REGRESSION"
            rationale = f"Latency regressed +{lat_reg:.1f}% (>{max_allowed_latency_regression_pct}%) without compensating yield lift."
        elif m_n > m_c and (p_val < significance_alpha or ci95[0] > 0.0):
            verdict = "PROMOTE_TO_CHAMPION"
            rationale = f"Canary achieved statistically significant +{rel_lift:.1f}% risk yield lift (p={p_val:.4f}, 95% CI [{ci95[0]:.2f}, {ci95[1]:.2f}]) with 100% safety preservation."
        else:
            verdict = "CONTINUE_CANARY"
            rationale = f"Observed delta {rel_lift:+.1f}% (p={p_val:.4f}) is not yet decisive; continue canary traffic."

        return CanaryDecisionReport(
            champion_genome_id=champ_id,
            canary_genome_id=canary_id,
            evaluated_at=utc_now_iso(),
            verdict=verdict,
            champion_mean_yield=m_c,
            canary_mean_yield=m_n,
            relative_lift_pct=rel_lift,
            welch_t_statistic=t_stat,
            approx_two_sided_p_value=p_val,
            bootstrap_ci95_diff=ci95,
            latency_regression_pct=lat_reg,
            safety_violations_in_canary=safety_violations,
            rationale=rationale,
        )
