"""
Online Scientific Calibration, PR-AUC / ROC-AUC, Temperature-Scaling Recalibrator &
CUSUM Telemetry Drift Evaluator for Harness² (`OnlineMetaTelemetryEvaluator`).

A security evaluation harness is only scientifically trustworthy if its reported confidence
probabilities are calibrated (i.e., when the harness predicts 0.90 confidence across 100
findings, ~90 should be true positives!) and its precision/recall does not silently degrade.

Pure zero-dependency Python 3.11 mathematical implementation providing:
  1. **Exact Calibration Metrics**:
       - **Expected Calibration Error (ECE)** across `M` uniform confidence bins
       - **Maximum Calibration Error (MCE)** (worst-case overconfidence spike)
       - **Brier Score** (`(1/N) * sum((p_i - y_i)^2)`)
       - Per-bin reliability diagram table `(bin_range, count, avg_conf, empirical_acc, gap)`.
  2. **Exact Ranking Quality Curves (Trapezoidal Integration)**:
       - **ROC-AUC** (Receiver Operating Characteristic Area Under Curve)
       - **PR-AUC** (Precision-Recall Area Under Curve — critical for imbalanced security scans)
       - **Optimal F1 Operating Threshold** (`best_threshold`, `best_f1`, `precision`, `recall`).
  3. **Deterministic Temperature-Scaling Probability Recalibrator**:
       - Fits optimal logit temperature `T* > 0` minimizing Negative Log-Likelihood (NLL /
         cross-entropy) via 1D golden-section / grid refinement search, proving empirical
         reduction in Brier Score and ECE without changing rank ordering!
  4. **Two-Sided Page-CUSUM Sequential Drift Monitor**:
       - Tracks run-over-run streams of F1, false-positive rate, or latency, raising an
         exact changepoint alarm (`DRIFT_ALARM_TRIGGERED`) when cumulative standardized
         deviation exceeds control threshold `h`.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ely_soe.core.models import utc_now_iso


@dataclass(frozen=True)
class ReliabilityBin:
    bin_index: int
    lower: float
    upper: float
    count: int
    avg_confidence: float
    empirical_accuracy: float
    abs_gap: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bin": f"[{self.lower:.2f}, {self.upper:.2f}]",
            "count": self.count,
            "avg_confidence": round(self.avg_confidence, 4),
            "empirical_accuracy": round(self.empirical_accuracy, 4),
            "abs_gap": round(self.abs_gap, 4),
        }


class OnlineMetaTelemetryEvaluator:
    """Scientific probability calibration, ROC/PR-AUC, temperature scaling & CUSUM drift evaluator."""

    @staticmethod
    def _clip_prob(p: float, eps: float = 1e-6) -> float:
        return max(eps, min(1.0 - eps, float(p)))

    @classmethod
    def _logit(cls, p: float) -> float:
        pc = cls._clip_prob(p)
        return math.log(pc / (1.0 - pc))

    @staticmethod
    def _sigmoid(z: float) -> float:
        if z >= 0:
            ez = math.exp(-min(z, 60.0))
            return 1.0 / (1.0 + ez)
        ez = math.exp(max(z, -60.0))
        return ez / (1.0 + ez)

    def evaluate_calibration(
        self,
        probabilities: Sequence[float],
        labels: Sequence[int],
        *,
        num_bins: int = 10,
    ) -> Dict[str, Any]:
        """Compute ECE, MCE, Brier Score, NLL, and reliability diagram bins."""
        if len(probabilities) != len(labels) or not probabilities:
            raise ValueError("`probabilities` and `labels` must be non-empty sequences of equal length.")
        n = len(probabilities)
        probs = [max(0.0, min(1.0, float(p))) for p in probabilities]
        ys = [1 if int(y) > 0 else 0 for y in labels]

        brier = sum((p - y) ** 2 for p, y in zip(probs, ys)) / n
        nll = -sum(
            y * math.log(self._clip_prob(p)) + (1 - y) * math.log(1.0 - self._clip_prob(p))
            for p, y in zip(probs, ys)
        ) / n

        bins_out: List[ReliabilityBin] = []
        ece = 0.0
        mce = 0.0
        step = 1.0 / max(2, num_bins)
        for b in range(max(2, num_bins)):
            lo = b * step
            hi = (b + 1) * step
            members = [
                (p, y) for p, y in zip(probs, ys)
                if (lo <= p <= hi if b == num_bins - 1 else lo <= p < hi)
            ]
            if not members:
                continue
            avg_c = sum(p for p, _ in members) / len(members)
            emp_a = sum(y for _, y in members) / len(members)
            gap = abs(avg_c - emp_a)
            ece += (len(members) / n) * gap
            mce = max(mce, gap)
            bins_out.append(ReliabilityBin(b, lo, hi, len(members), avg_c, emp_a, gap))

        roc_auc = self.compute_roc_auc(probs, ys)
        pr_auc = self.compute_pr_auc(probs, ys)
        best_op = self.find_optimal_f1_threshold(probs, ys)

        return {
            "evaluated_at": utc_now_iso(),
            "sample_count": n,
            "positive_rate": round(sum(ys) / n, 4),
            "ece": round(ece, 4),
            "mce": round(mce, 4),
            "brier_score": round(brier, 4),
            "negative_log_likelihood": round(nll, 4),
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "optimal_f1_operating_point": best_op,
            "calibration_verdict": (
                "WELL_CALIBRATED" if ece <= 0.06 else
                "MODERATELY_CALIBRATED" if ece <= 0.12 else "RECALIBRATION_REQUIRED"
            ),
            "reliability_diagram": [b.to_dict() for b in bins_out],
        }

    def compute_roc_auc(self, probabilities: Sequence[float], labels: Sequence[int]) -> float:
        """Exact Mann-Whitney / trapezoidal ROC-AUC."""
        ys = [1 if int(y) > 0 else 0 for y in labels]
        pos = sum(ys)
        neg = len(ys) - pos
        if pos == 0 or neg == 0:
            return 1.0
        pairs = sorted(zip(probabilities, ys), key=lambda x: x[0], reverse=True)
        tp = fp = 0
        prev_tpr = prev_fpr = 0.0
        auc = 0.0
        idx = 0
        while idx < len(pairs):
            score = pairs[idx][0]
            while idx < len(pairs) and pairs[idx][0] == score:
                if pairs[idx][1] == 1:
                    tp += 1
                else:
                    fp += 1
                idx += 1
            tpr = tp / pos
            fpr = fp / neg
            auc += (fpr - prev_fpr) * (tpr + prev_tpr) * 0.5
            prev_tpr, prev_fpr = tpr, fpr
        return max(0.0, min(1.0, auc))

    def compute_pr_auc(self, probabilities: Sequence[float], labels: Sequence[int]) -> float:
        """Exact Average Precision / PR-AUC under imbalanced security detections."""
        ys = [1 if int(y) > 0 else 0 for y in labels]
        pos = sum(ys)
        if pos == 0:
            return 0.0
        pairs = sorted(zip(probabilities, ys), key=lambda x: x[0], reverse=True)
        tp = fp = 0
        prev_rec = 0.0
        ap = 0.0
        for _, y in pairs:
            if y == 1:
                tp += 1
                prec = tp / (tp + fp)
                rec = tp / pos
                ap += (rec - prev_rec) * prec
                prev_rec = rec
            else:
                fp += 1
        return max(0.0, min(1.0, ap))

    def find_optimal_f1_threshold(
        self,
        probabilities: Sequence[float],
        labels: Sequence[int],
    ) -> Dict[str, float]:
        ys = [1 if int(y) > 0 else 0 for y in labels]
        thresholds = sorted(set([round(float(p), 4) for p in probabilities] + [0.5]))
        best = {"threshold": 0.5, "f1": 0.0, "precision": 0.0, "recall": 0.0}
        for th in thresholds:
            tp = sum(1 for p, y in zip(probabilities, ys) if p >= th and y == 1)
            fp = sum(1 for p, y in zip(probabilities, ys) if p >= th and y == 0)
            fn = sum(1 for p, y in zip(probabilities, ys) if p < th and y == 1)
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
            if f1 > best["f1"]:
                best = {
                    "threshold": round(th, 4),
                    "f1": round(f1, 4),
                    "precision": round(prec, 4),
                    "recall": round(rec, 4),
                }
        return best

    def fit_temperature_scaling(
        self,
        probabilities: Sequence[float],
        labels: Sequence[int],
    ) -> Dict[str, Any]:
        """Fit optimal temperature T* minimizing NLL via coarse-to-fine deterministic search."""
        before = self.evaluate_calibration(probabilities, labels)
        logits = [self._logit(p) for p in probabilities]
        ys = [1 if int(y) > 0 else 0 for y in labels]

        def _nll(temp: float) -> float:
            scaled = [self._sigmoid(z / temp) for z in logits]
            return -sum(
                y * math.log(self._clip_prob(p)) + (1 - y) * math.log(1.0 - self._clip_prob(p))
                for p, y in zip(scaled, ys)
            ) / len(ys)

        # Coarse grid [0.25 .. 6.0] then fine refinement around best T
        best_t = 1.0
        best_loss = _nll(1.0)
        for step_i in range(25, 601, 10):
            t = step_i / 100.0
            loss = _nll(t)
            if loss < best_loss:
                best_loss, best_t = loss, t

        lo = max(0.15, best_t - 0.15)
        hi = best_t + 0.15
        for k in range(61):
            t = lo + (hi - lo) * (k / 60.0)
            loss = _nll(t)
            if loss < best_loss:
                best_loss, best_t = loss, t

        recalibrated = [round(self._sigmoid(z / best_t), 6) for z in logits]
        after = self.evaluate_calibration(recalibrated, ys)
        return {
            "calibrated_at": utc_now_iso(),
            "optimal_temperature": round(best_t, 4),
            "before_calibration": {
                "ece": before["ece"],
                "brier_score": before["brier_score"],
                "nll": before["negative_log_likelihood"],
                "roc_auc": before["roc_auc"],
            },
            "after_calibration": {
                "ece": after["ece"],
                "brier_score": after["brier_score"],
                "nll": after["negative_log_likelihood"],
                "roc_auc": after["roc_auc"],
            },
            "ece_reduction": round(before["ece"] - after["ece"], 4),
            "brier_reduction": round(before["brier_score"] - after["brier_score"], 4),
            "rank_ordering_preserved": abs(before["roc_auc"] - after["roc_auc"]) < 1e-3,
            "calibrated_probabilities": recalibrated,
        }

    def run_cusum_drift_monitor(
        self,
        metric_series: Sequence[float],
        *,
        baseline_mean: float,
        baseline_std: float,
        allowance_k: float = 0.5,
        alarm_threshold_h: float = 4.0,
        metric_name: str = "harness_f1_score",
    ) -> Dict[str, Any]:
        """Two-sided standardized Page-CUSUM drift monitor detecting sudden or gradual decay."""
        sigma = max(1e-6, float(baseline_std))
        s_pos = 0.0
        s_neg = 0.0
        alarm_index: Optional[int] = None
        alarm_direction: Optional[str] = None
        trace: List[Dict[str, float]] = []

        for idx, val in enumerate(metric_series):
            z = (float(val) - float(baseline_mean)) / sigma
            s_pos = max(0.0, s_pos + z - allowance_k)
            s_neg = max(0.0, s_neg - z - allowance_k)
            trace.append({"step": idx, "value": round(float(val), 4), "s_pos": round(s_pos, 4), "s_neg": round(s_neg, 4)})
            if alarm_index is None and (s_pos > alarm_threshold_h or s_neg > alarm_threshold_h):
                alarm_index = idx
                alarm_direction = "UPWARD_SHIFT" if s_pos > alarm_threshold_h else "DOWNWARD_DEGRADATION"

        return {
            "checked_at": utc_now_iso(),
            "metric_name": metric_name,
            "samples_evaluated": len(metric_series),
            "baseline_mean": baseline_mean,
            "baseline_std": sigma,
            "alarm_threshold_h": alarm_threshold_h,
            "drift_alarm_triggered": alarm_index is not None,
            "first_alarm_step": alarm_index,
            "alarm_direction": alarm_direction,
            "max_s_pos": round(max((t["s_pos"] for t in trace), default=0.0), 4),
            "max_s_neg": round(max((t["s_neg"] for t in trace), default=0.0), 4),
            "status": "DRIFT_ALARM_TRIGGERED" if alarm_index is not None else "IN_CONTROL",
        }
