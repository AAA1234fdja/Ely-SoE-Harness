"""
Statistical Security Benchmark Metrics Calculator (Second Part, Section 5).

Evaluates any `(Model x HarnessConfiguration)` pair against `ElyLabCorpus` on all
6 required dimensions:
  1. Known lab vulnerability detection (True Positives / Recall)
  2. False Positives (FP), False Negatives (FN), Precision, F1-Score, FDR
  3. Reproducibility Rate (fraction of detections independently reproduced via PoC)
  4. Code Coverage Ratio (files & attack-surface fraction analyzed)
  5. Proposed Remediation / Patch Quality Score (verified PoC neutralization without regression)
  6. Per-Category Detection Breakdown across all 10 Security Domains + CVSS Calibration MAE

Also computes the **Harness Lift Summary** empirically quantifying how much a strong
harness elevates GLM 5.3 compared to bare-model execution and Frontier reference models.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from ely_soe.benchmark.corpus import CleanDecoySpecimen, ElyLabCorpus, GroundTruthSpecimen
from ely_soe.core.models import (
    BenchmarkRunMetrics,
    Finding,
    FindingStatus,
    SecurityDomain,
)


class BenchmarkMetricsCalculator:
    """Computes rigorous detection, reproducibility, coverage, and patch-quality metrics."""

    def evaluate_run(
        self,
        model_id: str,
        harness_config: str,
        corpus: ElyLabCorpus,
        emitted_findings: List[Finding],
        files_analyzed: int,
        patch_quality_scores: List[float],
        duration_seconds: float,
        estimated_tokens: int,
    ) -> BenchmarkRunMetrics:
        # Only count non-FALSE_POSITIVE findings as positive predictions!
        # (If independent validator filtered out an FP, it is NOT counted as a false alarm!)
        active_preds = [f for f in emitted_findings if f.status != FindingStatus.FALSE_POSITIVE]

        matched_vuln_ids: Set[str] = set()
        reproduced_vuln_ids: Set[str] = set()
        cvss_errors: List[float] = []
        fp_count = 0

        decoy_paths = {d.file_path for d in corpus.decoys}
        spec_by_path: Dict[str, List[GroundTruthSpecimen]] = {}
        for s in corpus.specimens:
            spec_by_path.setdefault(s.file_path, []).append(s)

        matched_pred_indices: Set[int] = set()

        for idx, pred in enumerate(active_preds):
            p_path = pred.location.file_path.replace("\\", "/")

            # Hit on a clean decoy file -> guaranteed False Positive!
            if p_path in decoy_paths or p_path.startswith("hardened/"):
                fp_count += 1
                continue

            # Check if prediction matches a known ground-truth vulnerability
            candidates = spec_by_path.get(p_path, [])
            matched_spec = None
            for spec in candidates:
                if spec.domain == pred.domain:
                    matched_spec = spec
                    break

            if matched_spec is not None:
                matched_pred_indices.add(idx)
                matched_vuln_ids.add(matched_spec.vuln_id)
                cvss_errors.append(abs(pred.cvss_score - matched_spec.true_cvss))
                if pred.status == FindingStatus.CONFIRMED and pred.validation is not None:
                    if pred.validation.reproducibility_ratio >= 0.66:
                        reproduced_vuln_ids.add(matched_spec.vuln_id)
            else:
                # Hallucinated / unmatched finding
                fp_count += 1

        tp = len(matched_vuln_ids)
        fn = corpus.total_vulnerabilities - tp
        fp = fp_count

        precision = tp / float(tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / float(tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        fdr = fp / float(tp + fp) if (tp + fp) > 0 else 0.0
        repro_rate = len(reproduced_vuln_ids) / float(tp) if tp > 0 else 0.0

        total_corpus_files = corpus.total_vulnerabilities + corpus.total_decoys
        coverage = min(1.0, files_analyzed / float(max(1, total_corpus_files)))
        patch_q = sum(patch_quality_scores) / float(len(patch_quality_scores)) if patch_quality_scores else 0.0
        cvss_mae = sum(cvss_errors) / float(len(cvss_errors)) if cvss_errors else 2.5

        # Per-domain breakdown across all 10 Ely security domains
        per_dom_recall: Dict[str, float] = {}
        per_dom_f1: Dict[str, float] = {}
        for dom, specs in corpus.specimens_by_domain().items():
            dom_tp = sum(1 for s in specs if s.vuln_id in matched_vuln_ids)
            dom_fn = len(specs) - dom_tp
            dom_fp = sum(
                1
                for i, pred in enumerate(active_preds)
                if i not in matched_pred_indices and pred.domain == dom
            )
            d_rec = dom_tp / float(dom_tp + dom_fn) if (dom_tp + dom_fn) > 0 else 1.0
            d_prec = dom_tp / float(dom_tp + dom_fp) if (dom_tp + dom_fp) > 0 else (1.0 if dom_tp == 0 else 0.0)
            d_f1 = (2.0 * d_prec * d_rec / (d_prec + d_rec)) if (d_prec + d_rec) > 0 else 0.0
            per_dom_recall[dom.value] = round(d_rec, 4)
            per_dom_f1[dom.value] = round(d_f1, 4)

        # Composite Frontier Security Index (0..100): balances F1, Reproducibility, Coverage, Patch Quality & Calibration
        cal_component = max(0.0, 1.0 - (cvss_mae / 5.0))
        composite = round(
            100.0
            * (
                0.35 * f1
                + 0.25 * repro_rate
                + 0.15 * coverage
                + 0.15 * patch_q
                + 0.10 * cal_component
            ),
            2,
        )

        return BenchmarkRunMetrics(
            model_id=model_id,
            harness_config=harness_config,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_discovery_rate=fdr,
            reproducibility_rate=repro_rate,
            code_coverage_ratio=coverage,
            patch_quality_score=patch_q,
            severity_calibration_mae=cvss_mae,
            per_domain_recall=per_dom_recall,
            per_domain_f1=per_dom_f1,
            duration_seconds=duration_seconds,
            estimated_tokens=estimated_tokens,
            composite_frontier_index=composite,
        )

    @staticmethod
    def compute_harness_lift_summary(runs: List[BenchmarkRunMetrics]) -> Dict[str, Any]:
        """
        Quantifies the empirical thesis:
        'Un modelo competente con un harness mediocre puede producir resultados
        bastante inferiores a los que conseguiría con un entorno bien diseñado.'
        """
        by_key = {(r.model_id, r.harness_config): r for r in runs}
        glm_bare = by_key.get(("glm-5.3", "bare_model"))
        glm_full = by_key.get(("glm-5.3", "full_soe_harness"))
        frontier_bare = by_key.get(("frontier-cyber-v2", "bare_model"))
        frontier_full = by_key.get(("frontier-cyber-v2", "full_soe_harness"))

        summary: Dict[str, Any] = {
            "total_configurations_evaluated": len(runs),
            "top_configuration": None,
            "glm_5_3_harness_lift": {},
            "glm_full_vs_frontier_bare": {},
        }
        if runs:
            best = max(runs, key=lambda r: r.composite_frontier_index)
            summary["top_configuration"] = {
                "model_id": best.model_id,
                "harness_config": best.harness_config,
                "composite_frontier_index": best.composite_frontier_index,
                "f1_score": round(best.f1_score, 4),
                "reproducibility_rate": round(best.reproducibility_rate, 4),
            }

        if glm_bare and glm_full:
            summary["glm_5_3_harness_lift"] = {
                "bare_f1": round(glm_bare.f1_score, 4),
                "full_harness_f1": round(glm_full.f1_score, 4),
                "delta_f1": round(glm_full.f1_score - glm_bare.f1_score, 4),
                "bare_fdr": round(glm_bare.false_discovery_rate, 4),
                "full_harness_fdr": round(glm_full.false_discovery_rate, 4),
                "fdr_reduction": round(glm_bare.false_discovery_rate - glm_full.false_discovery_rate, 4),
                "bare_reproducibility": round(glm_bare.reproducibility_rate, 4),
                "full_harness_reproducibility": round(glm_full.reproducibility_rate, 4),
                "composite_index_gain": round(glm_full.composite_frontier_index - glm_bare.composite_frontier_index, 2),
            }

        if glm_full and frontier_bare:
            summary["glm_full_vs_frontier_bare"] = {
                "glm_full_composite": glm_full.composite_frontier_index,
                "frontier_bare_composite": frontier_bare.composite_frontier_index,
                "glm_with_soe_beats_bare_frontier": glm_full.composite_frontier_index > frontier_bare.composite_frontier_index,
                "delta_composite": round(glm_full.composite_frontier_index - frontier_bare.composite_frontier_index, 2),
            }

        if glm_full and frontier_full:
            summary["glm_full_vs_frontier_full"] = {
                "glm_full_composite": glm_full.composite_frontier_index,
                "frontier_full_composite": frontier_full.composite_frontier_index,
                "gap_to_frontier_full": round(frontier_full.composite_frontier_index - glm_full.composite_frontier_index, 2),
            }

        return summary
