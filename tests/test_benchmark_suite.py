"""
Tests for Layer 6 (`ely_soe.benchmark` — ELY-Bench v1.0 Comparative Suite:
GLM 5.3 vs Frontier Models × Harness Configurations).
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from ely_soe.benchmark.corpus import ElyLabCorpus
from ely_soe.benchmark.metrics import BenchmarkMetricsCalculator
from ely_soe.benchmark.runner import ComparativeBenchmarkRunner
from ely_soe.core.models import SecurityDomain
from ely_soe.soe.store import AuditHistoryStore


class TestBenchmarkCorpusAndComparativeMatrix(unittest.TestCase):
    """Validates corpus ground truth, metrics calculation, and GLM 5.3 harness lift thesis."""

    def test_corpus_covers_all_10_domains_with_25_vulns_and_10_decoys(self) -> None:
        corpus = ElyLabCorpus()
        self.assertEqual(corpus.total_vulnerabilities, 25)
        self.assertEqual(corpus.total_decoys, 10)
        covered_domains = set(corpus.specimens_by_domain().keys())
        self.assertEqual(covered_domains, set(SecurityDomain))

        mat_dir = corpus.materialize()
        try:
            self.assertTrue(mat_dir.exists())
            files = list(mat_dir.rglob("*"))
            self.assertGreaterEqual(len([f for f in files if f.is_file()]), 30)
        finally:
            shutil.rmtree(mat_dir, ignore_errors=True)

    def test_comparative_matrix_proves_harness_lift_and_persists_to_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditHistoryStore(Path(tmp) / "bench.sqlite3")
            runner = ComparativeBenchmarkRunner(store=store)
            exp = runner.run_matrix(
                models=["glm-5.3", "frontier-cyber-v2", "baseline-small"],
                harness_configs=["bare_model", "static_only", "harness_no_validator", "full_soe_harness"],
                fast_validation_trials=1,
            )
            self.assertEqual(len(exp.runs), 12)

            # Verify GLM 5.3 + Full SOE Harness outperforms bare GLM 5.3 AND bare Frontier Cyber v2!
            glm_bare = next(r for r in exp.runs if r.model_id == "glm-5.3" and r.harness_config == "bare_model")
            glm_full = next(r for r in exp.runs if r.model_id == "glm-5.3" and r.harness_config == "full_soe_harness")
            frontier_bare = next(r for r in exp.runs if r.model_id == "frontier-cyber-v2" and r.harness_config == "bare_model")

            self.assertGreater(glm_full.f1_score, glm_bare.f1_score)
            self.assertGreater(glm_full.reproducibility_rate, 0.85)
            self.assertEqual(glm_bare.reproducibility_rate, 0.0)
            self.assertGreater(glm_full.composite_frontier_index, frontier_bare.composite_frontier_index)

            lift = exp.harness_lift_summary
            self.assertTrue(lift["glm_full_vs_frontier_bare"]["glm_with_soe_beats_bare_frontier"])

            # Markdown rendering & SQLite persistence
            md = runner.render_markdown_report(exp)
            self.assertIn("ELY-Bench Experimental Report", md)
            self.assertIn("glm-5.3", md)

            saved = store.list_benchmarks(limit=5)
            self.assertEqual(len(saved), 1)
            self.assertEqual(saved[0]["experiment_id"], exp.experiment_id)


if __name__ == "__main__":
    unittest.main()
